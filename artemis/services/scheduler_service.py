"""Scheduler service — background thread that executes scheduled scans."""

import json
import logging
import threading
from datetime import datetime, timedelta

from croniter import croniter

logger = logging.getLogger(__name__)

_scheduler_thread = None
_stop_event = threading.Event()


def start_scheduler(app):
    """Start the background scheduler thread."""
    global _scheduler_thread
    if _scheduler_thread and _scheduler_thread.is_alive():
        return
    _stop_event.clear()
    _scheduler_thread = threading.Thread(
        target=_scheduler_loop, args=(app,), daemon=True, name='artemis-scheduler'
    )
    _scheduler_thread.start()
    logger.info("Scheduler started")


def stop_scheduler():
    """Signal the scheduler to stop."""
    _stop_event.set()


def _now_iso():
    return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')


def _scheduler_loop(app):
    """Main loop — checks every 60s for due scheduled scans."""
    while not _stop_event.is_set():
        try:
            with app.app_context():
                _check_and_run(app)
        except Exception:
            logger.exception("Scheduler tick error")
        _stop_event.wait(60)


def _check_and_run(app):
    from artemis.extensions import db
    from artemis.models.scheduled_scan import ScheduledScan
    from artemis.models.site import Site

    now = datetime.utcnow()
    now_iso = now.strftime('%Y-%m-%dT%H:%M:%SZ')

    # Check individual scheduled scans
    due = ScheduledScan.query.filter(
        ScheduledScan.enabled == 1,
        ScheduledScan.next_run <= now_iso,
    ).all()

    from artemis.services.tenant import use_organization

    for sched in due:
        try:
            with use_organization(sched.organization_id):
                _execute_scheduled_scan(app, sched)
        except Exception:
            logger.exception(f"Failed to execute scheduled scan {sched.id}")
        finally:
            nxt = calculate_next_run(sched)
            sched.next_run = nxt
            sched.updated_at = _now_iso()
            if sched.schedule_type == 'once':
                sched.enabled = 0
            db.session.commit()

    # Check sites
    due_sites = Site.query.filter(
        Site.schedule_enabled == 1,
        Site.next_run <= now_iso,
        Site.last_status != 'running',
    ).all()

    for site in due_sites:
        try:
            from artemis.services.job_service import dispatch_site_scan
            dispatch_site_scan(site)
            site.last_status = 'queued'
        except Exception:
            logger.exception(f"Failed to queue site scan {site.id}")
            site.last_status = 'failed'
        finally:
            site.next_run = calculate_next_run_for_site(site)
            site.updated_at = _now_iso()
            db.session.commit()

    # Daily environment risk snapshot (at most once per calendar day).
    try:
        from artemis.services.risk_snapshot_service import maybe_capture_daily
        maybe_capture_daily()
    except Exception:
        logger.exception("Risk snapshot tick failed")

    # Due scheduled reports — generate + email.
    try:
        from artemis.services.report_schedule_runner import run_due_report_schedules
        run_due_report_schedules(now_iso)
    except Exception:
        logger.exception("Report schedule tick failed")


def dispatch_due_scans():
    """Beat entry point: create durable jobs for every due schedule/site.

    Unlike the legacy in-process ``_check_and_run``, this never executes a scan
    in the caller — it only enqueues jobs. Returns the number dispatched.
    """
    from artemis.extensions import db
    from artemis.models.scheduled_scan import ScheduledScan
    from artemis.models.site import Site
    from artemis.services.job_service import dispatch_adhoc_scan, dispatch_site_scan
    from artemis.services.tenant import SKIP_TENANT_FILTER, use_organization

    now_iso = _now_iso()
    dispatched = 0

    due = (ScheduledScan.query.execution_options(**{SKIP_TENANT_FILTER: True})
           .filter(ScheduledScan.enabled == 1, ScheduledScan.next_run <= now_iso).all())
    for sched in due:
        occurrence = f'sched-{sched.id}-{sched.next_run}'
        try:
            with use_organization(sched.organization_id):
                opts = json.loads(sched.scan_options_json) if sched.scan_options_json else {}
                opts.update({'schedule_id': sched.id, 'profile': sched.profile_id or opts.get('profile', ''),
                             'credential_ids': json.loads(sched.credential_ids_json or '[]')})
                dispatch_adhoc_scan(sched.target, sched.scan_type or 'port', opts,
                                    idempotency_key=occurrence)
                sched.last_run = now_iso
                sched.last_status = 'queued'
                dispatched += 1
        except Exception:
            logger.exception('Failed to dispatch scheduled scan %s', sched.id)
        finally:
            sched.next_run = calculate_next_run(sched)
            sched.updated_at = now_iso
            if sched.schedule_type == 'once':
                sched.enabled = 0
            db.session.commit()

    due_sites = (Site.query.execution_options(**{SKIP_TENANT_FILTER: True})
                 .filter(Site.schedule_enabled == 1, Site.next_run <= now_iso,
                         Site.last_status != 'running').all())
    for site in due_sites:
        try:
            with use_organization(site.organization_id):
                dispatch_site_scan(site)
                dispatched += 1
        except Exception:
            logger.exception('Failed to dispatch site scan %s', site.id)
            site.last_status = 'failed'
        finally:
            site.next_run = calculate_next_run_for_site(site)
            site.updated_at = now_iso
            db.session.commit()

    try:
        from artemis.services.risk_snapshot_service import maybe_capture_daily
        maybe_capture_daily()
    except Exception:
        logger.exception('Risk snapshot tick failed')

    return dispatched


def record_schedule_history(schedule_id, result, status, duration_seconds=0):
    """Called by the adhoc task when a job came from a schedule."""
    from artemis.extensions import db
    from artemis.models.scan_history import ScanHistory
    from artemis.models.scheduled_scan import ScheduledScan

    sched = db.session.get(ScheduledScan, schedule_id)
    if not sched:
        return
    history = ScanHistory(
        scheduled_scan_id=sched.id, target=sched.target, scan_type=sched.scan_type,
        status=status, started_at=_now_iso(), completed_at=_now_iso(),
        duration_seconds=duration_seconds,
        hosts_scanned=result.get('hosts_scanned', 0),
        ports_found=result.get('ports_found', 0),
        vulns_found=result.get('vulns_found', 0),
    )
    if status == 'success' and sched.compare_with_previous:
        delta = _compute_delta(sched, result)
        history.new_vulns = delta.get('new_vulns', 0)
        result = {**result, 'delta': delta}
    history.summary_json = json.dumps(result)
    if status != 'success':
        history.error_message = str(result.get('error', ''))[:1000]
    db.session.add(history)
    sched.last_status = status
    sched.last_duration_seconds = duration_seconds
    db.session.commit()


def _execute_scheduled_scan(app, sched):
    """Run one scheduled scan and record history."""
    from artemis.extensions import db, socketio
    from artemis.models.scan_history import ScanHistory

    start_time = datetime.utcnow()
    start_iso = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')

    history = ScanHistory(
        scheduled_scan_id=sched.id,
        target=sched.target,
        scan_type=sched.scan_type,
        status='running',
        started_at=start_iso,
    )
    db.session.add(history)
    db.session.commit()

    sched.last_run = start_iso
    sched.last_status = 'running'
    db.session.commit()

    socketio.emit('schedule_run_started', {
        'scheduled_scan_id': sched.id,
        'history_id': history.id,
        'target': sched.target,
        'scan_type': sched.scan_type,
        'started_at': start_iso,
    })

    try:
        result = _run_scan(app, sched)
        end_time = datetime.utcnow()
        duration = int((end_time - start_time).total_seconds())

        history.status = 'success'
        history.completed_at = end_time.strftime('%Y-%m-%dT%H:%M:%SZ')
        history.duration_seconds = duration
        history.hosts_scanned = result.get('hosts_scanned', 0)
        history.ports_found = result.get('ports_found', 0)
        history.vulns_found = result.get('vulns_found', 0)

        # Delta comparison
        if sched.compare_with_previous:
            delta = _compute_delta(sched, result)
            history.new_vulns = delta.get('new_vulns', 0)
            result['delta'] = delta

        history.summary_json = json.dumps(result)
        sched.last_status = 'success'
        sched.last_duration_seconds = duration

    except Exception as e:
        end_time = datetime.utcnow()
        duration = int((end_time - start_time).total_seconds())
        history.status = 'failed'
        history.completed_at = end_time.strftime('%Y-%m-%dT%H:%M:%SZ')
        history.duration_seconds = duration
        history.error_message = str(e)
        sched.last_status = 'failed'
        sched.last_duration_seconds = duration
        result = {'error': str(e)}

    db.session.commit()

    socketio.emit('schedule_run_completed', {
        'scheduled_scan_id': sched.id,
        'history_id': history.id,
        'status': history.status,
        'duration_seconds': history.duration_seconds,
        'summary': result,
    })


class _ScanCancelled(RuntimeError):
    """Cooperative cancellation between expanded targets."""


def _run_scan(app, sched, cancel_predicate=None, log_callback=None):
    """Execute the actual scan based on scan_type. Returns result dict.

    ``cancel_predicate`` is polled between expanded targets; ``log_callback`` (if
    given) receives progress lines for the job event stream.
    """
    def _check_cancel():
        if cancel_predicate and cancel_predicate():
            raise _ScanCancelled()

    def _log(msg, level='info'):
        if log_callback:
            try:
                log_callback(msg, level)
            except TypeError:
                log_callback(msg)

    scan_options = json.loads(sched.scan_options_json) if sched.scan_options_json else {}
    result = {'hosts_scanned': 0, 'ports_found': 0, 'vulns_found': 0, 'vulns': []}

    target = sched.target
    scan_type = sched.scan_type or 'port'

    # Resolve hostname targets
    from artemis.utils.validation import is_cidr, is_hostname
    from artemis.utils.network import expand_cidr
    if is_cidr(target):
        ips = expand_cidr(target, max_hosts=scan_options.get('max_hosts', 256))
    elif is_hostname(target):
        from artemis.utils.dns import resolve_target
        ips = [resolve_target(target)]
    else:
        ips = [target]

    if scan_type in ('port', 'full'):
        from artemis.scanners.nmap_scanner import (
            extract_host_info_from_scan,
            get_os_info_from_scan,
            parse_scan,
            scan as nmap_scan,
        )
        from artemis.services.scan_service import store_scan
        from artemis.services.asset_service import store_asset_info
        from artemis.utils.dns import dns_lookup

        for idx, ip in enumerate(ips):
            _check_cancel()
            _log(f'port scan {ip} ({idx + 1}/{len(ips)})')
            try:
                scan_result = nmap_scan(ip, options=scan_options, cancel_check=cancel_predicate)
                scan_data = parse_scan(scan_result)
                if scan_data:
                    store_scan(ip, scan_data)
                    result['ports_found'] += len(scan_data)

                os_info = get_os_info_from_scan(scan_result)
                host_info = extract_host_info_from_scan(scan_result)
                dns_info = dns_lookup(ip)
                store_asset_info(ip, dns_info=dns_info, os_info=os_info,
                                 mac_address=host_info.get('mac_address'),
                                 mac_vendor=host_info.get('mac_vendor'))
                result['hosts_scanned'] += 1
            except Exception as e:
                logger.warning(f"Port scan failed for {ip}: {e}")
                if scan_type == 'port' and len(ips) == 1:
                    raise

    if scan_type in ('vuln', 'full'):
        from artemis.scanners.nuclei_scanner import vuln_scan as nuclei_scan, parse_vuln_scan
        from artemis.services.vuln_service import store_vulnerabilities

        for idx, ip in enumerate(ips):
            _check_cancel()
            _log(f'vuln scan {ip} ({idx + 1}/{len(ips)})')
            try:
                nuclei_results = nuclei_scan(ip, options={
                    **scan_options,
                    'templates': sched.profile_id or scan_options.get('templates', ''),
                }, cancel_check=cancel_predicate)
                vulns = parse_vuln_scan(nuclei_results)
                if vulns:
                    store_vulnerabilities(ip, vulns)
                    result['vulns_found'] += len(vulns)
                    result['vulns'].extend([{'id': v['vuln_id'], 'name': v['vuln_name'],
                                             'severity': v['severity']} for v in vulns])
                if scan_type == 'vuln':
                    result['hosts_scanned'] += 1
            except Exception as e:
                logger.warning(f"Vuln scan failed for {ip}: {e}")
                if scan_type == 'vuln' and len(ips) == 1:
                    raise

    if scan_type == 'auth':
        from artemis.scanners.ssh_scanner import run_authenticated_scan
        from artemis.services.auth_scan_service import (
            get_all_credentials,
            get_credential,
            get_setting,
            resolve_credential_secrets,
            store_auth_scan_results,
        )
        from artemis.services.scan_service import get_open_ports_for_ip

        cred_ids = json.loads(sched.credential_ids_json) if sched.credential_ids_json else []
        if cred_ids:
            creds = [c for c in (get_credential(int(cid)) for cid in cred_ids) if c]
        else:
            creds = get_all_credentials()
        nvd_api_key = get_setting('nvd_api_key', '') or None
        logs = []

        for idx, ip in enumerate(ips):
            _check_cancel()
            _log(f'auth scan {ip} ({idx + 1}/{len(ips)})')
            open_ports = get_open_ports_for_ip(ip)
            if not open_ports:
                # No prior port data — probe the common SSH ports first so a
                # non-standard sshd is found (parity with the socket path). Kept
                # narrow and short so it never dominates the scan.
                try:
                    from artemis.scanners.nmap_scanner import scan as nmap_scan, parse_scan
                    from artemis.services.scan_service import store_scan
                    scan_data = parse_scan(nmap_scan(ip, options={
                        'ports': '22,2222,2200', 'host_timeout': 30,
                    }))
                    if scan_data:
                        store_scan(ip, scan_data)
                    open_ports = get_open_ports_for_ip(ip)
                except Exception as e:
                    logger.warning(f"Pre-auth SSH probe failed for {ip}: {e}")
            ssh_ports = [p['port'] for p in open_ports
                         if p['port'] in (22, 2222, 2200) or p.get('service') in ('ssh', 'openssh')]
            if not ssh_ports:
                ssh_ports = [22]

            done = False
            for cred in creds:
                if cred['cred_type'] not in ('ssh_key', 'ssh_password'):
                    continue
                for port in ssh_ports:
                    try:
                        secrets = resolve_credential_secrets(cred['id'], reason='scheduled_auth_scan')
                        auth_result = run_authenticated_scan(
                            host=ip, port=port, username=cred['username'],
                            password=secrets.get('password') if cred['cred_type'] == 'ssh_password' else None,
                            key_data=secrets.get('key_data') if cred['cred_type'] == 'ssh_key' else None,
                            nvd_api_key=nvd_api_key,
                            log_callback=lambda m, lvl='info': logs.append(m),
                        )
                        # store_auth_scan_results also enriches the asset row
                        # (hostname, MAC, OS) and reclassifies the device.
                        store_auth_scan_results(ip, auth_result['os_info'],
                                                auth_result['packages'], auth_result['cves'])
                        result['hosts_scanned'] += 1
                        result.setdefault('packages_found', 0)
                        result['packages_found'] += len(auth_result['packages'])
                        result['vulns_found'] += len(auth_result['cves'])
                        result['vulns'].extend([{'id': c['cve_id'], 'name': c['cve_id'],
                                                  'severity': c.get('severity', 'medium')}
                                                 for c in auth_result['cves']])
                        done = True
                        break
                    except Exception as e:
                        logger.warning(f"Auth scan failed for {ip}:{port} ({cred['name']}): {e}")
                if done:
                    break
        if logs:
            result['log_tail'] = logs[-40:]

    return result


def _compute_delta(sched, current_result):
    """Compare current scan results with the previous run for the same scheduled scan."""
    from artemis.models.scan_history import ScanHistory

    prev = ScanHistory.query.filter(
        ScanHistory.scheduled_scan_id == sched.id,
        ScanHistory.status == 'success',
    ).order_by(ScanHistory.id.desc()).first()

    if not prev or not prev.summary_json:
        return {'new_vulns': current_result.get('vulns_found', 0), 'removed_vulns': 0, 'note': 'no previous scan'}

    try:
        prev_data = json.loads(prev.summary_json)
        prev_vulns = {v.get('id', v.get('name', '')) for v in prev_data.get('vulns', [])}
        curr_vulns = {v.get('id', v.get('name', '')) for v in current_result.get('vulns', [])}
        new = curr_vulns - prev_vulns
        removed = prev_vulns - curr_vulns
        return {
            'new_vulns': len(new),
            'removed_vulns': len(removed),
            'new_vuln_ids': list(new),
            'removed_vuln_ids': list(removed),
        }
    except Exception:
        return {'new_vulns': 0, 'removed_vulns': 0, 'note': 'delta parse error'}


def calculate_next_run(sched):
    """Calculate the next run time for a scheduled scan. Returns ISO string or None."""
    now = datetime.utcnow()
    st = sched.schedule_type

    if st == 'once':
        return None
    elif st == 'hourly':
        nxt = now.replace(minute=sched.schedule_minute or 0, second=0, microsecond=0)
        if nxt <= now:
            nxt += timedelta(hours=1)
        return nxt.strftime('%Y-%m-%dT%H:%M:%SZ')
    elif st == 'daily':
        nxt = now.replace(hour=sched.schedule_hour or 2, minute=sched.schedule_minute or 0, second=0, microsecond=0)
        if nxt <= now:
            nxt += timedelta(days=1)
        return nxt.strftime('%Y-%m-%dT%H:%M:%SZ')
    elif st == 'weekly':
        dow = sched.schedule_day_of_week or 0
        days_ahead = dow - now.weekday()
        if days_ahead < 0:
            days_ahead += 7
        nxt = now + timedelta(days=days_ahead)
        nxt = nxt.replace(hour=sched.schedule_hour or 2, minute=sched.schedule_minute or 0, second=0, microsecond=0)
        if nxt <= now:
            nxt += timedelta(weeks=1)
        return nxt.strftime('%Y-%m-%dT%H:%M:%SZ')
    elif st == 'monthly':
        dom = sched.schedule_day_of_month or 1
        try:
            nxt = now.replace(
                day=dom, hour=sched.schedule_hour or 2,
                minute=sched.schedule_minute or 0, second=0, microsecond=0,
            )
        except ValueError:
            nxt = now.replace(
                day=28, hour=sched.schedule_hour or 2,
                minute=sched.schedule_minute or 0, second=0, microsecond=0,
            )
        if nxt <= now:
            if now.month == 12:
                nxt = nxt.replace(year=now.year + 1, month=1)
            else:
                nxt = nxt.replace(month=now.month + 1)
        return nxt.strftime('%Y-%m-%dT%H:%M:%SZ')
    elif st == 'cron' and sched.cron_expression:
        cron = croniter(sched.cron_expression, now)
        nxt = cron.get_next(datetime)
        return nxt.strftime('%Y-%m-%dT%H:%M:%SZ')
    return None


def calculate_next_run_for_site(site):
    """Calculate next run for a Site — reuses the same schedule logic."""
    # Create a lightweight object with the same schedule attributes
    class _Sched:
        pass
    s = _Sched()
    s.schedule_type = site.schedule_type
    s.schedule_hour = site.schedule_hour
    s.schedule_minute = site.schedule_minute
    s.schedule_day_of_week = site.schedule_day_of_week
    s.schedule_day_of_month = site.schedule_day_of_month
    s.cron_expression = site.cron_expression
    return calculate_next_run(s)
