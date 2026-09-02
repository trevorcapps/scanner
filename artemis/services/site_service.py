"""Site service — execute site-level scans across all targets."""

import json
import logging
from datetime import datetime

from artemis.extensions import db, socketio
from artemis.models.site import Site
from artemis.models.site_scan import SiteScan
from artemis.utils.validation import is_cidr, is_hostname
from artemis.utils.network import expand_cidr
from artemis.utils.dns import resolve_target, ScanError

logger = logging.getLogger(__name__)


def _now_iso():
    return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')


def resolve_site_targets(site):
    """Expand all site targets into individual IPs, excluding exclusions."""
    excluded = set()
    for exc in site.excluded_targets:
        exc = exc.strip()
        if is_cidr(exc):
            excluded.update(expand_cidr(exc, max_hosts=4096))
        else:
            excluded.add(exc)

    ips = []
    seen = set()
    scan_options = json.loads(site.scan_options_json) if site.scan_options_json else {}
    max_hosts = scan_options.get('max_hosts', 1024)

    for target in site.targets:
        target = target.strip()
        if not target:
            continue
        if is_cidr(target):
            for ip in expand_cidr(target, max_hosts=max_hosts):
                if ip not in excluded and ip not in seen:
                    ips.append(ip)
                    seen.add(ip)
        elif is_hostname(target):
            try:
                resolved = resolve_target(target)
                if resolved not in excluded and resolved not in seen:
                    # Keep hostname for scanning (SNI), store resolved IP for dedup
                    ips.append(target)
                    seen.add(resolved)
            except ScanError:
                ips.append(target)  # Let it fail at scan time
        else:
            if target not in excluded and target not in seen:
                ips.append(target)
                seen.add(target)

    return ips


def execute_site_scan(app, site, job=None):
    """Run a full site scan across all targets. Called by scheduler or manual trigger."""
    start_time = datetime.utcnow()
    start_iso = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')

    targets = resolve_site_targets(site)
    scan_options = json.loads(site.scan_options_json) if site.scan_options_json else {}
    scan_type = site.scan_type or 'full'

    site_scan = SiteScan(
        site_id=site.id,
        status='running',
        started_at=start_iso,
        targets_total=len(targets),
    )
    db.session.add(site_scan)
    db.session.commit()

    site.last_run = start_iso
    site.last_status = 'running'
    db.session.commit()

    socketio.emit('site_scan_started', {
        'site_id': site.id,
        'site_scan_id': site_scan.id,
        'site_name': site.name,
        'targets_total': len(targets),
        'started_at': start_iso,
    })
    socketio.emit('scan_log', {'message': f'[{site.name}] Site scan started — {len(targets)} target(s), mode: {scan_type}', 'level': 'info'})

    per_target_results = []
    total_ports = 0
    total_vulns = 0
    targets_ok = 0
    targets_fail = 0
    cancelled = False

    def _site_log(message, level='info'):
        """Emit a scan_log event so the UI log panel picks it up."""
        socketio.emit('scan_log', {'message': f'[{site.name}] {message}', 'level': level})

    for idx, target in enumerate(targets):
        if job:
            db.session.refresh(job)
            if job.status == 'cancel_requested':
                cancelled = True
                _site_log('Cancellation acknowledged; no additional targets will start', 'warning')
                break

        target_result = {'target': target, 'ports': 0, 'vulns': 0, 'status': 'pending', 'error': None}

        try:
            socketio.emit('site_scan_progress', {
                'site_scan_id': site_scan.id,
                'current': idx + 1,
                'total': len(targets),
                'target': target,
            })
            _site_log(f'Scanning target {idx + 1}/{len(targets)}: {target}')

            # Port scan
            if scan_type in ('port', 'full'):
                target_result['ports'] = _run_port_scan(target, scan_options)
                total_ports += target_result['ports']
                _site_log(f'{target}: {target_result["ports"]} open port(s)', 'success' if target_result['ports'] else 'info')

            # Vuln scan
            if scan_type in ('vuln', 'full'):
                target_result['vulns'] = _run_vuln_scan(target, site.profile_id, scan_options)
                total_vulns += target_result['vulns']
                if target_result['vulns']:
                    _site_log(f'{target}: {target_result["vulns"]} vulnerability(ies) found', 'warning')

            # Auth scan
            if scan_type == 'auth':
                cred_ids = json.loads(site.credential_ids_json) if site.credential_ids_json else []
                target_result['vulns'] = _run_auth_scan(target, cred_ids)
                total_vulns += target_result['vulns']

            target_result['status'] = 'success'
            targets_ok += 1

        except Exception as e:
            target_result['status'] = 'failed'
            target_result['error'] = str(e)
            targets_fail += 1
            _site_log(f'{target} failed: {e}', 'error')
            logger.warning(f"Site scan target {target} failed: {e}")

        per_target_results.append(target_result)

        # Update progress in DB periodically
        if idx % 5 == 0 or idx == len(targets) - 1:
            site_scan.targets_scanned = targets_ok
            site_scan.targets_failed = targets_fail
            site_scan.ports_found = total_ports
            site_scan.vulns_found = total_vulns
            db.session.commit()

    # Finalize
    end_time = datetime.utcnow()
    duration = int((end_time - start_time).total_seconds())

    # Delta comparison
    new_vulns = 0
    removed_vulns = 0
    if site.compare_with_previous:
        delta = _compute_site_delta(site, per_target_results)
        new_vulns = delta.get('new_vulns', 0)
        removed_vulns = delta.get('removed_vulns', 0)

    if cancelled:
        final_status = 'cancelled'
    else:
        final_status = 'success' if targets_fail == 0 else ('partial' if targets_ok > 0 else 'failed')

    site_scan.status = final_status
    site_scan.completed_at = end_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    site_scan.duration_seconds = duration
    site_scan.targets_scanned = targets_ok
    site_scan.targets_failed = targets_fail
    site_scan.ports_found = total_ports
    site_scan.vulns_found = total_vulns
    site_scan.new_vulns = new_vulns
    site_scan.removed_vulns = removed_vulns
    site_scan.summary_json = json.dumps(per_target_results)

    site.last_status = final_status
    site.last_duration_seconds = duration
    db.session.commit()

    socketio.emit('site_scan_completed', {
        'site_id': site.id,
        'site_scan_id': site_scan.id,
        'status': final_status,
        'duration_seconds': duration,
        'targets_scanned': targets_ok,
        'targets_failed': targets_fail,
        'ports_found': total_ports,
        'vulns_found': total_vulns,
        'new_vulns': new_vulns,
        'removed_vulns': removed_vulns,
    })

    return site_scan


def _run_port_scan(target, scan_options):
    """Run port scan on a single target. Returns port count."""
    from artemis.scanners.nmap_scanner import scan as nmap_scan, parse_scan, get_os_info_from_scan, extract_host_info_from_scan
    from artemis.services.scan_service import store_scan
    from artemis.services.asset_service import store_asset_info
    from artemis.utils.dns import dns_lookup

    store_ip = target
    if is_hostname(target):
        store_ip = resolve_target(target)

    scan_result = nmap_scan(target, options=scan_options)
    scan_data = parse_scan(scan_result)

    os_info = get_os_info_from_scan(scan_result)
    host_info = extract_host_info_from_scan(scan_result)
    dns_info = dns_lookup(store_ip)
    store_asset_info(store_ip, dns_info=dns_info, os_info=os_info,
                     mac_address=host_info.get('mac_address'),
                     mac_vendor=host_info.get('mac_vendor'))

    if scan_data:
        store_scan(store_ip, scan_data)
        return len(scan_data)
    return 0


def _run_vuln_scan(target, profile_id, scan_options):
    """Run Nuclei vuln scan on a single target. Returns vuln count."""
    from artemis.scanners.nuclei_scanner import vuln_scan as nuclei_scan, parse_vuln_scan
    from artemis.services.vuln_service import store_vulnerabilities

    store_ip = target
    if is_hostname(target):
        store_ip = resolve_target(target)

    opts = {**scan_options}
    if profile_id:
        opts['templates'] = profile_id

    results = nuclei_scan(target, options=opts)
    vulns = parse_vuln_scan(results)
    if vulns:
        store_vulnerabilities(store_ip, vulns)
        return len(vulns)
    return 0


def _run_auth_scan(target, cred_ids):
    """Run auth scan on a single target. Returns CVE count."""
    from artemis.scanners.ssh_scanner import run_authenticated_scan
    from artemis.services.auth_scan_service import store_auth_scan_results, get_credential
    from artemis.services.scan_service import get_open_ports_for_ip

    store_ip = target
    if is_hostname(target):
        store_ip = resolve_target(target)

    creds = [get_credential(int(cid)) for cid in cred_ids]
    creds = [c for c in creds if c]
    if not creds:
        return 0

    open_ports = get_open_ports_for_ip(store_ip)
    ssh_ports = [p['port'] for p in open_ports
                 if p['port'] in (22, 2222, 2200) or p.get('service') in ('ssh', 'openssh')]
    if not ssh_ports:
        ssh_ports = [22]

    for cred in creds:
        for port in ssh_ports:
            try:
                result = run_authenticated_scan(
                    host=store_ip, port=port, username=cred['username'],
                    password=cred.get('password') if cred['cred_type'] == 'ssh_password' else None,
                    key_path=cred.get('key_path') if cred['cred_type'] == 'ssh_key' else None,
                )
                store_auth_scan_results(store_ip, result['os_info'], result['packages'], result['cves'])
                return len(result['cves'])
            except Exception:
                continue
    return 0


def _compute_site_delta(site, current_results):
    """Compare current site scan with previous for delta."""
    prev = SiteScan.query.filter(
        SiteScan.site_id == site.id,
        SiteScan.status.in_(['success', 'partial']),
    ).order_by(SiteScan.id.desc()).first()

    if not prev or not prev.summary_json:
        return {'new_vulns': sum(r.get('vulns', 0) for r in current_results), 'removed_vulns': 0}

    try:
        prev_results = json.loads(prev.summary_json)
        prev_targets = {r['target']: r for r in prev_results}
        curr_targets = {r['target']: r for r in current_results}

        # Simple delta: count targets that got new vulns or lost vulns
        new_vulns = 0
        removed_vulns = 0
        for target, curr in curr_targets.items():
            prev_r = prev_targets.get(target, {})
            curr_v = curr.get('vulns', 0)
            prev_v = prev_r.get('vulns', 0)
            if curr_v > prev_v:
                new_vulns += (curr_v - prev_v)
            elif curr_v < prev_v:
                removed_vulns += (prev_v - curr_v)

        # New targets = all their vulns are new
        for target in set(curr_targets) - set(prev_targets):
            new_vulns += curr_targets[target].get('vulns', 0)

        return {'new_vulns': new_vulns, 'removed_vulns': removed_vulns}
    except Exception:
        return {'new_vulns': 0, 'removed_vulns': 0}
