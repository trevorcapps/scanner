"""SocketIO event handlers for real-time scanning — extracted from app.py.

All scan orchestration that was previously inline in app.py lives here.
The heavy scanning logic delegates to services/ and scanners/.
"""

import json
import threading
import logging

from flask import request
from flask_socketio import emit

from artemis.extensions import socketio
from artemis.utils.validation import validate_target, is_cidr, is_hostname
from artemis.utils.dns import ScanError, resolve_target
from artemis.utils.network import expand_cidr
from artemis.scanners.nmap_scanner import (
    extract_host_info_from_scan,
    get_os_info_from_scan,
    parse_scan,
    scan as nmap_scan,
)
from artemis.scanners.nuclei_scanner import vuln_scan, parse_vuln_scan
from artemis.scanners.ssh_scanner import run_authenticated_scan
from artemis.services.scan_service import store_scan, get_latest_scan, get_open_ports_for_ip
from artemis.services.asset_service import store_asset_info, update_device_type, get_asset_details
from artemis.services.fingerprint_service import (
    store_fingerprints, store_fpx_results, store_raw_fingerprints, get_fingerprint_engine,
)
from artemis.services.vuln_service import store_vulnerabilities, get_vulnerabilities
from artemis.services.auth_scan_service import store_auth_scan_results, get_all_credentials, get_credential

logger = logging.getLogger(__name__)

# Track running scans by session ID
active_scans = {}
scan_lock = threading.Lock()

# Lazy imports that need scanner dir on sys.path
_fpx_imported = False
_fpx_scan_host = None
_fpx_check_installed = None
_device_type_module = None
_wap_module = None
_jarm_module = None
_vulscan_module = None
_nvd_module = None
_exploit_module = None


@socketio.on('connect')
def handle_connect(auth=None):
    """Reject Socket.IO clients that did not pass the normal auth checks."""
    from artemis.models.user import User
    from artemis.services.auth_service import _get_current_user

    if User.query.count() == 0:
        return True
    return _get_current_user() is not None


def _require_socket_role(min_role='analyst'):
    from artemis.models.user import User
    from artemis.services.auth_service import ROLE_HIERARCHY, _get_current_user, get_effective_role

    if User.query.count() == 0:
        return True
    user = _get_current_user()
    if not user or ROLE_HIERARCHY.get(get_effective_role(user), 0) < ROLE_HIERARCHY[min_role]:
        emit('scan_error', {'error': 'Insufficient permissions'})
        return False
    return True


def _lazy_imports():
    """Import scanner-level modules lazily."""
    global _fpx_imported, _fpx_scan_host, _fpx_check_installed
    global _device_type_module, _wap_module, _jarm_module, _vulscan_module
    global _nvd_module, _exploit_module
    if _fpx_imported:
        return
    try:
        from fingerprint.fpx import scan_host as fpx_scan, check_installed as fpx_check
        _fpx_scan_host = fpx_scan
        _fpx_check_installed = fpx_check
    except ImportError:
        pass
    try:
        import device_type as dt
        _device_type_module = dt
    except ImportError:
        pass
    try:
        from fingerprint.wap_engine import analyze_response, get_wappalyzer
        _wap_module = type('M', (), {'analyze_response': staticmethod(analyze_response),
                                      'get_wappalyzer': staticmethod(get_wappalyzer)})()
    except ImportError:
        pass
    try:
        from fingerprint.jarm import scan_host_tls_ports
        _jarm_module = type('M', (), {'scan_host_tls_ports': staticmethod(scan_host_tls_ports)})()
    except ImportError:
        pass
    try:
        from vulscan_integration import is_vulscan_available, parse_vulscan_output, store_vulscan_results
        _vulscan_module = type('M', (), {
            'is_vulscan_available': staticmethod(is_vulscan_available),
            'parse_vulscan_output': staticmethod(parse_vulscan_output),
            'store_vulscan_results': staticmethod(store_vulscan_results)})()
    except ImportError:
        pass
    try:
        from nvd_feeds import sync_nvd_database, get_nvd_sync_status
        _nvd_module = type('M', (), {
            'sync_nvd_database': staticmethod(sync_nvd_database),
            'get_nvd_sync_status': staticmethod(get_nvd_sync_status)})()
    except ImportError:
        pass
    try:
        from exploit_ref import ensure_exploit_db
        _exploit_module = type('M', (), {'ensure_exploit_db': staticmethod(ensure_exploit_db)})()
    except ImportError:
        pass
    try:
        from cpe_dict import sync_cpe_dictionary
        _nvd_module.sync_cpe_dictionary = staticmethod(sync_cpe_dictionary)
    except (ImportError, AttributeError):
        pass
    _fpx_imported = True


def emit_log(sid, message, level='info'):
    """Emit a log message to the client and normal application log history."""
    log_method = getattr(logger, level, logger.info)
    log_method(message)
    socketio.emit('scan_log', {'message': message, 'level': level}, room=sid)


def is_scan_cancelled(sid):
    with scan_lock:
        return active_scans.get(sid, {}).get('cancelled', False)


def _spawn_scan_thread(target, *args, **kwargs):
    """Run ``target`` in a daemon thread that holds a Flask app context.

    Socket.IO event handlers execute inside an app/request context, but the
    worker threads they start do not. The scan services use ``db.session`` /
    ``current_app.config`` and raise outside an app context, so every scan
    worker must push one (mirrors what ``scheduler_service`` already does).
    """
    from flask import current_app
    app = current_app._get_current_object()

    def _run():
        with app.app_context():
            target(*args, **kwargs)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return thread


def _get_setting(key, default=None):
    from artemis.services.auth_scan_service import get_setting
    return get_setting(key, default)


# --------------- Port Scan ---------------

def scan_single_ip(ip, sid, current=1, total=1, scan_options=None):
    """Execute scan on a single target and emit results. Mirrors old app.py logic."""
    _lazy_imports()
    from artemis.utils.dns import dns_lookup

    scan_target_str = ip
    store_ip = ip
    original_hostname = None

    if is_hostname(ip):
        original_hostname = ip
        try:
            store_ip = resolve_target(ip)
            emit_log(sid, f'Resolved {ip} -> {store_ip}', 'info')
        except ScanError as e:
            emit_log(sid, str(e), 'error')
            return {'ip': ip, 'error': str(e), 'success': False}

    try:
        socketio.emit('scan_progress', {
            'status': 'running', 'message': f'Scanning {ip}...',
            'current': current, 'total': total, 'ip': store_ip
        }, room=sid)

        emit_log(sid, f'Initiating nmap scan on {scan_target_str}', 'debug')
        scan_result = nmap_scan(
            scan_target_str,
            options=scan_options,
            log_callback=lambda msg: emit_log(sid, msg, 'debug'),
            cancel_check=lambda: is_scan_cancelled(sid),
        )
        scan_data = parse_scan(scan_result)

        os_info = get_os_info_from_scan(scan_result)
        if os_info.get('os_name'):
            emit_log(sid, f'Detected OS: {os_info["os_name"]}', 'info')

        host_info = extract_host_info_from_scan(scan_result)
        mac_address = host_info.get('mac_address')
        mac_vendor = host_info.get('mac_vendor')
        nmap_hostname = host_info.get('hostname')

        if mac_address:
            emit_log(sid, f'MAC: {mac_address} ({mac_vendor or "unknown vendor"})', 'info')
        if nmap_hostname:
            emit_log(sid, f'Hostname (nmap): {nmap_hostname}', 'info')

        emit_log(sid, f'Performing DNS lookup for {store_ip}', 'debug')
        dns_info = dns_lookup(store_ip)
        if dns_info.get('hostname'):
            emit_log(sid, f'DNS: {store_ip} -> {dns_info["hostname"]}', 'info')

        if nmap_hostname and not dns_info.get('hostname'):
            dns_info['hostname'] = nmap_hostname
        if nmap_hostname and not dns_info.get('reverse_dns'):
            dns_info['reverse_dns'] = nmap_hostname
        if original_hostname and not dns_info.get('hostname'):
            dns_info['hostname'] = original_hostname

        store_asset_info(store_ip, dns_info=dns_info, os_info=os_info,
                         mac_address=mac_address, mac_vendor=mac_vendor)

        if scan_data:
            store_scan(store_ip, scan_data)
            emit_log(sid, f'Found {len(scan_data)} open port(s) on {scan_target_str}', 'success')

            # Vulscan
            if (
                scan_options and scan_options.get('vulscan')
                and _vulscan_module and _vulscan_module.is_vulscan_available()
            ):
                try:
                    vulscan_results = _vulscan_module.parse_vulscan_output(scan_result)
                    if vulscan_results:
                        _vulscan_module.store_vulscan_results(store_ip, vulscan_results)
                        emit_log(sid, f'Vulscan found {len(vulscan_results)} CVE matches for {store_ip}', 'success')
                except Exception as e:
                    emit_log(sid, f'Vulscan parsing error: {e}', 'warning')

            # Fingerprinting
            emit_log(sid, f'Starting endpoint fingerprinting on {store_ip}', 'info')
            ports_for_fp = []
            for result in scan_data:
                if result[2] == 'open':
                    ports_for_fp.append({
                        'port': result[1], 'protocol': result[0], 'service': result[3],
                        'product': result[4], 'version': result[5], 'extrainfo': '',
                    })

            if ports_for_fp:
                try:
                    engine = get_fingerprint_engine()
                    fp_results = engine.fingerprint_all_ports(
                        store_ip, ports_for_fp,
                        log_callback=lambda msg: emit_log(sid, msg, 'debug'),
                    )
                    store_fingerprints(store_ip, fp_results)
                    identified = sum(1 for r in fp_results if r.best_match is not None)
                    emit_log(
                        sid,
                        f'Fingerprinting complete: identified {identified}/{len(fp_results)} services on {store_ip}',
                        'success',
                    )
                    for r in fp_results:
                        if r.best_match:
                            m = r.best_match
                            ver = f' v{m.version}' if m.version else ''
                            emit_log(
                                sid,
                                f'  Port {r.port}: {m.name}{ver} ({m.category}, {m.confidence}% confidence)',
                                'info',
                            )
                except Exception as e:
                    emit_log(sid, f'Fingerprinting error: {e}', 'warning')

                # fingerprintx
                try:
                    if _fpx_check_installed and _fpx_check_installed():
                        emit_log(sid, f'Running protocol fingerprinting (fingerprintx) on {store_ip}', 'info')
                        fpx_results = _fpx_scan_host(
                            store_ip, ports_for_fp, timeout_ms=3000,
                            log_callback=lambda msg: emit_log(sid, msg, 'debug'),
                        )
                        if fpx_results:
                            store_fpx_results(store_ip, fpx_results)
                            emit_log(
                                sid,
                                f'fingerprintx identified {len(fpx_results)} service(s) on {store_ip}',
                                'success',
                            )
                            for r in fpx_results:
                                ver = f' v{r.version}' if r.version else ''
                                emit_log(sid, f'  Port {r.port}: {r.service}{ver} (protocol handshake)', 'info')
                except Exception as e:
                    emit_log(sid, f'fingerprintx error: {e}', 'warning')

                # Wappalyzer
                try:
                    if _wap_module:
                        wap = _wap_module.get_wappalyzer()
                        if wap:
                            wap_stored = 0
                            for port_info in ports_for_fp:
                                port_num = port_info['port']
                                service = port_info.get('service', '')
                                if service in ('http', 'https', 'http-proxy') or port_num in (80, 443, 8080, 8443):
                                    scheme = 'https' if port_num == 443 or service == 'https' else 'http'
                                    url = f"{scheme}://{scan_target_str}:{port_num}"
                                    try:
                                        import urllib.request
                                        req = urllib.request.Request(url, headers={'User-Agent': 'Artemis-Scanner/1.0'})
                                        with urllib.request.urlopen(req, timeout=5) as resp:
                                            html = resp.read().decode('utf-8', errors='replace')
                                            headers = dict(resp.headers)
                                        wap_results = _wap_module.analyze_response(url, html, headers)
                                        if wap_results:
                                            store_raw_fingerprints(store_ip, [{
                                                'port': port_num, 'protocol': 'tcp',
                                                'signature_id': f"wap-{wr['name'].lower().replace(' ', '-')}",
                                                'name': wr['name'],
                                                'category': (
                                                    wr['categories'][0]
                                                    if wr.get('categories') else 'web-technology'
                                                ),
                                                'vendor': '', 'version': wr.get('version'), 'cpe': None,
                                                'confidence': wr.get('confidence', 100),
                                                'evidence': ['wappalyzer'],
                                            } for wr in wap_results])
                                            wap_stored += len(wap_results)
                                            emit_log(
                                                sid,
                                                f'  Wappalyzer found {len(wap_results)} tech(s) on port {port_num}',
                                                'info',
                                            )
                                    except Exception:
                                        pass
                            if wap_stored:
                                emit_log(
                                    sid,
                                    f'Wappalyzer: detected {wap_stored} web technologies on {store_ip}',
                                    'success',
                                )
                except Exception:
                    pass

                # JARM
                try:
                    if _jarm_module:
                        emit_log(sid, f'Running JARM TLS fingerprinting on {store_ip}', 'debug')
                        jarm_results = _jarm_module.scan_host_tls_ports(
                            store_ip, ports_for_fp, timeout=10,
                            log_callback=lambda msg: emit_log(sid, msg, 'debug'),
                        )
                        if jarm_results:
                            store_raw_fingerprints(store_ip, [{
                                'port': jr['port'], 'protocol': 'tcp',
                                'signature_id': f"jarm-{jr['port']}",
                                'name': jr.get('identified_as') or 'TLS Fingerprint',
                                'category': 'tls-fingerprint', 'vendor': '',
                                'version': None, 'cpe': None,
                                'confidence': 70 if jr.get('identified_as') else 50,
                                'evidence': [f"jarm:{jr['jarm_hash']}"],
                            } for jr in jarm_results])
                            emit_log(
                                sid,
                                f'JARM: fingerprinted {len(jarm_results)} TLS port(s) on {store_ip}',
                                'success',
                            )
                except Exception:
                    pass

                # Device type classification
                try:
                    device_type = update_device_type(store_ip)
                    if device_type and device_type != 'unknown' and _device_type_module:
                        icon = _device_type_module.get_device_icon(device_type)
                        emit_log(sid, f'Device type: {icon} {device_type}', 'info')
                except Exception:
                    pass
        else:
            emit_log(sid, f'No open ports found on {scan_target_str}', 'info')

        return {'ip': store_ip, 'scan_data': scan_data, 'success': True}
    except ScanError as e:
        emit_log(sid, f'Scan error for {scan_target_str}: {e}', 'error')
        return {'ip': store_ip, 'error': str(e), 'success': False}
    except Exception as e:
        emit_log(sid, f'Unexpected error scanning {scan_target_str}: {e}', 'error')
        return {'ip': store_ip, 'error': 'Scan failed unexpectedly', 'success': False}


def scan_target(target, sid, scan_options=None):
    """Execute scan on a target (single IP, CIDR, or hostname)."""
    try:
        if not validate_target(target):
            socketio.emit('scan_error', {'error': 'Invalid target'}, room=sid)
            return

        max_hosts = 256
        if scan_options and 'max_hosts' in scan_options:
            max_hosts = min(max(1, scan_options['max_hosts']), 1024)

        if is_cidr(target):
            ips = expand_cidr(target, max_hosts=max_hosts)
            if not ips:
                socketio.emit('scan_error', {'error': 'Failed to expand CIDR range'}, room=sid)
                return
            emit_log(sid, f'Expanded CIDR {target} to {len(ips)} hosts', 'info')
        else:
            ips = [target]

        total = len(ips)
        results = []

        for i, ip in enumerate(ips, 1):
            if is_scan_cancelled(sid):
                emit_log(sid, 'Scan cancelled by user', 'warning')
                socketio.emit('scan_complete', {
                    'target': target, 'results': results,
                    'successful_count': len([r for r in results if r['success']]),
                    'failed_count': len([r for r in results if not r['success']]),
                    'total': total, 'cancelled': True
                }, room=sid)
                return
            result = scan_single_ip(ip, sid, current=i, total=total, scan_options=scan_options)
            results.append(result)

        successful = [r for r in results if r['success']]
        failed = [r for r in results if not r['success']]
        socketio.emit('scan_complete', {
            'target': target, 'results': results,
            'successful_count': len(successful), 'failed_count': len(failed),
            'total': total, 'cancelled': False
        }, room=sid)
        try:
            from artemis.services.webhook_service import emit as _emit_wh
            _emit_wh('scan.completed', {
                'target': target, 'scan_type': 'port', 'total': total,
                'successful': len(successful), 'failed': len(failed),
                'hosts': [r.get('ip') for r in successful],
            })
        except Exception:
            logger.debug('webhook emit failed', exc_info=True)
    finally:
        with scan_lock:
            active_scans.pop(sid, None)


@socketio.on('start_scan')
def handle_start_scan(data):
    if not _require_socket_role():
        return
    target = data.get('ip', '').strip()
    sid = request.sid

    if not target:
        emit('scan_error', {'error': 'IP address or CIDR is required'})
        return
    if not validate_target(target):
        emit('scan_error', {'error': 'Invalid target (IP, CIDR, or hostname)'})
        return

    scan_options = {
        'ports': data.get('ports', ''),
        'scan_speed': data.get('scan_speed', 'T3'),
        'host_timeout': data.get('host_timeout', 300),
        'max_hosts': data.get('max_hosts', 256),
        'vulscan': data.get('vulscan', False),
    }

    with scan_lock:
        active_scans[sid] = {'type': 'port_scan', 'target': target, 'cancelled': False}

    _spawn_scan_thread(scan_target, target, sid, scan_options)


@socketio.on('stop_scan')
def handle_stop_scan():
    if not _require_socket_role():
        return
    sid = request.sid
    with scan_lock:
        if sid in active_scans:
            active_scans[sid]['cancelled'] = True
            emit_log(sid, 'Stopping scan...', 'warning')
        else:
            emit('scan_error', {'error': 'No active scan to stop'})


# --------------- Vuln Scan ---------------

def vuln_scan_single_ip(ip, sid, current=1, total=1, scan_options=None):
    scan_target_str = ip
    store_ip = ip
    original_hostname = None

    if is_hostname(ip):
        original_hostname = ip
        try:
            store_ip = resolve_target(ip)
            emit_log(sid, f'Resolved {ip} -> {store_ip}', 'info')
        except ScanError as e:
            emit_log(sid, str(e), 'error')
            return {'ip': ip, 'error': str(e), 'success': False}

    try:
        socketio.emit('vuln_scan_progress', {
            'status': 'running', 'message': f'Scanning {scan_target_str} for vulnerabilities...',
            'current': current, 'total': total, 'ip': store_ip
        }, room=sid)

        emit_log(sid, f'Running Nuclei vulnerability scan on {scan_target_str}', 'info')

        def nuclei_log_callback(message):
            emit_log(sid, message, 'debug')

        scan_result = vuln_scan(scan_target_str, options=scan_options, log_callback=nuclei_log_callback)
        vulnerabilities = parse_vuln_scan(scan_result)

        if vulnerabilities:
            socketio.emit('vuln_scan_progress', {
                'status': 'running', 'message': f'Enriching vulnerability data for {store_ip}...',
                'current': current, 'total': total, 'ip': store_ip
            }, room=sid)
            emit_log(sid, f'Enriching {len(vulnerabilities)} finding(s) with NVD data', 'debug')
            store_vulnerabilities(store_ip, vulnerabilities)
            emit_log(sid, f'Found {len(vulnerabilities)} vulnerability finding(s) on {scan_target_str}', 'warning')
        else:
            emit_log(sid, f'No vulnerabilities detected on {scan_target_str}', 'success')

        if original_hostname:
            store_asset_info(store_ip, dns_info={'hostname': original_hostname})

        return {'ip': store_ip, 'vuln_count': len(vulnerabilities), 'success': True}
    except ScanError as e:
        emit_log(sid, f'Vulnerability scan error for {scan_target_str}: {e}', 'error')
        return {'ip': store_ip, 'error': str(e), 'success': False}
    except Exception as e:
        emit_log(sid, f'Unexpected error in vuln scan for {scan_target_str}: {e}', 'error')
        return {'ip': store_ip, 'error': 'Vulnerability scan failed unexpectedly', 'success': False}


def vuln_scan_target(target, sid, scan_options=None):
    try:
        if not validate_target(target):
            socketio.emit('vuln_scan_error', {'error': 'Invalid target'}, room=sid)
            return

        max_hosts = 256
        if scan_options and 'max_hosts' in scan_options:
            max_hosts = min(max(1, scan_options['max_hosts']), 1024)

        if is_cidr(target):
            ips = expand_cidr(target, max_hosts=max_hosts)
            if not ips:
                socketio.emit('vuln_scan_error', {'error': 'Failed to expand CIDR'}, room=sid)
                return
            emit_log(sid, f'Expanded CIDR {target} to {len(ips)} hosts for vulnerability scan', 'info')
        else:
            ips = [target]

        total = len(ips)
        results = []

        for i, ip in enumerate(ips, 1):
            if is_scan_cancelled(sid):
                emit_log(sid, 'Vulnerability scan cancelled by user', 'warning')
                socketio.emit('vuln_scan_complete', {
                    'target': target, 'results': results, 'vulnerabilities': [],
                    'successful_count': len([r for r in results if r['success']]),
                    'failed_count': len([r for r in results if not r['success']]),
                    'total_vulns': 0, 'total': total, 'cancelled': True
                }, room=sid)
                return
            result = vuln_scan_single_ip(ip, sid, current=i, total=total, scan_options=scan_options)
            results.append(result)

        all_vulns = []
        for ip in ips:
            all_vulns.extend(get_vulnerabilities(ip))

        successful = [r for r in results if r['success']]
        failed = [r for r in results if not r['success']]
        socketio.emit('vuln_scan_complete', {
            'target': target, 'results': results, 'vulnerabilities': all_vulns,
            'successful_count': len(successful), 'failed_count': len(failed),
            'total_vulns': len(all_vulns), 'total': total, 'cancelled': False
        }, room=sid)
    finally:
        with scan_lock:
            active_scans.pop(sid, None)


@socketio.on('start_vuln_scan')
def handle_start_vuln_scan(data):
    if not _require_socket_role():
        return
    target = data.get('ip', '').strip()
    sid = request.sid

    if not target:
        emit('vuln_scan_error', {'error': 'IP address or CIDR is required'})
        return
    if not validate_target(target):
        emit('vuln_scan_error', {'error': 'Invalid target (IP, CIDR, or hostname)'})
        return

    # Load scan profile if selected
    profile_id = data.get('profile', '')
    profile = None
    if profile_id:
        try:
            from flask import current_app
            profiles_path = current_app.config.get('SCAN_PROFILES_PATH', '')
            with open(profiles_path, 'r') as f:
                profiles_data = json.load(f)
                for p in profiles_data.get('profiles', []):
                    if p['id'] == profile_id:
                        profile = p
                        break
        except Exception:
            pass

    scan_options = {
        'vuln_timeout': data.get('vuln_timeout', 600),
        'severity': data.get('severity', 'critical,high,medium,low'),
        'rate_limit': data.get('rate_limit', 150),
        'templates': data.get('templates', ''),
        'max_hosts': data.get('max_hosts', 256),
    }

    if profile:
        if profile.get('tags'):
            scan_options['templates'] = profile['tags']
        if profile.get('severity'):
            scan_options['severity'] = profile['severity']
        if profile.get('rate_limit'):
            scan_options['rate_limit'] = profile['rate_limit']

    with scan_lock:
        active_scans[sid] = {'type': 'vuln_scan', 'target': target, 'cancelled': False}

    _spawn_scan_thread(vuln_scan_target, target, sid, scan_options)


# --------------- Fingerprint Scan ---------------

@socketio.on('start_fingerprint_scan')
def handle_start_fingerprint_scan(data):
    if not _require_socket_role():
        return
    target = data.get('ip', '').strip()
    sid = request.sid

    if not target or not validate_target(target):
        emit('scan_error', {'error': 'Invalid target'})
        return

    if is_hostname(target):
        try:
            target = resolve_target(target)
        except ScanError as e:
            emit('scan_error', {'error': str(e)})
            return

    def run_fingerprint(ip, sid):
        _lazy_imports()
        try:
            emit_log(sid, f'Starting fingerprint scan for {ip}', 'info')
            socketio.emit('scan_progress', {
                'status': 'running', 'message': f'Fingerprinting {ip}...',
                'current': 1, 'total': 1, 'ip': ip
            }, room=sid)

            latest_scan = get_latest_scan(ip)
            if not latest_scan:
                emit_log(sid, f'No scan data for {ip}. Run a port scan first.', 'error')
                socketio.emit('scan_error', {'error': f'No scan data for {ip}.'}, room=sid)
                return

            engine = get_fingerprint_engine()
            ports_for_fp = [{'port': row[1], 'protocol': row[0], 'service': row[3],
                             'product': row[4], 'version': row[5], 'extrainfo': ''}
                            for row in latest_scan if row[2] == 'open']

            if not ports_for_fp:
                emit_log(sid, f'No open ports found for {ip}', 'warning')
                socketio.emit('scan_complete', {
                    'target': ip, 'results': [{'ip': ip, 'scan_data': [], 'success': True}],
                    'successful_count': 1, 'failed_count': 0, 'total': 1, 'cancelled': False
                }, room=sid)
                return

            emit_log(sid, f'Fingerprinting {len(ports_for_fp)} open port(s) on {ip}', 'info')
            fp_results = engine.fingerprint_all_ports(ip, ports_for_fp,
                                                      log_callback=lambda msg: emit_log(sid, msg, 'debug'))
            store_fingerprints(ip, fp_results)

            identified = sum(1 for r in fp_results if r.best_match is not None)
            emit_log(sid, f'HTTP fingerprinting: identified {identified}/{len(fp_results)} services', 'success')

            for r in fp_results:
                if r.best_match:
                    m = r.best_match
                    ver = f' v{m.version}' if m.version else ''
                    emit_log(sid, f'  Port {r.port}: {m.name}{ver} ({m.category}, {m.confidence}% confidence)', 'info')

            fpx_count = 0
            try:
                if _fpx_check_installed and _fpx_check_installed():
                    emit_log(sid, f'Running protocol fingerprinting (fingerprintx) on {ip}', 'info')
                    fpx_results = _fpx_scan_host(ip, ports_for_fp, timeout_ms=3000,
                                                  log_callback=lambda msg: emit_log(sid, msg, 'debug'))
                    if fpx_results:
                        store_fpx_results(ip, fpx_results)
                        fpx_count = len(fpx_results)
                        emit_log(sid, f'fingerprintx identified {fpx_count} service(s)', 'success')
            except Exception as e:
                emit_log(sid, f'fingerprintx error: {e}', 'warning')

            socketio.emit('scan_complete', {
                'target': ip, 'results': [{'ip': ip, 'scan_data': latest_scan, 'success': True}],
                'successful_count': 1, 'failed_count': 0, 'total': 1, 'cancelled': False,
                'fingerprint_results': [r.to_dict() for r in fp_results],
                'fpx_count': fpx_count,
            }, room=sid)

        except Exception as e:
            emit_log(sid, f'Fingerprint scan error: {e}', 'error')
            socketio.emit('scan_error', {'error': str(e)}, room=sid)
        finally:
            with scan_lock:
                active_scans.pop(sid, None)

    with scan_lock:
        active_scans[sid] = {'type': 'fingerprint', 'target': target, 'cancelled': False}

    _spawn_scan_thread(run_fingerprint, target, sid)


# --------------- Auth Scan ---------------

@socketio.on('start_auth_scan')
def handle_start_auth_scan(data):
    if not _require_socket_role():
        return
    target = data.get('ip', '').strip()
    sid = request.sid

    if not target or not validate_target(target):
        emit('scan_error', {'error': 'Invalid target'})
        return

    credential_ids = data.get('credential_ids', [])
    use_all = data.get('use_all_credentials', False)

    if use_all:
        creds = get_all_credentials()
    else:
        creds = []
        for cid in credential_ids:
            c = get_credential(int(cid))
            if c:
                creds.append(c)

    if not creds:
        emit('scan_error', {'error': 'No credentials selected.'})
        return

    nvd_api_key = _get_setting('nvd_api_key', '') or None

    def run_smart_auth_scan(target, sid, creds):
        try:
            if is_cidr(target):
                ips = expand_cidr(target, max_hosts=256)
            elif is_hostname(target):
                try:
                    resolved = resolve_target(target)
                    emit_log(sid, f'Resolved {target} -> {resolved}', 'info')
                    ips = [resolved]
                except ScanError as e:
                    emit_log(sid, str(e), 'error')
                    socketio.emit('auth_scan_complete', {'error': str(e)}, room=sid)
                    return
            else:
                ips = [target]

            all_results = []
            for ip_idx, ip in enumerate(ips, 1):
                if is_scan_cancelled(sid):
                    emit_log(sid, 'Auth scan cancelled', 'warning')
                    break

                socketio.emit('scan_progress', {
                    'status': 'running', 'message': f'Auth scan {ip} ({ip_idx}/{len(ips)})...',
                    'current': ip_idx, 'total': len(ips), 'ip': ip
                }, room=sid)

                open_ports = get_open_ports_for_ip(ip)
                if not open_ports:
                    emit_log(sid, f'No port scan data for {ip} — running port scan first...', 'info')
                    result = scan_single_ip(ip, sid, current=ip_idx, total=len(ips))
                    if not result['success']:
                        emit_log(sid, f'Port scan failed for {ip}, skipping auth scan', 'error')
                        continue
                    open_ports = get_open_ports_for_ip(ip)

                if not open_ports:
                    emit_log(sid, f'No open ports on {ip}, skipping', 'info')
                    continue

                ssh_ports = [p['port'] for p in open_ports
                             if p['port'] in (22, 2222, 2200) or p['service'] in ('ssh', 'openssh')]

                asset_details = get_asset_details(ip)
                os_hint = ''
                if asset_details:
                    os_hint = (asset_details.get('os_name') or '').lower() + ' ' + \
                              (asset_details.get('os_family') or '').lower()
                is_likely_windows = any(w in os_hint for w in ['windows', 'microsoft'])

                for cred in creds:
                    cred_type = cred['cred_type']

                    if cred_type in ('ssh_key', 'ssh_password'):
                        if not ssh_ports:
                            continue
                        if is_likely_windows and 22 not in [p['port'] for p in open_ports]:
                            continue

                        for ssh_port in ssh_ports:
                            emit_log(sid, f'Trying "{cred["name"]}" ({cred_type}) on {ip}:{ssh_port}', 'info')
                            try:
                                def log_cb(msg, level='info'):
                                    emit_log(sid, msg, level)

                                result = run_authenticated_scan(
                                    host=ip, port=ssh_port, username=cred['username'],
                                    password=cred['password'] if cred_type == 'ssh_password' else None,
                                    key_path=cred['key_path'] if cred_type == 'ssh_key' else None,
                                    nvd_api_key=nvd_api_key, log_callback=log_cb
                                )

                                # also enriches the asset (hostname, MAC, OS) + reclassifies
                                store_auth_scan_results(ip, result['os_info'], result['packages'], result['cves'])

                                facts = result['os_info'].get('system') or {}
                                if facts.get('hostname'):
                                    emit_log(sid, f'Hostname: {facts["hostname"]}', 'info')
                                if facts.get('listening_ports'):
                                    emit_log(
                                        sid,
                                        f'{len(facts["listening_ports"])} listening service(s) enumerated',
                                        'info',
                                    )

                                emit_log(sid, f'✓ Auth scan success on {ip}:{ssh_port} with "{cred["name"]}": '
                                         f'{len(result["packages"])} packages, {len(result["cves"])} CVEs', 'success')

                                all_results.append({
                                    'ip': ip, 'credential': cred['name'], 'port': ssh_port,
                                    'packages': len(result['packages']), 'cves': len(result['cves']),
                                    'success': True
                                })
                                break

                            except Exception as e:
                                emit_log(sid, f'✗ Failed "{cred["name"]}" on {ip}:{ssh_port}: {e}', 'warning')
                                all_results.append({
                                    'ip': ip, 'credential': cred['name'], 'port': ssh_port,
                                    'error': str(e), 'success': False
                                })

            successful = [r for r in all_results if r['success']]
            socketio.emit('auth_scan_complete', {
                'target': target, 'results': all_results,
                'successful_count': len(successful), 'total_count': len(all_results),
                'success': len(successful) > 0
            }, room=sid)

        except Exception as e:
            emit_log(sid, f'Auth scan error: {e}', 'error')
            socketio.emit('scan_error', {'error': str(e)}, room=sid)
        finally:
            with scan_lock:
                active_scans.pop(sid, None)

    emit_log(sid, f'Starting smart authenticated scan on {target} with {len(creds)} credential(s)', 'info')

    with scan_lock:
        active_scans[sid] = {'type': 'auth_scan', 'target': target, 'cancelled': False}

    _spawn_scan_thread(run_smart_auth_scan, target, sid, creds)


# --------------- NVD Sync ---------------

@socketio.on('start_nvd_sync')
def handle_start_nvd_sync(data):
    if not _require_socket_role('admin'):
        return
    _lazy_imports()
    sid = request.sid
    full_sync = data.get('full', False)
    api_key = _get_setting('nvd_api_key', '') or None

    def run_sync():
        try:
            if _nvd_module:
                _nvd_module.sync_nvd_database(socketio=socketio, api_key=api_key, full_sync=full_sync)

                if hasattr(_nvd_module, 'sync_cpe_dictionary'):
                    socketio.emit('nvd_sync_progress', {'status': 'running', 'message': 'Syncing CPE dictionary...'})
                    _nvd_module.sync_cpe_dictionary(socketio=socketio)

            if _exploit_module:
                exploit_ready = _exploit_module.ensure_exploit_db(force=True)
                socketio.emit('nvd_sync_progress', {
                    'status': 'running' if exploit_ready else 'error',
                    'message': (
                        'ExploitDB mapping ready' if exploit_ready
                        else 'ExploitDB mapping could not be downloaded; see server logs'
                    ),
                })

        except Exception as e:
            socketio.emit('nvd_sync_progress', {'status': 'error', 'message': str(e)})

    emit_log(sid, f'Starting NVD database sync ({"full" if full_sync else "incremental"})...', 'info')
    _spawn_scan_thread(run_sync)


def register_socketio_handlers():
    """Register all events on the current Socket.IO server instance."""
    handlers = {
        'connect': handle_connect,
        'start_scan': handle_start_scan,
        'stop_scan': handle_stop_scan,
        'start_vuln_scan': handle_start_vuln_scan,
        'start_fingerprint_scan': handle_start_fingerprint_scan,
        'start_auth_scan': handle_start_auth_scan,
        'start_nvd_sync': handle_start_nvd_sync,
    }
    for event, handler in handlers.items():
        socketio.on_event(event, handler)
