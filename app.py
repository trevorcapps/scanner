import os
import re
import json
import sqlite3
import logging
import threading
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for
from flask_socketio import SocketIO, emit
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend for thread safety
import matplotlib.pyplot as plt

import vuln_scan
from vuln_scan import (ScanError, validate_ip, validate_target, validate_hostname,
                       is_cidr, is_hostname, expand_cidr, resolve_target,
                       DB_PATH, dns_lookup, get_os_info_from_scan, extract_host_info_from_scan,
                       store_asset_info, update_device_type,
                       get_asset_details, get_fingerprints, get_fingerprint_summary,
                       store_fingerprints, store_fpx_results, get_fingerprint_engine,
                       fpx_check_installed, store_auth_scan_results,
                       get_asset_os_details, get_installed_software, get_cve_matches,
                       get_all_credentials, get_credential, save_credential,
                       delete_credential, get_setting, set_setting, get_open_ports_for_ip)
from fingerprint.fpx import scan_host as fpx_scan_host
from auth_scan import run_authenticated_scan
from device_type import get_device_icon, DEVICE_TYPE_ICONS
from nvd_feeds import sync_nvd_database, get_nvd_sync_status
from fingerprint.wap_engine import analyze_response as wap_analyze, get_wappalyzer
from fingerprint.jarm import scan_host_tls_ports as jarm_scan
from vulscan_integration import is_vulscan_available, get_vulscan_nmap_args, parse_vulscan_output, store_vulscan_results
from exploit_ref import enrich_cves_with_exploits, ensure_exploit_db

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load scan profiles
SCAN_PROFILES = {}
_profiles_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scan_profiles.json')
try:
    with open(_profiles_path, 'r') as _f:
        _profiles_data = json.load(_f)
        for p in _profiles_data.get('profiles', []):
            SCAN_PROFILES[p['id']] = p
    logger.info(f"Loaded {len(SCAN_PROFILES)} scan profiles")
except Exception as _e:
    logger.warning(f"Could not load scan profiles: {_e}")

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
socketio = SocketIO(app)

# Track running scans by session ID
active_scans = {}
scan_lock = threading.Lock()

# Initialize the database
vuln_scan.init_db()
logger.info(f"Using database: {DB_PATH}")

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/assets')
def get_assets():
    """Get list of previously scanned hosts with their latest scan info and vulnerability counts."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        # Get unique IPs with their latest scan date
        cursor.execute('''
            SELECT
                ip,
                MAX(scan_date) as last_scan
            FROM scans
            GROUP BY ip
            ORDER BY last_scan DESC
        ''')
        hosts = cursor.fetchall()

        assets = []
        for host in hosts:
            ip, last_scan = host
            # Get the open ports for this IP from the latest scan
            cursor.execute('''
                SELECT protocol, port, state, service, product, version
                FROM scans
                WHERE ip = ? AND scan_date = ?
            ''', (ip, last_scan))
            ports = cursor.fetchall()

            # Count ports from latest scan only
            port_count = len(ports)

            # Get vulnerability counts for this IP
            vuln_counts = vuln_scan.get_vulnerability_counts_by_severity(ip)

            # Get fingerprint summary for this IP
            fp_summary = get_fingerprint_summary(ip)
            fp_techs = fp_summary.get('technologies', [])
            fp_by_port = fp_summary.get('by_port', {})

            # Get asset metadata (hostname, device type, MAC, etc.)
            cursor.execute('''SELECT hostname, reverse_dns, device_type, mac_address, mac_vendor, os_name
                              FROM assets WHERE ip = ?''', (ip,))
            asset_row = cursor.fetchone()
            hostname = asset_row[0] if asset_row else None
            reverse_dns = asset_row[1] if asset_row else None
            device_type = asset_row[2] if asset_row else None
            mac_address = asset_row[3] if asset_row else None
            mac_vendor = asset_row[4] if asset_row else None
            os_name = asset_row[5] if asset_row else None
            device_icon = get_device_icon(device_type) if device_type else None

            assets.append({
                'ip': ip,
                'hostname': hostname,
                'reverse_dns': reverse_dns,
                'device_type': device_type,
                'device_icon': device_icon,
                'mac_address': mac_address,
                'mac_vendor': mac_vendor,
                'os_name': os_name,
                'last_scan': last_scan,
                'port_count': port_count,
                'vuln_counts': vuln_counts,
                'technologies': fp_techs[:5],  # Top 5 technologies
                'ports': [
                    {
                        'protocol': p[0],
                        'port': p[1],
                        'state': p[2],
                        'service': p[3],
                        'product': p[4],
                        'version': p[5],
                        'fingerprint': fp_by_port.get(p[1], {})
                    } for p in ports
                ]
            })

        logger.info(f"Retrieved {len(assets)} assets")
        return {'assets': assets}
    except sqlite3.Error as e:
        logger.error(f"Database error in get_assets: {e}")
        return {'error': str(e)}, 500
    finally:
        conn.close()


def resolve_ip_param(value):
    """Resolve a hostname parameter to an IP address. Returns IP string.
    Raises ValueError if invalid."""
    if not value:
        raise ValueError("Target is required")
    value = value.strip()
    if validate_ip(value):
        return value
    if validate_hostname(value):
        return resolve_target(value)
    raise ValueError("Invalid target (IP, CIDR, or hostname)")


@app.route('/api/vulnerabilities')
def get_vulnerabilities():
    """Get unified list of all vulnerabilities from all sources, deduplicated by CVE ID."""
    ip = request.args.get('ip')
    source = request.args.get('source')  # nuclei, nvd-local, nmap-vulscan, auth-scan, exploit-db
    has_exploit = request.args.get('has_exploit')
    search = request.args.get('search')

    try:
        if ip:
            try:
                ip = resolve_ip_param(ip)
            except (ValueError, ScanError) as e:
                return {'error': str(e)}, 400

        # Convert has_exploit to boolean
        exploit_filter = None
        if has_exploit is not None:
            exploit_filter = has_exploit.lower() in ('true', '1', 'yes')

        vulnerabilities = vuln_scan.get_unified_vulnerabilities(
            ip=ip, source=source, has_exploit=exploit_filter, search=search
        )
        summary = vuln_scan.get_unified_vulnerability_summary(ip=ip)

        logger.info(f"Retrieved {len(vulnerabilities)} unified vulnerabilities")
        return {
            'vulnerabilities': vulnerabilities,
            'summary': summary
        }
    except Exception as e:
        logger.error(f"Error retrieving vulnerabilities: {e}")
        return {'error': str(e)}, 500


@app.route('/api/asset/<ip>')
def get_asset(ip):
    """Get detailed information for a specific asset."""
    try:
        try:
            ip = resolve_ip_param(ip)
        except (ValueError, ScanError) as e:
            return {'error': str(e)}, 400

        asset = get_asset_details(ip)
        if not asset:
            return {'error': 'Asset not found'}, 404

        logger.info(f"Retrieved asset details for {ip}")
        return {'asset': asset}
    except Exception as e:
        logger.error(f"Error retrieving asset {ip}: {e}")
        return {'error': str(e)}, 500


@app.route('/api/scan-profiles')
def get_scan_profiles():
    """Get available scan profiles."""
    return {'profiles': list(SCAN_PROFILES.values())}


@app.route('/api/fingerprints/<ip>')
def get_fingerprints_api(ip):
    """Get fingerprint data for a specific IP."""
    try:
        try:
            ip = resolve_ip_param(ip)
        except (ValueError, ScanError) as e:
            return {'error': str(e)}, 400

        port = request.args.get('port', type=int)
        fingerprints = get_fingerprints(ip, port=port)
        summary = get_fingerprint_summary(ip)

        return {
            'fingerprints': fingerprints,
            'technologies': summary.get('technologies', []),
            'by_port': {str(k): v for k, v in summary.get('by_port', {}).items()},
        }
    except Exception as e:
        logger.error(f"Error retrieving fingerprints for {ip}: {e}")
        return {'error': str(e)}, 500


@app.route('/report/<ip>')
def generate_asset_report(ip):
    """Generate a report for an existing asset without performing a new scan."""
    try:
        try:
            ip = resolve_ip_param(ip)
        except (ValueError, ScanError) as e:
            logger.warning(f"Invalid target for report: {ip}")
            return render_template('report.html', ip=ip, error=str(e))

        # Get existing scan results, changes, and vulnerabilities (without performing a new scan)
        scan_results, changes, vulnerabilities = vuln_scan.generate_report_from_existing(ip)

        # Generate a report plot
        generate_report_plot(ip)

        return render_template('report.html', ip=ip, scan_results=scan_results, changes=changes, vulnerabilities=vulnerabilities)
    except ScanError as e:
        logger.error(f"Report generation error for {ip}: {e}")
        return render_template('report.html', ip=ip, error=str(e))
    except Exception as e:
        logger.error(f"Unexpected error generating report for {ip}: {e}")
        return render_template('report.html', ip=ip, error="An unexpected error occurred generating the report.")


@app.route('/scan', methods=['POST'])
def scan():
    ip = request.form.get('ip', '').strip()

    # Validate IP address
    if not ip:
        return render_template('report.html', ip=ip, error="IP address is required.")

    if not validate_target(ip):
        logger.warning(f"Invalid target submitted: {ip}")
        return render_template('report.html', ip=ip, error="Invalid target (IP, CIDR, or hostname).")

    try:
        scan_results, changes = vuln_scan.generate_report(ip)

        # Generate a report plot
        generate_report_plot(ip)

        return render_template('report.html', ip=ip, scan_results=scan_results, changes=changes)
    except ScanError as e:
        logger.error(f"Scan error for {ip}: {e}")
        return render_template('report.html', ip=ip, error=str(e))
    except Exception as e:
        logger.error(f"Unexpected error scanning {ip}: {e}")
        return render_template('report.html', ip=ip, error="An unexpected error occurred during the scan.")

def sanitize_filename(ip):
    """Sanitize IP address for safe use in filenames."""
    return re.sub(r'[^0-9.]', '_', ip)


def generate_report_plot(ip):
    """Generate a matplotlib plot showing vulnerability trends over time."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        cursor.execute('''SELECT scan_date, COUNT(*)
                          FROM scans
                          WHERE ip = ?
                          GROUP BY scan_date
                          ORDER BY scan_date''', (ip,))
        data = cursor.fetchall()

        if not data:
            logger.warning(f"No data to plot for {ip}")
            return

        dates = []
        counts = []
        for row in data:
            try:
                # Handle both formats with and without microseconds
                date_str = row[0]
                if '.' in date_str:
                    dates.append(datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S.%f'))
                else:
                    dates.append(datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S'))
                counts.append(row[1])
            except ValueError as e:
                logger.warning(f"Could not parse date {row[0]}: {e}")
                continue

        if not dates:
            logger.warning(f"No valid dates to plot for {ip}")
            return

        plt.figure()
        plt.plot(dates, counts, marker='o')
        plt.title(f'Open Ports Over Time for {ip}')
        plt.xlabel('Date')
        plt.ylabel('Number of Open Ports')
        plt.grid(True)
        plt.xticks(rotation=45)
        plt.tight_layout()

        # Use sanitized filename
        safe_filename = f'report_{sanitize_filename(ip)}.png'
        plt.savefig(os.path.join('static', safe_filename))
        logger.info(f"Generated report plot: {safe_filename}")
    except Exception as e:
        logger.error(f"Error generating plot for {ip}: {e}")
    finally:
        plt.close()
        conn.close()

def emit_log(sid, message, level='info'):
    """Emit a log message to the client."""
    socketio.emit('scan_log', {
        'message': message,
        'level': level
    }, room=sid)


def scan_single_ip(ip, sid, current=1, total=1, scan_options=None):
    """Execute scan on a single target (IP or hostname) and emit results."""
    # Determine if target is a hostname; resolve for storage but scan by original
    scan_target_str = ip  # What we pass to nmap
    store_ip = ip         # What we use as DB key
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
            'status': 'running',
            'message': f'Scanning {ip}...',
            'current': current,
            'total': total,
            'ip': store_ip
        }, room=sid)

        emit_log(sid, f'Initiating nmap scan on {scan_target_str}', 'debug')
        scan_result = vuln_scan.scan(scan_target_str, options=scan_options)
        scan_data = vuln_scan.parse_scan(scan_result)

        # Extract OS info from scan result
        os_info = get_os_info_from_scan(scan_result)
        if os_info.get('os_name'):
            emit_log(sid, f'Detected OS: {os_info["os_name"]}', 'info')

        # Extract hostname and MAC from nmap result
        host_info = extract_host_info_from_scan(scan_result)
        mac_address = host_info.get('mac_address')
        mac_vendor = host_info.get('mac_vendor')
        nmap_hostname = host_info.get('hostname')

        if mac_address:
            emit_log(sid, f'MAC: {mac_address} ({mac_vendor or "unknown vendor"})', 'info')
        if nmap_hostname:
            emit_log(sid, f'Hostname (nmap): {nmap_hostname}', 'info')

        # Perform reverse DNS lookup (supplements nmap hostname)
        emit_log(sid, f'Performing DNS lookup for {store_ip}', 'debug')
        dns_info = dns_lookup(store_ip)
        if dns_info.get('hostname'):
            emit_log(sid, f'DNS: {store_ip} -> {dns_info["hostname"]}', 'info')

        # Merge: prefer nmap hostname if dns didn't find one
        if nmap_hostname and not dns_info.get('hostname'):
            dns_info['hostname'] = nmap_hostname
        # Also store nmap hostname as reverse_dns fallback
        if nmap_hostname and not dns_info.get('reverse_dns'):
            dns_info['reverse_dns'] = nmap_hostname

        # If we scanned by hostname, make sure it's stored
        if original_hostname and not dns_info.get('hostname'):
            dns_info['hostname'] = original_hostname

        # Store asset info
        store_asset_info(store_ip, dns_info=dns_info, os_info=os_info,
                        mac_address=mac_address, mac_vendor=mac_vendor)

        # Store port scan results in database
        if scan_data:
            vuln_scan.store_scan(store_ip, scan_data)
            logger.info(f"Stored {len(scan_data)} ports for {store_ip}")
            emit_log(sid, f'Found {len(scan_data)} open port(s) on {scan_target_str}', 'success')

            # Parse vulscan results if enabled
            if scan_options and scan_options.get('vulscan') and is_vulscan_available():
                try:
                    vulscan_results = parse_vulscan_output(scan_result)
                    if vulscan_results:
                        store_vulscan_results(store_ip, vulscan_results)
                        emit_log(sid, f'Vulscan found {len(vulscan_results)} CVE matches for {store_ip}', 'success')
                    else:
                        emit_log(sid, f'Vulscan: no CVE matches for {store_ip}', 'debug')
                except Exception as e:
                    emit_log(sid, f'Vulscan parsing error: {e}', 'warning')
                    logger.warning(f"Vulscan error for {store_ip}: {e}")

            # Run fingerprinting on discovered ports
            emit_log(sid, f'Starting endpoint fingerprinting on {store_ip}', 'info')
            try:
                engine = get_fingerprint_engine()
                ports_for_fp = []
                for result in scan_data:
                    # scan_data is tuples: (protocol, port, state, service, product, version)
                    if result[2] == 'open':
                        ports_for_fp.append({
                            'port': result[1],
                            'protocol': result[0],
                            'service': result[3],
                            'product': result[4],
                            'version': result[5],
                            'extrainfo': '',
                        })

                if ports_for_fp:
                    def fp_log(msg):
                        emit_log(sid, msg, 'debug')

                    fp_results = engine.fingerprint_all_ports(store_ip, ports_for_fp, log_callback=fp_log)
                    store_fingerprints(store_ip, fp_results)

                    # Count identified services
                    identified = sum(1 for r in fp_results if r.best_match is not None)
                    total = len(fp_results)
                    emit_log(sid, f'Fingerprinting complete: identified {identified}/{total} services on {store_ip}', 'success')

                    # Log top matches
                    for r in fp_results:
                        if r.best_match:
                            m = r.best_match
                            ver = f' v{m.version}' if m.version else ''
                            emit_log(sid, f'  Port {r.port}: {m.name}{ver} ({m.category}, {m.confidence}% confidence)', 'info')

            except Exception as e:
                logger.error(f"Fingerprinting error for {store_ip}: {e}")
                emit_log(sid, f'Fingerprinting error: {e}', 'warning')

            # Run fingerprintx protocol-level identification
            try:
                if fpx_check_installed():
                    emit_log(sid, f'Running protocol fingerprinting (fingerprintx) on {store_ip}', 'info')

                    def fpx_log(msg):
                        emit_log(sid, msg, 'debug')

                    fpx_results = fpx_scan_host(store_ip, ports_for_fp, timeout_ms=3000,
                                                log_callback=fpx_log)
                    if fpx_results:
                        store_fpx_results(store_ip, fpx_results)
                        emit_log(sid, f'fingerprintx identified {len(fpx_results)} service(s) on {store_ip}', 'success')
                        for r in fpx_results:
                            ver = f' v{r.version}' if r.version else ''
                            emit_log(sid, f'  Port {r.port}: {r.service}{ver} (protocol handshake)', 'info')
                    else:
                        emit_log(sid, f'fingerprintx: no additional services identified on {store_ip}', 'debug')
                else:
                    emit_log(sid, 'fingerprintx not installed — skipping protocol fingerprinting', 'debug')
            except Exception as e:
                logger.error(f"fingerprintx error for {store_ip}: {e}")
                emit_log(sid, f'fingerprintx error: {e}', 'warning')

            # Wappalyzer web technology detection
            try:
                wap = get_wappalyzer()
                if wap:
                    emit_log(sid, f'Running Wappalyzer technology detection on {store_ip}', 'debug')
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
                                wap_results = wap_analyze(url, html, headers)
                                if wap_results:
                                    # Store as fingerprints
                                    from vuln_scan import store_fingerprints as _store_fp
                                    from fingerprint.engine import FingerprintResult, FingerprintMatch
                                    for wr in wap_results:
                                        cat = wr['categories'][0] if wr.get('categories') else 'web-technology'
                                        sig_id = f"wap-{wr['name'].lower().replace(' ', '-')}"
                                        conn = __import__('sqlite3').connect(DB_PATH)
                                        cur = conn.cursor()
                                        cur.execute('''INSERT OR REPLACE INTO fingerprints
                                            (ip, port, protocol, signature_id, name, category, vendor,
                                             version, cpe, confidence, evidence_json,
                                             tls_subject_cn, tls_subject_org, tls_issuer_org, tls_self_signed,
                                             http_title, http_server, favicon_hash, scan_date)
                                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                                            (store_ip, port_num, 'tcp', sig_id, wr['name'], cat, '',
                                             wr.get('version'), None, wr.get('confidence', 100),
                                             json.dumps(['wappalyzer']),
                                             None, None, None, 0, '', '', None,
                                             datetime.now().isoformat()))
                                        conn.commit()
                                        conn.close()
                                        wap_stored += 1
                                    emit_log(sid, f'  Wappalyzer found {len(wap_results)} tech(s) on port {port_num}', 'info')
                            except Exception as e:
                                logger.debug(f"Wappalyzer HTTP fetch error for {ip}:{port_num}: {e}")
                    if wap_stored:
                        emit_log(sid, f'Wappalyzer: detected {wap_stored} web technologies on {store_ip}', 'success')
            except Exception as e:
                logger.debug(f"Wappalyzer error for {store_ip}: {e}")

            # JARM TLS fingerprinting
            try:
                emit_log(sid, f'Running JARM TLS fingerprinting on {store_ip}', 'debug')
                def jarm_log(msg):
                    emit_log(sid, msg, 'debug')
                jarm_results = jarm_scan(store_ip, ports_for_fp, timeout=10, log_callback=jarm_log)
                if jarm_results:
                    import sqlite3 as _sq3
                    conn = _sq3.connect(DB_PATH)
                    cur = conn.cursor()
                    for jr in jarm_results:
                        sig_id = f"jarm-{jr['port']}"
                        name = jr.get('identified_as') or 'TLS Fingerprint'
                        cur.execute('''INSERT OR REPLACE INTO fingerprints
                            (ip, port, protocol, signature_id, name, category, vendor,
                             version, cpe, confidence, evidence_json,
                             tls_subject_cn, tls_subject_org, tls_issuer_org, tls_self_signed,
                             http_title, http_server, favicon_hash, scan_date)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                            (store_ip, jr['port'], 'tcp', sig_id, name, 'tls-fingerprint', '',
                             None, None, 70 if jr.get('identified_as') else 50,
                             json.dumps([f"jarm:{jr['jarm_hash']}"]),
                             None, None, None, 0, '', '', None,
                             datetime.now().isoformat()))
                    conn.commit()
                    conn.close()
                    emit_log(sid, f'JARM: fingerprinted {len(jarm_results)} TLS port(s) on {store_ip}', 'success')
            except Exception as e:
                logger.debug(f"JARM error for {store_ip}: {e}")

            # Classify device type using all available signals
            try:
                device_type = update_device_type(store_ip)
                if device_type and device_type != 'unknown':
                    icon = get_device_icon(device_type)
                    emit_log(sid, f'Device type: {icon} {device_type}', 'info')
            except Exception as e:
                logger.debug(f"Device type classification error for {store_ip}: {e}")
        else:
            emit_log(sid, f'No open ports found on {scan_target_str}', 'info')

        return {'ip': store_ip, 'scan_data': scan_data, 'success': True}
    except ScanError as e:
        logger.error(f"Scan error for {scan_target_str}: {e}")
        emit_log(sid, f'Scan error for {scan_target_str}: {e}', 'error')
        return {'ip': store_ip, 'error': str(e), 'success': False}
    except Exception as e:
        logger.error(f"Unexpected error scanning {scan_target_str}: {e}")
        emit_log(sid, f'Unexpected error scanning {scan_target_str}: {e}', 'error')
        return {'ip': store_ip, 'error': 'Scan failed unexpectedly', 'success': False}


def is_scan_cancelled(sid):
    """Check if scan for this session has been cancelled."""
    with scan_lock:
        return active_scans.get(sid, {}).get('cancelled', False)


def scan_target(target, sid, scan_options=None):
    """Execute scan on a target (single IP, CIDR range, or hostname)."""
    try:
        if not validate_target(target):
            socketio.emit('scan_error', {'error': 'Invalid target (IP, CIDR, or hostname)'}, room=sid)
            return

        # Get max hosts from options
        max_hosts = 256
        if scan_options and 'max_hosts' in scan_options:
            max_hosts = min(max(1, scan_options['max_hosts']), 1024)

        # Determine if this is a CIDR range, hostname, or single IP
        if is_cidr(target):
            ips = expand_cidr(target, max_hosts=max_hosts)
            if not ips:
                socketio.emit('scan_error', {'error': 'Failed to expand CIDR range'}, room=sid)
                return
            logger.info(f"CIDR scan started for {target} ({len(ips)} hosts, max {max_hosts})")
            emit_log(sid, f'Expanded CIDR {target} to {len(ips)} hosts', 'info')
        else:
            ips = [target]  # Could be IP or hostname — scan_single_ip handles resolution
            logger.info(f"Scan started for {target}")

        total = len(ips)
        results = []

        for i, ip in enumerate(ips, 1):
            # Check if scan has been cancelled
            if is_scan_cancelled(sid):
                emit_log(sid, 'Scan cancelled by user', 'warning')
                socketio.emit('scan_complete', {
                    'target': target,
                    'results': results,
                    'successful_count': len([r for r in results if r['success']]),
                    'failed_count': len([r for r in results if not r['success']]),
                    'total': total,
                    'cancelled': True
                }, room=sid)
                return

            result = scan_single_ip(ip, sid, current=i, total=total, scan_options=scan_options)
            results.append(result)

        # Emit final results
        successful = [r for r in results if r['success']]
        failed = [r for r in results if not r['success']]

        socketio.emit('scan_complete', {
            'target': target,
            'results': results,
            'successful_count': len(successful),
            'failed_count': len(failed),
            'total': total,
            'cancelled': False
        }, room=sid)
        logger.info(f"Scan completed for {target}: {len(successful)} successful, {len(failed)} failed")
    finally:
        # Clean up active scan tracking
        with scan_lock:
            if sid in active_scans:
                del active_scans[sid]


@socketio.on('start_scan')
def handle_start_scan(data):
    target = data.get('ip', '').strip()
    sid = request.sid  # Get the session ID of the requesting client

    if not target:
        emit('scan_error', {'error': 'IP address or CIDR is required'})
        return

    if not validate_target(target):
        emit('scan_error', {'error': 'Invalid target (IP, CIDR, or hostname)'})
        return

    # Extract scan options from data
    scan_options = {
        'ports': data.get('ports', ''),
        'scan_speed': data.get('scan_speed', 'T3'),
        'host_timeout': data.get('host_timeout', 300),
        'max_hosts': data.get('max_hosts', 256),
        'vulscan': data.get('vulscan', False)
    }

    # Track this scan
    with scan_lock:
        active_scans[sid] = {'type': 'port_scan', 'target': target, 'cancelled': False}

    logger.info(f"Received scan request for {target} from session {sid} with options: {scan_options}")
    thread = threading.Thread(target=scan_target, args=(target, sid, scan_options))
    thread.daemon = True  # Allow app to exit even if thread is running
    thread.start()


@socketio.on('stop_scan')
def handle_stop_scan():
    sid = request.sid
    with scan_lock:
        if sid in active_scans:
            active_scans[sid]['cancelled'] = True
            logger.info(f"Scan cancellation requested for session {sid}")
            emit_log(sid, 'Stopping scan...', 'warning')
        else:
            logger.warning(f"No active scan found for session {sid}")
            emit('scan_error', {'error': 'No active scan to stop'})


def vuln_scan_single_ip(ip, sid, current=1, total=1, scan_options=None):
    """Execute vulnerability scan on a single target using Nuclei."""
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
            'status': 'running',
            'message': f'Scanning {scan_target_str} for vulnerabilities...',
            'current': current,
            'total': total,
            'ip': store_ip
        }, room=sid)

        emit_log(sid, f'Running Nuclei vulnerability scan on {scan_target_str}', 'info')

        # Create a callback for nuclei progress logging
        def nuclei_log_callback(message):
            emit_log(sid, message, 'debug')

        # Pass original target to nuclei (hostname-aware scanning for SNI)
        scan_result = vuln_scan.vuln_scan(scan_target_str, options=scan_options, log_callback=nuclei_log_callback)
        vulnerabilities = vuln_scan.parse_vuln_scan(scan_result)
        emit_log(sid, f'Nuclei scan completed for {scan_target_str}, parsing results...', 'info')

        # Store results in database (this enriches with NVD data)
        if vulnerabilities:
            socketio.emit('vuln_scan_progress', {
                'status': 'running',
                'message': f'Enriching vulnerability data for {store_ip}...',
                'current': current,
                'total': total,
                'ip': store_ip
            }, room=sid)
            emit_log(sid, f'Enriching {len(vulnerabilities)} finding(s) with NVD data', 'debug')
            vuln_scan.store_vulnerabilities(store_ip, vulnerabilities)
            logger.info(f"Stored {len(vulnerabilities)} vulnerabilities for {store_ip}")
            emit_log(sid, f'Found {len(vulnerabilities)} vulnerability finding(s) on {scan_target_str}', 'warning')
        else:
            emit_log(sid, f'No vulnerabilities detected on {scan_target_str}', 'success')

        # Store hostname in asset if scanned by hostname
        if original_hostname:
            store_asset_info(store_ip, dns_info={'hostname': original_hostname})

        return {'ip': store_ip, 'vuln_count': len(vulnerabilities), 'success': True}
    except ScanError as e:
        logger.error(f"Vulnerability scan error for {scan_target_str}: {e}")
        emit_log(sid, f'Vulnerability scan error for {scan_target_str}: {e}', 'error')
        return {'ip': store_ip, 'error': str(e), 'success': False}
    except Exception as e:
        logger.error(f"Unexpected error in vuln scan for {scan_target_str}: {e}")
        emit_log(sid, f'Unexpected error in vuln scan for {scan_target_str}: {e}', 'error')
        return {'ip': store_ip, 'error': 'Vulnerability scan failed unexpectedly', 'success': False}


def vuln_scan_target(target, sid, scan_options=None):
    """Execute vulnerability scan on a target (single IP or CIDR range)."""
    try:
        if not validate_target(target):
            socketio.emit('vuln_scan_error', {'error': 'Invalid target (IP, CIDR, or hostname)'}, room=sid)
            return

        # Get max hosts from options
        max_hosts = 256
        if scan_options and 'max_hosts' in scan_options:
            max_hosts = min(max(1, scan_options['max_hosts']), 1024)

        # Determine if this is a CIDR range or single IP
        if is_cidr(target):
            ips = expand_cidr(target, max_hosts=max_hosts)
            if not ips:
                socketio.emit('vuln_scan_error', {'error': 'Failed to expand CIDR range'}, room=sid)
                return
            logger.info(f"CIDR vulnerability scan started for {target} ({len(ips)} hosts, max {max_hosts})")
            emit_log(sid, f'Expanded CIDR {target} to {len(ips)} hosts for vulnerability scan', 'info')
        else:
            ips = [target]
            logger.info(f"Single IP vulnerability scan started for {target}")

        total = len(ips)
        results = []

        for i, ip in enumerate(ips, 1):
            # Check if scan has been cancelled
            if is_scan_cancelled(sid):
                emit_log(sid, 'Vulnerability scan cancelled by user', 'warning')
                socketio.emit('vuln_scan_complete', {
                    'target': target,
                    'results': results,
                    'vulnerabilities': [],
                    'successful_count': len([r for r in results if r['success']]),
                    'failed_count': len([r for r in results if not r['success']]),
                    'total_vulns': 0,
                    'total': total,
                    'cancelled': True
                }, room=sid)
                return

            result = vuln_scan_single_ip(ip, sid, current=i, total=total, scan_options=scan_options)
            results.append(result)

        # Fetch all enriched vulnerabilities for the scanned IPs
        all_vulns = []
        for ip in ips:
            all_vulns.extend(vuln_scan.get_vulnerabilities(ip))

        successful = [r for r in results if r['success']]
        failed = [r for r in results if not r['success']]

        socketio.emit('vuln_scan_complete', {
            'target': target,
            'results': results,
            'vulnerabilities': all_vulns,
            'successful_count': len(successful),
            'failed_count': len(failed),
            'total_vulns': len(all_vulns),
            'total': total,
            'cancelled': False
        }, room=sid)
        logger.info(f"Vulnerability scan completed for {target}: {len(successful)} successful, {len(failed)} failed, {len(all_vulns)} vulns")
    finally:
        # Clean up active scan tracking
        with scan_lock:
            if sid in active_scans:
                del active_scans[sid]


@socketio.on('start_fingerprint_scan')
def handle_start_fingerprint_scan(data):
    """Run fingerprinting on an already-scanned target using stored port data."""
    target = data.get('ip', '').strip()
    sid = request.sid

    if not target:
        emit('scan_error', {'error': 'IP address is required'})
        return

    if not validate_target(target):
        emit('scan_error', {'error': 'Invalid target (IP, CIDR, or hostname)'})
        return

    # Resolve hostname to IP if needed
    if is_hostname(target):
        try:
            target = resolve_target(target)
        except ScanError as e:
            emit('scan_error', {'error': str(e)})
            return

    def run_fingerprint(ip, sid):
        try:
            emit_log(sid, f'Starting fingerprint scan for {ip}', 'info')
            socketio.emit('scan_progress', {
                'status': 'running',
                'message': f'Fingerprinting {ip}...',
                'current': 1,
                'total': 1,
                'ip': ip
            }, room=sid)

            # Get latest port data from DB
            latest_scan = vuln_scan.get_latest_scan(ip)
            if not latest_scan:
                emit_log(sid, f'No scan data for {ip}. Run a port scan first.', 'error')
                socketio.emit('scan_error', {'error': f'No scan data for {ip}. Run a port scan first.'}, room=sid)
                return

            engine = get_fingerprint_engine()
            ports_for_fp = []
            for row in latest_scan:
                # row: (protocol, port, state, service, product, version)
                if row[2] == 'open':
                    ports_for_fp.append({
                        'port': row[1],
                        'protocol': row[0],
                        'service': row[3],
                        'product': row[4],
                        'version': row[5],
                        'extrainfo': '',
                    })

            if not ports_for_fp:
                emit_log(sid, f'No open ports found for {ip}', 'warning')
                socketio.emit('scan_complete', {
                    'target': ip,
                    'results': [{'ip': ip, 'scan_data': [], 'success': True}],
                    'successful_count': 1,
                    'failed_count': 0,
                    'total': 1,
                    'cancelled': False
                }, room=sid)
                return

            emit_log(sid, f'Fingerprinting {len(ports_for_fp)} open port(s) on {ip}', 'info')

            def fp_log(msg):
                emit_log(sid, msg, 'debug')

            # HTTP-level fingerprinting
            fp_results = engine.fingerprint_all_ports(ip, ports_for_fp, log_callback=fp_log)
            store_fingerprints(ip, fp_results)

            identified = sum(1 for r in fp_results if r.best_match is not None)
            total_ports = len(fp_results)
            emit_log(sid, f'HTTP fingerprinting: identified {identified}/{total_ports} services', 'success')

            for r in fp_results:
                if r.best_match:
                    m = r.best_match
                    ver = f' v{m.version}' if m.version else ''
                    emit_log(sid, f'  Port {r.port}: {m.name}{ver} ({m.category}, {m.confidence}% confidence)', 'info')

            # Protocol-level fingerprinting (fingerprintx)
            fpx_count = 0
            try:
                if fpx_check_installed():
                    emit_log(sid, f'Running protocol fingerprinting (fingerprintx) on {ip}', 'info')

                    def fpx_log(msg):
                        emit_log(sid, msg, 'debug')

                    fpx_results = fpx_scan_host(ip, ports_for_fp, timeout_ms=3000,
                                                log_callback=fpx_log)
                    if fpx_results:
                        store_fpx_results(ip, fpx_results)
                        fpx_count = len(fpx_results)
                        emit_log(sid, f'fingerprintx identified {fpx_count} service(s)', 'success')
                        for r in fpx_results:
                            ver = f' v{r.version}' if r.version else ''
                            emit_log(sid, f'  Port {r.port}: {r.service}{ver} (protocol handshake)', 'info')
            except Exception as e:
                emit_log(sid, f'fingerprintx error: {e}', 'warning')

            socketio.emit('scan_complete', {
                'target': ip,
                'results': [{'ip': ip, 'scan_data': latest_scan, 'success': True}],
                'successful_count': 1,
                'failed_count': 0,
                'total': 1,
                'cancelled': False,
                'fingerprint_results': [r.to_dict() for r in fp_results],
                'fpx_count': fpx_count,
            }, room=sid)

        except Exception as e:
            logger.error(f"Fingerprint scan error for {ip}: {e}")
            emit_log(sid, f'Fingerprint scan error: {e}', 'error')
            socketio.emit('scan_error', {'error': str(e)}, room=sid)
        finally:
            with scan_lock:
                if sid in active_scans:
                    del active_scans[sid]

    with scan_lock:
        active_scans[sid] = {'type': 'fingerprint', 'target': target, 'cancelled': False}

    thread = threading.Thread(target=run_fingerprint, args=(target, sid))
    thread.daemon = True
    thread.start()


@socketio.on('start_vuln_scan')
def handle_start_vuln_scan(data):
    target = data.get('ip', '').strip()
    sid = request.sid

    if not target:
        emit('vuln_scan_error', {'error': 'IP address or CIDR is required'})
        return

    if not validate_target(target):
        emit('vuln_scan_error', {'error': 'Invalid target (IP, CIDR, or hostname)'})
        return

    # Check if a scan profile was selected
    profile_id = data.get('profile', '')
    profile = SCAN_PROFILES.get(profile_id) if profile_id else None

    # Extract Nuclei vuln scan options — profile overrides manual settings
    scan_options = {
        'vuln_timeout': data.get('vuln_timeout', 600),
        'severity': data.get('severity', 'critical,high,medium,low'),
        'rate_limit': data.get('rate_limit', 150),
        'templates': data.get('templates', ''),
        'max_hosts': data.get('max_hosts', 256)
    }

    if profile:
        if profile.get('tags'):
            scan_options['templates'] = profile['tags']
        if profile.get('severity'):
            scan_options['severity'] = profile['severity']
        if profile.get('rate_limit'):
            scan_options['rate_limit'] = profile['rate_limit']
        logger.info(f"Using scan profile '{profile['name']}': tags={scan_options['templates']}, severity={scan_options['severity']}")

    # Track this scan
    with scan_lock:
        active_scans[sid] = {'type': 'vuln_scan', 'target': target, 'cancelled': False}

    logger.info(f"Received Nuclei vulnerability scan request for {target} from session {sid} with options: {scan_options}")
    thread = threading.Thread(target=vuln_scan_target, args=(target, sid, scan_options))
    thread.daemon = True
    thread.start()


@app.route('/api/asset/<ip>/auth-details')
def get_asset_auth_details(ip):
    """Get authenticated scan details: OS info, installed software, CVE matches."""
    try:
        if not validate_ip(ip) and not validate_hostname(ip):
            return {'error': 'Invalid target (IP, CIDR, or hostname)'}, 400
        if is_hostname(ip):
            ip = resolve_target(ip)

        os_details = get_asset_os_details(ip)
        software = get_installed_software(ip)
        cves = get_cve_matches(ip)

        # Enrich CVEs with exploit info if not already present
        for cve in cves:
            if not cve.get('has_exploit') and cve.get('cve_id'):
                try:
                    from exploit_ref import lookup_exploits
                    info = lookup_exploits(cve['cve_id'])
                    cve['has_exploit'] = info['has_exploit']
                    cve['exploit_ids'] = ','.join(info['exploit_ids'])
                    cve['exploit_url'] = info['exploit_urls'][0] if info['exploit_urls'] else ''
                except Exception:
                    pass

        return {
            'os_details': os_details,
            'software': software,
            'software_count': len(software),
            'cves': cves,
            'cve_count': len(cves)
        }
    except Exception as e:
        logger.error(f"Error getting auth details for {ip}: {e}")
        return {'error': str(e)}, 500


# ============== Credentials & Settings API ==============

@app.route('/api/credentials', methods=['GET'])
def api_get_credentials():
    """Get all credentials (passwords masked in response)."""
    creds = get_all_credentials()
    # Mask passwords in response
    for c in creds:
        if c['password']:
            c['password_set'] = True
            c['password'] = ''
        else:
            c['password_set'] = False
    return {'credentials': creds}


@app.route('/api/credentials', methods=['POST'])
def api_save_credential():
    """Create or update a credential."""
    data = request.get_json()
    if not data:
        return {'error': 'JSON body required'}, 400

    name = data.get('name', '').strip()
    cred_type = data.get('cred_type', 'ssh_key')
    username = data.get('username', 'root').strip()
    key_path = data.get('key_path', '').strip()
    password = data.get('password', '').strip()
    cred_id = data.get('id')

    if not name:
        return {'error': 'Credential name is required'}, 400
    if not username:
        return {'error': 'Username is required'}, 400
    if cred_type == 'ssh_key' and not key_path:
        return {'error': 'Key path is required for SSH key auth'}, 400
    if cred_type == 'ssh_password' and not password:
        # If editing and no new password provided, keep existing
        if cred_id:
            existing = get_credential(cred_id)
            if existing:
                password = existing['password']
        if not password:
            return {'error': 'Password is required for password auth'}, 400

    try:
        result_id = save_credential(name, cred_type, username, key_path, password, cred_id)
        return {'id': result_id, 'success': True}
    except ValueError as e:
        return {'error': str(e)}, 400


@app.route('/api/credentials/<int:cred_id>', methods=['DELETE'])
def api_delete_credential(cred_id):
    """Delete a credential."""
    if delete_credential(cred_id):
        return {'success': True}
    return {'error': 'Credential not found'}, 404


@app.route('/api/nvd-status')
def api_nvd_status():
    """Get NVD local database sync status."""
    status = get_nvd_sync_status()
    return status


@socketio.on('start_nvd_sync')
def handle_start_nvd_sync(data):
    """Start NVD database sync in background."""
    sid = request.sid
    full_sync = data.get('full', False)
    api_key = get_setting('nvd_api_key', '') or None

    def run_sync():
        try:
            sync_nvd_database(socketio=socketio, api_key=api_key, full_sync=full_sync)

            # Also sync CPE dictionary
            try:
                from cpe_dict import sync_cpe_dictionary
                socketio.emit('nvd_sync_progress', {'status': 'running', 'message': 'Syncing CPE dictionary...'})
                sync_cpe_dictionary(socketio=socketio)
            except Exception as e:
                logger.warning(f"CPE dictionary sync error: {e}")

            # Update ExploitDB mapping
            try:
                ensure_exploit_db()
                socketio.emit('nvd_sync_progress', {'status': 'running', 'message': 'ExploitDB mapping updated'})
            except Exception as e:
                logger.warning(f"ExploitDB update error: {e}")

        except Exception as e:
            logger.error(f"NVD sync error: {e}")
            socketio.emit('nvd_sync_progress', {'status': 'error', 'message': str(e)})

    emit_log(sid, f'Starting NVD database sync ({"full" if full_sync else "incremental"})...', 'info')
    thread = threading.Thread(target=run_sync)
    thread.daemon = True
    thread.start()


@app.route('/api/settings/nvd-key', methods=['GET'])
def api_get_nvd_key():
    """Get NVD API key (masked)."""
    key = get_setting('nvd_api_key', '')
    return {'has_key': bool(key), 'masked': ('••••' + key[-4:]) if key and len(key) > 4 else ('••••' if key else '')}


@app.route('/api/settings/nvd-key', methods=['POST'])
def api_set_nvd_key():
    """Set NVD API key."""
    data = request.get_json()
    if not data:
        return {'error': 'JSON body required'}, 400
    key = data.get('key', '').strip()
    set_setting('nvd_api_key', key)
    return {'success': True}


@socketio.on('start_auth_scan')
def handle_start_auth_scan(data):
    """Handle authenticated scan request with smart credential selection."""
    target = data.get('ip', '').strip()
    sid = request.sid

    if not target:
        emit('scan_error', {'error': 'IP address is required'})
        return

    if not validate_target(target):
        emit('scan_error', {'error': 'Invalid target (IP, CIDR, or hostname)'})
        return

    # Get selected credential IDs (list of IDs or 'all')
    credential_ids = data.get('credential_ids', [])
    use_all = data.get('use_all_credentials', False)

    # Resolve credentials
    if use_all:
        creds = get_all_credentials()
    else:
        creds = []
        for cid in credential_ids:
            c = get_credential(int(cid))
            if c:
                creds.append(c)

    if not creds:
        emit('scan_error', {'error': 'No credentials selected. Configure credentials in Settings.'})
        return

    # Get NVD API key from settings
    nvd_api_key = get_setting('nvd_api_key', '') or None

    def run_smart_auth_scan(target, sid, creds):
        try:
            # Resolve IPs
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

            total_ips = len(ips)
            all_results = []

            for ip_idx, ip in enumerate(ips, 1):
                if is_scan_cancelled(sid):
                    emit_log(sid, 'Auth scan cancelled', 'warning')
                    break

                socketio.emit('scan_progress', {
                    'status': 'running',
                    'message': f'Auth scan {ip} ({ip_idx}/{total_ips})...',
                    'current': ip_idx, 'total': total_ips, 'ip': ip
                }, room=sid)

                # Step 1: Check if port scan data exists; if not, run one first
                open_ports = get_open_ports_for_ip(ip)
                if not open_ports:
                    emit_log(sid, f'No port scan data for {ip} — running port scan first...', 'info')
                    result = scan_single_ip(ip, sid, current=ip_idx, total=total_ips)
                    if not result['success']:
                        emit_log(sid, f'Port scan failed for {ip}, skipping auth scan', 'error')
                        continue
                    open_ports = get_open_ports_for_ip(ip)

                if not open_ports:
                    emit_log(sid, f'No open ports on {ip}, skipping', 'info')
                    continue

                # Step 2: Determine which ports are SSH-capable
                ssh_ports = [p['port'] for p in open_ports
                             if p['port'] in (22, 2222, 2200) or p['service'] in ('ssh', 'openssh')]

                # Get OS hints from nmap/assets for smart decisions
                asset_details = vuln_scan.get_asset_details(ip)
                os_hint = ''
                if asset_details:
                    os_hint = (asset_details.get('os_name') or '').lower() + ' ' + \
                              (asset_details.get('os_family') or '').lower()

                is_likely_windows = any(w in os_hint for w in ['windows', 'microsoft'])

                # Step 3: Smart credential matching
                for cred in creds:
                    cred_type = cred['cred_type']

                    if cred_type in ('ssh_key', 'ssh_password'):
                        if not ssh_ports:
                            emit_log(sid, f'Skipping SSH cred "{cred["name"]}" for {ip}: no SSH port open', 'debug')
                            continue
                        if is_likely_windows and 22 not in [p['port'] for p in open_ports]:
                            emit_log(sid, f'Skipping SSH cred "{cred["name"]}" for {ip}: Windows host, SSH not detected', 'debug')
                            continue

                        # Try each SSH port
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

                                # Store results
                                store_auth_scan_results(ip, result['os_info'], result['packages'], result['cves'])

                                # Also update the assets table with auth OS info
                                if result['os_info'].get('pretty_name') or result['os_info'].get('distro'):
                                    os_update = {
                                        'os_name': result['os_info'].get('pretty_name') or result['os_info'].get('distro'),
                                        'os_family': result['os_info'].get('os_family'),
                                    }
                                    store_asset_info(ip, os_info=os_update)

                                emit_log(sid, f'✓ Auth scan success on {ip}:{ssh_port} with "{cred["name"]}": '
                                         f'{len(result["packages"])} packages, {len(result["cves"])} CVEs', 'success')

                                all_results.append({
                                    'ip': ip, 'credential': cred['name'], 'port': ssh_port,
                                    'packages': len(result['packages']), 'cves': len(result['cves']),
                                    'success': True
                                })
                                break  # Success — don't try other SSH ports with same cred

                            except Exception as e:
                                emit_log(sid, f'✗ Failed "{cred["name"]}" on {ip}:{ssh_port}: {e}', 'warning')
                                all_results.append({
                                    'ip': ip, 'credential': cred['name'], 'port': ssh_port,
                                    'error': str(e), 'success': False
                                })

                    # Future: WinRM/WMI credential types would check ports 5985/5986 here

            successful = [r for r in all_results if r['success']]
            socketio.emit('auth_scan_complete', {
                'target': target,
                'results': all_results,
                'successful_count': len(successful),
                'total_count': len(all_results),
                'success': len(successful) > 0
            }, room=sid)

        except Exception as e:
            logger.error(f"Auth scan error: {e}")
            emit_log(sid, f'Auth scan error: {e}', 'error')
            socketio.emit('scan_error', {'error': str(e)}, room=sid)
        finally:
            with scan_lock:
                if sid in active_scans:
                    del active_scans[sid]

    emit_log(sid, f'Starting smart authenticated scan on {target} with {len(creds)} credential(s)', 'info')

    with scan_lock:
        active_scans[sid] = {'type': 'auth_scan', 'target': target, 'cancelled': False}

    thread = threading.Thread(target=run_smart_auth_scan, args=(target, sid, creds))
    thread.daemon = True
    thread.start()


@app.route('/api/sql', methods=['POST'])
def api_sql_query():
    """Execute a read-only SQL query against the scanner database."""
    import time as _time
    data = request.get_json()
    if not data or not data.get('query'):
        return {'error': 'Query is required'}, 400

    query = data['query'].strip()
    if not query:
        return {'error': 'Query is required'}, 400

    # Validate read-only: only allow SELECT and common read statements
    normalized = re.sub(r'--.*$', '', query, flags=re.MULTILINE)  # strip comments
    normalized = re.sub(r'/\*.*?\*/', '', normalized, flags=re.DOTALL)
    normalized = normalized.strip().upper()

    allowed_prefixes = ('SELECT', 'PRAGMA', 'EXPLAIN', 'WITH')
    if not any(normalized.startswith(p) for p in allowed_prefixes):
        return {'error': 'Only SELECT queries are allowed (read-only mode).'}, 400

    # Block dangerous keywords even in subqueries
    dangerous = ['INSERT', 'UPDATE', 'DELETE', 'DROP', 'ALTER', 'CREATE', 'REPLACE',
                 'ATTACH', 'DETACH', 'REINDEX', 'VACUUM']
    # Check tokens (word boundaries)
    for kw in dangerous:
        if re.search(r'\b' + kw + r'\b', normalized):
            return {'error': f'{kw} statements are not allowed (read-only mode).'}, 400

    try:
        start = _time.monotonic()
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(query)
        rows_raw = cursor.fetchmany(1000)
        columns = [desc[0] for desc in cursor.description] if cursor.description else []
        rows = [list(row) for row in rows_raw]
        elapsed = round((_time.monotonic() - start) * 1000, 1)
        conn.close()

        return {
            'columns': columns,
            'rows': rows,
            'count': len(rows),
            'time_ms': elapsed,
            'truncated': len(rows_raw) == 1000
        }
    except sqlite3.Error as e:
        return {'error': str(e)}, 400
    except Exception as e:
        logger.error(f"SQL query error: {e}")
        return {'error': str(e)}, 500


if __name__ == '__main__':
    debug_mode = os.environ.get('DEBUG', 'false').lower() == 'true'
    socketio.run(app, debug=debug_mode)
