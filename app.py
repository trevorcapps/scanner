import os
import re
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
from vuln_scan import (ScanError, validate_ip, validate_target, is_cidr, expand_cidr,
                       DB_PATH, dns_lookup, get_os_info_from_scan, store_asset_info,
                       get_asset_details, get_fingerprints, get_fingerprint_summary,
                       store_fingerprints, store_fpx_results, get_fingerprint_engine,
                       fpx_check_installed)
from fingerprint.fpx import scan_host as fpx_scan_host

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

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

            assets.append({
                'ip': ip,
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


@app.route('/api/vulnerabilities')
def get_vulnerabilities():
    """Get list of all vulnerabilities, optionally filtered by IP."""
    ip = request.args.get('ip')

    try:
        if ip and not validate_ip(ip):
            return {'error': 'Invalid IP address'}, 400

        vulnerabilities = vuln_scan.get_vulnerabilities(ip)
        summary = vuln_scan.get_vulnerability_summary()

        logger.info(f"Retrieved {len(vulnerabilities)} vulnerabilities")
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
        if not validate_ip(ip):
            return {'error': 'Invalid IP address'}, 400

        asset = get_asset_details(ip)
        if not asset:
            return {'error': 'Asset not found'}, 404

        logger.info(f"Retrieved asset details for {ip}")
        return {'asset': asset}
    except Exception as e:
        logger.error(f"Error retrieving asset {ip}: {e}")
        return {'error': str(e)}, 500


@app.route('/api/fingerprints/<ip>')
def get_fingerprints_api(ip):
    """Get fingerprint data for a specific IP."""
    try:
        if not validate_ip(ip):
            return {'error': 'Invalid IP address'}, 400

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
        if not validate_ip(ip):
            logger.warning(f"Invalid IP address for report: {ip}")
            return render_template('report.html', ip=ip, error="Invalid IP address format.")

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

    if not validate_ip(ip):
        logger.warning(f"Invalid IP address submitted: {ip}")
        return render_template('report.html', ip=ip, error="Invalid IP address format.")

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
    """Execute scan on a single IP and emit results."""
    try:
        socketio.emit('scan_progress', {
            'status': 'running',
            'message': f'Scanning {ip}...',
            'current': current,
            'total': total,
            'ip': ip
        }, room=sid)

        # Perform DNS lookup first
        emit_log(sid, f'Performing DNS lookup for {ip}', 'debug')
        dns_info = dns_lookup(ip)
        if dns_info.get('hostname'):
            emit_log(sid, f'DNS: {ip} -> {dns_info["hostname"]}', 'info')

        emit_log(sid, f'Initiating nmap scan on {ip}', 'debug')
        scan_result = vuln_scan.scan(ip, options=scan_options)
        scan_data = vuln_scan.parse_scan(scan_result)

        # Extract OS info from scan result
        os_info = get_os_info_from_scan(scan_result)
        if os_info.get('os_name'):
            emit_log(sid, f'Detected OS: {os_info["os_name"]}', 'info')

        # Extract MAC address if available
        mac_address = None
        mac_vendor = None
        if hasattr(scan_result, 'get'):
            addresses = scan_result.get('addresses', {})
            mac_address = addresses.get('mac')
            vendor = scan_result.get('vendor', {})
            if mac_address and mac_address in vendor:
                mac_vendor = vendor[mac_address]

        # Store asset info
        store_asset_info(ip, dns_info=dns_info, os_info=os_info,
                        mac_address=mac_address, mac_vendor=mac_vendor)

        # Store port scan results in database
        if scan_data:
            vuln_scan.store_scan(ip, scan_data)
            logger.info(f"Stored {len(scan_data)} ports for {ip}")
            emit_log(sid, f'Found {len(scan_data)} open port(s) on {ip}', 'success')

            # Run fingerprinting on discovered ports
            emit_log(sid, f'Starting endpoint fingerprinting on {ip}', 'info')
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

                    fp_results = engine.fingerprint_all_ports(ip, ports_for_fp, log_callback=fp_log)
                    store_fingerprints(ip, fp_results)

                    # Count identified services
                    identified = sum(1 for r in fp_results if r.best_match is not None)
                    total = len(fp_results)
                    emit_log(sid, f'Fingerprinting complete: identified {identified}/{total} services on {ip}', 'success')

                    # Log top matches
                    for r in fp_results:
                        if r.best_match:
                            m = r.best_match
                            ver = f' v{m.version}' if m.version else ''
                            emit_log(sid, f'  Port {r.port}: {m.name}{ver} ({m.category}, {m.confidence}% confidence)', 'info')

            except Exception as e:
                logger.error(f"Fingerprinting error for {ip}: {e}")
                emit_log(sid, f'Fingerprinting error: {e}', 'warning')

            # Run fingerprintx protocol-level identification
            try:
                if fpx_check_installed():
                    emit_log(sid, f'Running protocol fingerprinting (fingerprintx) on {ip}', 'info')

                    def fpx_log(msg):
                        emit_log(sid, msg, 'debug')

                    fpx_results = fpx_scan_host(ip, ports_for_fp, timeout_ms=3000,
                                                log_callback=fpx_log)
                    if fpx_results:
                        store_fpx_results(ip, fpx_results)
                        emit_log(sid, f'fingerprintx identified {len(fpx_results)} service(s) on {ip}', 'success')
                        for r in fpx_results:
                            ver = f' v{r.version}' if r.version else ''
                            emit_log(sid, f'  Port {r.port}: {r.service}{ver} (protocol handshake)', 'info')
                    else:
                        emit_log(sid, f'fingerprintx: no additional services identified on {ip}', 'debug')
                else:
                    emit_log(sid, 'fingerprintx not installed — skipping protocol fingerprinting', 'debug')
            except Exception as e:
                logger.error(f"fingerprintx error for {ip}: {e}")
                emit_log(sid, f'fingerprintx error: {e}', 'warning')
        else:
            emit_log(sid, f'No open ports found on {ip}', 'info')

        return {'ip': ip, 'scan_data': scan_data, 'success': True}
    except ScanError as e:
        logger.error(f"Scan error for {ip}: {e}")
        emit_log(sid, f'Scan error for {ip}: {e}', 'error')
        return {'ip': ip, 'error': str(e), 'success': False}
    except Exception as e:
        logger.error(f"Unexpected error scanning {ip}: {e}")
        emit_log(sid, f'Unexpected error scanning {ip}: {e}', 'error')
        return {'ip': ip, 'error': 'Scan failed unexpectedly', 'success': False}


def is_scan_cancelled(sid):
    """Check if scan for this session has been cancelled."""
    with scan_lock:
        return active_scans.get(sid, {}).get('cancelled', False)


def scan_target(target, sid, scan_options=None):
    """Execute scan on a target (single IP or CIDR range)."""
    try:
        if not validate_target(target):
            socketio.emit('scan_error', {'error': 'Invalid IP address or CIDR notation'}, room=sid)
            return

        # Get max hosts from options
        max_hosts = 256
        if scan_options and 'max_hosts' in scan_options:
            max_hosts = min(max(1, scan_options['max_hosts']), 1024)

        # Determine if this is a CIDR range or single IP
        if is_cidr(target):
            ips = expand_cidr(target, max_hosts=max_hosts)
            if not ips:
                socketio.emit('scan_error', {'error': 'Failed to expand CIDR range'}, room=sid)
                return
            logger.info(f"CIDR scan started for {target} ({len(ips)} hosts, max {max_hosts})")
            emit_log(sid, f'Expanded CIDR {target} to {len(ips)} hosts', 'info')
        else:
            ips = [target]
            logger.info(f"Single IP scan started for {target}")

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
        emit('scan_error', {'error': 'Invalid IP address or CIDR format (e.g., 192.168.1.1 or 10.0.0.0/24)'})
        return

    # Extract scan options from data
    scan_options = {
        'ports': data.get('ports', ''),
        'scan_speed': data.get('scan_speed', 'T3'),
        'host_timeout': data.get('host_timeout', 300),
        'max_hosts': data.get('max_hosts', 256)
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
    """Execute vulnerability scan on a single IP using Nuclei."""
    try:
        socketio.emit('vuln_scan_progress', {
            'status': 'running',
            'message': f'Scanning {ip} for vulnerabilities...',
            'current': current,
            'total': total,
            'ip': ip
        }, room=sid)

        emit_log(sid, f'Running Nuclei vulnerability scan on {ip}', 'info')

        # Create a callback for nuclei progress logging
        def nuclei_log_callback(message):
            emit_log(sid, message, 'debug')

        scan_result = vuln_scan.vuln_scan(ip, options=scan_options, log_callback=nuclei_log_callback)
        vulnerabilities = vuln_scan.parse_vuln_scan(scan_result)
        emit_log(sid, f'Nuclei scan completed for {ip}, parsing results...', 'info')

        # Store results in database (this enriches with NVD data)
        if vulnerabilities:
            socketio.emit('vuln_scan_progress', {
                'status': 'running',
                'message': f'Enriching vulnerability data for {ip}...',
                'current': current,
                'total': total,
                'ip': ip
            }, room=sid)
            emit_log(sid, f'Enriching {len(vulnerabilities)} finding(s) with NVD data', 'debug')
            vuln_scan.store_vulnerabilities(ip, vulnerabilities)
            logger.info(f"Stored {len(vulnerabilities)} vulnerabilities for {ip}")
            emit_log(sid, f'Found {len(vulnerabilities)} vulnerability finding(s) on {ip}', 'warning')
        else:
            emit_log(sid, f'No vulnerabilities detected on {ip}', 'success')

        return {'ip': ip, 'vuln_count': len(vulnerabilities), 'success': True}
    except ScanError as e:
        logger.error(f"Vulnerability scan error for {ip}: {e}")
        emit_log(sid, f'Vulnerability scan error for {ip}: {e}', 'error')
        return {'ip': ip, 'error': str(e), 'success': False}
    except Exception as e:
        logger.error(f"Unexpected error in vuln scan for {ip}: {e}")
        emit_log(sid, f'Unexpected error in vuln scan for {ip}: {e}', 'error')
        return {'ip': ip, 'error': 'Vulnerability scan failed unexpectedly', 'success': False}


def vuln_scan_target(target, sid, scan_options=None):
    """Execute vulnerability scan on a target (single IP or CIDR range)."""
    try:
        if not validate_target(target):
            socketio.emit('vuln_scan_error', {'error': 'Invalid IP address or CIDR notation'}, room=sid)
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

    if not validate_ip(target):
        emit('scan_error', {'error': 'Invalid IP address'})
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
        emit('vuln_scan_error', {'error': 'Invalid IP address or CIDR format (e.g., 192.168.1.1 or 10.0.0.0/24)'})
        return

    # Extract Nuclei vuln scan options from data
    scan_options = {
        'vuln_timeout': data.get('vuln_timeout', 600),
        'severity': data.get('severity', 'critical,high,medium,low'),
        'rate_limit': data.get('rate_limit', 150),
        'templates': data.get('templates', ''),
        'max_hosts': data.get('max_hosts', 256)
    }

    # Track this scan
    with scan_lock:
        active_scans[sid] = {'type': 'vuln_scan', 'target': target, 'cancelled': False}

    logger.info(f"Received Nuclei vulnerability scan request for {target} from session {sid} with options: {scan_options}")
    thread = threading.Thread(target=vuln_scan_target, args=(target, sid, scan_options))
    thread.daemon = True
    thread.start()


if __name__ == '__main__':
    debug_mode = os.environ.get('DEBUG', 'false').lower() == 'true'
    socketio.run(app, debug=debug_mode)
