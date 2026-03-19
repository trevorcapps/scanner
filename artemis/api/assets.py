"""Assets API blueprint."""

import sqlite3
import logging

from flask import Blueprint, request

from artemis.utils.validation import validate_ip, validate_hostname, is_hostname
from artemis.utils.dns import ScanError, resolve_target, resolve_ip_param
from artemis.services.asset_service import get_asset_details
from artemis.services.vuln_service import get_vulnerability_counts_by_severity
from artemis.services.fingerprint_service import get_fingerprint_summary
from artemis.services.auth_scan_service import get_asset_os_details, get_installed_software, get_cve_matches

logger = logging.getLogger(__name__)

assets_bp = Blueprint('assets', __name__)


def _get_db_path():
    from flask import current_app
    return current_app.config['DB_PATH']


@assets_bp.route('/assets')
def get_assets():
    """Get list of previously scanned hosts with their latest scan info."""
    import sys, os
    scanner_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if scanner_dir not in sys.path:
        sys.path.insert(0, scanner_dir)
    from device_type import get_device_icon

    conn = sqlite3.connect(_get_db_path())
    cursor = conn.cursor()

    try:
        cursor.execute('''
            SELECT ip, MAX(scan_date) as last_scan
            FROM scans GROUP BY ip ORDER BY last_scan DESC
        ''')
        hosts = cursor.fetchall()

        assets = []
        for host in hosts:
            ip, last_scan = host
            cursor.execute('''
                SELECT protocol, port, state, service, product, version
                FROM scans WHERE ip = ? AND scan_date = ?
            ''', (ip, last_scan))
            ports = cursor.fetchall()
            port_count = len(ports)

            vuln_counts = get_vulnerability_counts_by_severity(ip)
            fp_summary = get_fingerprint_summary(ip)
            fp_techs = fp_summary.get('technologies', [])
            fp_by_port = fp_summary.get('by_port', {})

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
                'technologies': fp_techs[:5],
                'ports': [
                    {
                        'protocol': p[0], 'port': p[1], 'state': p[2],
                        'service': p[3], 'product': p[4], 'version': p[5],
                        'fingerprint': fp_by_port.get(p[1], {})
                    } for p in ports
                ]
            })

        return {'assets': assets}
    except sqlite3.Error as e:
        logger.error(f"Database error in get_assets: {e}")
        return {'error': str(e)}, 500
    finally:
        conn.close()


@assets_bp.route('/asset/<ip>')
def get_asset(ip):
    """Get detailed information for a specific asset."""
    try:
        ip = resolve_ip_param(ip)
    except (ValueError, ScanError) as e:
        return {'error': str(e)}, 400

    asset = get_asset_details(ip)
    if not asset:
        return {'error': 'Asset not found'}, 404

    return {'asset': asset}


@assets_bp.route('/asset/<ip>/auth-details')
def get_asset_auth_details(ip):
    """Get authenticated scan details."""
    try:
        if not validate_ip(ip) and not validate_hostname(ip):
            return {'error': 'Invalid target'}, 400
        if is_hostname(ip):
            ip = resolve_target(ip)

        os_details = get_asset_os_details(ip)
        software = get_installed_software(ip)
        cves = get_cve_matches(ip)

        # Enrich CVEs with exploit info
        for cve in cves:
            if not cve.get('has_exploit') and cve.get('cve_id'):
                try:
                    from artemis.services.nvd_service import lookup_exploits
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
