"""Asset CRUD & device classification service — extracted from vuln_scan.py."""

import json
import sqlite3
import logging
from datetime import datetime

from artemis.utils.validation import validate_ip, validate_hostname
from artemis.utils.dns import ScanError

logger = logging.getLogger(__name__)


def _get_db_path():
    try:
        from flask import current_app
        return current_app.config['DB_PATH']
    except Exception:
        import os
        return os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__)))), 'vuln_scan.db')


def store_asset_info(ip, dns_info=None, os_info=None, mac_address=None, mac_vendor=None):
    """Store or update asset information in the database."""
    conn = sqlite3.connect(_get_db_path())
    cursor = conn.cursor()
    now = datetime.now().isoformat()

    try:
        cursor.execute('SELECT id, scan_count, first_seen FROM assets WHERE ip = ?', (ip,))
        existing = cursor.fetchone()

        hostname = dns_info.get('hostname') if dns_info else None
        reverse_dns = dns_info.get('reverse_dns') if dns_info else None
        aliases_json = json.dumps(dns_info.get('aliases', [])) if dns_info else None

        os_name = os_info.get('os_name') if os_info else None
        os_family = os_info.get('os_family') if os_info else None
        os_vendor = os_info.get('os_vendor') if os_info else None
        os_accuracy = os_info.get('os_accuracy') if os_info else None
        device_type = os_info.get('device_type') if os_info else None

        if existing:
            cursor.execute('''UPDATE assets SET
                hostname = COALESCE(?, hostname),
                reverse_dns = COALESCE(?, reverse_dns),
                aliases_json = COALESCE(?, aliases_json),
                os_name = COALESCE(?, os_name),
                os_family = COALESCE(?, os_family),
                os_vendor = COALESCE(?, os_vendor),
                os_accuracy = COALESCE(?, os_accuracy),
                device_type = COALESCE(?, device_type),
                mac_address = COALESCE(?, mac_address),
                mac_vendor = COALESCE(?, mac_vendor),
                last_seen = ?,
                scan_count = scan_count + 1
                WHERE ip = ?''',
                (hostname, reverse_dns, aliases_json, os_name, os_family,
                 os_vendor, os_accuracy, device_type, mac_address, mac_vendor, now, ip))
        else:
            cursor.execute('''INSERT INTO assets
                (ip, hostname, reverse_dns, aliases_json, os_name, os_family,
                 os_vendor, os_accuracy, device_type, mac_address, mac_vendor,
                 first_seen, last_seen, scan_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)''',
                (ip, hostname, reverse_dns, aliases_json, os_name, os_family,
                 os_vendor, os_accuracy, device_type, mac_address, mac_vendor, now, now))

        conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Database error storing asset info for {ip}: {e}")
    finally:
        conn.close()


def get_asset_details(ip):
    """Retrieve full asset details including ports, vulnerabilities, and metadata."""
    from artemis.services.scan_service import get_latest_scan, get_open_ports_for_ip
    from artemis.services.vuln_service import get_vulnerability_counts_by_severity, get_vulnerabilities
    from artemis.services.fingerprint_service import get_fingerprint_summary
    from artemis.services.auth_scan_service import get_asset_os_details, get_installed_software, get_cve_matches

    conn = sqlite3.connect(_get_db_path())
    cursor = conn.cursor()

    try:
        cursor.execute('''SELECT ip, hostname, reverse_dns, aliases_json,
                          os_name, os_family, os_vendor, os_accuracy, device_type,
                          mac_address, mac_vendor, first_seen, last_seen, scan_count
                          FROM assets WHERE ip = ?''', (ip,))
        asset_row = cursor.fetchone()

        asset = {
            'ip': ip, 'hostname': None, 'reverse_dns': None, 'aliases': [],
            'os_name': None, 'os_family': None, 'os_vendor': None,
            'os_accuracy': None, 'device_type': None,
            'mac_address': None, 'mac_vendor': None,
            'first_seen': None, 'last_seen': None, 'scan_count': 0,
            'ports': [], 'vulnerabilities': []
        }

        if asset_row:
            asset['hostname'] = asset_row[1]
            asset['reverse_dns'] = asset_row[2]
            try:
                asset['aliases'] = json.loads(asset_row[3]) if asset_row[3] else []
            except json.JSONDecodeError:
                asset['aliases'] = []
            asset['os_name'] = asset_row[4]
            asset['os_family'] = asset_row[5]
            asset['os_vendor'] = asset_row[6]
            asset['os_accuracy'] = asset_row[7]
            asset['device_type'] = asset_row[8]
            asset['mac_address'] = asset_row[9]
            asset['mac_vendor'] = asset_row[10]
            asset['first_seen'] = asset_row[11]
            asset['last_seen'] = asset_row[12]
            asset['scan_count'] = asset_row[13]

        cursor.execute('''SELECT MAX(scan_date) FROM scans WHERE ip = ?''', (ip,))
        latest = cursor.fetchone()
        if latest and latest[0]:
            cursor.execute('''SELECT protocol, port, state, service, product, version
                              FROM scans WHERE ip = ? AND scan_date = ?''', (ip, latest[0]))
            for row in cursor.fetchall():
                asset['ports'].append({
                    'protocol': row[0], 'port': row[1], 'state': row[2],
                    'service': row[3], 'product': row[4], 'version': row[5]
                })

        asset['vuln_counts'] = get_vulnerability_counts_by_severity(ip)
        asset['vulnerabilities'] = get_vulnerabilities(ip)

        fp_summary = get_fingerprint_summary(ip)
        asset['fingerprints'] = fp_summary.get('technologies', [])
        asset['fingerprints_by_port'] = fp_summary.get('by_port', {})

        asset['auth_os'] = get_asset_os_details(ip)
        asset['installed_software'] = get_installed_software(ip)
        asset['cve_matches'] = get_cve_matches(ip)

        return asset
    except sqlite3.Error as e:
        logger.error(f"Database error getting asset details for {ip}: {e}")
        return None
    finally:
        conn.close()


def update_device_type(ip):
    """Re-classify device type for an asset using all available signals."""
    import sys
    import os
    scanner_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if scanner_dir not in sys.path:
        sys.path.insert(0, scanner_dir)
    from device_type import classify_device, get_device_icon
    from artemis.services.scan_service import get_open_ports_for_ip
    from artemis.services.fingerprint_service import get_fingerprints

    conn = sqlite3.connect(_get_db_path())
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT os_name, os_family, os_vendor, os_accuracy, device_type, mac_vendor FROM assets WHERE ip = ?', (ip,))
        row = cursor.fetchone()
        if not row:
            return None

        os_info = {
            'os_name': row[0], 'os_family': row[1], 'os_vendor': row[2],
            'os_accuracy': row[3], 'device_type': row[4]
        }
        mac_vendor = row[5]

        open_ports = get_open_ports_for_ip(ip)
        fingerprints = get_fingerprints(ip)

        device_type = classify_device(
            os_info=os_info,
            mac_vendor=mac_vendor,
            open_ports=open_ports,
            fingerprints=fingerprints
        )

        cursor.execute('UPDATE assets SET device_type = ? WHERE ip = ?', (device_type, ip))
        conn.commit()
        logger.info(f"Updated device type for {ip}: {device_type}")
        return device_type
    except Exception as e:
        logger.error(f"Error updating device type for {ip}: {e}")
        return None
    finally:
        conn.close()
