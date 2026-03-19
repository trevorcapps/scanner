"""Authenticated scanning orchestration service — extracted from vuln_scan.py."""

import sqlite3
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


def _get_db_path():
    try:
        from flask import current_app
        return current_app.config['DB_PATH']
    except Exception:
        import os
        return os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__)))), 'vuln_scan.db')


def store_auth_scan_results(ip, os_info, packages, cves):
    """Store results from an authenticated SSH scan."""
    conn = sqlite3.connect(_get_db_path())
    cursor = conn.cursor()
    scan_date = datetime.now().isoformat()

    try:
        cursor.execute('''INSERT OR REPLACE INTO asset_os_details
            (ip, distro, version, kernel, arch, os_family, os_id, pretty_name, scan_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (ip, os_info.get('distro'), os_info.get('version'), os_info.get('kernel'),
             os_info.get('arch'), os_info.get('os_family'), os_info.get('os_id'),
             os_info.get('pretty_name'), scan_date))

        for pkg in packages:
            cursor.execute('''INSERT OR REPLACE INTO installed_software
                (ip, package_name, package_version, cpe, scan_date)
                VALUES (?, ?, ?, ?, ?)''',
                (ip, pkg['name'], pkg['version'], pkg.get('cpe', ''), scan_date))

        for cve in cves:
            cursor.execute('''INSERT OR REPLACE INTO cve_matches
                (ip, cve_id, severity, cvss_score, description, affected_cpe,
                 has_exploit, exploit_ids, exploit_url, scan_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (ip, cve['cve_id'], cve['severity'], cve.get('cvss_score'),
                 cve.get('description', ''), cve.get('affected_cpe', ''),
                 1 if cve.get('has_exploit') else 0,
                 cve.get('exploit_ids', ''), cve.get('exploit_url', ''),
                 scan_date))

        conn.commit()
        logger.info(f"Stored auth scan: {ip} - OS: {os_info.get('distro')}, "
                     f"{len(packages)} packages, {len(cves)} CVEs")
    except sqlite3.Error as e:
        logger.error(f"Database error storing auth scan for {ip}: {e}")
    finally:
        conn.close()


def get_asset_os_details(ip):
    """Get authenticated OS details for an asset."""
    conn = sqlite3.connect(_get_db_path())
    cursor = conn.cursor()
    try:
        cursor.execute('''SELECT distro, version, kernel, arch, os_family, os_id, pretty_name, scan_date
                          FROM asset_os_details WHERE ip = ?''', (ip,))
        row = cursor.fetchone()
        if row:
            return {
                'distro': row[0], 'version': row[1], 'kernel': row[2],
                'arch': row[3], 'os_family': row[4], 'os_id': row[5],
                'pretty_name': row[6], 'scan_date': row[7]
            }
        return None
    finally:
        conn.close()


def get_installed_software(ip):
    """Get installed software inventory for an asset."""
    conn = sqlite3.connect(_get_db_path())
    cursor = conn.cursor()
    try:
        cursor.execute('''SELECT package_name, package_version, cpe, scan_date
                          FROM installed_software WHERE ip = ?
                          ORDER BY package_name''', (ip,))
        return [{'name': r[0], 'version': r[1], 'cpe': r[2], 'scan_date': r[3]}
                for r in cursor.fetchall()]
    finally:
        conn.close()


def get_cve_matches(ip):
    """Get CVE matches for an asset from authenticated scanning."""
    conn = sqlite3.connect(_get_db_path())
    cursor = conn.cursor()
    try:
        cursor.execute('''SELECT cve_id, severity, cvss_score, description, affected_cpe,
                          has_exploit, exploit_ids, exploit_url, scan_date
                          FROM cve_matches WHERE ip = ?
                          ORDER BY has_exploit DESC, cvss_score DESC''', (ip,))
        return [{'cve_id': r[0], 'severity': r[1], 'cvss_score': r[2],
                 'description': r[3], 'affected_cpe': r[4],
                 'has_exploit': bool(r[5]), 'exploit_ids': r[6] or '',
                 'exploit_url': r[7] or '', 'scan_date': r[8]}
                for r in cursor.fetchall()]
    finally:
        conn.close()


def get_all_credentials():
    """Get all stored credentials."""
    conn = sqlite3.connect(_get_db_path())
    cursor = conn.cursor()
    try:
        cursor.execute('''SELECT id, name, cred_type, username, key_path, password, created_at, updated_at
                          FROM credentials ORDER BY name''')
        return [{
            'id': r[0], 'name': r[1], 'cred_type': r[2], 'username': r[3],
            'key_path': r[4] or '', 'password': r[5] or '',
            'created_at': r[6], 'updated_at': r[7]
        } for r in cursor.fetchall()]
    finally:
        conn.close()


def get_credential(cred_id):
    """Get a single credential by ID."""
    conn = sqlite3.connect(_get_db_path())
    cursor = conn.cursor()
    try:
        cursor.execute('''SELECT id, name, cred_type, username, key_path, password
                          FROM credentials WHERE id = ?''', (cred_id,))
        r = cursor.fetchone()
        if r:
            return {
                'id': r[0], 'name': r[1], 'cred_type': r[2], 'username': r[3],
                'key_path': r[4] or '', 'password': r[5] or ''
            }
        return None
    finally:
        conn.close()


def save_credential(name, cred_type, username, key_path='', password='', cred_id=None):
    """Create or update a credential set."""
    conn = sqlite3.connect(_get_db_path())
    cursor = conn.cursor()
    now = datetime.now().isoformat()
    try:
        if cred_id:
            cursor.execute('''UPDATE credentials SET name=?, cred_type=?, username=?,
                              key_path=?, password=?, updated_at=? WHERE id=?''',
                           (name, cred_type, username, key_path, password, now, cred_id))
        else:
            cursor.execute('''INSERT INTO credentials (name, cred_type, username, key_path, password, created_at, updated_at)
                              VALUES (?, ?, ?, ?, ?, ?, ?)''',
                           (name, cred_type, username, key_path, password, now, now))
        conn.commit()
        return cursor.lastrowid if not cred_id else cred_id
    except sqlite3.IntegrityError:
        raise ValueError(f"Credential name '{name}' already exists")
    finally:
        conn.close()


def delete_credential(cred_id):
    """Delete a credential by ID."""
    conn = sqlite3.connect(_get_db_path())
    cursor = conn.cursor()
    try:
        cursor.execute('DELETE FROM credentials WHERE id = ?', (cred_id,))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def get_setting(key, default=None):
    """Get a setting value."""
    conn = sqlite3.connect(_get_db_path())
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
        row = cursor.fetchone()
        return row[0] if row else default
    finally:
        conn.close()


def set_setting(key, value):
    """Set a setting value."""
    conn = sqlite3.connect(_get_db_path())
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (key, value))
        conn.commit()
    finally:
        conn.close()
