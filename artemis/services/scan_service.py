"""Port scanning orchestration service — extracted from vuln_scan.py store/query logic."""

import json
import sqlite3
import logging
from datetime import datetime

from artemis.utils.validation import validate_ip, validate_hostname
from artemis.utils.dns import ScanError

logger = logging.getLogger(__name__)


def _get_db_path():
    """Get DB path from current app config or fallback."""
    try:
        from flask import current_app
        return current_app.config['DB_PATH']
    except Exception:
        import os
        return os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__)))), 'vuln_scan.db')


def store_scan_from_agent(ip, ports):
    """Store agent-reported listening ports as scan data.
    ports is a list of dicts like: {"port": 22, "state": "listen", "protocol": "tcp"}
    """
    conn = sqlite3.connect(_get_db_path())
    cursor = conn.cursor()
    try:
        scan_date = datetime.now().isoformat()
        # Clear previous agent-reported ports for this IP (keep nmap scans)
        # We use 'agent' as the service marker to distinguish
        for p in ports:
            port_num = p.get('port')
            proto = p.get('protocol', 'tcp')
            if not port_num:
                continue
            # Check if we already have a nmap scan for this port — don't overwrite
            cursor.execute(
                'SELECT id FROM scans WHERE ip = ? AND port = ? AND protocol = ? AND service != "agent-reported" ORDER BY scan_date DESC LIMIT 1',
                (ip, port_num, proto))
            if cursor.fetchone():
                continue  # nmap data is richer, skip
            # Upsert agent-reported port
            cursor.execute(
                'DELETE FROM scans WHERE ip = ? AND port = ? AND protocol = ? AND service = "agent-reported"',
                (ip, port_num, proto))
            cursor.execute(
                'INSERT INTO scans (ip, protocol, port, state, service, product, version, scan_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                (ip, proto, port_num, p.get('state', 'open'), 'agent-reported', '', '', scan_date))
        conn.commit()
        logger.info(f"Stored {len(ports)} agent-reported ports for {ip}")
    except sqlite3.Error as e:
        logger.error(f"DB error storing agent ports for {ip}: {e}")
    finally:
        conn.close()


def store_scan(ip, scan_results):
    """Store port scan results in the database."""
    conn = sqlite3.connect(_get_db_path())
    cursor = conn.cursor()
    try:
        stored_count = 0
        scan_date = datetime.now().isoformat()
        for result in scan_results:
            cursor.execute('''INSERT INTO scans (ip, protocol, port, state, service, product, version, scan_date)
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                           (ip, result[0], result[1], result[2], result[3], result[4], result[5], scan_date))
            stored_count += 1
        conn.commit()
        logger.info(f"Stored {stored_count} port scan results for {ip}")
    except sqlite3.Error as e:
        logger.error(f"Database error storing scan results for {ip}: {e}")
    finally:
        conn.close()


def get_latest_scan(ip):
    """Retrieve all ports from the most recent scan for an IP."""
    conn = sqlite3.connect(_get_db_path())
    cursor = conn.cursor()
    try:
        cursor.execute('''SELECT MAX(scan_date) FROM scans WHERE ip = ?''', (ip,))
        result = cursor.fetchone()
        latest_date = result[0] if result else None
        if not latest_date:
            return []
        cursor.execute('''SELECT protocol, port, state, service, product, version
                          FROM scans WHERE ip = ? AND scan_date = ?''', (ip, latest_date))
        return cursor.fetchall()
    except sqlite3.Error as e:
        logger.error(f"Database error in get_latest_scan: {e}")
        return []
    finally:
        conn.close()


def get_previous_scan(ip, before_date):
    """Retrieve all ports from the scan before the given date."""
    conn = sqlite3.connect(_get_db_path())
    cursor = conn.cursor()
    try:
        cursor.execute('''SELECT MAX(scan_date) FROM scans
                          WHERE ip = ? AND scan_date < ?''', (ip, before_date))
        result = cursor.fetchone()
        previous_date = result[0] if result else None
        if not previous_date:
            return [], None
        cursor.execute('''SELECT protocol, port, state, service, product, version
                          FROM scans WHERE ip = ? AND scan_date = ?''', (ip, previous_date))
        return cursor.fetchall(), previous_date
    except sqlite3.Error as e:
        logger.error(f"Database error in get_previous_scan: {e}")
        return [], None
    finally:
        conn.close()


def compare_scans(old_scan, new_scan):
    """Compare two scans and identify added, removed, and changed ports."""
    old_ports = {(r[0], r[1]): r for r in old_scan}
    new_ports = {(r[0], r[1]): r for r in new_scan}

    changes = {
        'added': [new_ports[k] for k in new_ports if k not in old_ports],
        'removed': [old_ports[k] for k in old_ports if k not in new_ports],
        'changed': [
            {'old': old_ports[k], 'new': new_ports[k]}
            for k in old_ports
            if k in new_ports and old_ports[k] != new_ports[k]
        ]
    }
    return changes


def get_open_ports_for_ip(ip):
    """Get the list of open ports from the latest scan for an IP."""
    latest = get_latest_scan(ip)
    ports = []
    for row in latest:
        if row[2] == 'open':
            ports.append({'port': row[1], 'protocol': row[0], 'service': row[3],
                          'product': row[4] if len(row) > 4 else ''})
    return ports
