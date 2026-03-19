"""Fingerprint orchestration service — extracted from vuln_scan.py."""

import json
import sqlite3
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Singleton fingerprint engine
_fingerprint_engine = None


def get_fingerprint_engine():
    """Get or create the singleton FingerprintEngine."""
    global _fingerprint_engine
    if _fingerprint_engine is None:
        import sys
        import os
        scanner_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        if scanner_dir not in sys.path:
            sys.path.insert(0, scanner_dir)
        from fingerprint.engine import FingerprintEngine
        _fingerprint_engine = FingerprintEngine()
    return _fingerprint_engine


def _get_db_path():
    try:
        from flask import current_app
        return current_app.config['DB_PATH']
    except Exception:
        import os
        return os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__)))), 'vuln_scan.db')


def store_fingerprints(ip, fingerprint_results):
    """Store fingerprint results in the database."""
    conn = sqlite3.connect(_get_db_path())
    cursor = conn.cursor()
    scan_date = datetime.now().isoformat()

    try:
        stored_count = 0
        for fp_result in fingerprint_results:
            for match in fp_result.matches:
                if match.confidence < 10:
                    continue

                tls_info = fp_result.tls_info or {}
                http_info = fp_result.http_info or {}

                cursor.execute('''INSERT OR REPLACE INTO fingerprints
                    (ip, port, protocol, signature_id, name, category, vendor,
                     version, cpe, confidence, evidence_json,
                     tls_subject_cn, tls_subject_org, tls_issuer_org, tls_self_signed,
                     http_title, http_server, favicon_hash, scan_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (ip, fp_result.port, fp_result.protocol,
                     match.signature_id, match.name, match.category, match.vendor,
                     match.version, match.cpe, match.confidence,
                     json.dumps(match.evidence),
                     tls_info.get('subject_cn'), tls_info.get('subject_org'),
                     tls_info.get('issuer_org'),
                     1 if tls_info.get('self_signed') else 0,
                     http_info.get('title', ''), http_info.get('server', ''),
                     fp_result.favicon_hash, scan_date))
                stored_count += 1

        conn.commit()
        logger.info(f"Stored {stored_count} fingerprint matches for {ip}")
    except sqlite3.Error as e:
        logger.error(f"Database error storing fingerprints for {ip}: {e}")
    finally:
        conn.close()


def store_fpx_results(ip, fpx_results):
    """Store fingerprintx protocol-level identification results."""
    conn = sqlite3.connect(_get_db_path())
    cursor = conn.cursor()
    scan_date = datetime.now().isoformat()

    try:
        stored_count = 0
        for fpx in fpx_results:
            sig_id = f"fpx-{fpx.service}"
            name = fpx.service.upper() if len(fpx.service) <= 5 else fpx.service.title()

            service_categories = {
                'ssh': 'remote-access', 'rdp': 'remote-access', 'vnc': 'remote-access',
                'telnet': 'remote-access',
                'http': 'web-server', 'https': 'web-server',
                'mysql': 'database', 'postgresql': 'database', 'mssql': 'database',
                'mongodb': 'database', 'redis': 'database', 'elasticsearch': 'database',
                'couchdb': 'database', 'cassandra': 'database', 'oracle': 'database',
                'influxdb': 'database', 'neo4j': 'database', 'memcached': 'database',
                'smtp': 'email', 'imap': 'email', 'pop3': 'email',
                'ftp': 'file-transfer', 'smb': 'file-transfer', 'rsync': 'file-transfer',
                'dns': 'dns', 'ldap': 'directory', 'snmp': 'network-management',
                'ntp': 'network-service', 'dhcp': 'network-service',
                'kafka': 'message-queue', 'mqtt': 'message-queue',
                'modbus': 'industrial', 'ipmi': 'management',
            }
            category = service_categories.get(fpx.service.lower(), 'service')

            service_vendors = {
                'ssh': 'OpenBSD' if fpx.version and 'openssh' in (fpx.version or '').lower() else 'Various',
                'mysql': 'Oracle', 'mssql': 'Microsoft', 'postgresql': 'PostgreSQL',
                'mongodb': 'MongoDB', 'redis': 'Redis', 'elasticsearch': 'Elastic',
                'rdp': 'Microsoft', 'smb': 'Microsoft',
            }
            vendor = service_vendors.get(fpx.service.lower(), '')

            evidence = [f'fpx_protocol_handshake:{fpx.service}']
            if fpx.metadata:
                for k, v in fpx.metadata.items():
                    if v and isinstance(v, str) and len(v) < 200:
                        evidence.append(f'fpx_meta:{k}={v[:100]}')

            confidence = 90

            cursor.execute('''INSERT OR REPLACE INTO fingerprints
                (ip, port, protocol, signature_id, name, category, vendor,
                 version, cpe, confidence, evidence_json,
                 tls_subject_cn, tls_subject_org, tls_issuer_org, tls_self_signed,
                 http_title, http_server, favicon_hash, scan_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (ip, fpx.port, fpx.transport,
                 sig_id, name, category, vendor,
                 fpx.version, None, confidence,
                 json.dumps(evidence),
                 None, None, None, 0,
                 '', '', None, scan_date))
            stored_count += 1

        conn.commit()
        logger.info(f"Stored {stored_count} fingerprintx results for {ip}")
    except sqlite3.Error as e:
        logger.error(f"Database error storing fpx results for {ip}: {e}")
    finally:
        conn.close()


def get_fingerprints(ip, port=None):
    """Retrieve fingerprint data for an IP, optionally filtered by port."""
    conn = sqlite3.connect(_get_db_path())
    cursor = conn.cursor()

    try:
        if port is not None:
            cursor.execute('''SELECT ip, port, protocol, signature_id, name, category, vendor,
                              version, cpe, confidence, evidence_json,
                              tls_subject_cn, tls_subject_org, tls_issuer_org, tls_self_signed,
                              http_title, http_server, favicon_hash, scan_date
                              FROM fingerprints
                              WHERE ip = ? AND port = ?
                              ORDER BY confidence DESC''', (ip, port))
        else:
            cursor.execute('''SELECT ip, port, protocol, signature_id, name, category, vendor,
                              version, cpe, confidence, evidence_json,
                              tls_subject_cn, tls_subject_org, tls_issuer_org, tls_self_signed,
                              http_title, http_server, favicon_hash, scan_date
                              FROM fingerprints
                              WHERE ip = ?
                              ORDER BY port, confidence DESC''', (ip,))

        results = []
        for row in cursor.fetchall():
            evidence = []
            try:
                evidence = json.loads(row[10]) if row[10] else []
            except json.JSONDecodeError:
                pass

            results.append({
                'ip': row[0], 'port': row[1], 'protocol': row[2],
                'signature_id': row[3], 'name': row[4], 'category': row[5],
                'vendor': row[6], 'version': row[7], 'cpe': row[8],
                'confidence': row[9], 'evidence': evidence,
                'tls_subject_cn': row[11], 'tls_subject_org': row[12],
                'tls_issuer_org': row[13], 'tls_self_signed': bool(row[14]),
                'http_title': row[15], 'http_server': row[16],
                'favicon_hash': row[17], 'scan_date': row[18],
            })

        return results
    except sqlite3.Error as e:
        logger.error(f"Database error getting fingerprints for {ip}: {e}")
        return []
    finally:
        conn.close()


def get_fingerprint_summary(ip):
    """Get a summary of identified technologies for an IP."""
    fingerprints = get_fingerprints(ip)
    if not fingerprints:
        return {'technologies': [], 'by_port': {}}

    by_port = {}
    all_techs = {}
    for fp in fingerprints:
        port = fp['port']
        if port not in by_port:
            by_port[port] = fp
        sig_id = fp['signature_id']
        if sig_id not in all_techs or fp['confidence'] > all_techs[sig_id]['confidence']:
            all_techs[sig_id] = fp

    technologies = sorted(all_techs.values(), key=lambda t: t['confidence'], reverse=True)

    return {
        'technologies': technologies,
        'by_port': by_port,
    }
