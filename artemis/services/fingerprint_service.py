"""Fingerprint orchestration service.

System of record: Postgres via the ``Fingerprint`` model. Rows are upserted on
``(ip, port, protocol, signature_id)``.
"""

import json
import logging
from datetime import datetime

from artemis.extensions import db
from artemis.models.fingerprint_model import Fingerprint
from artemis.services._db import upsert

logger = logging.getLogger(__name__)

# Singleton fingerprint engine
_fingerprint_engine = None

_MATCH_KEYS = ('port', 'protocol', 'signature_id')


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


def _write(ip, rows):
    """Upsert a batch of fingerprint dicts. Each row carries at least
    port/protocol/signature_id/name/category; the rest default sensibly."""
    scan_date = datetime.now().isoformat()
    stored = 0
    for r in rows:
        evidence = r.get('evidence')
        values = {
            'name': r.get('name'), 'category': r.get('category'),
            'vendor': r.get('vendor', ''), 'version': r.get('version'),
            'cpe': r.get('cpe'), 'confidence': r.get('confidence'),
            'evidence_json': json.dumps(evidence) if evidence is not None else None,
            'tls_subject_cn': r.get('tls_subject_cn'), 'tls_subject_org': r.get('tls_subject_org'),
            'tls_issuer_org': r.get('tls_issuer_org'),
            'tls_self_signed': 1 if r.get('tls_self_signed') else 0,
            'http_title': r.get('http_title', ''), 'http_server': r.get('http_server', ''),
            'favicon_hash': r.get('favicon_hash'), 'scan_date': scan_date,
        }
        upsert(Fingerprint,
               {'ip': ip, 'port': r['port'], 'protocol': r['protocol'],
                'signature_id': r['signature_id']},
               values)
        stored += 1
    db.session.commit()
    return stored


def store_raw_fingerprints(ip, rows):
    """Public helper for callers that already have fingerprint dicts
    (Wappalyzer / JARM in socketio_handlers)."""
    try:
        return _write(ip, rows)
    except Exception as e:
        db.session.rollback()
        logger.error(f"Database error storing raw fingerprints for {ip}: {e}")
        return 0


def store_fingerprints(ip, fingerprint_results):
    """Store engine fingerprint results (objects with .matches / .tls_info / .http_info)."""
    rows = []
    for fp in fingerprint_results:
        tls = fp.tls_info or {}
        http = fp.http_info or {}
        for m in fp.matches:
            if m.confidence < 10:
                continue
            rows.append({
                'port': fp.port, 'protocol': fp.protocol,
                'signature_id': m.signature_id, 'name': m.name, 'category': m.category,
                'vendor': m.vendor, 'version': m.version, 'cpe': m.cpe,
                'confidence': m.confidence, 'evidence': m.evidence,
                'tls_subject_cn': tls.get('subject_cn'), 'tls_subject_org': tls.get('subject_org'),
                'tls_issuer_org': tls.get('issuer_org'), 'tls_self_signed': tls.get('self_signed'),
                'http_title': http.get('title', ''), 'http_server': http.get('server', ''),
                'favicon_hash': fp.favicon_hash,
            })
    try:
        stored = _write(ip, rows)
        logger.info(f"Stored {stored} fingerprint matches for {ip}")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Database error storing fingerprints for {ip}: {e}")


def store_fpx_results(ip, fpx_results):
    """Store fingerprintx protocol-level identification results."""
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
    service_vendors = {
        'mysql': 'Oracle', 'mssql': 'Microsoft', 'postgresql': 'PostgreSQL',
        'mongodb': 'MongoDB', 'redis': 'Redis', 'elasticsearch': 'Elastic',
        'rdp': 'Microsoft', 'smb': 'Microsoft',
    }

    rows = []
    for fpx in fpx_results:
        svc = fpx.service
        vendor = service_vendors.get(svc.lower(), '')
        if svc.lower() == 'ssh':
            vendor = 'OpenBSD' if fpx.version and 'openssh' in (fpx.version or '').lower() else 'Various'
        evidence = [f'fpx_protocol_handshake:{svc}']
        if fpx.metadata:
            for k, v in fpx.metadata.items():
                if v and isinstance(v, str) and len(v) < 200:
                    evidence.append(f'fpx_meta:{k}={v[:100]}')
        rows.append({
            'port': fpx.port, 'protocol': fpx.transport,
            'signature_id': f"fpx-{svc}",
            'name': svc.upper() if len(svc) <= 5 else svc.title(),
            'category': service_categories.get(svc.lower(), 'service'),
            'vendor': vendor, 'version': fpx.version, 'cpe': None,
            'confidence': 90, 'evidence': evidence,
        })
    try:
        stored = _write(ip, rows)
        logger.info(f"Stored {stored} fingerprintx results for {ip}")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Database error storing fpx results for {ip}: {e}")


def get_fingerprints(ip, port=None):
    """Retrieve fingerprint data for an IP, optionally filtered by port."""
    try:
        q = Fingerprint.query.filter_by(ip=ip)
        if port is not None:
            q = q.filter_by(port=port).order_by(Fingerprint.confidence.desc())
        else:
            q = q.order_by(Fingerprint.port, Fingerprint.confidence.desc())
        return [fp.to_dict() for fp in q.all()]
    except Exception as e:
        logger.error(f"Database error getting fingerprints for {ip}: {e}")
        return []


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
    return {'technologies': technologies, 'by_port': by_port}
