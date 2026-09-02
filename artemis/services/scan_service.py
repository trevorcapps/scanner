"""Port scanning orchestration service.

System of record: Postgres via the ``Scan`` model. Query helpers return plain
tuples ``(protocol, port, state, service, product, version)`` because callers
(``report.html``, ``socketio_handlers``) index them positionally.
"""

import logging
from datetime import datetime

from sqlalchemy import func

from artemis.extensions import db
from artemis.models.scan import Scan

logger = logging.getLogger(__name__)

_ROW = (Scan.protocol, Scan.port, Scan.state, Scan.service, Scan.product, Scan.version)


def store_scan_from_agent(ip, ports):
    """Store agent-reported listening ports as scan data.

    ports is a list of dicts like: {"port": 22, "state": "listen", "protocol": "tcp"}
    Existing richer nmap rows for the same port are left untouched.
    """
    try:
        scan_date = datetime.now().isoformat()
        stored = 0
        for p in ports:
            port_num = p.get('port')
            proto = p.get('protocol', 'tcp')
            if not port_num:
                continue

            has_nmap = db.session.query(Scan.id).filter(
                Scan.ip == ip, Scan.port == port_num, Scan.protocol == proto,
                Scan.service != 'agent-reported',
            ).first()
            if has_nmap:
                continue

            Scan.query.filter_by(
                ip=ip, port=port_num, protocol=proto, service='agent-reported',
            ).delete()
            db.session.add(Scan(
                ip=ip, protocol=proto, port=port_num, state=p.get('state', 'open'),
                service='agent-reported', product='', version='', scan_date=scan_date,
            ))
            stored += 1
        db.session.commit()
        logger.info(f"Stored {stored} agent-reported ports for {ip}")
    except Exception as e:
        db.session.rollback()
        logger.error(f"DB error storing agent ports for {ip}: {e}")


def store_scan(ip, scan_results):
    """Store port scan results. ``scan_results`` rows are
    ``(protocol, port, state, service, product, version)`` tuples."""
    try:
        scan_date = datetime.now().isoformat()
        for r in scan_results:
            db.session.add(Scan(
                ip=ip, protocol=r[0], port=r[1], state=r[2],
                service=r[3], product=r[4], version=r[5], scan_date=scan_date,
            ))
        db.session.commit()
        logger.info(f"Stored {len(scan_results)} port scan results for {ip}")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Database error storing scan results for {ip}: {e}")


def _rows_for_scan(ip, scan_date):
    return [tuple(r) for r in db.session.query(*_ROW).filter(
        Scan.ip == ip, Scan.scan_date == scan_date,
    ).all()]


def get_latest_scan(ip):
    """All ports from the most recent scan for an IP (list of 6-tuples)."""
    try:
        latest_date = db.session.query(func.max(Scan.scan_date)).filter(Scan.ip == ip).scalar()
        if not latest_date:
            return []
        return _rows_for_scan(ip, latest_date)
    except Exception as e:
        logger.error(f"Database error in get_latest_scan: {e}")
        return []


def get_previous_scan(ip, before_date):
    """All ports from the scan before ``before_date`` (rows, date)."""
    try:
        prev_date = db.session.query(func.max(Scan.scan_date)).filter(
            Scan.ip == ip, Scan.scan_date < before_date,
        ).scalar()
        if not prev_date:
            return [], None
        return _rows_for_scan(ip, prev_date), prev_date
    except Exception as e:
        logger.error(f"Database error in get_previous_scan: {e}")
        return [], None


def compare_scans(old_scan, new_scan):
    """Compare two scans and identify added, removed, and changed ports."""
    old_ports = {(r[0], r[1]): r for r in old_scan}
    new_ports = {(r[0], r[1]): r for r in new_scan}

    return {
        'added': [new_ports[k] for k in new_ports if k not in old_ports],
        'removed': [old_ports[k] for k in old_ports if k not in new_ports],
        'changed': [
            {'old': old_ports[k], 'new': new_ports[k]}
            for k in old_ports
            if k in new_ports and old_ports[k] != new_ports[k]
        ],
    }


def get_open_ports_for_ip(ip):
    """Open ports from the latest scan as a list of dicts."""
    ports = []
    for row in get_latest_scan(ip):
        if row[2] == 'open':
            ports.append({'port': row[1], 'protocol': row[0], 'service': row[3],
                          'product': row[4] if len(row) > 4 else ''})
    return ports
