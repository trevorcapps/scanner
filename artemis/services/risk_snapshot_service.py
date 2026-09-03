"""Daily environment risk posture snapshots — powers report trend charts."""

import logging
from datetime import datetime, timezone, timedelta

from artemis.extensions import db
from artemis.models.risk_snapshot import RiskSnapshot
from artemis.models.asset import Asset

logger = logging.getLogger(__name__)

_SEVERITIES = ('critical', 'high', 'medium', 'low', 'info')
_RISK_WEIGHTS = {'critical': 10, 'high': 5, 'medium': 2, 'low': 1, 'info': 0}


def capture_snapshot(force=False):
    """Record today's posture. Idempotent per day unless force=True. Returns the row."""
    from sqlalchemy.exc import IntegrityError
    from artemis.services.vuln_service import get_unified_vulnerability_summary

    today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    row = RiskSnapshot.query.filter_by(snapshot_date=today).first()
    if row and not force:
        return row

    # Read-only aggregation first, then a short write window.
    summ = get_unified_vulnerability_summary()
    asset_count = Asset.query.count()
    sev = summ.get('by_severity', {})
    risk_score = sum(_RISK_WEIGHTS.get(s, 0) * sev.get(s, 0) for s in _SEVERITIES)

    with db.session.no_autoflush:
        row = RiskSnapshot.query.filter_by(snapshot_date=today).first()
        created = row is None
        if created:
            row = RiskSnapshot(snapshot_date=today)
            db.session.add(row)
        row.assets = asset_count
        row.affected_hosts = summ.get('affected_hosts', 0)
        row.critical = sev.get('critical', 0)
        row.high = sev.get('high', 0)
        row.medium = sev.get('medium', 0)
        row.low = sev.get('low', 0)
        row.info = sev.get('info', 0)
        row.exploitable = summ.get('with_exploits', 0)
        row.total_findings = summ.get('total_findings', 0)
        row.unique_cves = summ.get('unique_cves', 0)
        row.risk_score = risk_score
        row.created_at = datetime.now(timezone.utc).isoformat()

    try:
        db.session.commit()
    except IntegrityError:
        # Another worker/thread inserted today's row between our check and commit.
        db.session.rollback()
        row = RiskSnapshot.query.filter_by(snapshot_date=today).first()
    logger.info(f"Risk snapshot captured for {today}: score={risk_score}")
    return row


def get_snapshots(days=90):
    """Return snapshots for the last N days, oldest first, as dicts."""
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime('%Y-%m-%d')
    rows = RiskSnapshot.query.filter(RiskSnapshot.snapshot_date >= since)\
        .order_by(RiskSnapshot.snapshot_date).all()
    return [r.to_dict() for r in rows]


def maybe_capture_daily():
    """Called from the scheduler tick — captures at most once per calendar day."""
    today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    if RiskSnapshot.query.filter_by(snapshot_date=today).first():
        return
    try:
        capture_snapshot()
    except Exception:
        logger.exception("Daily risk snapshot failed")
