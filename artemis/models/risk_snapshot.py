"""RiskSnapshot model — one row per day capturing environment vulnerability posture."""

from artemis.extensions import db
from artemis.models._tenant import TenantMixin


class RiskSnapshot(TenantMixin, db.Model):
    __tablename__ = 'risk_snapshots'
    __table_args__ = (
        db.UniqueConstraint('organization_id', 'snapshot_date', name='uq_risk_snapshot_org_date'),
    )

    id = db.Column(db.Integer, primary_key=True)
    snapshot_date = db.Column(db.Text)   # YYYY-MM-DD
    assets = db.Column(db.Integer, default=0)
    affected_hosts = db.Column(db.Integer, default=0)
    critical = db.Column(db.Integer, default=0)
    high = db.Column(db.Integer, default=0)
    medium = db.Column(db.Integer, default=0)
    low = db.Column(db.Integer, default=0)
    info = db.Column(db.Integer, default=0)
    exploitable = db.Column(db.Integer, default=0)
    total_findings = db.Column(db.Integer, default=0)
    unique_cves = db.Column(db.Integer, default=0)
    risk_score = db.Column(db.Integer, default=0)     # weighted: 10c + 5h + 2m + 1l
    created_at = db.Column(db.Text)

    def to_dict(self):
        return {
            'date': self.snapshot_date,
            'assets': self.assets or 0,
            'affected_hosts': self.affected_hosts or 0,
            'critical': self.critical or 0,
            'high': self.high or 0,
            'medium': self.medium or 0,
            'low': self.low or 0,
            'info': self.info or 0,
            'exploitable': self.exploitable or 0,
            'total_findings': self.total_findings or 0,
            'unique_cves': self.unique_cves or 0,
            'risk_score': self.risk_score or 0,
        }
