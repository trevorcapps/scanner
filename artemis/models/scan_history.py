"""ScanHistory model — execution log for scheduled and ad-hoc scans."""

from artemis.extensions import db
from artemis.models._tenant import TenantMixin


class ScanHistory(TenantMixin, db.Model):
    __tablename__ = 'scan_history'

    id = db.Column(db.Integer, primary_key=True)
    scheduled_scan_id = db.Column(db.Integer)
    target = db.Column(db.Text, nullable=False)
    scan_type = db.Column(db.Text)
    status = db.Column(db.Text)
    started_at = db.Column(db.Text)
    completed_at = db.Column(db.Text)
    duration_seconds = db.Column(db.Integer)
    hosts_scanned = db.Column(db.Integer, default=0)
    ports_found = db.Column(db.Integer, default=0)
    vulns_found = db.Column(db.Integer, default=0)
    new_vulns = db.Column(db.Integer, default=0)
    error_message = db.Column(db.Text)
    summary_json = db.Column(db.Text)
    # Stable observation identity index captured at completion, for the next
    # run's delta comparison (see delta_service).
    baseline_json = db.Column(db.Text)

    def to_dict(self):
        return {
            'id': self.id,
            'scheduled_scan_id': self.scheduled_scan_id,
            'target': self.target,
            'scan_type': self.scan_type,
            'status': self.status,
            'started_at': self.started_at,
            'completed_at': self.completed_at,
            'duration_seconds': self.duration_seconds,
            'hosts_scanned': self.hosts_scanned,
            'ports_found': self.ports_found,
            'vulns_found': self.vulns_found,
            'new_vulns': self.new_vulns,
            'error_message': self.error_message,
            'summary_json': self.summary_json,
        }
