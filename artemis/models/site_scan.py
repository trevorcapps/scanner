"""SiteScan model — execution history for site-level scans."""

import json
from artemis.extensions import db
from artemis.models._tenant import TenantMixin


class SiteScan(TenantMixin, db.Model):
    __tablename__ = 'site_scans'

    id = db.Column(db.Integer, primary_key=True)
    site_id = db.Column(db.Integer, nullable=False, index=True)
    status = db.Column(db.Text, default='queued')          # queued, running, success, failed, partial, cancelled
    started_at = db.Column(db.Text)
    completed_at = db.Column(db.Text)
    duration_seconds = db.Column(db.Integer)

    # Aggregate stats
    targets_total = db.Column(db.Integer, default=0)
    targets_scanned = db.Column(db.Integer, default=0)
    targets_failed = db.Column(db.Integer, default=0)
    ports_found = db.Column(db.Integer, default=0)
    vulns_found = db.Column(db.Integer, default=0)
    new_vulns = db.Column(db.Integer, default=0)
    removed_vulns = db.Column(db.Integer, default=0)

    error_message = db.Column(db.Text)
    summary_json = db.Column(db.Text)                      # Per-target breakdown

    def to_dict(self):
        summary = None
        if self.summary_json:
            try:
                summary = json.loads(self.summary_json)
            except (json.JSONDecodeError, TypeError):
                pass
        return {
            'id': self.id,
            'site_id': self.site_id,
            'status': self.status,
            'started_at': self.started_at,
            'completed_at': self.completed_at,
            'duration_seconds': self.duration_seconds,
            'targets_total': self.targets_total,
            'targets_scanned': self.targets_scanned,
            'targets_failed': self.targets_failed,
            'ports_found': self.ports_found,
            'vulns_found': self.vulns_found,
            'new_vulns': self.new_vulns,
            'removed_vulns': self.removed_vulns,
            'error_message': self.error_message,
            'summary': summary,
        }
