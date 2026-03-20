"""Site model — a collection of targets scanned together on a schedule."""

import json
from artemis.extensions import db


class Site(db.Model):
    __tablename__ = 'sites'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False, unique=True)
    description = db.Column(db.Text)
    targets_json = db.Column(db.Text, default='[]')       # JSON list of IPs, CIDRs, hostnames
    excluded_targets_json = db.Column(db.Text, default='[]')  # Targets to skip
    scan_type = db.Column(db.Text, default='full')         # port, vuln, full, auth
    profile_id = db.Column(db.Text)                        # Nuclei scan profile
    scan_options_json = db.Column(db.Text)                  # JSON scan options
    credential_ids_json = db.Column(db.Text)                # JSON credential IDs for auth scans

    # Schedule
    schedule_enabled = db.Column(db.Integer, default=1)
    schedule_type = db.Column(db.Text, default='daily')    # hourly, daily, weekly, monthly, cron
    cron_expression = db.Column(db.Text)
    schedule_hour = db.Column(db.Integer, default=2)
    schedule_minute = db.Column(db.Integer, default=0)
    schedule_day_of_week = db.Column(db.Integer)           # 0=Mon..6=Sun
    schedule_day_of_month = db.Column(db.Integer)
    next_run = db.Column(db.Text)
    last_run = db.Column(db.Text)
    last_status = db.Column(db.Text)                       # success, failed, running, partial
    last_duration_seconds = db.Column(db.Integer)

    # Notifications
    notify_on_complete = db.Column(db.Integer, default=0)
    notify_on_new_vulns = db.Column(db.Integer, default=1)
    compare_with_previous = db.Column(db.Integer, default=1)

    # Meta
    created_at = db.Column(db.Text)
    updated_at = db.Column(db.Text)

    @property
    def targets(self):
        try:
            return json.loads(self.targets_json) if self.targets_json else []
        except (json.JSONDecodeError, TypeError):
            return []

    @targets.setter
    def targets(self, value):
        self.targets_json = json.dumps(value) if value else '[]'

    @property
    def excluded_targets(self):
        try:
            return json.loads(self.excluded_targets_json) if self.excluded_targets_json else []
        except (json.JSONDecodeError, TypeError):
            return []

    @excluded_targets.setter
    def excluded_targets(self, value):
        self.excluded_targets_json = json.dumps(value) if value else '[]'

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'targets': self.targets,
            'excluded_targets': self.excluded_targets,
            'target_count': len(self.targets),
            'scan_type': self.scan_type,
            'profile_id': self.profile_id,
            'scan_options_json': self.scan_options_json,
            'credential_ids_json': self.credential_ids_json,
            'schedule_enabled': self.schedule_enabled,
            'schedule_type': self.schedule_type,
            'cron_expression': self.cron_expression,
            'schedule_hour': self.schedule_hour,
            'schedule_minute': self.schedule_minute,
            'schedule_day_of_week': self.schedule_day_of_week,
            'schedule_day_of_month': self.schedule_day_of_month,
            'next_run': self.next_run,
            'last_run': self.last_run,
            'last_status': self.last_status,
            'last_duration_seconds': self.last_duration_seconds,
            'notify_on_complete': self.notify_on_complete,
            'notify_on_new_vulns': self.notify_on_new_vulns,
            'compare_with_previous': self.compare_with_previous,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
        }
