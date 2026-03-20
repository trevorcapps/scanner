"""ScheduledScan model — recurring and one-time scan schedules."""

from artemis.extensions import db


class ScheduledScan(db.Model):
    __tablename__ = 'scheduled_scans'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False)
    target = db.Column(db.Text, nullable=False)
    scan_type = db.Column(db.Text, default='port')
    profile_id = db.Column(db.Text)
    schedule_type = db.Column(db.Text, nullable=False)
    cron_expression = db.Column(db.Text)
    schedule_hour = db.Column(db.Integer, default=2)
    schedule_minute = db.Column(db.Integer, default=0)
    schedule_day_of_week = db.Column(db.Integer)
    schedule_day_of_month = db.Column(db.Integer)
    scan_options_json = db.Column(db.Text)
    credential_ids_json = db.Column(db.Text)
    enabled = db.Column(db.Integer, default=1)
    last_run = db.Column(db.Text)
    next_run = db.Column(db.Text)
    last_status = db.Column(db.Text)
    last_duration_seconds = db.Column(db.Integer)
    created_at = db.Column(db.Text)
    updated_at = db.Column(db.Text)
    notify_on_complete = db.Column(db.Integer, default=0)
    notify_on_new_vulns = db.Column(db.Integer, default=1)
    compare_with_previous = db.Column(db.Integer, default=1)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'target': self.target,
            'scan_type': self.scan_type,
            'profile_id': self.profile_id,
            'schedule_type': self.schedule_type,
            'cron_expression': self.cron_expression,
            'schedule_hour': self.schedule_hour,
            'schedule_minute': self.schedule_minute,
            'schedule_day_of_week': self.schedule_day_of_week,
            'schedule_day_of_month': self.schedule_day_of_month,
            'scan_options_json': self.scan_options_json,
            'credential_ids_json': self.credential_ids_json,
            'enabled': self.enabled,
            'last_run': self.last_run,
            'next_run': self.next_run,
            'last_status': self.last_status,
            'last_duration_seconds': self.last_duration_seconds,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'notify_on_complete': self.notify_on_complete,
            'notify_on_new_vulns': self.notify_on_new_vulns,
            'compare_with_previous': self.compare_with_previous,
        }
