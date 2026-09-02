"""Durable execution record for queued scanner work."""

import json
import uuid

from artemis.extensions import db


class ScanJob(db.Model):
    __tablename__ = 'scan_jobs'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    task_id = db.Column(db.String(80), unique=True, index=True)
    job_type = db.Column(db.String(32), nullable=False, index=True)
    status = db.Column(db.String(24), nullable=False, default='queued', index=True)
    target = db.Column(db.Text)
    site_id = db.Column(db.Integer, db.ForeignKey('sites.id', ondelete='SET NULL'), index=True)
    requested_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), index=True)
    options_json = db.Column(db.Text)
    result_json = db.Column(db.Text)
    error_message = db.Column(db.Text)
    attempt = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.Text, nullable=False)
    started_at = db.Column(db.Text)
    completed_at = db.Column(db.Text)
    cancel_requested_at = db.Column(db.Text)

    @staticmethod
    def _decode(value):
        if not value:
            return None
        try:
            return json.loads(value)
        except (TypeError, json.JSONDecodeError):
            return None

    def to_dict(self):
        return {
            'id': self.id,
            'task_id': self.task_id,
            'job_type': self.job_type,
            'status': self.status,
            'target': self.target,
            'site_id': self.site_id,
            'requested_by': self.requested_by,
            'options': self._decode(self.options_json),
            'result': self._decode(self.result_json),
            'error_message': self.error_message,
            'attempt': self.attempt,
            'created_at': self.created_at,
            'started_at': self.started_at,
            'completed_at': self.completed_at,
            'cancel_requested_at': self.cancel_requested_at,
        }
