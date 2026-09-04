"""Durable execution record for queued scanner work."""

import json
import uuid

from artemis.extensions import db
from artemis.models._tenant import TenantMixin


class ScanJob(TenantMixin, db.Model):
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
    progress_current = db.Column(db.Integer, nullable=False, default=0)
    progress_total = db.Column(db.Integer)
    parent_job_id = db.Column(
        db.String(36), db.ForeignKey('scan_jobs.id', ondelete='CASCADE'), index=True,
    )
    idempotency_key = db.Column(db.String(128), index=True)
    lease_expires_at = db.Column(db.Text)
    retention_until = db.Column(db.Text)
    created_at = db.Column(db.Text, nullable=False)
    started_at = db.Column(db.Text)
    completed_at = db.Column(db.Text)
    cancel_requested_at = db.Column(db.Text)

    events = db.relationship(
        'JobEvent', backref='job', cascade='all, delete-orphan',
        order_by='JobEvent.seq', lazy='dynamic',
    )

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
            'progress': {'current': self.progress_current, 'total': self.progress_total},
            'parent_job_id': self.parent_job_id,
            'idempotency_key': self.idempotency_key,
            'lease_expires_at': self.lease_expires_at,
            'retention_until': self.retention_until,
            'created_at': self.created_at,
            'started_at': self.started_at,
            'completed_at': self.completed_at,
            'cancel_requested_at': self.cancel_requested_at,
        }
