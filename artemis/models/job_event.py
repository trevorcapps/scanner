"""Immutable event log for a durable :class:`ScanJob`.

One row per lifecycle transition or progress/log point. Never updated or deleted
by application code (retention prune only). The full ordered stream is the
replay/fallback contract behind live Socket.IO delivery.
"""

import json

from artemis.extensions import db
from artemis.models._tenant import TenantMixin

# Event kinds
QUEUED = 'queued'
STARTED = 'started'
PROGRESS = 'progress'
LOG = 'log'
RESULT = 'result'
RETRY = 'retry'
CANCEL = 'cancel'
FAILURE = 'failure'


class JobEvent(TenantMixin, db.Model):
    __tablename__ = 'job_events'
    __table_args__ = (
        db.Index('ix_job_events_job_seq', 'job_id', 'seq'),
    )

    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(
        db.String(36), db.ForeignKey('scan_jobs.id', ondelete='CASCADE'),
        nullable=False, index=True,
    )
    # Monotonic per-job sequence for stable ordering and resume-after.
    seq = db.Column(db.Integer, nullable=False)
    kind = db.Column(db.String(16), nullable=False)
    message = db.Column(db.Text)
    level = db.Column(db.String(8))                 # info | warning | error
    progress_current = db.Column(db.Integer)
    progress_total = db.Column(db.Integer)
    data_json = db.Column(db.Text)
    created_at = db.Column(db.Text, nullable=False)

    def to_dict(self):
        try:
            data = json.loads(self.data_json) if self.data_json else None
        except (TypeError, ValueError):
            data = None
        return {
            'id': self.id,
            'job_id': self.job_id,
            'seq': self.seq,
            'kind': self.kind,
            'message': self.message,
            'level': self.level,
            'progress': (
                {'current': self.progress_current, 'total': self.progress_total}
                if self.progress_current is not None else None
            ),
            'data': data,
            'created_at': self.created_at,
        }
