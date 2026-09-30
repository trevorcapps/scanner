"""Remote agent PTY session metadata; terminal bytes never enter the database."""

import uuid
from datetime import datetime
from sqlalchemy import text

from artemis.extensions import db
from artemis.models._tenant import TenantMixin


class AgentShellSession(TenantMixin, db.Model):
    __tablename__ = 'agent_shell_sessions'

    __table_args__ = (db.Index(
        'uq_agent_shell_active_lease', 'organization_id', 'agent_id', unique=True,
        postgresql_where=text("status IN ('requested', 'running', 'closing')"),
        sqlite_where=text("status IN ('requested', 'running', 'closing')")),)

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = db.Column(db.Integer, db.ForeignKey('agents.id', ondelete='CASCADE'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), index=True)
    status = db.Column(db.String(24), nullable=False, default='requested', index=True)
    cols = db.Column(db.Integer, nullable=False, default=120)
    rows = db.Column(db.Integer, nullable=False, default=32)
    output_bytes = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.Text, nullable=False)
    started_at = db.Column(db.Text)
    last_activity_at = db.Column(db.Text, nullable=False)
    last_agent_poll_at = db.Column(db.Text)
    expires_at = db.Column(db.Text, nullable=False)
    closed_at = db.Column(db.Text)
    exit_code = db.Column(db.Integer)
    source = db.Column(db.Text)
    close_reason = db.Column(db.String(64))
    error_message = db.Column(db.Text)

    def to_dict(self):
        duration = None
        if self.started_at and self.closed_at:
            try:
                duration = max(0, (datetime.fromisoformat(self.closed_at.replace('Z', '+00:00'))
                                   - datetime.fromisoformat(self.started_at.replace('Z', '+00:00'))).total_seconds())
            except ValueError:
                pass
        return {
            'id': self.id,
            'agent_id': self.agent_id,
            'user_id': self.user_id,
            'status': self.status,
            'cols': self.cols,
            'rows': self.rows,
            'output_bytes': self.output_bytes,
            'created_at': self.created_at,
            'started_at': self.started_at,
            'last_activity_at': self.last_activity_at,
            'last_agent_poll_at': self.last_agent_poll_at,
            'expires_at': self.expires_at,
            'closed_at': self.closed_at,
            'exit_code': self.exit_code,
            'source': self.source,
            'duration_seconds': duration,
            'close_reason': self.close_reason,
            'privilege': 'agent_process (may be root)',
            'error_message': self.error_message,
        }
