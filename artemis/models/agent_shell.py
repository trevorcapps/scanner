"""Remote agent PTY sessions and their bounded transport queues."""

import uuid

from artemis.extensions import db
from artemis.models._tenant import TenantMixin


class AgentShellSession(TenantMixin, db.Model):
    __tablename__ = 'agent_shell_sessions'

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
    error_message = db.Column(db.Text)

    def to_dict(self):
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
            'error_message': self.error_message,
        }


class AgentShellInput(db.Model):
    __tablename__ = 'agent_shell_inputs'

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(
        db.String(36), db.ForeignKey('agent_shell_sessions.id', ondelete='CASCADE'), nullable=False, index=True,
    )
    data_b64 = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.Text, nullable=False)

    def to_dict(self):
        return {'id': self.id, 'data': self.data_b64}


class AgentShellOutput(db.Model):
    __tablename__ = 'agent_shell_outputs'

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(
        db.String(36), db.ForeignKey('agent_shell_sessions.id', ondelete='CASCADE'), nullable=False, index=True,
    )
    data_b64 = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.Text, nullable=False)

    def to_dict(self):
        return {'id': self.id, 'data': self.data_b64, 'created_at': self.created_at}
