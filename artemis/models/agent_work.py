"""Signed, typed agent work items (P3.4 / P5-D).

Automation for an outbound-only enrolled agent is delivered as a signed work
manifest — never as keystrokes through the unrestricted shell. The agent
verifies the HMAC signature and the content SHA-256 before executing anything,
and rejects a manifest whose signature or digest does not match the
server-created job.
"""

import hashlib
import hmac
import json
import uuid

from artemis.extensions import db
from artemis.models._tenant import TenantMixin

WORK_KINDS = ('inventory_refresh', 'ansible_local')
WORK_STATES = ('queued', 'delivered', 'running', 'succeeded', 'failed', 'rejected', 'expired')


class AgentWork(TenantMixin, db.Model):
    __tablename__ = 'agent_work'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = db.Column(db.Integer, db.ForeignKey('agents.id', ondelete='CASCADE'),
                         nullable=False, index=True)
    job_id = db.Column(db.String(36), db.ForeignKey('scan_jobs.id', ondelete='SET NULL'), index=True)
    kind = db.Column(db.String(24), nullable=False)
    status = db.Column(db.String(12), nullable=False, default='queued', index=True)

    content_digest = db.Column(db.String(64))
    payload_json = db.Column(db.Text, nullable=False)     # non-secret manifest body
    signature = db.Column(db.String(64), nullable=False)  # HMAC-SHA256 hex

    created_at = db.Column(db.Text, nullable=False)
    delivered_at = db.Column(db.Text)
    completed_at = db.Column(db.Text)
    expires_at = db.Column(db.Text, nullable=False)
    result_json = db.Column(db.Text)
    reject_reason = db.Column(db.Text)

    # --- signing ------------------------------------------------------
    @staticmethod
    def _signing_key(agent):
        # Derived from the agent's own enrolled identity — rotates with the key.
        return hashlib.sha256(f'artemis-work:{agent.agent_key}'.encode()).digest()

    @staticmethod
    def canonical(payload):
        return json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()

    @classmethod
    def sign(cls, agent, payload):
        return hmac.new(cls._signing_key(agent), cls.canonical(payload), hashlib.sha256).hexdigest()

    def verify(self, agent):
        expected = self.sign(agent, json.loads(self.payload_json))
        return hmac.compare_digest(expected, self.signature or '')

    def manifest(self):
        return {
            'id': self.id,
            'kind': self.kind,
            'content_digest': self.content_digest,
            'expires_at': self.expires_at,
            'signature': self.signature,
            'payload': json.loads(self.payload_json),
        }

    def to_dict(self):
        try:
            result = json.loads(self.result_json) if self.result_json else None
        except (TypeError, ValueError):
            result = None
        return {
            'id': self.id, 'agent_id': self.agent_id, 'job_id': self.job_id,
            'kind': self.kind, 'status': self.status, 'content_digest': self.content_digest,
            'created_at': self.created_at, 'delivered_at': self.delivered_at,
            'completed_at': self.completed_at, 'expires_at': self.expires_at,
            'result': result, 'reject_reason': self.reject_reason,
        }
