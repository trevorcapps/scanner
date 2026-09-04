"""Durable, security-relevant audit trail.

One immutable row per security-significant action: authentication, secret
access, role changes, scan lifecycle, remote-shell lifecycle, and data exports.
Rows are never updated or deleted by application code; retention is enforced by
a scheduled prune (see D8).
"""

import json
import uuid
from datetime import datetime, timezone

from artemis.extensions import db


class AuditEvent(db.Model):
    __tablename__ = 'audit_events'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    # ISO-8601 UTC, e.g. "2026-09-03T21:14:05Z"
    created_at = db.Column(db.Text, nullable=False, index=True)
    # Dotted action name: auth.login, secret.read, role.change, scan.start, ...
    action = db.Column(db.String(64), nullable=False, index=True)
    outcome = db.Column(db.String(16), nullable=False, default='success')  # success | failure | denied
    # Actor
    actor_user_id = db.Column(db.Integer, index=True)
    actor_label = db.Column(db.Text)              # username / api-key name / agent name
    actor_kind = db.Column(db.String(16))         # user | api_key | agent | system
    source_ip = db.Column(db.Text)
    # Target of the action
    target_type = db.Column(db.String(32), index=True)   # credential, user, scan_job, shell_session, ...
    target_id = db.Column(db.Text, index=True)
    # Correlation with the request / job that produced it
    request_id = db.Column(db.Text, index=True)
    organization_id = db.Column(db.Integer, index=True)   # populated from Phase 1 onward
    # Small JSON blob of non-sensitive context (never secret values)
    detail_json = db.Column(db.Text)

    @staticmethod
    def utcnow_iso():
        return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    def to_dict(self):
        try:
            detail = json.loads(self.detail_json) if self.detail_json else {}
        except (ValueError, TypeError):
            detail = {}
        return {
            'id': self.id,
            'created_at': self.created_at,
            'action': self.action,
            'outcome': self.outcome,
            'actor_user_id': self.actor_user_id,
            'actor_label': self.actor_label,
            'actor_kind': self.actor_kind,
            'source_ip': self.source_ip,
            'target_type': self.target_type,
            'target_id': self.target_id,
            'request_id': self.request_id,
            'organization_id': self.organization_id,
            'detail': detail,
        }
