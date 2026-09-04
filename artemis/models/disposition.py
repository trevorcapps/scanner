"""False-positive / risk-acceptance dispositions and reusable suppression rules.

A disposition is a *decision* about a finding (this is a false positive; we
accept this risk until Q3). It never deletes evidence — raw observations keep
flowing; only presentation and notifications are suppressed. Risk acceptance
and organization-wide suppression require approval.
"""

import json

from artemis.extensions import db
from artemis.models._tenant import TenantMixin

DISPOSITION_TYPES = ('false_positive', 'risk_accepted', 'wont_fix')
DISPOSITION_SCOPES = ('occurrence', 'asset', 'group', 'organization')
DISPOSITION_STATUSES = ('pending', 'approved', 'rejected', 'expired', 'revoked')

# Types/scopes that must be approved by a second person before taking effect.
NEEDS_APPROVAL = {
    ('risk_accepted', 'occurrence'), ('risk_accepted', 'asset'),
    ('risk_accepted', 'group'), ('risk_accepted', 'organization'),
    ('false_positive', 'organization'), ('wont_fix', 'organization'),
    ('false_positive', 'group'),
}


class Disposition(TenantMixin, db.Model):
    __tablename__ = 'dispositions'

    id = db.Column(db.Integer, primary_key=True)
    disposition_type = db.Column(db.String(24), nullable=False)
    scope = db.Column(db.String(16), nullable=False)
    # Target for the scope: occurrence id / asset id / group id / null for org.
    target_id = db.Column(db.Integer)
    # For occurrence/definition scope we also pin the stable fingerprint.
    fingerprint = db.Column(db.String(64), index=True)
    definition_id = db.Column(db.String(128), index=True)

    rationale = db.Column(db.Text, nullable=False)
    evidence_json = db.Column(db.Text)
    requested_by = db.Column(db.Integer)
    approved_by = db.Column(db.Integer)
    status = db.Column(db.String(16), nullable=False, default='pending', index=True)

    created_at = db.Column(db.Text, nullable=False)
    approved_at = db.Column(db.Text)
    expires_at = db.Column(db.Text)
    review_date = db.Column(db.Text)

    def needs_approval(self):
        return (self.disposition_type, self.scope) in NEEDS_APPROVAL

    def is_active(self, now_iso):
        return self.status == 'approved' and (not self.expires_at or self.expires_at > now_iso)

    def to_dict(self):
        try:
            evidence = json.loads(self.evidence_json) if self.evidence_json else None
        except (TypeError, ValueError):
            evidence = None
        return {
            'id': self.id,
            'type': self.disposition_type,
            'scope': self.scope,
            'target_id': self.target_id,
            'fingerprint': self.fingerprint,
            'definition_id': self.definition_id,
            'rationale': self.rationale,
            'evidence': evidence,
            'requested_by': self.requested_by,
            'approved_by': self.approved_by,
            'status': self.status,
            'created_at': self.created_at,
            'approved_at': self.approved_at,
            'expires_at': self.expires_at,
            'review_date': self.review_date,
            'needs_approval': self.needs_approval(),
        }


class SuppressionRule(TenantMixin, db.Model):
    """A reusable rule that suppresses matching findings from presentation and
    notifications while raw observations continue to be stored."""

    __tablename__ = 'suppression_rules'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False)
    # Match keys — any set narrows the rule.
    definition_id = db.Column(db.String(128), index=True)
    fingerprint = db.Column(db.String(64), index=True)
    ip_pattern = db.Column(db.Text)            # exact IP or CIDR
    component_pattern = db.Column(db.Text)     # substring match
    reason = db.Column(db.Text)
    disposition_id = db.Column(db.Integer, db.ForeignKey('dispositions.id', ondelete='SET NULL'))
    enabled = db.Column(db.Integer, nullable=False, default=1)
    created_by = db.Column(db.Integer)
    created_at = db.Column(db.Text, nullable=False)
    expires_at = db.Column(db.Text)

    def to_dict(self):
        return {
            'id': self.id, 'name': self.name, 'definition_id': self.definition_id,
            'fingerprint': self.fingerprint, 'ip_pattern': self.ip_pattern,
            'component_pattern': self.component_pattern, 'reason': self.reason,
            'disposition_id': self.disposition_id, 'enabled': bool(self.enabled),
            'created_at': self.created_at, 'expires_at': self.expires_at,
        }
