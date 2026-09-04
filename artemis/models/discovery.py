"""Monitored-subnet discovery scopes.

A scope is an authorised set of CIDR ranges to sweep for live hosts. Discovery
runs as an ordinary durable job; it upserts assets as ``discovered`` and raises
review events for reappearing decommissioned hosts.
"""

import json

from artemis.extensions import db
from artemis.models._tenant import TenantMixin

APPROVAL_STATES = ('pending', 'approved', 'rejected')


class DiscoveryScope(TenantMixin, db.Model):
    __tablename__ = 'discovery_scopes'
    __table_args__ = (
        db.UniqueConstraint('organization_id', 'name', name='uq_discovery_scope_org_name'),
    )

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    cidrs_json = db.Column(db.Text, nullable=False, default='[]')
    exclusions_json = db.Column(db.Text, nullable=False, default='[]')
    engine_pool = db.Column(db.String(64))
    cron_expression = db.Column(db.Text)
    next_run = db.Column(db.Text)
    max_hosts = db.Column(db.Integer, nullable=False, default=1024)
    enabled = db.Column(db.Integer, nullable=False, default=0)
    # Broad / public ranges must be explicitly approved before they dispatch.
    approval_state = db.Column(db.String(16), nullable=False, default='pending')
    approved_by = db.Column(db.Integer)
    approved_at = db.Column(db.Text)
    created_at = db.Column(db.Text, nullable=False)
    created_by = db.Column(db.Integer)
    last_run = db.Column(db.Text)
    last_status = db.Column(db.Text)

    @staticmethod
    def _load(value):
        try:
            return json.loads(value) if value else []
        except (TypeError, ValueError):
            return []

    @property
    def cidrs(self):
        return self._load(self.cidrs_json)

    @property
    def exclusions(self):
        return self._load(self.exclusions_json)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'cidrs': self.cidrs,
            'exclusions': self.exclusions,
            'engine_pool': self.engine_pool,
            'cron_expression': self.cron_expression,
            'next_run': self.next_run,
            'max_hosts': self.max_hosts,
            'enabled': bool(self.enabled),
            'approval_state': self.approval_state,
            'approved_by': self.approved_by,
            'approved_at': self.approved_at,
            'created_at': self.created_at,
            'last_run': self.last_run,
            'last_status': self.last_status,
        }
