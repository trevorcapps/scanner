"""Asset model — a discovered/managed host and its business context."""

import json

from artemis.extensions import db
from artemis.models._tenant import TenantMixin

LIFECYCLE_STATES = ('discovered', 'active', 'stale', 'decommissioned')
CRITICALITY = ('unknown', 'low', 'medium', 'high', 'critical')

# Fields an operator can set by hand. Discovery must never overwrite these once
# they carry a value; `manual_fields_json` records which ones the operator owns.
MANUAL_FIELDS = ('criticality', 'environment', 'business_owner', 'business_team',
                 'external_id', 'notes', 'hostname')


class Asset(TenantMixin, db.Model):
    __tablename__ = 'assets'
    __table_args__ = (
        db.UniqueConstraint('organization_id', 'ip', name='uq_asset_org_ip'),
    )

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.Text)
    hostname = db.Column(db.Text)
    reverse_dns = db.Column(db.Text)
    aliases_json = db.Column(db.Text)
    os_name = db.Column(db.Text)
    os_family = db.Column(db.Text)
    os_vendor = db.Column(db.Text)
    os_accuracy = db.Column(db.Text)
    device_type = db.Column(db.Text)
    mac_address = db.Column(db.Text)
    mac_vendor = db.Column(db.Text)
    first_seen = db.Column(db.Text)
    last_seen = db.Column(db.Text)
    scan_count = db.Column(db.Integer, default=1)

    # --- business context (P3.1) ---
    criticality = db.Column(db.String(16), nullable=False, default='unknown')
    environment = db.Column(db.String(32))          # prod | staging | dev | ...
    business_owner = db.Column(db.Text)
    business_team = db.Column(db.Text)
    external_id = db.Column(db.Text)                 # CMDB / ticketing id
    notes = db.Column(db.Text)
    manual_fields_json = db.Column(db.Text)          # ["criticality", ...]

    # --- lifecycle ---
    lifecycle = db.Column(db.String(16), nullable=False, default='discovered')
    decommission_reason = db.Column(db.Text)
    decommissioned_at = db.Column(db.Text)
    first_seen_source = db.Column(db.String(32))     # discovery | scan | agent | manual | import
    last_seen_source = db.Column(db.String(32))

    tags = db.relationship('AssetTag', secondary='asset_tag_links',
                           back_populates='assets', lazy='selectin')
    group_links = db.relationship('AssetGroupMember', back_populates='asset',
                                  cascade='all, delete-orphan', lazy='selectin')

    # ------------------------------------------------------------------
    @property
    def manual_fields(self):
        try:
            return set(json.loads(self.manual_fields_json)) if self.manual_fields_json else set()
        except (TypeError, ValueError):
            return set()

    def mark_manual(self, field):
        current = self.manual_fields
        current.add(field)
        self.manual_fields_json = json.dumps(sorted(current))

    def apply_discovery(self, **fields):
        """Set discovery-sourced fields, never clobbering operator-owned ones."""
        owned = self.manual_fields
        for key, value in fields.items():
            if value in (None, '') or key in owned:
                continue
            setattr(self, key, value)

    def to_dict(self):
        aliases = []
        if self.aliases_json:
            try:
                aliases = json.loads(self.aliases_json)
            except (json.JSONDecodeError, TypeError):
                pass
        return {
            'id': self.id,
            'ip': self.ip,
            'hostname': self.hostname,
            'reverse_dns': self.reverse_dns,
            'aliases': aliases,
            'os_name': self.os_name,
            'os_family': self.os_family,
            'os_vendor': self.os_vendor,
            'os_accuracy': self.os_accuracy,
            'device_type': self.device_type,
            'mac_address': self.mac_address,
            'mac_vendor': self.mac_vendor,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'scan_count': self.scan_count,
            'criticality': self.criticality,
            'environment': self.environment,
            'business_owner': self.business_owner,
            'business_team': self.business_team,
            'external_id': self.external_id,
            'notes': self.notes,
            'manual_fields': sorted(self.manual_fields),
            'lifecycle': self.lifecycle,
            'decommission_reason': self.decommission_reason,
            'decommissioned_at': self.decommissioned_at,
            'first_seen_source': self.first_seen_source,
            'last_seen_source': self.last_seen_source,
            'tags': [t.name for t in self.tags],
            'groups': [gl.group_id for gl in self.group_links],
        }
