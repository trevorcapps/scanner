"""Historical inventory: package observation intervals + asset timeline.

``InstalledSoftware`` stays as the derived "current" view. ``SoftwareObservation``
records one row per (asset, package, version) interval — when it was first and
last seen, and when it was observed removed. ``AssetTimelineEvent`` is the
append-only change log across ports, OS, identity, and software.
"""

import json

from artemis.extensions import db
from artemis.models._tenant import TenantMixin

TIMELINE_KINDS = (
    'port_opened', 'port_closed', 'service_changed',
    'os_changed', 'hostname_changed', 'identity_changed',
    'package_installed', 'package_removed', 'package_updated',
    'lifecycle_changed',
)


class SoftwareObservation(TenantMixin, db.Model):
    __tablename__ = 'software_observations'
    __table_args__ = (
        db.Index('ix_software_obs_asset_pkg', 'asset_id', 'package_name'),
    )

    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id', ondelete='CASCADE'),
                         nullable=False, index=True)
    ip = db.Column(db.Text, index=True)
    package_name = db.Column(db.Text, nullable=False)
    package_version = db.Column(db.Text)
    cpe = db.Column(db.Text)
    source = db.Column(db.String(24))            # agent | auth-scan | import
    job_id = db.Column(db.String(36))
    first_seen = db.Column(db.Text, nullable=False)
    last_seen = db.Column(db.Text, nullable=False)
    removed_at = db.Column(db.Text)              # set once observed absent

    def to_dict(self):
        return {
            'id': self.id, 'asset_id': self.asset_id, 'ip': self.ip,
            'package_name': self.package_name, 'package_version': self.package_version,
            'cpe': self.cpe, 'source': self.source, 'job_id': self.job_id,
            'first_seen': self.first_seen, 'last_seen': self.last_seen,
            'removed_at': self.removed_at,
            'active': self.removed_at is None,
        }


class AssetTimelineEvent(TenantMixin, db.Model):
    __tablename__ = 'asset_timeline_events'
    __table_args__ = (
        db.Index('ix_asset_timeline_asset_at', 'asset_id', 'created_at'),
    )

    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id', ondelete='CASCADE'),
                         nullable=False, index=True)
    kind = db.Column(db.String(32), nullable=False)
    summary = db.Column(db.Text)
    from_value = db.Column(db.Text)
    to_value = db.Column(db.Text)
    source = db.Column(db.String(24))
    job_id = db.Column(db.String(36))
    report_id = db.Column(db.Integer)
    detail_json = db.Column(db.Text)
    created_at = db.Column(db.Text, nullable=False)

    def to_dict(self):
        try:
            detail = json.loads(self.detail_json) if self.detail_json else None
        except (TypeError, ValueError):
            detail = None
        return {
            'id': self.id, 'asset_id': self.asset_id, 'kind': self.kind,
            'summary': self.summary, 'from': self.from_value, 'to': self.to_value,
            'source': self.source, 'job_id': self.job_id, 'report_id': self.report_id,
            'detail': detail, 'created_at': self.created_at,
        }
