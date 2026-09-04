"""Asset tags and groups (static membership + saved dynamic filters).

All join tables are normalized — no JSON arrays of ids on the asset row.
"""

import json

from artemis.extensions import db
from artemis.models._tenant import TenantMixin

asset_tag_links = db.Table(
    'asset_tag_links',
    db.Column('asset_id', db.Integer, db.ForeignKey('assets.id', ondelete='CASCADE'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('asset_tags.id', ondelete='CASCADE'), primary_key=True),
)


class AssetTag(TenantMixin, db.Model):
    __tablename__ = 'asset_tags'
    __table_args__ = (
        db.UniqueConstraint('organization_id', 'name', name='uq_asset_tag_org_name'),
    )

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    color = db.Column(db.String(16))
    created_at = db.Column(db.Text)

    assets = db.relationship('Asset', secondary=asset_tag_links, back_populates='tags')

    def to_dict(self):
        return {'id': self.id, 'name': self.name, 'color': self.color,
                'asset_count': len(self.assets)}


class AssetGroup(TenantMixin, db.Model):
    __tablename__ = 'asset_groups'
    __table_args__ = (
        db.UniqueConstraint('organization_id', 'name', name='uq_asset_group_org_name'),
    )

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text)
    kind = db.Column(db.String(8), nullable=False, default='static')   # static | dynamic
    # For dynamic groups: a saved filter spec, e.g.
    #   {"environment": "prod", "criticality": ["high", "critical"], "tag": "pci"}
    filter_json = db.Column(db.Text)
    created_at = db.Column(db.Text)
    created_by = db.Column(db.Integer)

    members = db.relationship('AssetGroupMember', back_populates='group',
                              cascade='all, delete-orphan', lazy='selectin')

    @property
    def filter_spec(self):
        try:
            return json.loads(self.filter_json) if self.filter_json else {}
        except (TypeError, ValueError):
            return {}

    def to_dict(self, member_count=None):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'kind': self.kind,
            'filter': self.filter_spec,
            'created_at': self.created_at,
            'member_count': member_count if member_count is not None else len(self.members),
        }


class AssetGroupMember(TenantMixin, db.Model):
    __tablename__ = 'asset_group_members'
    __table_args__ = (
        db.UniqueConstraint('group_id', 'asset_id', name='uq_asset_group_member'),
    )

    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('asset_groups.id', ondelete='CASCADE'),
                         nullable=False, index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id', ondelete='CASCADE'),
                         nullable=False, index=True)

    group = db.relationship('AssetGroup', back_populates='members')
    asset = db.relationship('Asset', back_populates='group_links')


class AssetReviewEvent(TenantMixin, db.Model):
    """Recorded when discovery hits a decommissioned asset (it is NOT silently
    reactivated) or a manual field would have been overwritten."""

    __tablename__ = 'asset_review_events'

    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id', ondelete='CASCADE'),
                         nullable=False, index=True)
    kind = db.Column(db.String(32), nullable=False)   # decommissioned_reappeared | manual_conflict
    detail_json = db.Column(db.Text)
    created_at = db.Column(db.Text, nullable=False)
    resolved_at = db.Column(db.Text)

    def to_dict(self):
        try:
            detail = json.loads(self.detail_json) if self.detail_json else {}
        except (TypeError, ValueError):
            detail = {}
        return {
            'id': self.id, 'asset_id': self.asset_id, 'kind': self.kind,
            'detail': detail, 'created_at': self.created_at, 'resolved_at': self.resolved_at,
        }
