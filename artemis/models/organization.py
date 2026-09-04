"""Organization (tenant) identity and membership.

`User` stays a global identity. Ordinary role (admin / analyst / readonly) is
assigned *per organization* through `OrganizationMembership`. A separate,
audited `User.platform_admin` flag grants cross-organization administration
(decision D1).
"""

import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from artemis.extensions import db

ORG_ROLES = ('admin', 'analyst', 'readonly')


def _now_iso():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def slugify(value):
    slug = re.sub(r'[^a-z0-9]+', '-', (value or '').lower()).strip('-')
    return slug or 'org'


class Organization(db.Model):
    __tablename__ = 'organizations'

    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(64), unique=True, nullable=False)
    name = db.Column(db.Text, nullable=False)
    is_default = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.Text, nullable=False, default=_now_iso)

    memberships = db.relationship(
        'OrganizationMembership', back_populates='organization',
        cascade='all, delete-orphan', lazy='dynamic',
    )

    def to_dict(self, role=None):
        data = {
            'id': self.id,
            'slug': self.slug,
            'name': self.name,
            'is_default': bool(self.is_default),
            'created_at': self.created_at,
        }
        if role is not None:
            data['role'] = role
        return data


class OrganizationMembership(db.Model):
    __tablename__ = 'organization_memberships'
    __table_args__ = (
        db.UniqueConstraint('organization_id', 'user_id', name='uq_org_membership'),
    )

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(
        db.Integer, db.ForeignKey('organizations.id', ondelete='CASCADE'),
        nullable=False, index=True,
    )
    user_id = db.Column(
        db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'),
        nullable=False, index=True,
    )
    role = db.Column(db.String(16), nullable=False, default='analyst')
    created_at = db.Column(db.Text, nullable=False, default=_now_iso)

    organization = db.relationship('Organization', back_populates='memberships')
    user = db.relationship('User')

    def to_dict(self):
        return {
            'id': self.id,
            'organization_id': self.organization_id,
            'user_id': self.user_id,
            'role': self.role,
            'created_at': self.created_at,
            'username': self.user.username if self.user else None,
        }


class OrganizationInvitation(db.Model):
    __tablename__ = 'organization_invitations'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id = db.Column(
        db.Integer, db.ForeignKey('organizations.id', ondelete='CASCADE'),
        nullable=False, index=True,
    )
    email = db.Column(db.Text, nullable=False)
    role = db.Column(db.String(16), nullable=False, default='analyst')
    token = db.Column(db.String(64), nullable=False, unique=True,
                      default=lambda: secrets.token_urlsafe(32))
    invited_by = db.Column(db.Integer)
    created_at = db.Column(db.Text, nullable=False, default=_now_iso)
    expires_at = db.Column(db.Text, nullable=False,
                           default=lambda: (datetime.now(timezone.utc) + timedelta(days=7))
                           .strftime('%Y-%m-%dT%H:%M:%SZ'))
    accepted_at = db.Column(db.Text)

    def is_expired(self):
        return _now_iso() > (self.expires_at or '')

    def to_dict(self, include_token=False):
        data = {
            'id': self.id,
            'organization_id': self.organization_id,
            'email': self.email,
            'role': self.role,
            'invited_by': self.invited_by,
            'created_at': self.created_at,
            'expires_at': self.expires_at,
            'accepted_at': self.accepted_at,
            'expired': self.is_expired(),
        }
        if include_token:
            data['token'] = self.token
        return data
