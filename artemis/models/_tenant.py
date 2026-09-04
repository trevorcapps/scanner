"""Mixin for tenant-owned tables.

Every row that belongs to an organization carries a non-null ``organization_id``.
Query scoping is enforced by :mod:`artemis.services.tenant` (Phase 1.3); this
mixin only guarantees the column, index, and convenience relationship exist
consistently.
"""

from sqlalchemy.orm import declared_attr

from artemis.extensions import db


class TenantMixin:
    @declared_attr
    def organization_id(cls):  # noqa: N805
        return db.Column(
            db.Integer,
            db.ForeignKey('organizations.id', ondelete='CASCADE'),
            nullable=False,
            index=True,
        )

    @declared_attr
    def organization(cls):  # noqa: N805
        return db.relationship('Organization')
