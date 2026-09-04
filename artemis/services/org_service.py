"""Organization membership resolution and per-request tenant context.

Every authenticated request resolves exactly one active organization and the
caller's effective role within it. Missing or unauthorized context fails closed.
"""

import logging

from flask import g, has_request_context, request

from artemis.extensions import db
from artemis.models.organization import (
    ORG_ROLES,
    Organization,
    OrganizationMembership,
    slugify,
)

logger = logging.getLogger(__name__)

ROLE_RANK = {'readonly': 1, 'analyst': 2, 'admin': 3}


class OrgContextError(Exception):
    """Raised when a valid active organization cannot be established."""

    def __init__(self, message, status=403):
        super().__init__(message)
        self.status = status


def get_default_organization():
    org = Organization.query.filter_by(is_default=1).first()
    if org is None:
        org = Organization.query.order_by(Organization.id).first()
    return org


def ensure_default_organization():
    """Return the Default organization, creating it if the table is empty."""
    org = get_default_organization()
    if org is None:
        org = Organization(name='Default', slug='default', is_default=1)
        db.session.add(org)
        db.session.flush()
    return org


def create_organization(name, *, slug=None, is_default=False, owner=None, owner_role='admin'):
    slug = slugify(slug or name)
    if Organization.query.filter_by(slug=slug).first():
        raise ValueError(f"organization slug '{slug}' already exists")
    org = Organization(name=name, slug=slug, is_default=1 if is_default else 0)
    db.session.add(org)
    db.session.flush()
    if owner is not None:
        add_member(org, owner, owner_role)
    return org


def add_member(org, user, role='analyst'):
    if role not in ORG_ROLES:
        raise ValueError(f"role must be one of {ORG_ROLES}")
    existing = OrganizationMembership.query.filter_by(
        organization_id=org.id, user_id=user.id
    ).first()
    if existing:
        existing.role = role
        return existing
    membership = OrganizationMembership(
        organization_id=org.id, user_id=user.id, role=role
    )
    db.session.add(membership)
    return membership


def memberships_for(user):
    return (
        OrganizationMembership.query.filter_by(user_id=user.id)
        .join(Organization)
        .order_by(Organization.is_default.desc(), Organization.name)
        .all()
    )


def membership(user, org_id):
    return OrganizationMembership.query.filter_by(
        organization_id=org_id, user_id=user.id
    ).first()


def _requested_org_ref():
    """Organization the caller is asking to act in (header wins, then session)."""
    if not has_request_context():
        return None
    ref = request.headers.get('X-Organization') or request.args.get('organization')
    if ref:
        return ref.strip()
    from flask import session
    return session.get('organization_id')


def _resolve_org(ref):
    if ref is None:
        return None
    if isinstance(ref, int) or (isinstance(ref, str) and ref.isdigit()):
        return db.session.get(Organization, int(ref))
    return Organization.query.filter_by(slug=str(ref)).first()


def resolve_context(user):
    """Populate g.organization_id / g.organization / g.org_role for this request.

    API-key auth is pinned to the key's organization. Interactive auth honours an
    ``X-Organization`` header / session selection, else the user's primary
    membership. Platform admins may enter any organization.
    """
    api_key_org_id = getattr(g, 'api_key_organization_id', None)
    requested = api_key_org_id if api_key_org_id is not None else _requested_org_ref()

    org = _resolve_org(requested) if requested is not None else None
    if requested is not None and org is None:
        raise OrgContextError('Unknown organization', status=404)

    is_platform_admin = bool(getattr(user, 'platform_admin', 0))

    if org is None:
        member_rows = memberships_for(user)
        if not member_rows:
            if is_platform_admin:
                org = get_default_organization()
            if org is None:
                raise OrgContextError('User has no organization membership')
            role = 'admin'
        else:
            row = member_rows[0]
            org, role = row.organization, row.role
    else:
        row = membership(user, org.id)
        if row is None:
            if not is_platform_admin:
                # Do not disclose existence — same shape as "unknown".
                raise OrgContextError('Unknown organization', status=404)
            role = 'admin'
        else:
            role = row.role

    if api_key_org_id is None and _requested_org_ref() and not str(_requested_org_ref()).isdigit():
        pass  # slug selection already resolved above

    g.organization = org
    g.organization_id = org.id
    g.org_role = role
    g.is_platform_admin = is_platform_admin
    return org


def effective_org_role(user=None):
    """Role in the active org, capped by any API-key role. Platform admin => admin."""
    if getattr(g, 'is_platform_admin', False):
        return 'admin'
    role = getattr(g, 'org_role', None)
    if role is None:
        return None
    key_role = getattr(g, 'api_key_role', None)
    if key_role is None:
        return role
    return min((role, key_role), key=lambda r: ROLE_RANK.get(r, 0))


def require_org_role(min_role):
    role = effective_org_role()
    if ROLE_RANK.get(role, 0) < ROLE_RANK.get(min_role, 0):
        raise OrgContextError('Insufficient permissions in this organization')
    return role
