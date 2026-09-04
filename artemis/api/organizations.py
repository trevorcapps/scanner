"""Organization, membership, and invitation management."""

import logging

from flask import Blueprint, g, jsonify, request, session

from artemis.extensions import db
from artemis.models.organization import (
    ORG_ROLES,
    Organization,
    OrganizationInvitation,
    OrganizationMembership,
)
from artemis.models.user import User
from artemis.services import audit_service, org_service
from artemis.services.auth_service import login_required

logger = logging.getLogger(__name__)

organizations_bp = Blueprint('organizations', __name__)


def _current_user():
    return getattr(g, 'current_user', None)


def _require_org_admin(org_id):
    """The caller must administer this organization (or be a platform admin)."""
    user = _current_user()
    if user is None:
        return None, (jsonify({'error': 'Authentication required'}), 401)
    if getattr(user, 'platform_admin', 0):
        return org_service.membership(user, org_id) or True, None
    row = org_service.membership(user, org_id)
    if row is None:
        return None, (jsonify({'error': 'Unknown organization'}), 404)
    if row.role != 'admin':
        return None, (jsonify({'error': 'Organization admin required'}), 403)
    return row, None


@organizations_bp.route('/organizations', methods=['GET'])
@login_required
def list_organizations():
    """Organizations the caller belongs to (platform admins see all)."""
    user = _current_user()
    if getattr(user, 'platform_admin', 0):
        orgs = Organization.query.order_by(Organization.name).all()
        roles = {m.organization_id: m.role for m in org_service.memberships_for(user)}
        return jsonify({'organizations': [o.to_dict(role=roles.get(o.id, 'admin')) for o in orgs],
                        'active_organization_id': getattr(g, 'organization_id', None)})
    rows = org_service.memberships_for(user)
    return jsonify({
        'organizations': [m.organization.to_dict(role=m.role) for m in rows],
        'active_organization_id': getattr(g, 'organization_id', None),
    })


@organizations_bp.route('/organizations', methods=['POST'])
@login_required
def create_organization():
    """Create an organization; the caller becomes its first admin."""
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'name is required'}), 400
    try:
        org = org_service.create_organization(
            name, slug=data.get('slug'), owner=_current_user(), owner_role='admin',
        )
        db.session.commit()
    except ValueError as exc:
        db.session.rollback()
        return jsonify({'error': str(exc)}), 409
    audit_service.record('org.create', target_type='organization', target_id=org.id,
                         detail={'slug': org.slug}, commit=True)
    return jsonify({'organization': org.to_dict(role='admin')}), 201


@organizations_bp.route('/organizations/switch', methods=['POST'])
@login_required
def switch_organization():
    """Set the session's active organization (interactive auth only)."""
    data = request.get_json(silent=True) or {}
    ref = data.get('organization_id') or data.get('slug')
    org = None
    if ref is not None:
        org = (db.session.get(Organization, int(ref)) if str(ref).isdigit()
               else Organization.query.filter_by(slug=str(ref)).first())
    if org is None:
        return jsonify({'error': 'Unknown organization'}), 404
    user = _current_user()
    if not getattr(user, 'platform_admin', 0) and org_service.membership(user, org.id) is None:
        return jsonify({'error': 'Unknown organization'}), 404
    session['organization_id'] = org.id
    return jsonify({'organization': org.to_dict()})


@organizations_bp.route('/organizations/<int:org_id>/members', methods=['GET'])
@login_required
def list_members(org_id):
    _row, err = _require_org_admin(org_id)
    if err:
        return err
    members = OrganizationMembership.query.filter_by(organization_id=org_id).all()
    return jsonify({'members': [m.to_dict() for m in members]})


@organizations_bp.route('/organizations/<int:org_id>/members', methods=['POST'])
@login_required
def add_or_invite_member(org_id):
    _row, err = _require_org_admin(org_id)
    if err:
        return err
    org = db.session.get(Organization, org_id)
    data = request.get_json(silent=True) or {}
    role = data.get('role', 'analyst')
    if role not in ORG_ROLES:
        return jsonify({'error': f'role must be one of {ORG_ROLES}'}), 400

    if data.get('user_id'):
        user = db.session.get(User, int(data['user_id']))
        if user is None:
            return jsonify({'error': 'user not found'}), 404
        org_service.add_member(org, user, role)
        db.session.commit()
        audit_service.record('org.member.add', target_type='organization', target_id=org_id,
                             detail={'user_id': user.id, 'role': role}, commit=True)
        return jsonify({'member': org_service.membership(user, org_id).to_dict()}), 201

    email = (data.get('email') or '').strip()
    if not email:
        return jsonify({'error': 'user_id or email is required'}), 400
    invitation = OrganizationInvitation(
        organization_id=org_id, email=email, role=role,
        invited_by=_current_user().id,
    )
    db.session.add(invitation)
    db.session.commit()
    audit_service.record('org.member.invite', target_type='organization', target_id=org_id,
                         detail={'email': email, 'role': role}, commit=True)
    return jsonify({'invitation': invitation.to_dict(include_token=True)}), 201


@organizations_bp.route('/organizations/<int:org_id>/members/<int:user_id>', methods=['PUT'])
@login_required
def update_member_role(org_id, user_id):
    _row, err = _require_org_admin(org_id)
    if err:
        return err
    data = request.get_json(silent=True) or {}
    role = data.get('role')
    if role not in ORG_ROLES:
        return jsonify({'error': f'role must be one of {ORG_ROLES}'}), 400
    membership = OrganizationMembership.query.filter_by(
        organization_id=org_id, user_id=user_id).first()
    if membership is None:
        return jsonify({'error': 'membership not found'}), 404
    if membership.role == 'admin' and role != 'admin':
        remaining = OrganizationMembership.query.filter_by(
            organization_id=org_id, role='admin').count()
        if remaining <= 1:
            return jsonify({'error': 'an organization must keep at least one admin'}), 409
    old = membership.role
    membership.role = role
    db.session.commit()
    audit_service.record('org.member.role', target_type='organization', target_id=org_id,
                         detail={'user_id': user_id, 'from': old, 'to': role}, commit=True)
    return jsonify({'member': membership.to_dict()})


@organizations_bp.route('/organizations/<int:org_id>/members/<int:user_id>', methods=['DELETE'])
@login_required
def remove_member(org_id, user_id):
    _row, err = _require_org_admin(org_id)
    if err:
        return err
    membership = OrganizationMembership.query.filter_by(
        organization_id=org_id, user_id=user_id).first()
    if membership is None:
        return jsonify({'error': 'membership not found'}), 404
    if membership.role == 'admin' and OrganizationMembership.query.filter_by(
            organization_id=org_id, role='admin').count() <= 1:
        return jsonify({'error': 'an organization must keep at least one admin'}), 409
    db.session.delete(membership)
    db.session.commit()
    audit_service.record('org.member.remove', target_type='organization', target_id=org_id,
                         detail={'user_id': user_id}, commit=True)
    return jsonify({'status': 'removed'})
