"""Audit trail API — admin-only, read-only."""

from flask import Blueprint, jsonify, request

from artemis.services import audit_service
from artemis.services.auth_service import role_required

audit_bp = Blueprint('audit', __name__)


@audit_bp.route('/audit-events', methods=['GET'])
@role_required('admin')
def list_audit_events():
    """
    ---
    get:
      summary: Recent security audit events (admin only)
      tags: [Audit]
      parameters:
        - {in: query, name: action, schema: {type: string}}
        - {in: query, name: target_type, schema: {type: string}}
        - {in: query, name: target_id, schema: {type: string}}
        - {in: query, name: actor_user_id, schema: {type: integer}}
        - {in: query, name: limit, schema: {type: integer, default: 100}}
      responses:
        200: {description: A page of audit events, newest first}
      security: [{bearerAuth: []}]
    """
    events = audit_service.query(
        limit=request.args.get('limit', 100, type=int),
        action=request.args.get('action') or None,
        target_type=request.args.get('target_type') or None,
        target_id=request.args.get('target_id') or None,
        actor_user_id=request.args.get('actor_user_id', type=int),
        before=request.args.get('before') or None,
    )
    return jsonify({'events': [e.to_dict() for e in events], 'count': len(events)})
