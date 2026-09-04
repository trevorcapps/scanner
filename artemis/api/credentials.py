"""Credentials CRUD API blueprint. Administration is admin-only (P0.4)."""

import logging
import os

from flask import Blueprint, request

from artemis.services.auth_scan_service import (
    delete_credential,
    get_all_credentials,
    get_credential,
    save_credential,
)
from artemis.services.auth_service import role_required

logger = logging.getLogger(__name__)

credentials_bp = Blueprint('credentials', __name__)


@credentials_bp.route('/credentials', methods=['GET'])
@role_required('analyst')
def api_get_credentials():
    """List credentials. Secret material is never returned."""
    return {'credentials': get_all_credentials()}


@credentials_bp.route('/credentials', methods=['POST'])
@role_required('admin')
def api_save_credential():
    """Create or update a credential."""
    data = request.get_json(silent=True)
    if not data:
        return {'error': 'JSON body required'}, 400

    name = data.get('name', '').strip()
    cred_type = data.get('cred_type', 'ssh_key')
    username = data.get('username', 'root').strip()
    key_path = data.get('key_path', '').strip()
    password = data.get('password', '').strip()
    private_key = data.get('private_key', '') or ''
    cred_id = data.get('id')

    if not name:
        return {'error': 'Credential name is required'}, 400
    if not username:
        return {'error': 'Username is required'}, 400

    # Legacy convenience: a server-side key file path still works, but the key is
    # read once and stored encrypted — the path is kept only as a label.
    if cred_type == 'ssh_key' and not private_key and key_path:
        if not os.path.isfile(key_path):
            return {'error': f'Key file not found: {key_path}'}, 400
        try:
            with open(key_path) as handle:
                private_key = handle.read()
        except OSError as exc:
            return {'error': f'Cannot read key file: {exc}'}, 400

    existing = get_credential(cred_id) if cred_id else None
    if cred_type == 'ssh_key' and not private_key and not (existing and existing['private_key_set']):
        return {'error': 'A private key is required for SSH key auth'}, 400
    if cred_type == 'ssh_password' and not password and not (existing and existing['secret_set']):
        return {'error': 'A password is required for password auth'}, 400

    try:
        result_id = save_credential(
            name, cred_type, username, key_path, password, cred_id, private_key=private_key,
        )
        return {'id': result_id, 'success': True}
    except ValueError as e:
        return {'error': str(e)}, 400


@credentials_bp.route('/credentials/<int:cred_id>', methods=['GET'])
@role_required('analyst')
def api_get_credential(cred_id):
    """
    ---
    get:
      summary: One credential (secret material never returned)
      tags: [Credentials]
      parameters:
        - {in: path, name: cred_id, required: true, schema: {type: integer}}
      responses:
        200: {description: The credential}
        404: {description: Not found}
      security: [{bearerAuth: []}]
    """
    c = get_credential(cred_id)
    if not c:
        return {'error': 'Credential not found'}, 404
    return {'credential': c}


@credentials_bp.route('/credentials/<int:cred_id>', methods=['DELETE'])
@role_required('admin')
def api_delete_credential(cred_id):
    """Delete a credential."""
    from artemis.services import audit_service

    if delete_credential(cred_id):
        audit_service.record(
            audit_service.SECRET_WRITE, target_type='credential', target_id=cred_id,
            detail={'deleted': True}, commit=True,
        )
        return {'success': True}
    return {'error': 'Credential not found'}, 404
