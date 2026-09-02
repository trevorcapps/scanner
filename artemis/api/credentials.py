"""Credentials CRUD API blueprint."""

import logging

from flask import Blueprint, request

from artemis.services.auth_scan_service import (
    get_all_credentials, get_credential, save_credential, delete_credential
)

logger = logging.getLogger(__name__)

credentials_bp = Blueprint('credentials', __name__)


@credentials_bp.route('/credentials', methods=['GET'])
def api_get_credentials():
    """Get all credentials (passwords masked)."""
    creds = get_all_credentials()
    for c in creds:
        if c['password']:
            c['password_set'] = True
            c['password'] = ''
        else:
            c['password_set'] = False
    return {'credentials': creds}


@credentials_bp.route('/credentials', methods=['POST'])
def api_save_credential():
    """Create or update a credential."""
    data = request.get_json()
    if not data:
        return {'error': 'JSON body required'}, 400

    name = data.get('name', '').strip()
    cred_type = data.get('cred_type', 'ssh_key')
    username = data.get('username', 'root').strip()
    key_path = data.get('key_path', '').strip()
    password = data.get('password', '').strip()
    cred_id = data.get('id')

    if not name:
        return {'error': 'Credential name is required'}, 400
    if not username:
        return {'error': 'Username is required'}, 400
    if cred_type == 'ssh_key' and not key_path:
        return {'error': 'Key path is required for SSH key auth'}, 400
    if cred_type == 'ssh_password' and not password:
        if cred_id:
            existing = get_credential(cred_id)
            if existing:
                password = existing['password']
        if not password:
            return {'error': 'Password is required for password auth'}, 400

    try:
        result_id = save_credential(name, cred_type, username, key_path, password, cred_id)
        return {'id': result_id, 'success': True}
    except ValueError as e:
        return {'error': str(e)}, 400


@credentials_bp.route('/credentials/<int:cred_id>', methods=['GET'])
def api_get_credential(cred_id):
    """
    ---
    get:
      summary: One credential (password redacted)
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
    c['password_set'] = bool(c.pop('password', ''))
    return {'credential': c}


@credentials_bp.route('/credentials/<int:cred_id>', methods=['DELETE'])
def api_delete_credential(cred_id):
    """Delete a credential."""
    if delete_credential(cred_id):
        return {'success': True}
    return {'error': 'Credential not found'}, 404
