"""Settings API blueprint."""

import logging

from flask import Blueprint, request

from artemis.models.setting import Setting
from artemis.services.auth_scan_service import get_setting, set_setting
from artemis.services.auth_service import role_required
from artemis.services.nvd_service import get_nvd_sync_status

logger = logging.getLogger(__name__)

settings_bp = Blueprint('settings', __name__)

# Never returned in the clear or writable through the generic endpoint.
_SECRET_KEYS = {'nvd_api_key', 'smtp_password'}
# Internal bookkeeping — hidden from the generic list.
_HIDDEN_PREFIXES = ('_',)


def _is_hidden(key):
    return key.startswith(_HIDDEN_PREFIXES)


@settings_bp.route('/nvd-status')
def api_nvd_status():
    """
    ---
    get:
      summary: NVD local feed-cache sync status
      tags: [Settings]
      responses:
        200: {description: Sync status}
      security: [{bearerAuth: []}, {apiKeyAuth: []}]
    """
    return get_nvd_sync_status()


@settings_bp.route('/logs')
def api_recent_logs():
    """Return recent in-process application logs for the activity panel."""
    from artemis.services.log_service import get_recent_logs

    limit = request.args.get('limit', 200, type=int)
    level = (request.args.get('level') or '').strip() or None
    records = get_recent_logs(limit=limit, minimum_level=level)
    return {'logs': records, 'count': len(records)}


@settings_bp.route('/settings')
def api_list_settings():
    """
    ---
    get:
      summary: All non-secret settings
      tags: [Settings]
      responses:
        200: {description: Key/value map (secret values redacted)}
      security: [{bearerAuth: []}]
    """
    out = {}
    for row in Setting.query.all():
        if _is_hidden(row.key):
            continue
        out[row.key] = '••••' if row.key in _SECRET_KEYS and row.value else row.value
    return {'settings': out}


@settings_bp.route('/settings/<key>', methods=['PUT'])
@role_required('admin')
def api_put_setting(key):
    """
    ---
    put:
      summary: Set one setting value
      tags: [Settings]
      parameters:
        - {in: path, name: key, required: true, schema: {type: string}}
      requestBody:
        required: true
        content:
          application/json:
            schema: {type: object, properties: {value: {type: string}}}
      responses:
        200: {description: Stored}
        400: {description: Reserved key}
      security: [{bearerAuth: []}]
    """
    if _is_hidden(key):
        return {'error': 'Reserved key'}, 400
    data = request.get_json(silent=True) or {}
    set_setting(key, str(data.get('value', '')))
    return {'success': True, 'key': key}


@settings_bp.route('/settings/nvd-key', methods=['GET'])
def api_get_nvd_key():
    """
    ---
    get:
      summary: Whether an NVD API key is configured (masked)
      tags: [Settings]
      responses:
        200: {description: Masked key state}
      security: [{bearerAuth: []}]
    """
    key = get_setting('nvd_api_key', '')
    return {
        'has_key': bool(key),
        'masked': ('••••' + key[-4:]) if key and len(key) > 4 else ('••••' if key else '')
    }


@settings_bp.route('/settings/nvd-key', methods=['POST'])
def api_set_nvd_key():
    """
    ---
    post:
      summary: Set the NVD API key
      tags: [Settings]
      requestBody:
        content:
          application/json:
            schema: {type: object, properties: {key: {type: string}}}
      responses:
        200: {description: Stored}
      security: [{bearerAuth: []}]
    """
    data = request.get_json()
    if not data:
        return {'error': 'JSON body required'}, 400
    set_setting('nvd_api_key', data.get('key', '').strip())
    return {'success': True}
