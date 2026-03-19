"""Settings API blueprint."""

import logging

from flask import Blueprint, request

from artemis.services.auth_scan_service import get_setting, set_setting
from artemis.services.nvd_service import get_nvd_sync_status

logger = logging.getLogger(__name__)

settings_bp = Blueprint('settings', __name__)


@settings_bp.route('/nvd-status')
def api_nvd_status():
    """Get NVD local database sync status."""
    return get_nvd_sync_status()


@settings_bp.route('/settings/nvd-key', methods=['GET'])
def api_get_nvd_key():
    """Get NVD API key (masked)."""
    key = get_setting('nvd_api_key', '')
    return {
        'has_key': bool(key),
        'masked': ('••••' + key[-4:]) if key and len(key) > 4 else ('••••' if key else '')
    }


@settings_bp.route('/settings/nvd-key', methods=['POST'])
def api_set_nvd_key():
    """Set NVD API key."""
    data = request.get_json()
    if not data:
        return {'error': 'JSON body required'}, 400
    key = data.get('key', '').strip()
    set_setting('nvd_api_key', key)
    return {'success': True}
