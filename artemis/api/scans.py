"""Scans API blueprint — scan profiles endpoint."""

import os
import json
import logging

from flask import Blueprint

logger = logging.getLogger(__name__)

scans_bp = Blueprint('scans', __name__)


def _load_scan_profiles():
    from flask import current_app
    profiles_path = current_app.config.get('SCAN_PROFILES_PATH', '')
    profiles = {}
    try:
        with open(profiles_path, 'r') as f:
            data = json.load(f)
            for p in data.get('profiles', []):
                profiles[p['id']] = p
    except Exception as e:
        logger.warning(f"Could not load scan profiles: {e}")
    return profiles


@scans_bp.route('/scan-profiles')
def get_scan_profiles():
    """Get available scan profiles."""
    profiles = _load_scan_profiles()
    return {'profiles': list(profiles.values())}
