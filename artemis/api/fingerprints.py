"""Fingerprints API blueprint."""

import logging

from flask import Blueprint, request

from artemis.utils.dns import ScanError, resolve_ip_param
from artemis.services.fingerprint_service import get_fingerprints, get_fingerprint_summary

logger = logging.getLogger(__name__)

fingerprints_bp = Blueprint('fingerprints', __name__)


@fingerprints_bp.route('/fingerprints/<ip>')
def get_fingerprints_api(ip):
    """Get fingerprint data for a specific IP."""
    try:
        ip = resolve_ip_param(ip)
    except (ValueError, ScanError) as e:
        return {'error': str(e)}, 400

    port = request.args.get('port', type=int)
    fingerprints = get_fingerprints(ip, port=port)
    summary = get_fingerprint_summary(ip)

    return {
        'fingerprints': fingerprints,
        'technologies': summary.get('technologies', []),
        'by_port': {str(k): v for k, v in summary.get('by_port', {}).items()},
    }
