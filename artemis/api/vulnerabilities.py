"""Vulnerabilities API blueprint."""

import logging

from flask import Blueprint, request

from artemis.utils.dns import ScanError, resolve_ip_param
from artemis.services.vuln_service import get_unified_vulnerabilities, get_unified_vulnerability_summary

logger = logging.getLogger(__name__)

vulnerabilities_bp = Blueprint('vulnerabilities', __name__)


@vulnerabilities_bp.route('/vulnerabilities')
def get_vulnerabilities():
    """Get unified list of all vulnerabilities from all sources."""
    ip = request.args.get('ip')
    source = request.args.get('source')
    has_exploit = request.args.get('has_exploit')
    search = request.args.get('search')

    try:
        if ip:
            try:
                ip = resolve_ip_param(ip)
            except (ValueError, ScanError) as e:
                return {'error': str(e)}, 400

        exploit_filter = None
        if has_exploit is not None:
            exploit_filter = has_exploit.lower() in ('true', '1', 'yes')

        vulnerabilities = get_unified_vulnerabilities(
            ip=ip, source=source, has_exploit=exploit_filter, search=search
        )
        summary = get_unified_vulnerability_summary(ip=ip)

        return {
            'vulnerabilities': vulnerabilities,
            'summary': summary
        }
    except Exception as e:
        logger.error(f"Error retrieving vulnerabilities: {e}")
        return {'error': str(e)}, 500
