"""Vulnerabilities API blueprint."""

import logging

from flask import Blueprint, request

from artemis.utils.dns import ScanError, resolve_ip_param
from artemis.services.vuln_service import get_unified_vulnerabilities, get_unified_vulnerability_summary

logger = logging.getLogger(__name__)

vulnerabilities_bp = Blueprint('vulnerabilities', __name__)


@vulnerabilities_bp.route('/vulnerabilities')
def get_vulnerabilities():
    """
    ---
    get:
      summary: Unified vulnerability list across all detection sources
      tags: [Vulnerabilities]
      parameters:
        - {in: query, name: ip, schema: {type: string}}
        - {in: query, name: source, schema: {type: string}, description: "nuclei | nvd-local | auth-scan | exploit-db"}
        - {in: query, name: has_exploit, schema: {type: boolean}}
        - {in: query, name: search, schema: {type: string}}
      responses:
        200:
          description: Findings plus a rollup summary
      security: [{bearerAuth: []}, {apiKeyAuth: []}]
    """
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


@vulnerabilities_bp.route('/vulnerabilities/<vuln_id>')
def get_vulnerability(vuln_id):
    """
    ---
    get:
      summary: One unified finding by CVE / template id, with affected assets
      tags: [Vulnerabilities]
      parameters:
        - {in: path, name: vuln_id, required: true, schema: {type: string}}
      responses:
        200: {description: The finding}
        404: {description: Not found}
      security: [{bearerAuth: []}, {apiKeyAuth: []}]
    """
    target = vuln_id.upper() if vuln_id.upper().startswith('CVE-') else vuln_id
    for v in get_unified_vulnerabilities():
        if v['cve_id'] == target or v.get('template_id') == vuln_id:
            return {'vulnerability': v}
    return {'error': 'Vulnerability not found'}, 404
