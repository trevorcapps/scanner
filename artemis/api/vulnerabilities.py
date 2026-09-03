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
        - in: query
          name: source
          schema: {type: string}
          description: "nuclei | nvd-local | auth-scan | agent | exploit-db"
        - {in: query, name: has_exploit, schema: {type: boolean}}
        - {in: query, name: search, schema: {type: string}}
        - {in: query, name: severity, schema: {type: string}}
        - {in: query, name: sort, schema: {type: string, enum: [cvss, severity, assets, name]}}
        - {in: query, name: order, schema: {type: string, enum: [asc, desc]}}
        - {in: query, name: page, schema: {type: integer}}
        - {in: query, name: per_page, schema: {type: integer}}
      responses:
        200:
          description: Findings plus a rollup summary (paginated envelope under `vulnerabilities` when page is set)
      security: [{bearerAuth: []}, {apiKeyAuth: []}]
    """
    ip = request.args.get('ip')
    source = request.args.get('source')
    has_exploit = request.args.get('has_exploit')
    search = request.args.get('search')
    severity = (request.args.get('severity') or '').strip().lower()
    sort = (request.args.get('sort') or '').strip()
    order = (request.args.get('order') or 'desc').strip()

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

        if severity:
            vulnerabilities = [v for v in vulnerabilities if v.get('severity') == severity]

        _SEV_ORD = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        keyers = {
            'cvss': lambda v: v.get('cvss_score') or 0,
            'severity': lambda v: -_SEV_ORD.get(v.get('severity'), 5),
            'assets': lambda v: len(v.get('affected_assets', [])),
            'name': lambda v: (v.get('vuln_name') or '').lower(),
        }
        if sort in keyers:
            reverse = order != 'asc'
            if sort == 'name':
                reverse = order == 'desc'
            vulnerabilities.sort(key=keyers[sort], reverse=reverse)

        total = len(vulnerabilities)
        if request.args.get('page') is not None:
            from artemis.api._pagination import paginate_list
            env = paginate_list(vulnerabilities, key='vulnerabilities')
            env['summary'] = summary
            env['filtered_total'] = total
            return env

        return {'vulnerabilities': vulnerabilities, 'summary': summary}
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
