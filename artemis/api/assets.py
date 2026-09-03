"""Assets API blueprint."""

import logging

from flask import Blueprint, request
from sqlalchemy import func

from artemis.extensions import db
from artemis.models.asset import Asset
from artemis.models.scan import Scan
from artemis.utils.validation import validate_ip, validate_hostname, is_hostname
from artemis.utils.dns import ScanError, resolve_target, resolve_ip_param
from artemis.services.asset_service import get_asset_details, delete_asset, update_device_type
from artemis.services.vuln_service import get_vulnerability_counts_by_severity
from artemis.services.fingerprint_service import get_fingerprint_summary
from artemis.services.auth_scan_service import get_asset_os_details, get_installed_software, get_cve_matches
from artemis.services.auth_service import role_required

logger = logging.getLogger(__name__)

assets_bp = Blueprint('assets', __name__)


def _device_icon(device_type):
    import sys
    import os
    scanner_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if scanner_dir not in sys.path:
        sys.path.insert(0, scanner_dir)
    from device_type import get_device_icon
    return get_device_icon(device_type) if device_type else None


def _asset_summary(asset_row, ip, last_scan):
    """Build the list-view payload for one asset."""
    ports = Scan.query.filter_by(ip=ip, scan_date=last_scan).all() if last_scan else []
    fp_summary = get_fingerprint_summary(ip)
    fp_by_port = fp_summary.get('by_port', {})

    return {
        'ip': ip,
        'hostname': asset_row.hostname if asset_row else None,
        'reverse_dns': asset_row.reverse_dns if asset_row else None,
        'device_type': asset_row.device_type if asset_row else None,
        'device_icon': _device_icon(asset_row.device_type) if asset_row else None,
        'mac_address': asset_row.mac_address if asset_row else None,
        'mac_vendor': asset_row.mac_vendor if asset_row else None,
        'os_name': asset_row.os_name if asset_row else None,
        'last_scan': last_scan,
        'port_count': len(ports),
        'vuln_counts': get_vulnerability_counts_by_severity(ip),
        'technologies': fp_summary.get('technologies', [])[:5],
        'ports': [
            {
                'protocol': p.protocol, 'port': p.port, 'state': p.state,
                'service': p.service, 'product': p.product, 'version': p.version,
                'fingerprint': fp_by_port.get(p.port, {}),
            } for p in ports
        ],
    }


@assets_bp.route('/assets')
def get_assets():
    """
    ---
    get:
      summary: List scanned assets
      tags: [Assets]
      parameters:
        - {in: query, name: device_type, schema: {type: string}}
        - {in: query, name: q, schema: {type: string}, description: Substring match on IP or hostname}
        - in: query
          name: severity
          schema: {type: string}
          description: "only assets with >=1 finding at this severity"
        - {in: query, name: has_vulns, schema: {type: boolean}}
        - {in: query, name: sort, schema: {type: string, enum: [ip, hostname, last_scan, port_count, risk]}}
        - {in: query, name: order, schema: {type: string, enum: [asc, desc]}}
        - in: query
          name: page
          schema: {type: integer}
          description: "when set, returns the {data, pagination} envelope"
        - {in: query, name: per_page, schema: {type: integer}}
      responses:
        200:
          description: Assets (bare list, or paginated envelope when page is set)
      security: [{bearerAuth: []}, {apiKeyAuth: []}]
    """
    device_type = request.args.get('device_type')
    q = (request.args.get('q') or '').strip().lower()
    severity = (request.args.get('severity') or '').strip().lower()
    has_vulns = request.args.get('has_vulns')
    sort = (request.args.get('sort') or 'last_scan').strip()
    order = (request.args.get('order') or 'desc').strip()

    try:
        latest = db.session.query(
            Scan.ip, func.max(Scan.scan_date).label('last_scan'),
        ).group_by(Scan.ip).all()
        latest_by_ip = {ip: ls for ip, ls in latest}

        asset_rows = {a.ip: a for a in Asset.query.all()}
        ips = set(latest_by_ip) | set(asset_rows)

        assets = []
        for ip in ips:
            row = asset_rows.get(ip)
            if device_type and (not row or (row.device_type or 'unknown') != device_type):
                continue
            if q and q not in ip.lower() and not (row and row.hostname and q in row.hostname.lower()):
                continue
            summary = _asset_summary(row, ip, latest_by_ip.get(ip))
            vc = summary.get('vuln_counts') or {}
            if severity in ('critical', 'high', 'medium', 'low', 'info') and not vc.get(severity):
                continue
            if has_vulns is not None:
                want = has_vulns.lower() in ('1', 'true', 'yes')
                if bool(vc.get('total')) != want:
                    continue
            assets.append(summary)

        _RISK_W = {'critical': 10, 'high': 5, 'medium': 2, 'low': 1, 'info': 0}
        keyers = {
            'ip': lambda a: a['ip'],
            'hostname': lambda a: (a.get('hostname') or '').lower(),
            'last_scan': lambda a: a.get('last_scan') or '',
            'port_count': lambda a: a.get('port_count') or 0,
            'risk': lambda a: sum(_RISK_W[s] * (a.get('vuln_counts') or {}).get(s, 0) for s in _RISK_W),
        }
        assets.sort(key=keyers.get(sort, keyers['last_scan']), reverse=(order != 'asc'))

        if request.args.get('page') is not None:
            from artemis.api._pagination import paginate_list
            return paginate_list(assets, key='assets')
        return {'assets': assets}
    except Exception as e:
        logger.error(f"Database error in get_assets: {e}")
        return {'error': str(e)}, 500


@assets_bp.route('/asset/<ip>')
@assets_bp.route('/assets/<ip>')
def get_asset(ip):
    """
    ---
    get:
      summary: Get one asset with full detail
      tags: [Assets]
      parameters:
        - in: path
          name: ip
          required: true
          schema: {type: string}
      responses:
        200: {description: Asset detail}
        404: {description: Not found}
      security: [{bearerAuth: []}, {apiKeyAuth: []}]
    """
    try:
        ip = resolve_ip_param(ip)
    except (ValueError, ScanError) as e:
        return {'error': str(e)}, 400

    asset = get_asset_details(ip)
    if not asset:
        return {'error': 'Asset not found'}, 404
    return {'asset': asset}


@assets_bp.route('/asset/<ip>', methods=['PATCH'])
@assets_bp.route('/assets/<ip>', methods=['PATCH'])
@role_required('analyst')
def patch_asset(ip):
    """
    ---
    patch:
      summary: Edit asset metadata (hostname / device_type override)
      tags: [Assets]
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                hostname: {type: string}
                device_type: {type: string}
      responses:
        200: {description: Updated asset detail}
        404: {description: Not found}
      security: [{bearerAuth: []}]
    """
    try:
        ip = resolve_ip_param(ip)
    except (ValueError, ScanError) as e:
        return {'error': str(e)}, 400

    data = request.get_json(silent=True) or {}
    asset = Asset.query.filter_by(ip=ip).first()
    if not asset:
        return {'error': 'Asset not found'}, 404

    if 'hostname' in data:
        asset.hostname = (data['hostname'] or '').strip() or None
    if 'device_type' in data:
        asset.device_type = (data['device_type'] or '').strip() or None
    db.session.commit()
    return {'asset': get_asset_details(ip)}


@assets_bp.route('/asset/<ip>', methods=['DELETE'])
@assets_bp.route('/assets/<ip>', methods=['DELETE'])
@role_required('analyst')
def remove_asset(ip):
    """
    ---
    delete:
      summary: Purge an asset and every scan/vuln/fingerprint row for its IP
      tags: [Assets]
      responses:
        200: {description: Row counts removed per table}
        404: {description: Not found}
      security: [{bearerAuth: []}]
    """
    try:
        ip = resolve_ip_param(ip)
    except (ValueError, ScanError) as e:
        return {'error': str(e)}, 400

    if not Asset.query.filter_by(ip=ip).first() and not Scan.query.filter_by(ip=ip).first():
        return {'error': 'Asset not found'}, 404
    try:
        removed = delete_asset(ip)
        return {'deleted': ip, 'removed': removed}
    except Exception as e:
        return {'error': str(e)}, 500


@assets_bp.route('/asset/<ip>/reclassify', methods=['POST'])
@role_required('analyst')
def reclassify_asset(ip):
    """
    ---
    post:
      summary: Re-run device-type classification for an asset
      tags: [Assets]
      responses:
        200: {description: New device type}
      security: [{bearerAuth: []}]
    """
    try:
        ip = resolve_ip_param(ip)
    except (ValueError, ScanError) as e:
        return {'error': str(e)}, 400
    return {'ip': ip, 'device_type': update_device_type(ip)}


@assets_bp.route('/asset/<ip>/auth-details')
@assets_bp.route('/assets/<ip>/auth-details')
def get_asset_auth_details(ip):
    """
    ---
    get:
      summary: Authenticated-scan detail for an asset (OS, packages, CVEs)
      tags: [Assets]
      responses:
        200: {description: Auth scan detail}
      security: [{bearerAuth: []}, {apiKeyAuth: []}]
    """
    try:
        if not validate_ip(ip) and not validate_hostname(ip):
            return {'error': 'Invalid target'}, 400
        if is_hostname(ip):
            ip = resolve_target(ip)

        os_details = get_asset_os_details(ip)
        software = get_installed_software(ip)
        cves = get_cve_matches(ip)

        for cve in cves:
            if not cve.get('has_exploit') and cve.get('cve_id'):
                try:
                    from artemis.services.nvd_service import lookup_exploits
                    info = lookup_exploits(cve['cve_id'])
                    cve['has_exploit'] = info['has_exploit']
                    cve['exploit_ids'] = ','.join(info['exploit_ids'])
                    cve['exploit_url'] = info['exploit_urls'][0] if info['exploit_urls'] else ''
                except Exception:
                    pass

        return {
            'os_details': os_details,
            'software': software,
            'software_count': len(software),
            'cves': cves,
            'cve_count': len(cves),
        }
    except Exception as e:
        logger.error(f"Error getting auth details for {ip}: {e}")
        return {'error': str(e)}, 500
