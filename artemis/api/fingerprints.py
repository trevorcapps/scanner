"""Fingerprints API blueprint."""

import logging

from flask import Blueprint, request

from artemis.utils.dns import ScanError, resolve_ip_param
from artemis.models.fingerprint_model import Fingerprint
from artemis.services.fingerprint_service import get_fingerprints, get_fingerprint_summary
from artemis.api._pagination import paginate

logger = logging.getLogger(__name__)

fingerprints_bp = Blueprint('fingerprints', __name__)


@fingerprints_bp.route('/fingerprints')
def list_fingerprints():
    """
    ---
    get:
      summary: All fingerprint matches (paginated)
      tags: [Fingerprints]
      parameters:
        - {in: query, name: ip, schema: {type: string}}
        - {in: query, name: category, schema: {type: string}}
        - {in: query, name: page, schema: {type: integer}}
        - {in: query, name: per_page, schema: {type: integer}}
      responses:
        200: {description: Paginated Fingerprint rows}
      security: [{bearerAuth: []}, {apiKeyAuth: []}]
    """
    q = Fingerprint.query
    if request.args.get('ip'):
        q = q.filter_by(ip=request.args['ip'])
    if request.args.get('category'):
        q = q.filter_by(category=request.args['category'])
    q = q.order_by(Fingerprint.ip, Fingerprint.port, Fingerprint.confidence.desc())
    return paginate(q, key='fingerprints')


@fingerprints_bp.route('/fingerprints/<ip>')
def get_fingerprints_api(ip):
    """
    ---
    get:
      summary: Fingerprint data for one IP
      tags: [Fingerprints]
      parameters:
        - {in: path, name: ip, required: true, schema: {type: string}}
        - {in: query, name: port, schema: {type: integer}}
      responses:
        200: {description: Fingerprints plus a technology rollup}
      security: [{bearerAuth: []}, {apiKeyAuth: []}]
    """
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
