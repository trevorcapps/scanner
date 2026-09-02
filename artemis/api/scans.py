"""Scans API blueprint — scan profiles endpoint."""

import json
import logging

from flask import Blueprint, jsonify, request, g

from artemis.extensions import db
from artemis.models.scan_job import ScanJob
from artemis.models.scan import Scan
from artemis.services.auth_service import role_required
from artemis.services.job_service import (
    TERMINAL_STATES, cancel_job, dispatch_adhoc_scan, QueueDispatchError,
)
from artemis.utils.validation import validate_target
from artemis.api._pagination import paginate

logger = logging.getLogger(__name__)

scans_bp = Blueprint('scans', __name__)

_SCAN_TYPES = ('port', 'vuln', 'full', 'auth')


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


@scans_bp.route('/scans', methods=['GET'])
def list_scans():
    """
    ---
    get:
      summary: Raw port-scan history
      tags: [Scans]
      parameters:
        - {in: query, name: ip, schema: {type: string}}
        - {in: query, name: page, schema: {type: integer}}
        - {in: query, name: per_page, schema: {type: integer}}
      responses:
        200: {description: Paginated Scan rows}
      security: [{bearerAuth: []}, {apiKeyAuth: []}]
    """
    q = Scan.query
    ip = request.args.get('ip')
    if ip:
        q = q.filter_by(ip=ip)
    q = q.order_by(Scan.scan_date.desc(), Scan.port)
    return paginate(q, key='scans')


@scans_bp.route('/scans', methods=['POST'])
@role_required('analyst')
def create_scan():
    """
    ---
    post:
      summary: Launch a scan against a target (IP, CIDR or hostname)
      tags: [Scans]
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [target]
              properties:
                target: {type: string}
                scan_type: {type: string, enum: [port, vuln, full, auth], default: port}
                options: {type: object}
      responses:
        202: {description: Scan job accepted}
        400: {description: Invalid target or scan_type}
        503: {description: Scan queue unavailable}
      security: [{bearerAuth: []}]
    """
    data = request.get_json(silent=True) or {}
    target = (data.get('target') or '').strip()
    scan_type = (data.get('scan_type') or 'port').strip().lower()

    if not target or not validate_target(target):
        return {'error': 'A valid target (IP, CIDR or hostname) is required'}, 400
    if scan_type not in _SCAN_TYPES:
        return {'error': f'scan_type must be one of {", ".join(_SCAN_TYPES)}'}, 400

    user = getattr(g, 'current_user', None)
    try:
        job = dispatch_adhoc_scan(target, scan_type, data.get('options') or {},
                                  requested_by=user.id if user else None)
    except QueueDispatchError as e:
        return {'error': str(e), 'job': e.job.to_dict()}, 503
    return jsonify(job.to_dict()), 202


@scans_bp.route('/scan-jobs', methods=['GET'])
def list_scan_jobs():
    """List durable scanner jobs, newest first."""
    query = ScanJob.query
    status = request.args.get('status', '').strip()
    if status:
        query = query.filter_by(status=status)
    limit = min(max(request.args.get('limit', 50, type=int), 1), 200)
    jobs = query.order_by(ScanJob.created_at.desc()).limit(limit).all()
    return jsonify({'jobs': [job.to_dict() for job in jobs], 'count': len(jobs)})


@scans_bp.route('/scan-jobs/<job_id>', methods=['GET'])
def get_scan_job(job_id):
    """Return current execution state and result for a scan job."""
    job = db.get_or_404(ScanJob, job_id)
    return jsonify(job.to_dict())


@scans_bp.route('/scan-jobs/<job_id>/cancel', methods=['POST'])
@role_required('analyst')
def cancel_scan_job(job_id):
    """Request cooperative cancellation of a queued or running scan job."""
    job = db.get_or_404(ScanJob, job_id)
    if not cancel_job(job):
        return jsonify({
            'error': f'Job is already {job.status}',
            'terminal': job.status in TERMINAL_STATES,
            'job': job.to_dict(),
        }), 409
    return jsonify(job.to_dict()), 202
