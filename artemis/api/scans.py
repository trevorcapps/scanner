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
                # Authenticated inventory is a first-class scan type. Older
                # profile files exposed the same SSH workflow as a Nuclei
                # profile, which produced two controls for one operation.
                if p.get('auth_required'):
                    continue
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
                options:
                  type: object
                  description: >
                    scan_type=vuln accepts `profile`, `templates`, `severity`,
                    `rate_limit`. scan_type=auth requires `credential_ids`
                    (array of credential ids) OR `use_all_credentials: true`.
      responses:
        202: {description: Scan job accepted}
        400: {description: Invalid target, scan_type, or missing credentials}
        503: {description: Scan queue unavailable}
      security: [{bearerAuth: []}]
    """
    data = request.get_json(silent=True) or {}
    target = (data.get('target') or '').strip()
    scan_type = (data.get('scan_type') or 'port').strip().lower()
    options = data.get('options') or {}

    if not target or not validate_target(target):
        return {'error': 'A valid target (IP, CIDR or hostname) is required'}, 400
    if scan_type not in _SCAN_TYPES:
        return {'error': f'scan_type must be one of {", ".join(_SCAN_TYPES)}'}, 400
    if scan_type == 'auth':
        cred_ids = options.get('credential_ids') or []
        if not cred_ids and not options.get('use_all_credentials'):
            return {'error': 'auth scans require options.credential_ids or use_all_credentials'}, 400

    user = getattr(g, 'current_user', None)
    try:
        job = dispatch_adhoc_scan(target, scan_type, options,
                                  requested_by=user.id if user else None)
    except QueueDispatchError as e:
        return {'error': str(e), 'job': e.job.to_dict()}, 503

    from artemis.services import audit_service
    audit_service.record(
        audit_service.SCAN_START, target_type='scan_job', target_id=job.id,
        detail={'scan_type': scan_type, 'target': target}, commit=True,
    )
    return jsonify(job.to_dict()), 202


def _list_jobs():
    from artemis.services.tenant import current_org_id
    query = ScanJob.query.filter(ScanJob.organization_id == current_org_id())
    status = request.args.get('status', '').strip()
    if status:
        query = query.filter(ScanJob.status == status)
    job_type = request.args.get('type', '').strip()
    if job_type:
        query = query.filter(ScanJob.job_type == job_type)
    limit = min(max(request.args.get('limit', 50, type=int), 1), 200)
    jobs = query.order_by(ScanJob.created_at.desc()).limit(limit).all()
    return jsonify({'jobs': [job.to_dict() for job in jobs], 'count': len(jobs)})


def _get_job_or_404(job_id):
    from artemis.services.tenant import scoped_get
    return scoped_get(ScanJob, job_id)


@scans_bp.route('/jobs', methods=['GET'])
@scans_bp.route('/scan-jobs', methods=['GET'])
def list_scan_jobs():
    """List durable jobs for the active organization, newest first."""
    return _list_jobs()


@scans_bp.route('/jobs', methods=['POST'])
@role_required('analyst')
def create_job_endpoint():
    """
    ---
    post:
      summary: Create and dispatch a scan job (async; 202 + job URL)
      tags: [Jobs]
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [type, target]
              properties:
                type: {type: string, enum: [port, vuln, fingerprint, auth, full]}
                target: {type: string}
                options: {type: object}
      responses:
        202: {description: Job accepted}
        400: {description: Invalid request}
      security: [{bearerAuth: []}]
    """
    data = request.get_json(silent=True) or {}
    job_type = data.get('type', 'port')
    target = (data.get('target') or '').strip()
    options = data.get('options') or {}
    if job_type not in ('port', 'vuln', 'fingerprint', 'auth', 'full'):
        return {'error': 'type must be one of port, vuln, fingerprint, auth, full'}, 400
    if not validate_target(target):
        return {'error': 'A valid target (IP, CIDR or hostname) is required'}, 400
    if job_type == 'auth' and not (options.get('credential_ids') or options.get('use_all_credentials')):
        return {'error': 'auth jobs require options.credential_ids or use_all_credentials'}, 400

    user = getattr(g, 'current_user', None)
    try:
        job = dispatch_adhoc_scan(target, job_type, options,
                                  requested_by=user.id if user else None,
                                  idempotency_key=request.headers.get('Idempotency-Key'))
    except QueueDispatchError as e:
        return {'error': str(e), 'job': e.job.to_dict()}, 503

    from artemis.services import audit_service
    audit_service.record(audit_service.SCAN_START, target_type='scan_job', target_id=job.id,
                         detail={'scan_type': job_type, 'target': target}, commit=True)
    resp = jsonify(job.to_dict())
    resp.status_code = 202
    resp.headers['Location'] = f'/api/v1/jobs/{job.id}'
    return resp


@scans_bp.route('/jobs/<job_id>', methods=['GET'])
@scans_bp.route('/scan-jobs/<job_id>', methods=['GET'])
def get_scan_job(job_id):
    """Return current execution state and result for a job."""
    job = _get_job_or_404(job_id)
    if not job:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(job.to_dict())


@scans_bp.route('/jobs/<job_id>/events', methods=['GET'])
@scans_bp.route('/scan-jobs/<job_id>/events', methods=['GET'])
def get_job_events(job_id):
    """Ordered, replayable job event stream. Pass ?after=<seq> to resume."""
    job = _get_job_or_404(job_id)
    if not job:
        return jsonify({'error': 'Not found'}), 404
    from artemis.services.job_service import job_events
    after = request.args.get('after', 0, type=int)
    limit = min(max(request.args.get('limit', 500, type=int), 1), 2000)
    events = job_events(job, after_seq=after, limit=limit)
    return jsonify({
        'job': job.to_dict(),
        'events': [e.to_dict() for e in events],
        'last_seq': events[-1].seq if events else after,
    })


@scans_bp.route('/jobs/<job_id>/cancel', methods=['POST'])
@scans_bp.route('/scan-jobs/<job_id>/cancel', methods=['POST'])
@role_required('analyst')
def cancel_scan_job(job_id):
    """Request cooperative cancellation of a queued or running job."""
    job = _get_job_or_404(job_id)
    if not job:
        return jsonify({'error': 'Not found'}), 404
    if not cancel_job(job):
        return jsonify({
            'error': f'Job is already {job.status}',
            'terminal': job.status in TERMINAL_STATES,
            'job': job.to_dict(),
        }), 409
    from artemis.services import audit_service
    audit_service.record(
        audit_service.SCAN_CANCEL, target_type='scan_job', target_id=job.id, commit=True,
    )
    return jsonify(job.to_dict()), 202
