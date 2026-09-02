"""Scans API blueprint — scan profiles endpoint."""

import json
import logging

from flask import Blueprint, jsonify, request

from artemis.extensions import db
from artemis.models.scan_job import ScanJob
from artemis.services.auth_service import role_required
from artemis.services.job_service import TERMINAL_STATES, cancel_job

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
