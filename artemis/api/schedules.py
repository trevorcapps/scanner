"""Schedules API blueprint — CRUD for scheduled scans and scan history."""

import json
import logging
from datetime import datetime

from flask import Blueprint, request, jsonify

from artemis.extensions import db
from artemis.models.scheduled_scan import ScheduledScan
from artemis.models.scan_history import ScanHistory
from artemis.services.scheduler_service import calculate_next_run

logger = logging.getLogger(__name__)

schedules_bp = Blueprint('schedules', __name__)


def _now_iso():
    return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')


@schedules_bp.route('/schedules', methods=['GET'])
def list_schedules():
    """List all scheduled scans."""
    scheds = ScheduledScan.query.order_by(ScheduledScan.id.desc()).all()
    return jsonify([s.to_dict() for s in scheds])


@schedules_bp.route('/schedules', methods=['POST'])
def create_schedule():
    """Create a new scheduled scan."""
    from artemis.services.scan_profile_service import validate_cron, validate_missed_run_policy

    data = request.get_json(force=True)
    now = _now_iso()

    cron = data.get('cron_expression')
    if data.get('schedule_type') == 'cron' or cron:
        if not cron or not validate_cron(cron):
            return jsonify({'error': 'invalid cron_expression'}), 400
    policy = data.get('missed_run_policy', 'skip')
    if not validate_missed_run_policy(policy):
        return jsonify({'error': 'missed_run_policy must be skip, run_once, or catch_up'}), 400

    sched = ScheduledScan(
        name=data.get('name', 'Unnamed Schedule'),
        target=data['target'],
        scan_type=data.get('scan_type', 'port'),
        profile_id=data.get('profile_id'),
        execution_profile_id=data.get('execution_profile_id'),
        missed_run_policy=policy,
        schedule_type=data.get('schedule_type', 'daily'),
        cron_expression=cron,
        schedule_hour=data.get('schedule_hour', 2),
        schedule_minute=data.get('schedule_minute', 0),
        schedule_day_of_week=data.get('schedule_day_of_week'),
        schedule_day_of_month=data.get('schedule_day_of_month'),
        scan_options_json=json.dumps(data['scan_options']) if data.get('scan_options') else None,
        credential_ids_json=json.dumps(data['credential_ids']) if data.get('credential_ids') else None,
        enabled=data.get('enabled', 1),
        notify_on_complete=data.get('notify_on_complete', 0),
        notify_on_new_vulns=data.get('notify_on_new_vulns', 1),
        compare_with_previous=data.get('compare_with_previous', 1),
        created_at=now,
        updated_at=now,
    )

    # Calculate initial next_run
    sched.next_run = calculate_next_run(sched)

    db.session.add(sched)
    db.session.commit()
    return jsonify(sched.to_dict()), 201


@schedules_bp.route('/schedules/<int:sid>', methods=['GET'])
def get_schedule(sid):
    """Get schedule details."""
    sched = ScheduledScan.query.get_or_404(sid)
    return jsonify(sched.to_dict())


@schedules_bp.route('/schedules/<int:sid>', methods=['PUT'])
def update_schedule(sid):
    """Update a scheduled scan."""
    sched = ScheduledScan.query.get_or_404(sid)
    data = request.get_json(force=True)

    for field in ('name', 'target', 'scan_type', 'profile_id', 'schedule_type',
                  'cron_expression', 'schedule_hour', 'schedule_minute',
                  'schedule_day_of_week', 'schedule_day_of_month',
                  'enabled', 'notify_on_complete', 'notify_on_new_vulns',
                  'compare_with_previous'):
        if field in data:
            setattr(sched, field, data[field])

    if 'scan_options' in data:
        sched.scan_options_json = json.dumps(data['scan_options']) if data['scan_options'] else None
    if 'credential_ids' in data:
        sched.credential_ids_json = json.dumps(data['credential_ids']) if data['credential_ids'] else None

    sched.next_run = calculate_next_run(sched)
    sched.updated_at = _now_iso()
    db.session.commit()
    return jsonify(sched.to_dict())


@schedules_bp.route('/schedules/<int:sid>', methods=['DELETE'])
def delete_schedule(sid):
    """Delete a scheduled scan."""
    sched = ScheduledScan.query.get_or_404(sid)
    db.session.delete(sched)
    db.session.commit()
    return jsonify({'status': 'deleted', 'id': sid})


@schedules_bp.route('/schedules/<int:sid>/run', methods=['POST'])
def run_schedule_now(sid):
    """Trigger a scheduled scan immediately."""
    sched = ScheduledScan.query.get_or_404(sid)
    sched.next_run = _now_iso()
    sched.enabled = 1
    db.session.commit()
    return jsonify({'status': 'triggered', 'id': sid, 'next_run': sched.next_run})


@schedules_bp.route('/schedules/<int:sid>/toggle', methods=['POST'])
def toggle_schedule(sid):
    """Enable or disable a scheduled scan."""
    sched = ScheduledScan.query.get_or_404(sid)
    sched.enabled = 0 if sched.enabled else 1
    if sched.enabled:
        sched.next_run = calculate_next_run(sched)
    sched.updated_at = _now_iso()
    db.session.commit()
    return jsonify({'status': 'enabled' if sched.enabled else 'disabled', 'id': sid})


@schedules_bp.route('/execution-profiles', methods=['GET'])
def list_execution_profiles():
    """Reusable scan execution profiles for the active organization."""
    from artemis.services import scan_profile_service
    history = request.args.get('history') in ('1', 'true')
    return jsonify({'profiles': [p.to_dict()
                                 for p in scan_profile_service.list_profiles(include_history=history)]})


@schedules_bp.route('/execution-profiles', methods=['POST'])
def create_execution_profile():
    """Create a profile, or a new version of an existing name."""
    from flask import g
    from artemis.services import scan_profile_service
    from artemis.services.auth_service import get_effective_role

    if get_effective_role(getattr(g, 'current_user', None)) == 'readonly':
        return jsonify({'error': 'Read-only credentials cannot modify resources'}), 403
    data = request.get_json(silent=True) or {}
    try:
        user = getattr(g, 'current_user', None)
        profile = scan_profile_service.create_profile(data, created_by=user.id if user else None)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    return jsonify({'profile': profile.to_dict()}), 201


@schedules_bp.route('/execution-profiles/<int:pid>', methods=['GET'])
def get_execution_profile(pid):
    from artemis.services import scan_profile_service
    profile = scan_profile_service.get_profile(pid)
    if not profile:
        return jsonify({'error': 'Not found'}), 404
    return jsonify({'profile': profile.to_dict()})


@schedules_bp.route('/scan-history', methods=['GET'])
def list_scan_history():
    """List scan execution history. Filter by ?scheduled_scan_id=N."""
    query = ScanHistory.query
    ssid = request.args.get('scheduled_scan_id')
    if ssid:
        query = query.filter(ScanHistory.scheduled_scan_id == int(ssid))
    history = query.order_by(ScanHistory.id.desc()).limit(100).all()
    return jsonify([h.to_dict() for h in history])


@schedules_bp.route('/scan-history/<int:hid>', methods=['GET'])
def get_scan_history(hid):
    """Get scan history details with delta summary."""
    h = ScanHistory.query.get_or_404(hid)
    result = h.to_dict()
    if h.summary_json:
        try:
            result['summary'] = json.loads(h.summary_json)
        except Exception:
            pass
    return jsonify(result)
