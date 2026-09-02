"""Sites API blueprint — manage scan sites (collections of targets)."""

import json
import logging
from datetime import datetime

from flask import Blueprint, request, jsonify, g

from artemis.extensions import db
from artemis.models.site import Site
from artemis.models.site_scan import SiteScan
from artemis.services.site_service import resolve_site_targets
from artemis.services.job_service import QueueDispatchError, dispatch_site_scan
from artemis.services.scheduler_service import calculate_next_run_for_site

logger = logging.getLogger(__name__)

sites_bp = Blueprint('sites', __name__)


def _now_iso():
    return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')


@sites_bp.route('/sites', methods=['GET'])
def list_sites():
    """List all sites with summary stats."""
    sites = Site.query.order_by(Site.id.desc()).all()
    results = []
    for s in sites:
        d = s.to_dict()
        # Attach latest scan summary
        latest = SiteScan.query.filter_by(site_id=s.id).order_by(SiteScan.id.desc()).first()
        d['latest_scan'] = latest.to_dict() if latest else None
        d['scan_count'] = SiteScan.query.filter_by(site_id=s.id).count()
        results.append(d)
    return jsonify(results)


@sites_bp.route('/sites', methods=['POST'])
def create_site():
    """Create a new site."""
    data = request.get_json(force=True)
    now = _now_iso()

    if not data.get('name'):
        return jsonify({'error': 'Site name is required'}), 400
    if not data.get('targets'):
        return jsonify({'error': 'At least one target is required'}), 400

    site = Site(
        name=data['name'],
        description=data.get('description', ''),
        targets_json=json.dumps(data['targets']),
        excluded_targets_json=json.dumps(data.get('excluded_targets', [])),
        scan_type=data.get('scan_type', 'full'),
        profile_id=data.get('profile_id'),
        scan_options_json=json.dumps(data['scan_options']) if data.get('scan_options') else None,
        credential_ids_json=json.dumps(data['credential_ids']) if data.get('credential_ids') else None,
        schedule_enabled=data.get('schedule_enabled', 1),
        schedule_type=data.get('schedule_type', 'daily'),
        cron_expression=data.get('cron_expression'),
        schedule_hour=data.get('schedule_hour', 2),
        schedule_minute=data.get('schedule_minute', 0),
        schedule_day_of_week=data.get('schedule_day_of_week'),
        schedule_day_of_month=data.get('schedule_day_of_month'),
        notify_on_complete=data.get('notify_on_complete', 0),
        notify_on_new_vulns=data.get('notify_on_new_vulns', 1),
        compare_with_previous=data.get('compare_with_previous', 1),
        created_at=now,
        updated_at=now,
    )

    site.next_run = calculate_next_run_for_site(site)

    db.session.add(site)
    db.session.commit()

    result = site.to_dict()
    result['resolved_targets'] = resolve_site_targets(site)
    result['resolved_target_count'] = len(result['resolved_targets'])
    return jsonify(result), 201


@sites_bp.route('/sites/<int:site_id>', methods=['GET'])
def get_site(site_id):
    """Get site details with resolved targets and scan history."""
    site = Site.query.get_or_404(site_id)
    result = site.to_dict()
    result['resolved_targets'] = resolve_site_targets(site)
    result['resolved_target_count'] = len(result['resolved_targets'])

    # Recent scans
    scans = SiteScan.query.filter_by(site_id=site_id).order_by(SiteScan.id.desc()).limit(20).all()
    result['recent_scans'] = [s.to_dict() for s in scans]
    result['scan_count'] = SiteScan.query.filter_by(site_id=site_id).count()
    return jsonify(result)


@sites_bp.route('/sites/<int:site_id>', methods=['PUT'])
def update_site(site_id):
    """Update a site."""
    site = Site.query.get_or_404(site_id)
    data = request.get_json(force=True)

    for field in ('name', 'description', 'scan_type', 'profile_id',
                  'schedule_enabled', 'schedule_type', 'cron_expression',
                  'schedule_hour', 'schedule_minute', 'schedule_day_of_week',
                  'schedule_day_of_month', 'notify_on_complete',
                  'notify_on_new_vulns', 'compare_with_previous'):
        if field in data:
            setattr(site, field, data[field])

    if 'targets' in data:
        site.targets_json = json.dumps(data['targets'])
    if 'excluded_targets' in data:
        site.excluded_targets_json = json.dumps(data['excluded_targets'])
    if 'scan_options' in data:
        site.scan_options_json = json.dumps(data['scan_options']) if data['scan_options'] else None
    if 'credential_ids' in data:
        site.credential_ids_json = json.dumps(data['credential_ids']) if data['credential_ids'] else None

    site.next_run = calculate_next_run_for_site(site)
    site.updated_at = _now_iso()
    db.session.commit()
    return jsonify(site.to_dict())


@sites_bp.route('/sites/<int:site_id>', methods=['DELETE'])
def delete_site(site_id):
    """Delete a site and its scan history."""
    site = Site.query.get_or_404(site_id)
    SiteScan.query.filter_by(site_id=site_id).delete()
    db.session.delete(site)
    db.session.commit()
    return jsonify({'status': 'deleted', 'id': site_id})


@sites_bp.route('/sites/<int:site_id>/scan', methods=['POST'])
def trigger_site_scan(site_id):
    """Persist and enqueue an immediate site scan."""
    site = Site.query.get_or_404(site_id)

    if site.last_status in ('queued', 'running'):
        return jsonify({'error': 'Site scan already queued or running'}), 409

    requested_by = getattr(getattr(g, 'current_user', None), 'id', None)
    targets = resolve_site_targets(site)
    try:
        job = dispatch_site_scan(site, requested_by=requested_by)
    except QueueDispatchError as exc:
        return jsonify({'error': str(exc), 'job': exc.job.to_dict()}), 503

    return jsonify({
        'status': job.status,
        'job': job.to_dict(),
        'site_id': site_id,
        'targets': targets,
        'target_count': len(targets),
    }), 202


@sites_bp.route('/sites/<int:site_id>/toggle', methods=['POST'])
def toggle_site(site_id):
    """Enable or disable site scheduling."""
    site = Site.query.get_or_404(site_id)
    site.schedule_enabled = 0 if site.schedule_enabled else 1
    if site.schedule_enabled:
        site.next_run = calculate_next_run_for_site(site)
    site.updated_at = _now_iso()
    db.session.commit()
    return jsonify({'status': 'enabled' if site.schedule_enabled else 'disabled', 'id': site_id})


@sites_bp.route('/sites/<int:site_id>/targets', methods=['POST'])
def add_targets(site_id):
    """Add targets to a site."""
    site = Site.query.get_or_404(site_id)
    data = request.get_json(force=True)
    new_targets = data.get('targets', [])
    if not new_targets:
        return jsonify({'error': 'targets list required'}), 400

    current = site.targets
    added = [t for t in new_targets if t not in current]
    site.targets = current + added
    site.updated_at = _now_iso()
    db.session.commit()
    return jsonify({'added': added, 'total_targets': len(site.targets)})


@sites_bp.route('/sites/<int:site_id>/targets', methods=['DELETE'])
def remove_targets(site_id):
    """Remove targets from a site."""
    site = Site.query.get_or_404(site_id)
    data = request.get_json(force=True)
    to_remove = set(data.get('targets', []))
    if not to_remove:
        return jsonify({'error': 'targets list required'}), 400

    site.targets = [t for t in site.targets if t not in to_remove]
    site.updated_at = _now_iso()
    db.session.commit()
    return jsonify({'removed': list(to_remove), 'total_targets': len(site.targets)})


@sites_bp.route('/sites/<int:site_id>/scans', methods=['GET'])
def list_site_scans(site_id):
    """List scan history for a site."""
    Site.query.get_or_404(site_id)
    scans = SiteScan.query.filter_by(site_id=site_id).order_by(SiteScan.id.desc()).limit(50).all()
    return jsonify([s.to_dict() for s in scans])


@sites_bp.route('/sites/<int:site_id>/scans/<int:scan_id>', methods=['GET'])
def get_site_scan(site_id, scan_id):
    """Get detailed results for a specific site scan."""
    scan = SiteScan.query.filter_by(id=scan_id, site_id=site_id).first_or_404()
    return jsonify(scan.to_dict())
