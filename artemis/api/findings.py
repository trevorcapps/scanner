"""Canonical finding read + lifecycle API (P4.1)."""

from flask import Blueprint, jsonify, request

from artemis.services import finding_service
from artemis.services.auth_service import role_required
from artemis.services.tenant import scoped_get

findings_bp = Blueprint('findings', __name__)


@findings_bp.route('/findings', methods=['GET'])
def list_findings():
    """
    ---
    get:
      summary: Canonical findings for the active organization
      tags: [Findings]
      parameters:
        - {in: query, name: status, schema: {type: string}}
        - {in: query, name: severity, schema: {type: string}}
        - {in: query, name: kev, schema: {type: boolean}}
        - {in: query, name: ip, schema: {type: string}}
        - {in: query, name: limit, schema: {type: integer, default: 200}}
      responses:
        200: {description: A ranked list of finding occurrences}
      security: [{bearerAuth: []}]
    """
    rows = finding_service.list_findings(
        status=request.args.get('status') or None,
        severity=request.args.get('severity') or None,
        kev_only=request.args.get('kev') in ('1', 'true'),
        ip=request.args.get('ip') or None,
        limit=request.args.get('limit', 200, type=int),
    )
    return jsonify({'findings': [r.to_dict() for r in rows], 'count': len(rows)})


@findings_bp.route('/findings/<int:occ_id>', methods=['GET'])
def get_finding(occ_id):
    from artemis.models.finding import FindingOccurrence
    occ = scoped_get(FindingOccurrence, occ_id)
    if not occ:
        return jsonify({'error': 'Not found'}), 404
    data = occ.to_dict()
    data['observations'] = [o.to_dict() for o in
                            occ.observations.order_by(None).limit(200).all()]
    return jsonify({'finding': data})


@findings_bp.route('/findings/<int:occ_id>/status', methods=['PUT'])
@role_required('analyst')
def set_finding_status(occ_id):
    data = request.get_json(silent=True) or {}
    try:
        occ = finding_service.set_status(occ_id, data.get('status', ''),
                                         reason=data.get('reason'))
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    if not occ:
        return jsonify({'error': 'Not found'}), 404
    from artemis.services import audit_service
    audit_service.record('finding.status', target_type='finding', target_id=occ_id,
                         detail={'status': occ.status}, commit=True)
    return jsonify({'finding': occ.to_dict()})


@findings_bp.route('/findings/<int:occ_id>/remediation', methods=['GET'])
def finding_remediation(occ_id):
    """Informational remediation guidance (no credentials, no runnable payload)."""
    from artemis.services.remediation_service import build_guidance
    guidance = build_guidance(occ_id)
    if guidance is None:
        return jsonify({'error': 'Not found'}), 404
    return jsonify({'remediation': guidance})


@findings_bp.route('/findings/<int:occ_id>/priority', methods=['GET'])
def finding_priority(occ_id):
    """The priority score with every contributing factor exposed."""
    from artemis.models.finding import FindingOccurrence
    from artemis.services.intel_service import compute_priority
    occ = scoped_get(FindingOccurrence, occ_id)
    if not occ:
        return jsonify({'error': 'Not found'}), 404
    score, factors = compute_priority(occ)
    return jsonify({'occurrence_id': occ_id, 'score': score, 'factors': factors})


@findings_bp.route('/intel/sync', methods=['POST'])
@role_required('admin')
def sync_intel():
    """Trigger an EPSS + KEV + exploit-maturity refresh (async)."""
    from artemis.tasks.scan_tasks import sync_intel as task
    try:
        task.delay()
        return jsonify({'status': 'queued'}), 202
    except Exception:  # noqa: BLE001
        from artemis.services.intel_service import sync_all
        return jsonify({'result': sync_all(), 'mode': 'inline'})


@findings_bp.route('/intel/status', methods=['GET'])
def intel_status():
    from artemis.extensions import db
    from artemis.models.finding import VulnerabilityDefinition
    epss = db.session.query(db.func.count(), db.func.max(VulnerabilityDefinition.epss_model_date)).filter(
        VulnerabilityDefinition.epss_score.isnot(None)).one()
    kev = db.session.query(db.func.count()).filter(VulnerabilityDefinition.kev == 1).scalar()
    total = db.session.query(db.func.count()).select_from(VulnerabilityDefinition).scalar()
    return jsonify({
        'definitions': total,
        'epss': {'scored': epss[0], 'model_date': epss[1]},
        'kev_listed': kev,
    })


@findings_bp.route('/vulnerability-definitions/<path:def_id>', methods=['GET'])
def get_definition(def_id):
    from artemis.extensions import db
    from artemis.models.finding import VulnerabilityDefinition
    definition = db.session.get(VulnerabilityDefinition, def_id)
    if not definition:
        return jsonify({'error': 'Not found'}), 404
    return jsonify({'definition': definition.to_dict()})
