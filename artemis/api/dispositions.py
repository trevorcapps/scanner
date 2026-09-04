"""Disposition + suppression-rule + effective-risk API (P4.4)."""

from flask import Blueprint, g, jsonify, request

from artemis.services import disposition_service as svc
from artemis.services.auth_service import role_required
from artemis.services.tenant import scoped, scoped_get

dispositions_bp = Blueprint('dispositions', __name__)


def _uid():
    user = getattr(g, 'current_user', None)
    return user.id if user else None


@dispositions_bp.route('/dispositions', methods=['GET'])
def list_dispositions():
    from artemis.models.disposition import Disposition
    q = scoped(Disposition)
    if request.args.get('status'):
        q = q.filter(Disposition.status == request.args['status'])
    return jsonify({'dispositions': [d.to_dict() for d in
                                     q.order_by(Disposition.created_at.desc()).limit(500).all()]})


@dispositions_bp.route('/dispositions', methods=['POST'])
@role_required('analyst')
def create_disposition():
    try:
        disp = svc.create_disposition(request.get_json(silent=True) or {}, requested_by=_uid())
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    return jsonify({'disposition': disp.to_dict()}), 201


@dispositions_bp.route('/dispositions/<int:disp_id>/decision', methods=['POST'])
@role_required('admin')
def decide_disposition(disp_id):
    approve = (request.get_json(silent=True) or {}).get('approve', True)
    disp = svc.decide(disp_id, approve, _uid())
    if not disp:
        return jsonify({'error': 'Not found or not pending'}), 404
    return jsonify({'disposition': disp.to_dict()})


@dispositions_bp.route('/dispositions/bulk', methods=['POST'])
@role_required('analyst')
def bulk_disposition():
    data = request.get_json(silent=True) or {}
    ids = data.get('occurrence_ids') or []
    created = []
    for occ_id in ids:
        try:
            disp = svc.create_disposition({**data, 'scope': 'occurrence', 'target_id': occ_id},
                                          requested_by=_uid())
            created.append(disp.id)
        except ValueError:
            continue
    return jsonify({'created': created})


@dispositions_bp.route('/suppression-rules', methods=['GET'])
def list_rules():
    from artemis.models.disposition import SuppressionRule
    return jsonify({'rules': [r.to_dict() for r in scoped(SuppressionRule)
                              .order_by(SuppressionRule.created_at.desc()).all()]})


@dispositions_bp.route('/suppression-rules', methods=['POST'])
@role_required('analyst')
def create_rule():
    from artemis.extensions import db
    from artemis.models.disposition import SuppressionRule
    data = request.get_json(silent=True) or {}
    if not (data.get('name') or '').strip():
        return jsonify({'error': 'name is required'}), 400
    rule = SuppressionRule(
        name=data['name'].strip(), definition_id=data.get('definition_id'),
        fingerprint=data.get('fingerprint'), ip_pattern=data.get('ip_pattern'),
        component_pattern=data.get('component_pattern'), reason=data.get('reason'),
        enabled=1, created_by=_uid(), created_at=svc._now(), expires_at=data.get('expires_at'),
    )
    db.session.add(rule)
    db.session.commit()
    return jsonify({'rule': rule.to_dict()}), 201


@dispositions_bp.route('/suppression-rules/<int:rule_id>', methods=['DELETE'])
@role_required('analyst')
def delete_rule(rule_id):
    from artemis.extensions import db
    from artemis.models.disposition import SuppressionRule
    rule = scoped_get(SuppressionRule, rule_id)
    if not rule:
        return jsonify({'error': 'Not found'}), 404
    db.session.delete(rule)
    db.session.commit()
    return jsonify({'status': 'deleted'})


@dispositions_bp.route('/findings/effective-risk', methods=['GET'])
def effective_risk():
    return jsonify(svc.effective_risk())
