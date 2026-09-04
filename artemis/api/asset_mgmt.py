"""Asset lifecycle, business context, tags, groups, and bulk operations (P3.1)."""

from flask import Blueprint, g, jsonify, request

from artemis.services import asset_lifecycle_service as svc
from artemis.services.auth_service import role_required

asset_mgmt_bp = Blueprint('asset_mgmt', __name__)


def _uid():
    user = getattr(g, 'current_user', None)
    return user.id if user else None


@asset_mgmt_bp.route('/assets/<int:asset_id>/context', methods=['PUT'])
@role_required('analyst')
def set_context(asset_id):
    try:
        asset = svc.update_business_context(asset_id, request.get_json(silent=True) or {})
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    if not asset:
        return jsonify({'error': 'Not found'}), 404
    return jsonify({'asset': asset.to_dict()})


@asset_mgmt_bp.route('/assets/<int:asset_id>/decommission', methods=['POST'])
@role_required('analyst')
def decommission(asset_id):
    data = request.get_json(silent=True) or {}
    asset = svc.decommission(asset_id, data.get('reason', ''), actor_id=_uid())
    if not asset:
        return jsonify({'error': 'Not found'}), 404
    return jsonify({'asset': asset.to_dict()})


@asset_mgmt_bp.route('/assets/<int:asset_id>/reactivate', methods=['POST'])
@role_required('analyst')
def reactivate(asset_id):
    asset = svc.reactivate(asset_id)
    if not asset:
        return jsonify({'error': 'Not found'}), 404
    return jsonify({'asset': asset.to_dict()})


@asset_mgmt_bp.route('/assets/bulk', methods=['POST'])
@role_required('analyst')
def bulk():
    data = request.get_json(silent=True) or {}
    op = data.get('op')
    ids = data.get('asset_ids') or []
    if op not in ('tag', 'untag', 'set_context', 'decommission', 'add_to_group', 'remove_from_group'):
        return jsonify({'error': 'unknown op'}), 400
    if not ids:
        return jsonify({'error': 'asset_ids is required'}), 400
    try:
        touched = svc.bulk_operation(op, ids, tag=data.get('tag'), context=data.get('context'),
                                     reason=data.get('reason'), group_id=data.get('group_id'))
    except (KeyError, ValueError) as exc:
        return jsonify({'error': f'missing/invalid argument: {exc}'}), 400
    return jsonify({'updated': touched})


# ---- tags ----------------------------------------------------------------
@asset_mgmt_bp.route('/asset-tags', methods=['GET'])
def list_tags():
    return jsonify({'tags': [t.to_dict() for t in svc.list_tags()]})


@asset_mgmt_bp.route('/asset-tags', methods=['POST'])
@role_required('analyst')
def create_tag():
    data = request.get_json(silent=True) or {}
    if not (data.get('name') or '').strip():
        return jsonify({'error': 'name is required'}), 400
    from artemis.extensions import db
    tag = svc.get_or_create_tag(data['name'], color=data.get('color'))
    db.session.commit()
    return jsonify({'tag': tag.to_dict()}), 201


@asset_mgmt_bp.route('/assets/<int:asset_id>/tags', methods=['POST'])
@role_required('analyst')
def tag_asset(asset_id):
    name = (request.get_json(silent=True) or {}).get('name', '')
    if not name.strip():
        return jsonify({'error': 'name is required'}), 400
    if svc.add_tag(asset_id, name) is None:
        return jsonify({'error': 'Not found'}), 404
    return jsonify({'status': 'tagged'})


@asset_mgmt_bp.route('/assets/<int:asset_id>/tags/<name>', methods=['DELETE'])
@role_required('analyst')
def untag_asset(asset_id, name):
    svc.remove_tag(asset_id, name)
    return jsonify({'status': 'untagged'})


# ---- groups -------------------------------------------------------------
@asset_mgmt_bp.route('/asset-groups', methods=['GET'])
def list_groups():
    out = []
    for grp in svc.list_groups():
        out.append(grp.to_dict(member_count=len(svc.group_members(grp.id))))
    return jsonify({'groups': out})


@asset_mgmt_bp.route('/asset-groups', methods=['POST'])
@role_required('analyst')
def create_group():
    data = request.get_json(silent=True) or {}
    if not (data.get('name') or '').strip():
        return jsonify({'error': 'name is required'}), 400
    try:
        grp = svc.create_group(data['name'], kind=data.get('kind', 'static'),
                               description=data.get('description'),
                               filter_spec=data.get('filter'), created_by=_uid())
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    return jsonify({'group': grp.to_dict()}), 201


@asset_mgmt_bp.route('/asset-groups/<int:group_id>/members', methods=['GET'])
def group_members(group_id):
    return jsonify({'assets': [a.to_dict() for a in svc.group_members(group_id)]})


@asset_mgmt_bp.route('/asset-groups/<int:group_id>/members/<int:asset_id>', methods=['POST'])
@role_required('analyst')
def add_member(group_id, asset_id):
    if svc.add_to_group(group_id, asset_id) is None:
        return jsonify({'error': 'Not found or not a static group'}), 404
    return jsonify({'status': 'added'})


@asset_mgmt_bp.route('/asset-groups/<int:group_id>/members/<int:asset_id>', methods=['DELETE'])
@role_required('analyst')
def remove_member(group_id, asset_id):
    svc.remove_from_group(group_id, asset_id)
    return jsonify({'status': 'removed'})


@asset_mgmt_bp.route('/assets/<int:asset_id>/timeline', methods=['GET'])
def asset_timeline(asset_id):
    from artemis.services import inventory_service
    kinds = request.args.get('kinds', '').split(',') if request.args.get('kinds') else None
    limit = min(max(request.args.get('limit', 200, type=int), 1), 1000)
    events = inventory_service.asset_timeline(asset_id, limit=limit, kinds=kinds)
    return jsonify({'events': [e.to_dict() for e in events]})


@asset_mgmt_bp.route('/assets/<int:asset_id>/software-history', methods=['GET'])
def software_history(asset_id):
    from artemis.services import inventory_service
    rows = inventory_service.software_history(asset_id, package_name=request.args.get('package'))
    return jsonify({'observations': [o.to_dict() for o in rows]})


@asset_mgmt_bp.route('/asset-review-events', methods=['GET'])
def review_events():
    unresolved = request.args.get('all') not in ('1', 'true')
    return jsonify({'events': [e.to_dict() for e in svc.list_review_events(unresolved_only=unresolved)]})
