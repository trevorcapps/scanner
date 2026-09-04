"""Discovery scope CRUD, approval, and manual run."""

from flask import Blueprint, g, jsonify, request

from artemis.services import discovery_service as svc
from artemis.services.auth_service import role_required

discovery_bp = Blueprint('discovery', __name__)


def _uid():
    user = getattr(g, 'current_user', None)
    return user.id if user else None


@discovery_bp.route('/discovery-scopes', methods=['GET'])
def list_scopes():
    return jsonify({'scopes': [s.to_dict() for s in svc.list_scopes()]})


@discovery_bp.route('/discovery-scopes', methods=['POST'])
@role_required('analyst')
def create_scope():
    try:
        scope = svc.create_scope(request.get_json(silent=True) or {}, created_by=_uid())
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    return jsonify({'scope': scope.to_dict()}), 201


@discovery_bp.route('/discovery-scopes/<int:scope_id>', methods=['GET'])
def get_scope(scope_id):
    scope = svc.get_scope(scope_id)
    if not scope:
        return jsonify({'error': 'Not found'}), 404
    return jsonify({'scope': scope.to_dict()})


@discovery_bp.route('/discovery-scopes/<int:scope_id>/approve', methods=['POST'])
@role_required('admin')
def approve_scope(scope_id):
    approve = (request.get_json(silent=True) or {}).get('approve', True)
    scope = svc.approve_scope(scope_id, _uid(), approve=approve)
    if not scope:
        return jsonify({'error': 'Not found'}), 404
    return jsonify({'scope': scope.to_dict()})


@discovery_bp.route('/discovery-scopes/<int:scope_id>/run', methods=['POST'])
@role_required('analyst')
def run_scope(scope_id):
    from artemis.services.job_service import QueueDispatchError
    try:
        job = svc.dispatch_discovery(scope_id, requested_by=_uid())
    except PermissionError as exc:
        return jsonify({'error': str(exc)}), 403
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 404
    except QueueDispatchError as exc:
        return jsonify({'error': str(exc), 'job': exc.job.to_dict()}), 503
    resp = jsonify(job.to_dict())
    resp.status_code = 202
    resp.headers['Location'] = f'/api/v1/jobs/{job.id}'
    return resp
