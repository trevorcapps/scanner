"""Ad-hoc automation run + content + execution-environment API (P5-C).

Start with POST /automation/runs (multipart or pasted content). Reuse the
shared /jobs endpoints for status / events / cancel — there is no approval
endpoint (D9).
"""

from flask import Blueprint, g, jsonify, request

from artemis.services.auth_service import role_required

automation_bp = Blueprint('automation', __name__)


def _uid():
    user = getattr(g, 'current_user', None)
    return user.id if user else None


@automation_bp.route('/automation/executor', methods=['GET'])
def executor_status():
    from artemis.services.automation.executor import get_executor
    ex = get_executor()
    return jsonify({'executor': ex.name, 'available': ex.available()})


@automation_bp.route('/automation/runs', methods=['POST'])
@role_required('analyst')
def create_run():
    from artemis.services.automation.content_service import ContentError
    from artemis.services.automation.run_service import launch_run

    if request.content_type and 'multipart/form-data' in request.content_type:
        upload = request.files.get('content')
        if not upload:
            return jsonify({'error': 'multipart field "content" is required'}), 400
        raw = upload.read()
        kind = 'bundle' if (upload.filename or '').endswith(('.zip', '.tar', '.tar.gz', '.tgz')) else 'playbook'
        form = request.form
        targets = _json_field(form.get('targets'))
        variables = _json_field(form.get('variables'))
        credential_refs = _json_field(form.get('credential_refs'), [])
        check_mode = form.get('check_mode') in ('1', 'true')
        filename = upload.filename
    else:
        data = request.get_json(silent=True) or {}
        raw = data.get('content')
        if not raw:
            return jsonify({'error': '"content" (pasted playbook) is required'}), 400
        kind = data.get('kind', 'playbook')
        targets = data.get('targets') or {}
        variables = data.get('variables') or {}
        credential_refs = data.get('credential_refs') or []
        check_mode = bool(data.get('check_mode'))
        filename = data.get('filename')

    try:
        run, job = launch_run(
            content_raw=raw, content_kind=kind, filename=filename, targets=targets,
            variables=variables, credential_refs=credential_refs,
            execution_environment_id=(request.form.get('execution_environment_id')
                                      if request.form else None),
            check_mode=check_mode,
            serial=_int_or_none((request.form or request.get_json(silent=True) or {}).get('serial')),
            max_fail_percentage=_int_or_none(
                (request.form or request.get_json(silent=True) or {}).get('max_fail_percentage')),
            launched_by=_uid(),
        )
    except (ContentError, ValueError) as exc:
        return jsonify({'error': str(exc)}), 400

    body = {'run': run.to_dict(), 'job': job.to_dict()}
    resp = jsonify(body)
    resp.status_code = 202
    resp.headers['Location'] = f'/api/v1/jobs/{job.id}'
    return resp


@automation_bp.route('/automation/runs', methods=['GET'])
def list_runs():
    from artemis.models.automation import AutomationRun
    from artemis.services.tenant import scoped
    rows = scoped(AutomationRun).order_by(AutomationRun.created_at.desc()).limit(200).all()
    return jsonify({'runs': [r.to_dict() for r in rows]})


@automation_bp.route('/automation/runs/<int:run_id>', methods=['GET'])
def get_run(run_id):
    from artemis.models.automation import AutomationRun
    from artemis.services.tenant import scoped_get
    run = scoped_get(AutomationRun, run_id)
    if not run:
        return jsonify({'error': 'Not found'}), 404
    return jsonify({'run': run.to_dict()})


@automation_bp.route('/automation/content/<int:content_id>', methods=['GET'])
def get_content(content_id):
    from artemis.models.automation import AutomationContent
    from artemis.services.tenant import scoped_get
    content = scoped_get(AutomationContent, content_id)
    if not content:
        return jsonify({'error': 'Not found'}), 404
    return jsonify({'content': content.to_dict()})   # metadata only, never the body


@automation_bp.route('/automation/starters', methods=['GET'])
def list_starters():
    from artemis.services.automation.starters import list_starters as _list
    return jsonify({'starters': _list()})


@automation_bp.route('/automation/campaigns', methods=['GET'])
def list_campaigns():
    from artemis.models.campaign import PatchCampaign
    from artemis.services.tenant import scoped
    rows = scoped(PatchCampaign).order_by(PatchCampaign.created_at.desc()).limit(100).all()
    return jsonify({'campaigns': [c.to_dict() for c in rows]})


@automation_bp.route('/automation/campaigns', methods=['POST'])
@role_required('analyst')
def create_campaign():
    from artemis.services.automation.campaign_service import create_campaign as _create
    try:
        campaign = _create(request.get_json(silent=True) or {}, created_by=_uid())
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    return jsonify({'campaign': campaign.to_dict()}), 201


@automation_bp.route('/automation/campaigns/<int:cid>', methods=['GET'])
def get_campaign(cid):
    from artemis.models.campaign import PatchCampaign
    from artemis.services.tenant import scoped_get
    campaign = scoped_get(PatchCampaign, cid)
    if not campaign:
        return jsonify({'error': 'Not found'}), 404
    return jsonify({'campaign': campaign.to_dict()})


@automation_bp.route('/automation/campaigns/<int:cid>/<action>', methods=['POST'])
@role_required('analyst')
def campaign_action(cid, action):
    from artemis.services.automation import campaign_service
    fn = {'preview': campaign_service.preview, 'start': campaign_service.start,
          'advance': campaign_service.advance, 'cancel': campaign_service.cancel}.get(action)
    if not fn:
        return jsonify({'error': 'unknown action'}), 400
    result = fn(cid)
    if result is None:
        return jsonify({'error': 'Not found or invalid state'}), 404
    return jsonify({'result': result.to_dict()})


@automation_bp.route('/automation/execution-environments', methods=['GET'])
def list_envs():
    from artemis.services.automation.run_service import list_environments
    return jsonify({'environments': [e.to_dict() for e in list_environments()]})


@automation_bp.route('/automation/execution-environments', methods=['POST'])
@role_required('admin')
def create_env():
    from artemis.services.automation.run_service import create_environment
    data = request.get_json(silent=True) or {}
    if not data.get('image'):
        return jsonify({'error': 'image is required'}), 400
    env = create_environment(data, created_by=_uid())
    return jsonify({'environment': env.to_dict()}), 201


def _json_field(value, default=None):
    import json
    if not value:
        return default if default is not None else {}
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default if default is not None else {}


def _int_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
