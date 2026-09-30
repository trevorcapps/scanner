"""Agents API blueprint — agent registration, reporting, and management."""

import logging
import os

from flask import Blueprint, g, jsonify, request, send_file

from artemis.extensions import db
from artemis.models.agent import Agent
from artemis.models.agent_report import AgentReport
from artemis.services.agent_service import (
    aggregate_agent_telemetry,
    deregister_agent,
    generate_agent_key,
    process_report,
    register_agent,
    summarize_agent,
)
from artemis.services.auth_service import role_required
from artemis.services.agent_shell_service import (
    ShellSessionError,
    create_session,
    get_output,
    get_session,
    poll_agent,
    queue_input,
    record_agent_event,
    request_close,
    resize_session,
)

_AGENT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'agent')

logger = logging.getLogger(__name__)

agents_bp = Blueprint('agents', __name__)



@agents_bp.route('/install.sh', methods=['GET'])
def agent_install_script():
    """Serve the agent install shell script."""
    return send_file(os.path.join(_AGENT_DIR, 'install.sh'),
                     mimetype='text/plain', download_name='install.sh')


@agents_bp.route('/artemis_agent.py', methods=['GET'])
def agent_python_script():
    """Serve the lightweight agent used by the installer."""
    return send_file(os.path.join(_AGENT_DIR, 'artemis_agent.py'),
                     mimetype='text/x-python', download_name='artemis_agent.py')


@agents_bp.route('/requirements.lock', methods=['GET'])
def agent_requirements():
    """Pinned and hashed optional agent transport dependencies."""
    return send_file(os.path.join(_AGENT_DIR, 'requirements.lock'), mimetype='text/plain')


@agents_bp.route('/uninstall.sh', methods=['GET'])
def agent_uninstall_script():
    """Serve the agent uninstall shell script."""
    return send_file(os.path.join(_AGENT_DIR, 'uninstall.sh'),
                     mimetype='text/plain', download_name='uninstall.sh')



def _get_agent_by_key():
    """Authenticate agent via X-Agent-Key header."""
    key = request.headers.get('X-Agent-Key')
    if not key:
        return None
    return Agent.query.filter_by(agent_key=key, enabled=1).first()


@agents_bp.route('/agents/register', methods=['POST'])
def agent_register():
    """Register a new agent. Returns agent_key for future auth."""
    data = request.get_json(force=True)
    agent = register_agent(data)
    return jsonify({
        'agent_id': agent.id,
        'agent_key': agent.agent_key,
        'status': 'registered',
    }), 201


@agents_bp.route('/agents/deregister', methods=['POST'])
def agent_deregister():
    """Agent removes itself during uninstall. Authenticated via X-Agent-Key."""
    agent = _get_agent_by_key()
    if not agent:
        return jsonify({'error': 'Invalid or missing agent key'}), 401
    agent_id = deregister_agent(agent)
    return jsonify({'status': 'deregistered', 'id': agent_id})


@agents_bp.route('/agents/report', methods=['POST'])
def agent_report():
    """Agent submits a report. Authenticated via X-Agent-Key header."""
    agent = _get_agent_by_key()
    if not agent:
        return jsonify({'error': 'Invalid or missing agent key'}), 401

    data = request.get_json(force=True)
    report = process_report(agent, data)
    return jsonify({
        'report_id': report.id,
        'status': 'accepted',
        'vulns_matched': report.vulns_matched,
    })


@agents_bp.route('/agents/channel-token', methods=['POST'])
def agent_channel_token():
    """Exchange an enrollment identity for a five-minute channel credential.
    ---
    post:
      summary: Issue a short-lived agent channel credential
      security: [{agentKeyAuth: []}]
      responses:
        200:
          description: Five-minute credential; Cache-Control is no-store
          content:
            application/json:
              schema:
                type: object
                required: [token, agent_id, v, expires_in]
                properties:
                  token: {type: string}
                  agent_id: {type: integer}
                  v: {type: integer, enum: [1]}
                  expires_in: {type: integer, enum: [300]}
        401: {description: Invalid or missing enrollment identity}
        503: {description: Persistent channel disabled}
    """
    agent = _get_agent_by_key()
    if not agent:
        return jsonify({'error': 'Invalid or missing agent key'}), 401
    from flask import current_app
    if not current_app.config.get('AGENT_CHANNEL_ENABLED', True):
        return jsonify({'error': 'Persistent channel disabled'}), 503
    from artemis.services.agent_channel_service import issue_token
    response = jsonify({'token': issue_token(agent), 'agent_id': agent.id, 'v': 1, 'expires_in': 300})
    response.headers['Cache-Control'] = 'no-store'
    return response


@agents_bp.route('/agents/shell/poll', methods=['GET'])
def agent_shell_poll():
    """Agent-authenticated outbound poll for a pending PTY session."""
    agent = _get_agent_by_key()
    if not agent:
        return jsonify({'error': 'Invalid or missing agent key'}), 401
    import time
    from artemis.services.tenant import use_organization
    from flask import g
    g.organization_id = agent.organization_id
    from artemis.services.tenant import bind_rls_org
    bind_rls_org(agent.organization_id)
    wait = max(0, min(request.args.get('wait', 0, type=float), 20))
    deadline = time.monotonic() + wait
    with use_organization(agent.organization_id):
        while True:
            payload = poll_agent(agent, after=request.args.get('after', type=int),
                                 input_session=request.args.get('input_session'))
            if payload or time.monotonic() >= deadline:
                return jsonify({'session': payload})
            db.session.remove()
            from artemis.extensions import socketio
            socketio.sleep(0.1)


@agents_bp.route('/agents/shell/output', methods=['POST'])
def agent_shell_output():
    """Agent-authenticated PTY output and lifecycle events."""
    agent = _get_agent_by_key()
    if not agent:
        return jsonify({'error': 'Invalid or missing agent key'}), 401
    g.organization_id = agent.organization_id
    from artemis.services.tenant import bind_rls_org
    bind_rls_org(agent.organization_id)
    data = request.get_json(silent=True) or {}
    try:
        session = record_agent_event(
            agent,
            data.get('session_id', ''),
            data.get('event', ''),
            data_b64=data.get('data'),
            exit_code=data.get('exit_code'),
            error=data.get('error'),
            event_id=data.get('event_id'),
            input_ack=data.get('input_ack'),
        )
    except ShellSessionError as exc:
        return jsonify({'error': str(exc)}), 400
    return jsonify({'session': session.to_dict()})


def _owned_shell_session(session_id):
    user = getattr(g, 'current_user', None)
    return get_session(session_id, user_id=user.id) if user else None


@agents_bp.route('/agents/<int:aid>/shell-sessions', methods=['POST'])
@role_required('admin')
def create_agent_shell_session(aid):
    """Start an admin-owned remote PTY session on an active agent."""
    agent = db.get_or_404(Agent, aid)
    data = request.get_json(silent=True) or {}
    user = getattr(g, 'current_user', None)
    if user is None:
        return jsonify({'error': 'An authenticated administrator is required'}), 403
    try:
        session = create_session(
            agent,
            user_id=user.id if user else None,
            cols=data.get('cols', 120),
            rows=data.get('rows', 32),
        )
    except (ShellSessionError, TypeError, ValueError) as exc:
        return jsonify({'error': str(exc)}), 409
    from artemis.services import audit_service
    audit_service.record(
        audit_service.SHELL_OPEN, target_type='shell_session', target_id=session.id,
        detail={'agent_id': agent.id, 'agent': agent.hostname}, commit=True,
    )
    return jsonify({'session': session.to_dict()}), 201


@agents_bp.route('/agent-shell-sessions/<session_id>', methods=['GET'])
@role_required('admin')
def get_agent_shell_session(session_id):
    """Return lifecycle state for an operator-owned shell session."""
    session = _owned_shell_session(session_id)
    if not session:
        return jsonify({'error': 'Shell session not found'}), 404
    return jsonify({'session': session.to_dict()})


@agents_bp.route('/agent-shell-sessions/<session_id>/input', methods=['POST'])
@role_required('admin')
def input_agent_shell_session(session_id):
    """Queue a base64-encoded input chunk for the remote PTY."""
    session = _owned_shell_session(session_id)
    if not session:
        return jsonify({'error': 'Shell session not found'}), 404
    try:
        queue_input(session, (request.get_json(silent=True) or {}).get('data'))
    except ShellSessionError as exc:
        return jsonify({'error': str(exc)}), 400
    return jsonify({'accepted': True}), 202


@agents_bp.route('/agent-shell-sessions/<session_id>/resize', methods=['POST'])
@role_required('admin')
def resize_agent_shell_session(session_id):
    """Update the requested PTY dimensions."""
    session = _owned_shell_session(session_id)
    if not session:
        return jsonify({'error': 'Shell session not found'}), 404
    data = request.get_json(silent=True) or {}
    try:
        resize_session(session, data.get('cols'), data.get('rows'))
    except (ShellSessionError, TypeError, ValueError) as exc:
        return jsonify({'error': str(exc)}), 400
    return jsonify({'session': session.to_dict()})


@agents_bp.route('/agent-shell-sessions/<session_id>/output', methods=['GET'])
@role_required('admin')
def output_agent_shell_session(session_id):
    """Read ordered PTY output chunks after a global sequence ID."""
    session = _owned_shell_session(session_id)
    if not session:
        return jsonify({'error': 'Shell session not found'}), 404
    rows = get_output(
        session,
        after=request.args.get('after', 0, type=int),
        limit=request.args.get('limit', 200, type=int),
    )
    return jsonify({'output': rows, 'session': session.to_dict()})


@agents_bp.route('/agent-shell-sessions/<session_id>', methods=['DELETE'])
@role_required('admin')
def close_agent_shell_session(session_id):
    """Request cooperative PTY termination on the agent."""
    session = _owned_shell_session(session_id)
    if not session:
        return jsonify({'error': 'Shell session not found'}), 404
    closed = request_close(session)
    from artemis.services import audit_service
    audit_service.record(
        audit_service.SHELL_CLOSE, target_type='shell_session', target_id=session_id,
        detail={'agent_id': session.agent_id}, commit=True,
    )
    return jsonify({'session': closed.to_dict()}), 202


@agents_bp.route('/agents/fleet', methods=['GET'])
@role_required('analyst')
def fleet_view():
    """Fleet summary: rollout rings, versions, patch state, capability health."""
    agents = Agent.query.filter_by(enabled=1).all()
    rings = {}
    reboots = pending = 0
    for a in agents:
        rings[a.rollout_ring or 'stable'] = rings.get(a.rollout_ring or 'stable', 0) + 1
        if a.reboot_required == 'true':
            reboots += 1
        if isinstance(a.pending_updates, int):
            pending += a.pending_updates
    return jsonify({
        'agents': [a.to_dict() for a in agents],
        'summary': {
            'total': len(agents),
            'by_ring': rings,
            'reboot_required': reboots,
            'pending_updates_total': pending,
            'min_supported_version': _min_supported(),
            'target_version': _target_version(),
        },
    })


def _min_supported():
    from artemis.services.agent_service import MIN_SUPPORTED_AGENT
    return MIN_SUPPORTED_AGENT


def _target_version():
    from artemis.services.auth_scan_service import get_setting
    from artemis.services.agent_service import CURRENT_AGENT_VERSION
    return get_setting('agent_target_version', CURRENT_AGENT_VERSION) or CURRENT_AGENT_VERSION


@agents_bp.route('/agents/<int:aid>/rollout-ring', methods=['PUT'])
@role_required('admin')
def set_rollout_ring(aid):
    agent = db.get_or_404(Agent, aid)
    ring = (request.get_json(silent=True) or {}).get('ring')
    if ring not in ('canary', 'early', 'stable'):
        return jsonify({'error': 'ring must be canary, early, or stable'}), 400
    agent.rollout_ring = ring
    db.session.commit()
    from artemis.services import audit_service
    audit_service.record('agent.rollout_ring', target_type='agent', target_id=aid,
                         detail={'ring': ring}, commit=True)
    return jsonify({'agent': agent.to_dict()})


@agents_bp.route('/agents/target-version', methods=['PUT'])
@role_required('admin')
def set_target_version():
    from artemis.services.auth_scan_service import set_setting
    version = (request.get_json(silent=True) or {}).get('version', '').strip()
    if not version:
        return jsonify({'error': 'version is required'}), 400
    set_setting('agent_target_version', version)
    from artemis.services import audit_service
    audit_service.record('agent.target_version', target_type='setting',
                         target_id='agent_target_version', detail={'version': version}, commit=True)
    return jsonify({'target_version': version})


@agents_bp.route('/agents', methods=['GET'])
def list_agents():
    """List all registered agents with status."""
    # Update stale statuses
    from artemis.services.agent_service import update_stale_agents
    update_stale_agents()

    agents = Agent.query.order_by(Agent.id.desc()).all()
    result = []
    for agent in agents:
        latest = AgentReport.query.filter_by(agent_id=agent.id).order_by(AgentReport.id.desc()).first()
        result.append(summarize_agent(agent, latest))
    return jsonify(result)


@agents_bp.route('/agents/telemetry', methods=['GET'])
def agent_telemetry():
    """Return fleet-level telemetry from each agent's latest collection."""
    from artemis.services.agent_service import update_stale_agents
    update_stale_agents()
    agents = Agent.query.order_by(Agent.id.desc()).all()
    return jsonify(aggregate_agent_telemetry(agents))


@agents_bp.route('/agents/<int:aid>', methods=['GET'])
def get_agent(aid):
    """Get agent details plus latest report."""
    agent = Agent.query.get_or_404(aid)
    latest = AgentReport.query.filter_by(agent_id=aid).order_by(AgentReport.id.desc()).first()
    result = summarize_agent(agent, latest)
    if latest:
        result['latest_report'] = latest.to_dict()
    return jsonify(result)


@agents_bp.route('/agents/<int:aid>', methods=['DELETE'])
@role_required('admin')
def delete_agent(aid):
    """Deregister an agent from the console.

    This only removes the server-side record; the endpoint keeps reporting (and
    re-registers on next check-in) until ``uninstall.sh`` is run on the host.
    """
    agent = Agent.query.get_or_404(aid)
    deregister_agent(agent)
    return jsonify({'status': 'deleted', 'id': aid})


@agents_bp.route('/agents/<int:aid>/generate-key', methods=['POST'])
@role_required('admin')
def regenerate_key(aid):
    """Regenerate agent API key. Admin only — this is agent-key administration."""
    agent = Agent.query.get_or_404(aid)
    agent.agent_key = generate_agent_key()
    db.session.commit()
    from artemis.services import audit_service
    audit_service.record(
        audit_service.AGENT_KEY_ISSUE, target_type='agent', target_id=aid,
        detail={'agent': agent.hostname, 'rotated': True}, commit=True,
    )
    return jsonify({'agent_id': aid, 'agent_key': agent.agent_key})


@agents_bp.route('/agents/<int:aid>/reports', methods=['GET'])
def agent_reports(aid):
    """List report history for an agent."""
    Agent.query.get_or_404(aid)
    reports = AgentReport.query.filter_by(agent_id=aid).order_by(AgentReport.id.desc()).limit(50).all()
    return jsonify([r.to_dict() for r in reports])
