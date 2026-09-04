"""Agent-authenticated typed work channel (P5-D)."""

from flask import Blueprint, jsonify, request

from artemis.models.agent import Agent
from artemis.services.automation import agent_local

agent_work_bp = Blueprint('agent_work', __name__)


def _agent():
    key = request.headers.get('X-Agent-Key', '')
    return Agent.query.filter_by(agent_key=key, enabled=1).first() if key else None


@agent_work_bp.route('/agents/work/poll', methods=['GET'])
def poll():
    agent = _agent()
    if not agent:
        return jsonify({'error': 'Invalid or missing agent key'}), 401
    from artemis.services.tenant import use_organization
    with use_organization(agent.organization_id):
        return jsonify({'work': agent_local.poll_work(agent)})


@agent_work_bp.route('/agents/work/result', methods=['POST'])
def result():
    agent = _agent()
    if not agent:
        return jsonify({'error': 'Invalid or missing agent key'}), 401
    data = request.get_json(silent=True) or {}
    from artemis.services.tenant import use_organization
    with use_organization(agent.organization_id):
        work = agent_local.record_result(agent, data.get('work_id', ''), data)
    if not work:
        return jsonify({'error': 'work item not found'}), 404
    return jsonify({'work': work.to_dict()})


@agent_work_bp.route('/agents/work/<work_id>/state', methods=['GET'])
def state(work_id):
    """Allow a running agent job to observe server-side cancellation."""
    agent = _agent()
    if not agent:
        return jsonify({'error': 'Invalid or missing agent key'}), 401
    from artemis.services.tenant import use_organization
    with use_organization(agent.organization_id):
        work = agent_local.get_work(agent, work_id)
    if not work:
        return jsonify({'error': 'work item not found'}), 404
    return jsonify({'status': work.status})
