"""Agents API blueprint — agent registration, reporting, and management."""

import logging
import os

from flask import Blueprint, request, jsonify, send_file

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
    """Serve the dependency-free agent used by the installer."""
    return send_file(os.path.join(_AGENT_DIR, 'artemis_agent.py'),
                     mimetype='text/x-python', download_name='artemis_agent.py')


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
def delete_agent(aid):
    """Deregister an agent from the console.

    This only removes the server-side record; the endpoint keeps reporting (and
    re-registers on next check-in) until ``uninstall.sh`` is run on the host.
    """
    agent = Agent.query.get_or_404(aid)
    deregister_agent(agent)
    return jsonify({'status': 'deleted', 'id': aid})


@agents_bp.route('/agents/<int:aid>/generate-key', methods=['POST'])
def regenerate_key(aid):
    """Regenerate agent API key."""
    agent = Agent.query.get_or_404(aid)
    agent.agent_key = generate_agent_key()
    db.session.commit()
    return jsonify({'agent_id': aid, 'agent_key': agent.agent_key})


@agents_bp.route('/agents/<int:aid>/reports', methods=['GET'])
def agent_reports(aid):
    """List report history for an agent."""
    Agent.query.get_or_404(aid)
    reports = AgentReport.query.filter_by(agent_id=aid).order_by(AgentReport.id.desc()).limit(50).all()
    return jsonify([r.to_dict() for r in reports])
