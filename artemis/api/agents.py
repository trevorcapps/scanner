"""Agents API blueprint — agent registration, reporting, and management."""

import json
import logging
from datetime import datetime

from flask import Blueprint, request, jsonify

from artemis.extensions import db
from artemis.models.agent import Agent
from artemis.models.agent_report import AgentReport
from artemis.services.agent_service import register_agent, process_report, generate_agent_key

logger = logging.getLogger(__name__)

agents_bp = Blueprint('agents', __name__)


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
    return jsonify([a.to_dict() for a in agents])


@agents_bp.route('/agents/<int:aid>', methods=['GET'])
def get_agent(aid):
    """Get agent details plus latest report."""
    agent = Agent.query.get_or_404(aid)
    result = agent.to_dict()
    latest = AgentReport.query.filter_by(agent_id=aid).order_by(AgentReport.id.desc()).first()
    if latest:
        result['latest_report'] = latest.to_dict()
    return jsonify(result)


@agents_bp.route('/agents/<int:aid>', methods=['DELETE'])
def delete_agent(aid):
    """Deregister an agent."""
    agent = Agent.query.get_or_404(aid)
    db.session.delete(agent)
    db.session.commit()
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
