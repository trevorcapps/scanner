"""Agent service — process agent reports and manage agent lifecycle."""

import json
import logging
import secrets
from datetime import datetime, timedelta

from artemis.extensions import db
from artemis.models.agent import Agent
from artemis.models.agent_report import AgentReport

logger = logging.getLogger(__name__)


def generate_agent_key():
    """Generate a secure agent API key."""
    return secrets.token_urlsafe(32)


def register_agent(data):
    """Register a new agent. Returns the agent record with its key."""
    key = generate_agent_key()
    now = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    agent = Agent(
        agent_key=key,
        name=data.get('name', ''),
        hostname=data.get('hostname', ''),
        ip=data.get('ip', ''),
        os_info_json=json.dumps(data.get('os_info', {})) if data.get('os_info') else None,
        agent_version=data.get('agent_version', ''),
        checkin_interval=data.get('checkin_interval', 21600),
        status='active',
        created_at=now,
        last_checkin=now,
        enabled=1,
    )
    db.session.add(agent)
    db.session.commit()
    return agent


def process_report(agent, data):
    """Process and store an agent report."""
    now = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

    report = AgentReport(
        agent_id=agent.id,
        report_type=data.get('report_type', 'full'),
        report_json=json.dumps(data),
        packages_count=len(data.get('packages', [])),
        ports_count=len(data.get('ports', [])),
        received_at=now,
    )

    # Update agent info from report
    if data.get('hostname'):
        agent.hostname = data['hostname']
    if data.get('ip'):
        agent.ip = data['ip']
    if data.get('os_info'):
        agent.os_info_json = json.dumps(data['os_info'])
    if data.get('system_info'):
        agent.system_info_json = json.dumps(data['system_info'])
    if data.get('agent_version'):
        agent.agent_version = data['agent_version']

    agent.last_checkin = now
    agent.status = 'active'

    db.session.add(report)
    db.session.commit()

    # Try to link agent to existing asset by IP
    _link_agent_to_asset(agent)

    # Try to match packages against CVEs
    vulns_matched = _match_package_cves(agent, data.get('packages', []))
    if vulns_matched > 0:
        report.vulns_matched = vulns_matched
        db.session.commit()

    return report


def _link_agent_to_asset(agent):
    """Link agent to an existing asset record by IP address."""
    if not agent.ip:
        return
    try:
        from artemis.models.asset import Asset
        asset = Asset.query.filter_by(ip=agent.ip).first()
        if asset:
            logger.info(f"Agent {agent.id} linked to asset {asset.id} ({agent.ip})")
    except Exception:
        pass


def _match_package_cves(agent, packages):
    """Match installed packages against NVD local DB for known CVEs."""
    if not packages:
        return 0
    matched = 0
    try:
        from flask import current_app
        import sqlite3
        db_path = current_app.config['DB_PATH']
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        # Check if nvd_cves table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='nvd_cves'")
        if not cursor.fetchone():
            conn.close()
            return 0
        for pkg in packages:
            name = pkg.get('name', '').lower()
            version = pkg.get('version', '')
            if not name:
                continue
            cursor.execute(
                "SELECT COUNT(*) FROM nvd_cves WHERE LOWER(affected_product) LIKE ? AND affected_version = ?",
                (f'%{name}%', version)
            )
            count = cursor.fetchone()[0]
            matched += count
        conn.close()
    except Exception as e:
        logger.warning(f"CVE matching failed: {e}")
    return matched


def update_stale_agents():
    """Mark agents as stale if no checkin in 2x their interval."""
    now = datetime.utcnow()
    agents = Agent.query.filter(Agent.enabled == 1, Agent.status != 'offline').all()
    for agent in agents:
        if not agent.last_checkin:
            continue
        try:
            last = datetime.strptime(agent.last_checkin, '%Y-%m-%dT%H:%M:%SZ')
            threshold = timedelta(seconds=(agent.checkin_interval or 21600) * 2)
            if now - last > threshold:
                agent.status = 'stale'
        except Exception:
            pass
    db.session.commit()
