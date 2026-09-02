"""Agent service — process agent reports and manage agent lifecycle."""

import json
import logging
import secrets
from datetime import datetime, timedelta

from artemis.extensions import db
from artemis.models.agent import Agent
from artemis.models.agent_report import AgentReport

logger = logging.getLogger(__name__)


def _report_payload(report):
    if not report or not report.report_json:
        return {}
    try:
        return json.loads(report.report_json)
    except (TypeError, ValueError):
        return {}


def summarize_agent(agent, latest_report=None):
    """Return the stable UI contract for an agent without exposing its key."""
    result = agent.to_dict()
    payload = _report_payload(latest_report)
    performance = payload.get('performance', {})
    processes = payload.get('processes', {})
    network = payload.get('network', {})
    telemetry = payload.get('telemetry', {})
    collectors = telemetry.get('collectors', {})
    result.update({
        'package_count': latest_report.packages_count if latest_report else 0,
        'port_count': latest_report.ports_count if latest_report else 0,
        'vulns_matched': latest_report.vulns_matched if latest_report else 0,
        'latest_report_at': latest_report.received_at if latest_report else None,
        'telemetry': {
            'schema_version': payload.get('telemetry_schema_version', 1),
            'collection_ms': telemetry.get('duration_ms'),
            'cpu_percent': performance.get('cpu', {}).get('usage_percent'),
            'memory_percent': performance.get('memory', {}).get('used_percent'),
            'process_count': processes.get('total'),
            'thread_count': processes.get('threads'),
            'established_connections': network.get('sockets', {}).get('tcp_established'),
            'collector_count': len(collectors),
            'degraded_collectors': sum(
                1 for value in collectors.values()
                if isinstance(value, dict) and value.get('status') != 'ok'
            ),
        },
    })
    return result


def aggregate_agent_telemetry(agents):
    """Aggregate the latest reports into fleet-level collection telemetry."""
    cutoff = datetime.utcnow() - timedelta(hours=24)
    summaries = []
    for agent in agents:
        latest = AgentReport.query.filter_by(agent_id=agent.id).order_by(AgentReport.id.desc()).first()
        summaries.append(summarize_agent(agent, latest))
    reports_24h = AgentReport.query.filter(
        AgentReport.received_at >= cutoff.strftime('%Y-%m-%dT%H:%M:%SZ')
    ).count()

    def average(field):
        values = [item['telemetry'].get(field) for item in summaries]
        values = [float(value) for value in values if isinstance(value, (int, float))]
        return round(sum(values) / len(values), 1) if values else None

    statuses = {'active': 0, 'stale': 0, 'offline': 0}
    for item in summaries:
        status = item.get('status') or 'offline'
        statuses[status] = statuses.get(status, 0) + 1
    return {
        'agents_total': len(summaries),
        'statuses': statuses,
        'reports_24h': reports_24h,
        'packages_observed': sum(item.get('package_count', 0) for item in summaries),
        'ports_observed': sum(item.get('port_count', 0) for item in summaries),
        'average_cpu_percent': average('cpu_percent'),
        'average_memory_percent': average('memory_percent'),
        'average_collection_ms': average('collection_ms'),
        'degraded_collectors': sum(item['telemetry'].get('degraded_collectors', 0) for item in summaries),
        'latest_report_at': max(
            (item['latest_report_at'] for item in summaries if item.get('latest_report_at')),
            default=None,
        ),
        'agents': summaries,
    }


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
        packages_count=data.get('package_count', len(data.get('packages', []))),
        ports_count=len(data.get('ports', [])),
        received_at=now,
    )

    # Update agent info from report
    if data.get('hostname'):
        agent.hostname = data['hostname']
    if data.get('ip'):
        agent.ip = data['ip']
    if data.get('mac_address'):
        agent.mac_address = data.get('mac_address', '')
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

    # Create/update asset from agent data
    _sync_agent_to_asset(agent, data)

    # Try to match packages against CVEs
    vulns_matched = _match_package_cves(agent, data.get('packages', []))
    if vulns_matched > 0:
        report.vulns_matched = vulns_matched
        db.session.commit()

    return report


def _sync_agent_to_asset(agent, data):
    """Create or update an asset record from agent report data."""
    if not agent.ip:
        return
    try:
        from artemis.services.asset_service import store_asset_info
        from artemis.services.scan_service import store_scan_from_agent

        os_info = data.get('os_info', {})
        if isinstance(os_info, str):
            os_info = {'os_name': os_info}

        system_info = data.get('system_info', {})

        # Map agent os_info to the format store_asset_info expects
        asset_os = {
            'os_name': os_info.get('os_name', ''),
            'os_family': os_info.get('os_family', ''),
            'os_vendor': os_info.get('os_vendor', ''),
            'os_accuracy': '100',  # Agent-reported = definitive
            'device_type': 'computer',
        }

        dns_info = {
            'hostname': agent.hostname or data.get('hostname', ''),
            'reverse_dns': None,
            'aliases': [],
        }

        mac_address = data.get('mac_address', '')
        store_asset_info(agent.ip, dns_info=dns_info, os_info=asset_os,
                         mac_address=mac_address, mac_vendor=None)

        # Store listening ports as scan data so they show in asset details
        ports = data.get('ports', [])
        if ports:
            store_scan_from_agent(agent.ip, ports)

        # Store packages and system info for asset detail view
        _store_agent_system_data(agent.ip, data)

        logger.info(f"Agent {agent.id} synced to asset ({agent.ip})")
    except Exception as e:
        logger.warning(f"Failed to sync agent {agent.id} to asset: {e}")


def _store_agent_system_data(ip, data):
    """Store agent-reported packages and system info in the DB for asset detail view."""
    try:
        import sqlite3
        from flask import current_app
        db_path = current_app.config['DB_PATH']
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Create agent_data table if not exists
        cursor.execute('''CREATE TABLE IF NOT EXISTS agent_data (
            ip TEXT PRIMARY KEY,
            packages_json TEXT,
            package_count INTEGER DEFAULT 0,
            system_info_json TEXT,
            os_info_json TEXT,
            updated_at TEXT
        )''')

        now = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        packages = data.get('packages', [])
        pkg_count = data.get('package_count', len(packages))
        system_info = data.get('system_info', {})
        os_info = data.get('os_info', {})

        cursor.execute('''INSERT OR REPLACE INTO agent_data
            (ip, packages_json, package_count, system_info_json, os_info_json, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)''',
            (ip, json.dumps(packages), pkg_count, json.dumps(system_info),
             json.dumps(os_info), now))

        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Failed to store agent system data for {ip}: {e}")


def _match_package_cves(agent, packages):
    """Return matches only when package data has been normalized to CPEs.

    Distribution package names are not reliable CPE product identifiers. The
    authenticated scan pipeline performs CPE-aware matching; agent inventory is
    retained as evidence until that same normalization is available here.
    """
    return 0


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
