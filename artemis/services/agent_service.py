"""Agent service — process agent reports and manage agent lifecycle."""

import json
import logging
import secrets
from datetime import datetime, timedelta, timezone

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
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
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
    now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    agent = Agent(
        agent_key=key,
        name=data.get('name', ''),
        hostname=data.get('hostname', ''),
        ip=data.get('ip', ''),
        os_info_json=json.dumps(data.get('os_info', {})) if data.get('os_info') else None,
        agent_version=data.get('agent_version', ''),
        capabilities_json=json.dumps(data.get('capabilities', [])),
        checkin_interval=data.get('checkin_interval', 21600),
        status='active',
        created_at=now,
        last_checkin=now,
        enabled=1,
    )
    db.session.add(agent)
    db.session.commit()
    _emit_webhook('agent.registered', {
        'agent_id': agent.id, 'hostname': agent.hostname, 'ip': agent.ip,
        'os': agent.to_dict().get('os'), 'agent_version': agent.agent_version,
    })
    return agent


def _emit_webhook(event, payload):
    try:
        from artemis.services.webhook_service import emit
        emit(event, payload)
    except Exception:
        logger.debug("webhook emit failed", exc_info=True)


def process_report(agent, data):
    """Process and store an agent report, scoped to the agent's organization."""
    from artemis.services.tenant import use_organization

    with use_organization(agent.organization_id):
        return _process_report(agent, data)


def _process_report(agent, data):
    now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

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
    if isinstance(data.get('capabilities'), list):
        agent.capabilities_json = json.dumps(data['capabilities'])

    agent.last_checkin = now
    agent.status = 'active'

    db.session.add(report)
    db.session.commit()

    # Create/update asset from agent data
    _sync_agent_to_asset(agent, data)

    # Try to match packages against CVEs
    vulns_matched = _match_package_cves(
        agent,
        data.get('packages', []),
        os_info=data.get('os_info', {}),
        system_info=data.get('system_info', {}),
    )
    if vulns_matched > 0:
        report.vulns_matched = vulns_matched
        db.session.commit()

    _emit_webhook('agent.report.received', {
        'agent_id': agent.id, 'hostname': agent.hostname, 'ip': agent.ip,
        'report_id': report.id, 'package_count': report.packages_count,
        'ports_count': report.ports_count, 'vulns_matched': report.vulns_matched,
    })
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
    """Store agent-reported packages and system info for the asset detail view."""
    try:
        from artemis.models.agent_data import AgentData
        from artemis.services._db import upsert

        now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        packages = data.get('packages', [])
        upsert(AgentData, {'ip': ip}, {
            'packages_json': json.dumps(packages),
            'package_count': data.get('package_count', len(packages)),
            'system_info_json': json.dumps(data.get('system_info', {})),
            'os_info_json': json.dumps(data.get('os_info', {})),
            'updated_at': now,
        })
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.warning(f"Failed to store agent system data for {ip}: {e}")


def _match_package_cves(agent, packages, os_info=None, system_info=None):
    """Normalize agent packages to CPEs, match the local NVD cache, and persist.

    Agent check-ins never make per-package NVD API calls: report ingestion must
    stay bounded and reliable. If the local feed has not been synced, inventory
    is still stored and the report correctly records zero matches.
    """
    if not agent.ip or not isinstance(packages, list):
        return 0

    from auth_scan import generate_cpe
    from artemis.services.auth_scan_service import store_auth_scan_results

    normalized = []
    os_info = dict(os_info) if isinstance(os_info, dict) else {}
    if isinstance(system_info, dict) and system_info:
        os_info['system'] = system_info

    for package in packages:
        if not isinstance(package, dict):
            continue
        name = str(package.get('name') or '').strip()
        version = str(package.get('version') or '').strip()
        if not name:
            continue
        cpe = package.get('cpe') or generate_cpe(name, version, os_info)
        normalized.append({**package, 'name': name, 'version': version, 'cpe': cpe})

    cves = []
    versioned_cpes = [
        package['cpe'] for package in normalized
        if package.get('cpe') and len(package['cpe'].split(':')) > 5
        and package['cpe'].split(':')[5] not in ('', '*', '-')
    ]
    if versioned_cpes:
        try:
            from nvd_feeds import match_cpes_local
            cves = match_cpes_local(versioned_cpes) or []
        except Exception:
            logger.warning("Local NVD matching failed for agent %s", agent.id, exc_info=True)

    if cves:
        try:
            from exploit_ref import enrich_cves_with_exploits
            cves = enrich_cves_with_exploits(cves)
        except Exception:
            logger.debug("Exploit enrichment failed for agent %s", agent.id, exc_info=True)

    store_auth_scan_results(
        agent.ip,
        os_info,
        normalized,
        cves,
        detection_source='agent',
    )
    logger.info("Agent %s inventory matched %s CVEs", agent.id, len(cves))
    return len(cves)


def deregister_agent(agent):
    """Remove an agent and all of its stored reports.

    Used both by the authenticated UI (DELETE /agents/<id>) and by the agent
    itself calling /agents/deregister during uninstall. agent_reports has no FK
    cascade, so its rows are cleared explicitly to avoid orphans.
    """
    agent_id = agent.id
    label = agent.hostname or agent.ip or 'unknown'
    AgentReport.query.filter_by(agent_id=agent_id).delete()
    db.session.delete(agent)
    db.session.commit()
    logger.info(f"Deregistered agent #{agent_id} ({label})")
    return agent_id


def update_stale_agents():
    """Mark agents as stale if no checkin in 2x their interval."""
    now = datetime.now(timezone.utc)
    agents = Agent.query.filter(Agent.enabled == 1, Agent.status != 'offline').all()
    for agent in agents:
        if not agent.last_checkin:
            continue
        try:
            last = datetime.strptime(agent.last_checkin, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
            threshold = timedelta(seconds=(agent.checkin_interval or 21600) * 2)
            if now - last > threshold:
                agent.status = 'stale'
        except Exception:
            pass
    db.session.commit()
