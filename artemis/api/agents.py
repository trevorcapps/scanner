"""Agents API blueprint — agent registration, reporting, and management."""

import json
import logging
from datetime import datetime

from flask import Blueprint, request, jsonify, Response

from artemis.extensions import db
from artemis.models.agent import Agent
from artemis.models.agent_report import AgentReport
from artemis.services.agent_service import register_agent, process_report, generate_agent_key

logger = logging.getLogger(__name__)

agents_bp = Blueprint('agents', __name__)


INSTALL_SCRIPT = r'''#!/usr/bin/env bash
# Artemis Agent Installer
# Usage: curl -sSL http://SERVER:5005/agent/install.sh | bash -s -- [OPTIONS]
#   --server URL   Artemis server URL (default: auto-detect from download URL)
#   --name NAME    Agent display name (default: hostname)
#   --interval SEC Heartbeat interval in seconds (default: 300)

set -euo pipefail

SERVER=""
AGENT_NAME=""
INTERVAL=300
INSTALL_DIR="/opt/artemis-agent"

while [[ $# -gt 0 ]]; do
    case $1 in
        --server)  SERVER="$2"; shift 2 ;;
        --name)    AGENT_NAME="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [ -z "$SERVER" ]; then
    echo "Error: --server URL is required"
    echo "Usage: curl -sSL http://SERVER:5005/agent/install.sh | bash -s -- --server http://SERVER:5005"
    exit 1
fi

AGENT_NAME="${AGENT_NAME:-$(hostname)}"

echo "=== Artemis Agent Installer ==="
echo "Server:  $SERVER"
echo "Name:    $AGENT_NAME"
echo "Install: $INSTALL_DIR"
echo ""

# Check dependencies
for cmd in curl jq; do
    if ! command -v $cmd &>/dev/null; then
        echo "Installing $cmd..."
        if command -v apt-get &>/dev/null; then
            sudo apt-get install -y $cmd
        elif command -v yum &>/dev/null; then
            sudo yum install -y $cmd
        else
            echo "Error: $cmd not found and no package manager detected"
            exit 1
        fi
    fi
done

# Register with server
echo "Registering agent..."
REGISTER_RESP=$(curl -sS -X POST "$SERVER/api/v1/agents/register" \
    -H "Content-Type: application/json" \
    -d "{\"hostname\": \"$AGENT_NAME\", \"os\": \"$(uname -s)\", \"arch\": \"$(uname -m)\", \"kernel\": \"$(uname -r)\"}")

AGENT_KEY=$(echo "$REGISTER_RESP" | jq -r '.agent_key // empty')
AGENT_ID=$(echo "$REGISTER_RESP" | jq -r '.agent_id // empty')

if [ -z "$AGENT_KEY" ]; then
    echo "Error: Registration failed"
    echo "$REGISTER_RESP"
    exit 1
fi

echo "Registered as agent #$AGENT_ID"

# Create install directory
sudo mkdir -p "$INSTALL_DIR"

# Write config
sudo tee "$INSTALL_DIR/agent.conf" > /dev/null <<CONF
ARTEMIS_SERVER=$SERVER
ARTEMIS_AGENT_KEY=$AGENT_KEY
ARTEMIS_AGENT_ID=$AGENT_ID
ARTEMIS_INTERVAL=$INTERVAL
CONF
sudo chmod 600 "$INSTALL_DIR/agent.conf"

# Write agent script
sudo tee "$INSTALL_DIR/artemis-agent.sh" > /dev/null <<'AGENT'
#!/usr/bin/env bash
# Artemis Agent — periodic system reporter
source /opt/artemis-agent/agent.conf

report() {
    local os_info=""
    if [ -f /etc/os-release ]; then
        os_info=$(cat /etc/os-release | head -5 | tr '\n' ' ')
    fi

    local pkg_count=0
    if command -v dpkg &>/dev/null; then
        pkg_count=$(dpkg -l 2>/dev/null | grep ^ii | wc -l)
    elif command -v rpm &>/dev/null; then
        pkg_count=$(rpm -qa 2>/dev/null | wc -l)
    fi

    local load=$(cat /proc/loadavg 2>/dev/null | awk '{print $1}')
    local mem_total=$(free -m 2>/dev/null | awk '/Mem:/{print $2}')
    local mem_used=$(free -m 2>/dev/null | awk '/Mem:/{print $3}')
    local disk_usage=$(df -h / 2>/dev/null | awk 'NR==2{print $5}')
    local uptime_sec=$(awk '{print int($1)}' /proc/uptime 2>/dev/null)

    curl -sS -X POST "$ARTEMIS_SERVER/api/v1/agents/report" \
        -H "Content-Type: application/json" \
        -H "X-Agent-Key: $ARTEMIS_AGENT_KEY" \
        -d "{
            \"hostname\": \"$(hostname)\",
            \"os_info\": \"$os_info\",
            \"package_count\": $pkg_count,
            \"load\": \"$load\",
            \"mem_total_mb\": ${mem_total:-0},
            \"mem_used_mb\": ${mem_used:-0},
            \"disk_usage\": \"${disk_usage:-unknown}\",
            \"uptime_seconds\": ${uptime_sec:-0},
            \"kernel\": \"$(uname -r)\",
            \"arch\": \"$(uname -m)\"
        }" > /dev/null 2>&1
}

while true; do
    report
    sleep "$ARTEMIS_INTERVAL"
done
AGENT
sudo chmod +x "$INSTALL_DIR/artemis-agent.sh"

# Create systemd service
sudo tee /etc/systemd/system/artemis-agent.service > /dev/null <<SVC
[Unit]
Description=Artemis Security Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/artemis-agent/artemis-agent.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SVC

sudo systemctl daemon-reload
sudo systemctl enable artemis-agent
sudo systemctl start artemis-agent

echo ""
echo "=== Artemis Agent Installed ==="
echo "Agent ID:  $AGENT_ID"
echo "Status:    $(sudo systemctl is-active artemis-agent)"
echo "Config:    $INSTALL_DIR/agent.conf"
echo "Logs:      journalctl -u artemis-agent -f"
'''


@agents_bp.route('/install.sh', methods=['GET'])
def agent_install_script():
    """Serve the agent install shell script."""
    return Response(INSTALL_SCRIPT, mimetype='text/plain',
                    headers={'Content-Disposition': 'inline; filename="install.sh"'})



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
