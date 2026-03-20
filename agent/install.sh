#!/bin/bash
# Artemis Agent Installer
# Usage: curl -sSL https://your-server/agent/install.sh | bash -s -- --server https://artemis.example.com
set -e

AGENT_DIR="/opt/artemis-agent"
AGENT_URL=""
SERVER=""
NAME=""
AGENT_SCRIPT="artemis_agent.py"

usage() {
    echo "Usage: $0 --server <url> [--name <name>] [--agent-url <url>]"
    echo ""
    echo "Options:"
    echo "  --server     Artemis server URL (required)"
    echo "  --name       Friendly name for this agent (default: hostname)"
    echo "  --agent-url  URL to download agent script (default: \$SERVER/agent/artemis_agent.py)"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --server) SERVER="$2"; shift 2 ;;
        --name) NAME="$2"; shift 2 ;;
        --agent-url) AGENT_URL="$2"; shift 2 ;;
        *) usage ;;
    esac
done

if [ -z "$SERVER" ]; then
    echo "Error: --server is required"
    usage
fi

if [ -z "$AGENT_URL" ]; then
    AGENT_URL="${SERVER}/agent/artemis_agent.py"
fi

echo "=== Artemis Agent Installer ==="
echo "Server: $SERVER"
echo "Install dir: $AGENT_DIR"
echo ""

# Create directories
mkdir -p "$AGENT_DIR"
mkdir -p /etc/artemis

# Download agent (or copy if local)
if [ -f "$AGENT_SCRIPT" ]; then
    echo "Copying local agent script..."
    cp "$AGENT_SCRIPT" "$AGENT_DIR/artemis_agent.py"
else
    echo "Downloading agent..."
    if command -v curl &>/dev/null; then
        curl -sSL "$AGENT_URL" -o "$AGENT_DIR/artemis_agent.py"
    elif command -v wget &>/dev/null; then
        wget -q "$AGENT_URL" -O "$AGENT_DIR/artemis_agent.py"
    else
        echo "Error: curl or wget required"
        exit 1
    fi
fi

chmod +x "$AGENT_DIR/artemis_agent.py"

# Check Python
PYTHON=""
for p in python3 python; do
    if command -v "$p" &>/dev/null; then
        PYTHON="$p"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo "Error: Python 3 is required"
    exit 1
fi

echo "Using Python: $($PYTHON --version)"

# Register agent
echo "Registering agent with server..."
NAME_ARG=""
if [ -n "$NAME" ]; then
    NAME_ARG="--name $NAME"
fi
$PYTHON "$AGENT_DIR/artemis_agent.py" --server "$SERVER" --register $NAME_ARG

# Create systemd service
cat > /etc/systemd/system/artemis-agent.service << EOF
[Unit]
Description=Artemis Security Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$PYTHON $AGENT_DIR/artemis_agent.py
Restart=always
RestartSec=60
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
systemctl daemon-reload
systemctl enable artemis-agent
systemctl start artemis-agent

echo ""
echo "=== Installation Complete ==="
echo "Agent installed to: $AGENT_DIR"
echo "Service: artemis-agent.service"
echo "Config: /etc/artemis/agent.conf"
echo ""
echo "Commands:"
echo "  systemctl status artemis-agent"
echo "  journalctl -u artemis-agent -f"
echo "  systemctl restart artemis-agent"
