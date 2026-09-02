#!/usr/bin/env bash
# Artemis Agent Installer
# Usage: curl -fsSL https://SERVER/agent/install.sh | bash -s -- --server https://SERVER

set -euo pipefail

AGENT_DIR="/opt/artemis-agent"
CONFIG_DIR="/etc/artemis"
SERVER=""
NAME=""
INTERVAL="21600"

usage() {
    echo "Usage: $0 --server <url> [--name <name>] [--interval <seconds>]"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server) SERVER="${2:-}"; shift 2 ;;
        --name) NAME="${2:-}"; shift 2 ;;
        --interval) INTERVAL="${2:-}"; shift 2 ;;
        *) usage ;;
    esac
done

[[ -n "$SERVER" ]] || usage
[[ "$INTERVAL" =~ ^[0-9]+$ ]] || { echo "Interval must be an integer"; exit 1; }

if [[ $EUID -eq 0 ]]; then
    ROOT=()
elif command -v sudo >/dev/null 2>&1; then
    ROOT=(sudo)
else
    echo "Root access is required (sudo was not found)."
    exit 1
fi

PYTHON=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
        PYTHON="$(command -v "$candidate")"
        break
    fi
done
[[ -n "$PYTHON" ]] || { echo "Python 3 is required"; exit 1; }

TMP_AGENT="$(mktemp)"
SERVICE_FILE=""
trap 'rm -f "$TMP_AGENT" "$SERVICE_FILE"' EXIT

echo "ARTEMIS / AGENT INSTALL"
echo "server   $SERVER"
echo "interval ${INTERVAL}s"

if command -v curl >/dev/null 2>&1; then
    curl -fsSL "${SERVER%/}/agent/artemis_agent.py" -o "$TMP_AGENT"
elif command -v wget >/dev/null 2>&1; then
    wget -q "${SERVER%/}/agent/artemis_agent.py" -O "$TMP_AGENT"
else
    echo "curl or wget is required"
    exit 1
fi

"${ROOT[@]}" install -d -m 0755 "$AGENT_DIR" "$CONFIG_DIR"
"${ROOT[@]}" install -m 0755 "$TMP_AGENT" "$AGENT_DIR/artemis_agent.py"

register_args=(--server "$SERVER" --register)
[[ -n "$NAME" ]] && register_args+=(--name "$NAME")
"${ROOT[@]}" "$PYTHON" "$AGENT_DIR/artemis_agent.py" "${register_args[@]}"

SERVICE_FILE="$(mktemp)"
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Artemis Security Telemetry Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$PYTHON $AGENT_DIR/artemis_agent.py --interval $INTERVAL
Restart=always
RestartSec=60
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

"${ROOT[@]}" install -m 0644 "$SERVICE_FILE" /etc/systemd/system/artemis-agent.service
"${ROOT[@]}" systemctl daemon-reload
"${ROOT[@]}" systemctl enable --now artemis-agent.service

echo "status   $("${ROOT[@]}" systemctl is-active artemis-agent.service)"
echo "agent    $AGENT_DIR/artemis_agent.py"
echo "config   $CONFIG_DIR/agent.conf"
