#!/usr/bin/env bash
# Artemis Agent Uninstaller
# Usage: curl -fsSL https://SERVER/agent/uninstall.sh | bash
#   --keep-config   Leave /etc/artemis/agent.conf in place (for re-install)
#   --keep-remote   Do not deregister this agent from the Artemis server

set -euo pipefail

AGENT_DIR="/opt/artemis-agent"
CONFIG_DIR="/etc/artemis"
CONFIG_FILE="$CONFIG_DIR/agent.conf"
SERVICE="artemis-agent.service"
KEEP_CONFIG=false
KEEP_REMOTE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --keep-config) KEEP_CONFIG=true; shift ;;
        --keep-remote) KEEP_REMOTE=true; shift ;;
        *) echo "Unknown option: $1"; echo "Usage: $0 [--keep-config] [--keep-remote]"; exit 1 ;;
    esac
done

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

echo "ARTEMIS / AGENT UNINSTALL"

# 1. Deregister from the server while the config (key) still exists.
#    Read server+key straight from the JSON config so this works regardless of
#    the installed agent version.
if [[ "$KEEP_REMOTE" == false && -f "$CONFIG_FILE" && -n "$PYTHON" ]] && command -v curl >/dev/null 2>&1; then
    SERVER_URL="$("${ROOT[@]}" "$PYTHON" -c 'import json,sys;print(json.load(open(sys.argv[1])).get("server",""))' "$CONFIG_FILE" 2>/dev/null || true)"
    AGENT_KEY="$("${ROOT[@]}" "$PYTHON" -c 'import json,sys;print(json.load(open(sys.argv[1])).get("key",""))' "$CONFIG_FILE" 2>/dev/null || true)"
    if [[ -n "$SERVER_URL" && -n "$AGENT_KEY" ]]; then
        echo "deregister  ${SERVER_URL}"
        curl -fsSL -X POST "${SERVER_URL%/}/api/v1/agents/deregister" \
            -H "X-Agent-Key: $AGENT_KEY" -o /dev/null \
            && echo "deregister  ok" \
            || echo "deregister  failed (removing locally anyway)"
    fi
fi

# 2. Stop and remove the systemd service.
if "${ROOT[@]}" systemctl list-unit-files "$SERVICE" >/dev/null 2>&1; then
    echo "service     stopping $SERVICE"
    "${ROOT[@]}" systemctl disable --now "$SERVICE" >/dev/null 2>&1 || true
fi
"${ROOT[@]}" rm -f "/etc/systemd/system/$SERVICE"
"${ROOT[@]}" systemctl daemon-reload 2>/dev/null || true

# 3. Remove the agent program.
"${ROOT[@]}" rm -rf "$AGENT_DIR"
echo "removed     $AGENT_DIR"

# 4. Remove config unless asked to keep it.
if [[ "$KEEP_CONFIG" == true ]]; then
    echo "config      kept at $CONFIG_FILE"
else
    "${ROOT[@]}" rm -f "$CONFIG_FILE"
    "${ROOT[@]}" rmdir "$CONFIG_DIR" 2>/dev/null || true
    "${ROOT[@]}" rm -f "$HOME/.artemis/agent.conf"
    rmdir "$HOME/.artemis" 2>/dev/null || true
    echo "config      removed"
fi

echo "done        artemis agent uninstalled"
