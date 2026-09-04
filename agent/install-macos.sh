#!/usr/bin/env bash
# Artemis agent installer for macOS (launchd). Outbound-only enrollment.
#
#   curl -fsSL https://SERVER/agent/artemis_agent.py -o /tmp/artemis_agent.py
#   sudo bash install-macos.sh --server https://SERVER [--name NAME] [--interval 21600] [--upgrade]
set -euo pipefail

AGENT_DIR="/usr/local/artemis"
CONFIG_DIR="/etc/artemis"
PLIST="/Library/LaunchDaemons/com.artemis.agent.plist"
LABEL="com.artemis.agent"
SERVER="" NAME="" INTERVAL="21600" UPGRADE=false
PYTHON="$(command -v python3 || true)"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server) SERVER="${2:-}"; shift 2 ;;
        --name) NAME="${2:-}"; shift 2 ;;
        --interval) INTERVAL="${2:-}"; shift 2 ;;
        --upgrade) UPGRADE=true; shift ;;
        *) echo "Usage: $0 --server <url> [--name <name>] [--interval <s>] [--upgrade]"; exit 1 ;;
    esac
done
[[ -n "$PYTHON" ]] || { echo "python3 not found (install the Command Line Tools)"; exit 1; }
[[ "$UPGRADE" == true || -n "$SERVER" ]] || { echo "--server is required"; exit 1; }

TMP_AGENT="${TMP_AGENT:-/tmp/artemis_agent.py}"
[[ -f "$TMP_AGENT" ]] || { echo "agent source not found at $TMP_AGENT"; exit 1; }

mkdir -p "$AGENT_DIR" "$CONFIG_DIR"
# Atomic install: write beside, then rename.
install -m 0755 "$TMP_AGENT" "$AGENT_DIR/artemis_agent.py.new"
mv -f "$AGENT_DIR/artemis_agent.py.new" "$AGENT_DIR/artemis_agent.py"

if [[ "$UPGRADE" == true ]]; then
    [[ -f "$CONFIG_DIR/agent.conf" ]] || { echo "cannot upgrade: no $CONFIG_DIR/agent.conf"; exit 1; }
    echo "registration preserved"
else
    reg=(--server "$SERVER" --register)
    [[ -n "$NAME" ]] && reg+=(--name "$NAME")
    "$PYTHON" "$AGENT_DIR/artemis_agent.py" "${reg[@]}"
fi

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${PYTHON}</string>
    <string>${AGENT_DIR}/artemis_agent.py</string>
    <string>--interval</string>
    <string>${INTERVAL}</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>/var/log/artemis-agent.log</string>
  <key>StandardOutPath</key><string>/var/log/artemis-agent.log</string>
</dict>
</plist>
EOF
chmod 0644 "$PLIST"

# Reload atomically so an upgrade starts the new binary immediately.
launchctl bootout system "$PLIST" 2>/dev/null || true
launchctl bootstrap system "$PLIST"
launchctl enable "system/${LABEL}"
launchctl kickstart -k "system/${LABEL}"

echo "status   $(launchctl print system/${LABEL} 2>/dev/null | awk '/state = /{print $3; exit}')"
echo "agent    $AGENT_DIR/artemis_agent.py"
