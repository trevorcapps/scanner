#!/usr/bin/env bash
# Migration gate: fresh upgrade, head downgrade/upgrade roundtrip, and model
# drift detection. Runs against whatever DATABASE_URL points at — CI points it
# at PostgreSQL, which is the deployment target.
set -euo pipefail

cd "$(dirname "$0")/.."

export FLASK_APP=run.py
export AUTO_CREATE_SCHEMA=false
export INITIALIZE_LEGACY_SCHEMA=false
export START_BACKGROUND_SERVICES=false

echo "==> fresh upgrade to head"
flask db upgrade

echo "==> head revision downgrade / upgrade roundtrip"
# `flask db history` prints newest first: "<prev> -> <head> (head), <msg>".
# Grep for that exact shape so structured JSON log lines on stdout are ignored.
export ARTEMIS_LOG_LEVEL="${ARTEMIS_LOG_LEVEL:-ERROR}"
prev_rev="$(flask db history 2>/dev/null \
    | grep -oE '^[0-9a-f]{12,} -> [0-9a-f]{12,}' | head -1 | awk '{print $1}')"
if [ -n "${prev_rev:-}" ]; then
    flask db downgrade "$prev_rev"
    flask db upgrade
else
    echo "   (only one migration; skipping roundtrip)"
fi

echo "==> model / migration drift check"
flask db check

echo "OK: migrations are consistent with the models"
