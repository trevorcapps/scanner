#!/usr/bin/env bash
# Regenerate the hashed dependency lock files from pyproject.toml.
#
# pyproject.toml is the only human-edited dependency source. Run this after any
# change to [project.dependencies] or [project.optional-dependencies] and commit
# the updated lock files alongside pyproject.toml.
#
# Tool: uv (https://docs.astral.sh/uv/). Install with `pip install uv`.
# Locks are resolved for the deployment target interpreter (Python 3.12) and are
# "universal" so a single file covers every supported platform.
set -euo pipefail

cd "$(dirname "$0")/.."

command -v uv >/dev/null || {
    echo "uv not found. Run: pip install uv" >&2
    exit 1
}

COMMON=(--quiet --generate-hashes --universal --python-version 3.12)

# Production runtime: what the web and worker containers need.
uv pip compile "${COMMON[@]}" \
    --extra postgres --extra wsgi --extra fingerprint \
    -o requirements.lock \
    pyproject.toml

# Development / CI: production plus test and lint tooling.
uv pip compile "${COMMON[@]}" \
    --extra postgres --extra wsgi --extra fingerprint --extra dev \
    -o requirements-dev.lock \
    pyproject.toml

echo "Wrote requirements.lock and requirements-dev.lock"
