#!/usr/bin/env bash
# Artemis container entrypoint. Selects a role based on the first argument:
#   web    — run database migrations, then serve the Flask/SocketIO app
#   worker — run the Celery worker
#   beat   — reserved for a future Celery beat schedule
# Any other argument is executed verbatim (e.g. `flask db ...`, `bash`).
set -euo pipefail

ROLE="${1:-web}"

# Retry a command a few times — covers the brief window where Postgres/Redis
# are up but not yet accepting connections, even with compose healthchecks.
retry() {
    local n=0 max="${1}"; shift
    until "$@"; do
        n=$((n + 1))
        if [[ ${n} -ge ${max} ]]; then
            echo "Command failed after ${max} attempts: $*" >&2
            return 1
        fi
        echo "Attempt ${n}/${max} failed, retrying in 2s: $*" >&2
        sleep 2
    done
}

case "${ROLE}" in
    web)
        echo "Running database migrations (flask db upgrade)..."
        retry 30 flask db upgrade
        echo "Starting gunicorn on :${PORT:-5005}..."
        exec gunicorn \
            --worker-class geventwebsocket.gunicorn.workers.GeventWebSocketWorker \
            --workers "${WEB_CONCURRENCY:-1}" \
            --bind "0.0.0.0:${PORT:-5005}" \
            --timeout "${WEB_TIMEOUT:-120}" \
            --access-logfile - \
            --error-logfile - \
            run:app
        ;;
    worker)
        # Wait for the schema the web service creates before consuming jobs.
        retry 30 flask db current
        exec celery -A artemis.celery_app:celery_app worker \
            --loglevel="${CELERY_LOGLEVEL:-INFO}" \
            --concurrency="${CELERY_CONCURRENCY:-4}"
        ;;
    beat)
        exec celery -A artemis.celery_app:celery_app beat \
            --loglevel="${CELERY_LOGLEVEL:-INFO}"
        ;;
    *)
        exec "$@"
        ;;
esac
