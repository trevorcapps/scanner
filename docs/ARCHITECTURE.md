# Artemis architecture and logic

## Runtime shape

`run.py` creates the Flask application through `artemis.create_app`. The app
registers the REST blueprints, SQLAlchemy, migrations, Socket.IO, Celery, auth
middleware, the React build, and optional scheduler services.

The principal code boundaries are:

| Path | Responsibility |
|---|---|
| `artemis/api/` | HTTP validation and response contracts |
| `artemis/services/` | Application use cases, persistence, correlation, and orchestration |
| `artemis/scanners/` | Adapters for Nmap, Nuclei, and authenticated SSH collection |
| `artemis/tasks/` | Durable Celery job entry points |
| `artemis/models/` | SQLAlchemy system-of-record models |
| `artemis/socketio_handlers.py` | Interactive scan commands and live progress |
| `agent/artemis_agent.py` | Dependency-free endpoint collector |
| `frontend/src/` | React SPA, query hooks, pages, and shared UI state |
| top-level scanner modules | Legacy implementations still wrapped by `artemis/scanners/` |

PostgreSQL is the production system of record. SQLite is supported for local
development and tests. `NVD_CACHE_PATH` is a separate, rebuildable SQLite
read-cache containing NVD CVEs and CPE matches; it is not application state.

## Scan flows

There are four canonical scan methods:

| Method | Collector | Stored output |
|---|---|---|
| `port` | Nmap | assets, ports, OS hints, fingerprints |
| `vuln` | Nuclei | vulnerability/template findings |
| `full` | Nmap then Nuclei | both of the above |
| `auth` | SSH authenticated inventory | definitive OS facts, packages, CPE/CVE matches |

“Auth” and “SSH authenticated scan” are the same use case. Authenticated
inventory is a scan method, not a Nuclei profile. The API filters legacy
`auth_required` profiles so custom older profile files do not recreate the
duplicate UI path.

REST scan creation persists a `ScanJob` before dispatching it to Celery. The
task reconstructs scan options and invokes `scheduler_service._run_scan`.
Site scans use `site_service`; interactive scans currently use Socket.IO daemon
threads. Moving those remaining interactive paths onto durable jobs is still a
known architectural migration.

## Vulnerability correlation

`vuln_service.get_unified_vulnerabilities` merges:

1. Nuclei rows from `vulnerabilities`.
2. Package/CPE matches from `cve_matches`.
3. Metadata enrichment from the local NVD cache.
4. ExploitDB attribution when exploit evidence exists.

Findings are deduplicated by CVE/template identifier and retain affected assets
and detection sources. New package matches store explicit provenance:
`auth-scan` for SSH inventory and `agent` for endpoint reports. Older rows
without provenance retain the previous installed-software inference.

## Agent report flow

The agent collects OS, packages, listening ports, services, resource metrics,
process summaries, network counters, and storage data. `POST /agents/report`
authenticates with `X-Agent-Key`, then `agent_service.process_report`:

1. Stores the immutable report history and updates agent health.
2. Creates or enriches the corresponding asset and port records.
3. Stores the latest telemetry/package snapshot in `agent_data`.
4. Normalizes packages to CPE 2.3 using the authenticated-scan resolver.
5. Matches every versioned CPE against the local NVD cache.
6. Stores software and CVEs in the unified finding model with source `agent`.

Agent ingestion intentionally does not call the remote NVD API. This keeps
check-in latency bounded and avoids rate-limit failures. If the local feed is
empty, inventory is still stored and `vulns_matched` is zero until a later
report is processed after feed sync.

## Activity logging

Operational logs continue to go through Python logging (stdout/journal in
normal deployments). `log_service` also keeps the newest 500 in-process
records. `GET /api/v1/logs` seeds the activity panel, while `scan_log`
Socket.IO events append live scan output. The memory history is intentionally
bounded and process-local; durable retention belongs in the container/service
logging platform.

## Compatibility and cleanup boundaries

`app.py`, `vuln_scan.py`, and several top-level scanner helpers remain for
legacy compatibility. New HTTP behavior should be added to `artemis/api`, use
cases to `artemis/services`, and tool adapters to `artemis/scanners`. Avoid
adding new persistence logic to the legacy modules. Migrations in
`migrations/versions` are required for production model changes.

## Known limitations and next cleanup targets

- Interactive Socket.IO scans still use daemon threads, while REST and site
  work use durable Celery jobs. A single job/progress abstraction should
  eventually replace the interactive path.
- Recent UI logs are process-local. In a multi-process deployment, use the
  container/service log backend for a complete cross-worker history.
- CPE mapping is heuristic and upstream-version based. Distribution backports
  can make package vulnerability results conservative; remediation decisions
  should confirm against vendor advisories.
- `cve_matches` stores one current provenance value per asset/CVE. If both an
  agent and an SSH scan observe the same match, the most recent inventory run
  owns the source label.
- Credentials are application database fields today; the roadmap's external
  secret-vault integration remains security-relevant work.
