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
read-cache containing NVD CVEs, CPE matches, feed metadata, and ExploitDB CVE
references; it is not application state.

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

### Remote shell capability

Agent 1.3 advertises the `remote_shell` capability and runs a low-frequency
outbound poll alongside telemetry collection. An administrator can open a
session from the selected agent's inspector on the Agents tab. The server
queues terminal input; the agent starts a local login shell attached to a
POSIX PTY and returns output as base64 chunks. No inbound listener or SSH
service is required.

Shell sessions are admin-only and tied to the creating user and agent. Only one
session may be active per agent. Sessions have a 15-minute hard limit, a
5-minute operator-idle limit, 16 KiB input chunks, and 1 MiB total output.
Delivered input is deleted immediately. Output is retained for reconnects and
removed after 24 hours; lifecycle metadata remains for audit. Agents can opt
out with `--disable-remote-shell` or `"remote_shell_enabled": false` in their
configuration.

Existing installations can be upgraded without re-registering:

```bash
curl -fsSL https://SERVER/agent/install.sh | \
  sudo bash -s -- --server https://SERVER --upgrade
```

After restart, the next agent report advertises the new capability and enables
the selected agent's Remote shell button.

The installed service runs as root, so the PTY has root identity, subject to
the systemd unit's existing `NoNewPrivileges`, `ProtectSystem=full`,
`ProtectHome=read-only`, and `PrivateTmp` restrictions.

## Activity logging

Operational logs go through Python logging. `logging_setup.configure_logging`
installs a single stdout handler that emits **line-delimited JSON** by default
(plain text on a TTY; override with `ARTEMIS_LOG_FORMAT`). Every record carries
`request_id`, and `job_id` / `org_id` when set on `flask.g`, so a request can be
traced across web and worker. Container deployments rely on the runtime log
driver for rotation; `ARTEMIS_LOG_FILE` adds a size-based `RotatingFileHandler`
for non-container use. `log_service` still keeps the newest 500 records in
process for `GET /api/v1/logs`, and `scan_log` Socket.IO events carry live scan
output.

## Tenancy (Phase 1)

`Organization` is the tenant. `User` is a global identity; ordinary roles are
per-organization via `OrganizationMembership`, and `User.platform_admin` grants
audited cross-org administration. Every request and Socket.IO connection
resolves exactly one active organization (`org_service.resolve_context`, from an
`X-Organization` header / session / primary membership, or the API key's bound
org) and fails closed when none applies.

Every tenant-owned row carries a non-null `organization_id` (`TenantMixin`).
`artemis.services.tenant` enforces isolation:

- a `before_flush` hook stamps `organization_id` on new rows from the active
  organization (or the Default organization outside a request);
- a `do_orm_execute` hook adds `with_loader_criteria(TenantMixin, ...)` to every
  ORM SELECT, so services are scoped automatically; opt out per statement with
  `.execution_options(skip_tenant_filter=True)` for platform-admin cross-org
  views;
- background work (Celery tasks, the scheduler, report runner) sets the context
  from the job/schedule's own `organization_id` via `use_organization` /
  `set_task_organization`;
- report artifacts are written under `REPORTS_DIR/org-<id>/` and downloads are
  path-checked against that directory;
- migration `c4d5e6f7a8b9` adds PostgreSQL RLS policies (ENABLE, not FORCE) as
  defense in depth — inert until the app runs as a dedicated non-owner role with
  `ARTEMIS_ENABLE_RLS=1`.

## Security baseline (P0.4)

- **Secret encryption.** `crypto_service` seals every stored secret with
  per-secret AES-GCM data keys wrapped by a deployment KEK
  (`ARTEMIS_ENCRYPTION_KEY`, or `ARTEMIS_ENCRYPTION_KEYS` for rotation).
  `Credential` holds only `secret_enc` / `private_key_enc` envelopes; the
  plaintext columns and filesystem `key_path` auth were removed. Scanners call
  `resolve_credential_secrets()` at the point of use, which writes a
  `secret.read` audit event.
- **Production guard.** `security.validate_production_config` refuses to serve
  `production` without `SECRET_KEY`, an encryption key, and an HTTPS assertion,
  unless `ARTEMIS_ALLOW_INSECURE=1`.
- **Transport.** `security.init_security` adds request-ID correlation, `ProxyFix`
  (when `ARTEMIS_BEHIND_TLS_PROXY`), secure/SameSite cookies, HSTS/CSP/nosniff
  headers, and a `MAX_CONTENT_LENGTH` cap. `docker-compose.tls.yml` puts Caddy
  in front for ACME or bring-your-own-certificate TLS.
- **Rate limiting.** `rate_limit_service` applies Redis-backed fixed-window
  policies (`login`, `write`, `expensive`, `agent_report`, `shell_poll`) with a
  deterministic in-memory backend for tests; over-budget callers get `429` with
  `Retry-After`.
- **Audit trail.** `audit_service` writes immutable `AuditEvent` rows for auth,
  secret access, role changes, scan start/cancel, shell lifecycle, settings
  changes, agent-key issue, and exports. `GET /api/v1/audit-events` is
  admin-only.
- **Permission matrix.** Credential, agent-key, settings, and shell
  administration are `role_required('admin')`.

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
- Remote-shell transport uses short HTTPS polling. A future dedicated broker or
  authenticated WebSocket channel would reduce latency and database churn at
  larger agent fleet sizes.
