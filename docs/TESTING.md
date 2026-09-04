# Testing Artemis

## Commands

From the repository root:

```bash
python -m venv env
env/bin/python -m pip install -e '.[all]'
env/bin/python -m pytest -q                       # unit suite (SQLite in-memory)
env/bin/ruff check artemis agent tests --select E9,F63,F7,F82
npm --prefix frontend ci
npm --prefix frontend run typecheck
npm --prefix frontend run build
env/bin/bash scripts/check-migrations.sh          # needs DATABASE_URL
```

For coverage (the floor lives in `pyproject.toml` → `[tool.coverage.report]`):

```bash
env/bin/python -m pytest --cov --cov-report=term-missing
```

Run the same suite against a real database by exporting
`TEST_DATABASE_URL=postgresql+psycopg://…` before `pytest` — this is what CI's
`integration` job does, alongside a live Redis for Celery task tests.

The frontend build runs TypeScript type checking before the Vite production
bundle. `E9,F63,F7,F82` is the current blocking Ruff baseline. Broader style and
exception-policy rules can be ratcheted in incrementally.

## CI jobs

| Job | What it gates |
|---|---|
| `python` | Ruff baseline, unit suite, and the coverage floor |
| `frontend` | `npm ci`, strict `tsc --noEmit`, and the production build |
| `migrations` | Fresh PostgreSQL upgrade, head downgrade/upgrade roundtrip, model drift (`flask db check`), and upgrade from the previous release tag |
| `integration` | Full suite against PostgreSQL + Redis |
| `docker` | Production image build and a `/api/v1/health` smoke test |

`release.yml` runs only on protected `v*` tags: it builds, signs (cosign), and
publishes the image with CycloneDX SBOMs. It never deploys.

## Suite map

| Suite | Use cases |
|---|---|
| `test_agent_cli.py` | Agent CLI arg handling, register payload, and quiet HTTP-error behavior |
| `test_agent_reporting.py` | Agent package normalization, local NVD matching, unified source attribution, empty-cache behavior |
| `test_scanner_subprocess.py` | Scanner adapters against fake nmap/nuclei binaries (argv, output parsing) |
| `test_agent_shell.py` | Admin authorization, agent transport, lifecycle/limits, capability exposure, and a real local PTY |
| `test_agent_telemetry.py` | Endpoint collection contract and secret-safe serializers |
| `test_activity_logs.py` | In-memory history and authenticated log API |
| `test_auth_scan.py` | SSH host facts, version normalization, CPE resolution, auth scan API validation |
| `test_tier1_foundation.py` | roles, API keys, Socket.IO auth, durable job lifecycle/cancellation |
| `test_api_coverage.py` | core REST resources, permissions, scan profiles, settings redaction |
| `test_dashboard_api.py` | aggregation, sorting, filtering, pagination, topology integrity |
| `test_feed_caches.py` | NVD feed metadata schema and native ExploitDB CSV caching/lookups |
| `test_campaigns.py` | starter playbook registry, patch campaign staged rollout, canary, failure-threshold stop |
| `test_automation.py` | executor boundary, playbook validation + content-addressing, ephemeral inventory, run job + event mapping |
| `test_dispositions.py` | FP/risk-acceptance approval gating, suppression without evidence loss, auto-expiry + reopen, effective risk |
| `test_remediation.py` | informational remediation guidance: advisory-backed vs heuristic, no secrets/payload |
| `test_vuln_intel.py` | EPSS + CISA KEV ingestion (idempotent, tracked-only), exploit maturity, transparent priority score |
| `test_canonical_findings.py` | shared definitions, stable occurrence identity across sources, immutable observations, lifecycle |
| `test_agent_parity.py` | v3 agent report (patch state, service health, platform), capability health, rollout rings |
| `test_inventory_history.py` | package observation intervals, asset timeline, identity/port change events |
| `test_discovery.py` | discovery scope authorization, approval gating, bounded sweeps, scan allow/deny |
| `test_asset_lifecycle.py` | asset business context, lifecycle/decommission, tags, dynamic groups, discovery non-clobber |
| `test_exec_profiles.py` | versioned scan profiles, time-window/cron/timezone validation, missed-run policy, observation deltas |
| `test_api_contract.py` | uniform error envelope, legacy deprecation headers, expanded webhook events, OpenAPI coverage |
| `test_job_control.py` | generic /jobs API, immutable JobEvent stream, idempotency, lease reconcile, Beat due-work dispatch |
| `test_reports.py` | report scopes, rendering, and report records |
| `test_security_baseline.py` | envelope encryption, production config guard, audit trail, rate limiting, transport headers |
| `test_organizations.py` | memberships, per-org roles, platform admin, API-key org binding, org switch |
| `test_tenant_isolation.py` | two-org matrix: scoped lists, cross-org 404, auto-filtered direct queries, same-IP coexistence |
| `test_webhooks.py` | delivery signing, retries, filters, and CRUD |

## Test design conventions

- Use the `testing` app config and recreate the in-memory schema per test class.
- Mock network/process scanner boundaries; exercise real service and database
  logic beneath those boundaries.
- Assert both the immediate response and persisted/unified representation.
- Every bug fix should include a failing regression case before or alongside
  the implementation.
- Tests must not require Nmap, Nuclei, SSH access, Redis, PostgreSQL, or the
  internet unless explicitly marked as an integration test.

## Current coverage and gaps

The September 2026 baseline is 59 passing tests and 48% statement coverage
across `artemis` plus the standalone agent. Database/API aggregation has the
strongest coverage. The next valuable suites are scanner subprocess fixtures,
Socket.IO scan lifecycle tests, site/scheduler failure matrices, and agent CLI
registration/config-file tests. Coverage runs on Python 3.14 currently expose
resource warnings from repeated in-memory SQLite app teardown; they do not fail
the suite but should be removed as test-infrastructure cleanup.
