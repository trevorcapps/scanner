# Testing Artemis

## Commands

From the repository root:

```bash
python -m venv env
env/bin/python -m pip install -e '.[dev]'
env/bin/python -m pytest -q
env/bin/ruff check --select E,F artemis tests auth_scan.py nvd_feeds.py
npm --prefix frontend ci
npm --prefix frontend run build
```

For coverage:

```bash
env/bin/python -m pytest --cov=artemis --cov=agent --cov-report=term-missing
```

The frontend build runs TypeScript type checking before the Vite production
bundle. `E,F` is the current blocking Ruff baseline. Broader style and
exception-policy rules can be ratcheted in incrementally.

## Suite map

| Suite | Use cases |
|---|---|
| `test_agent_reporting.py` | Agent package normalization, local NVD matching, unified source attribution, empty-cache behavior |
| `test_agent_telemetry.py` | Endpoint collection contract and secret-safe serializers |
| `test_activity_logs.py` | In-memory history and authenticated log API |
| `test_auth_scan.py` | SSH host facts, version normalization, CPE resolution, auth scan API validation |
| `test_tier1_foundation.py` | roles, API keys, Socket.IO auth, durable job lifecycle/cancellation |
| `test_api_coverage.py` | core REST resources, permissions, scan profiles, settings redaction |
| `test_dashboard_api.py` | aggregation, sorting, filtering, pagination, topology integrity |
| `test_reports.py` | report scopes, rendering, and report records |
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
