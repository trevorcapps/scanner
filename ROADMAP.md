# 🏹 Artemis — Enterprise Readiness Roadmap

## Tier 1: Foundation (Do These First)
*Without these, nothing else scales.*

### Implementation Status
- [x] Application factory with `api/`, `models/`, `services/`, `scanners/`, and `tasks/` boundaries
- [x] Persistent Celery job model, Redis production configuration, retry policy, status API, and cooperative cancellation for site scans
- [ ] Move remaining interactive and scheduled scan types off daemon threads
- [x] Alembic baseline and PostgreSQL driver/configuration
- [ ] Convert remaining raw SQLite services and make PostgreSQL the production system of record
- [x] JWT, API keys, role hierarchy, read-only write protection, and authenticated Socket.IO commands
- [ ] Organization model and tenant isolation on every query and mutation
- [x] Versioned scan-job REST endpoints and initial CI test/build pipeline
- [ ] Complete `/api/v1` resource coverage, generated OpenAPI documentation, and webhooks

### 1. **Architecture Refactor**
- Break the monolith: `app.py` (1,449 lines) and `vuln_scan.py` (2,294 lines) need to become proper modules — `api/`, `models/`, `services/`, `scanners/`
- Introduce a task queue (Celery + Redis) to replace raw `threading` — scans should be durable, retryable, and not die with the process
- Replace SQLite with PostgreSQL — concurrent writes, proper migrations (Alembic), and it won't corrupt under load

### 2. **Authentication & Multi-Tenancy**
- User auth (JWT/session-based) with role-based access (admin, analyst, read-only)
- API key management for automation/integrations
- Org/tenant isolation — Qualys and Nexpose are multi-tenant; Artemis needs to be too

### 3. **REST API**
- Proper versioned API (`/api/v1/`) for everything: scans, assets, vulns, reports
- OpenAPI/Swagger docs auto-generated
- Webhook callbacks for scan completion
- This unlocks CI/CD integration, which is table stakes for enterprise

### 4. **Testing & CI/CD**
- Unit tests, integration tests, scan simulation tests
- [x] Split CI: Python lint/test, frontend type-check/build, PostgreSQL
  migration + drift, PostgreSQL/Redis integration, Docker image smoke
- [x] Enforced coverage floor, ratcheted per phase
- [x] Signed image + SBOM on protected tags; deploy stays manually gated

---

## Tier 2: Scanner Capabilities (Competitive Parity)
*What makes Nexpose/Qualys actually useful.*

### 5. **Scheduled & Recurring Scans**
- Cron-style scheduling per target/group
- Scan execution profiles (time windows, rate limits, excluded hosts)
- Scan comparison / delta reports ("what changed since last scan")

### 6. **Agent-Based Scanning**
- Lightweight agent for internal hosts (like Qualys Cloud Agent)
- Authenticated scans are good, but agents give continuous visibility without SSH creds everywhere
- Package inventory, patch status, reboot state, and fleet health
- Low-latency remote shell and typed endpoint-management jobs

### 7. **Vulnerability Intelligence**
- EPSS scores (Exploit Prediction Scoring) alongside CVSS
- CISA KEV integration (you have tags, but need first-class tracking)
- Exploit maturity indicators (PoC available, weaponized, in-the-wild)
- Vendor advisory linking (Microsoft, Ubuntu, Red Hat)
- **Remediation guidance** — not just "you have CVE-X" but "run `apt upgrade libfoo`"

### 8. **Asset Management (Real)**
- Asset groups, tags, business context (criticality, owner, environment)
- Auto-discovery of new hosts on monitored subnets
- Software inventory tracking over time (not just point-in-time)
- Asset decommission tracking

### 9. **Fleet Management & Orchestration**
- Treat agents and managed endpoints as first-class fleet resources, with groups,
  tags, health, inventory history, and rollout rings
- Run ad-hoc Ansible playbooks initially, then reusable Git-backed job templates,
  against assets, groups, or agent-local targets with preview, canary,
  serial-batch, pause, cancel, and retry controls
- Manage software updates, services, reboots, agent upgrades, and repeatable
  operator workflows with per-host results and live task logs
- Use an outbound persistent agent channel for responsive shell sessions and
  durable typed work; retain HTTPS polling only as a compatibility fallback

---

## Tier 3: Reporting & UX (What Sells It)
*Enterprise buyers live in dashboards and PDFs.*

### 10. **Executive Reporting** — 🔨 in progress
- [x] Branded HTML report generator (org name, logo, accent colour, confidentiality banner)
- [x] PDF export (WeasyPrint, server-side — works headless for scheduled delivery)
- [x] Executive summary vs. technical detail vs. full views
- [x] Risk trending over time — daily `risk_snapshots` rollup + trajectory chart
- [x] Report scope: whole environment, a site, or a severity/device filter
- [x] Generated-report history (list / download / delete), stored on the data volume
- [x] Reports page in the SPA + REST (`/api/v1/reports`)
- [x] SMTP settings + "send test email"
- [x] Scheduled report delivery via email (`report_schedules`, cron, scheduler hook)

### 11. **Dashboard Overhaul** — ✅ done
- [x] Risk heatmap (device type × severity), CVSS distribution histogram, top-10 findings
- [x] Asset topology / network map (force graph: root → subnet → asset, risk-coloured)
- [x] Scan queue status panel, 30-day activity trends
- [x] Filter / sort / search across the Assets and Findings pages
- [x] Single-payload dashboard aggregation API (`/api/v1/dashboard/*`)

### 12. **Frontend Rewrite** — ✅ done
- [x] React 18 + TypeScript + Vite SPA served at `/` (vanilla app kept at `/classic`)
- [x] Component architecture (`components/{ui,charts,layout}`), 11 routed pages
- [x] State management: TanStack Query (server state) + Zustand (UI state), React Router
- [x] Responsive layout (Tailwind, tablet/mobile breakpoints)

---

## Tier 4: Enterprise Features (Differentiation)
*What gets you into serious conversations.*

### 13. **Scan Engine Distribution**
- Remote scan engines (scan from inside different network segments)
- Engine health monitoring, auto-failover
- This is how Nexpose handles large/segmented environments

### 14. **Integrations**
- SIEM export (Syslog, Splunk, Elastic)
- Ticketing (Jira, ServiceNow) — auto-create tickets for critical vulns
- SOAR playbook triggers
- Slack/Teams notifications

### 15. **Container & Cloud Scanning**
- Docker image scanning (Trivy/Grype integration)
- Kubernetes workload/image inventory and vulnerability correlation
- Cloud instance/workload discovery and vulnerability correlation

### 16. **Credential Vault**
- Encrypted credential storage (not plaintext in scan profiles)
- Integration with HashiCorp Vault, CyberArk
- Credential rotation awareness

### 17. **False Positive Management**
- Mark vulns as false positive with evidence/notes
- Risk-acceptance rules with approval and expiry workflows
- Auto-suppress known FPs across future scans

---

## Quick Wins (Low Effort, High Impact)
*Sprinkle these in between the big items.*

- [x] `pyproject.toml` as the dependency source + hashed `requirements*.lock` files
- [ ] Environment config (`.env` file, not hardcoded paths)
- [x] Rate limiting (Redis-backed, per-category, `429` + `Retry-After`)
- [x] HTTPS deployment overlay (Caddy: ACME or BYO cert, HSTS, secure cookies)
- [ ] Scan cancellation (currently no clean abort mechanism)
- [ ] Input validation hardening (CIDR ranges, hostnames)
- [x] Structured JSON logs with correlation IDs; optional rotating file handler
- [ ] Docker Compose for one-command deployment
- [ ] License file + contribution guidelines

---

## Suggested Order of Attack

| Phase | Items | Timeframe |
|-------|-------|-----------|
| **Phase 1** | Architecture refactor, PostgreSQL, API, Auth | 4-6 weeks |
| **Phase 2** | Scheduled scans, asset management, vuln intel | 4-6 weeks |
| **Phase 3** | Reporting, dashboard, fleet orchestration | 6-8 weeks |
| **Phase 4** | Distributed engines, integrations, cloud | Ongoing |
