# Artemis remaining-roadmap implementation plan

Prepared September 3, 2026. This document is intended as a handoff to an
implementation agent. It reconciles `ROADMAP.md` with the repository as it
exists now; unchecked roadmap boxes are not assumed to be wholly unimplemented.

## Handoff preflight

1. Preserve the current dirty worktree. It contains the agent remote-shell,
   agent-upgrade restart, NVD cache schema, and native ExploitDB cache changes.
   Land or stash that work deliberately before starting a roadmap workstream.
2. Establish the baseline with `pytest`, Ruff, the frontend production build,
   `flask db upgrade` against a fresh PostgreSQL database, and
   `docker compose config`.
3. Record the answers in **Decision gates** below. Recommended defaults are
   supplied so work can continue where a decision is not yet available.
4. Work in the phase order below. Do not add new tenant-owned models before the
   organization boundary in Phase 1 is complete.

Owner decisions recorded September 3, 2026: D2, D9, and D11–D14 are resolved.

## Decision gates for the owner

| # | Question | Decision/default | Blocks |
|---|---|---|---|
| D1 | Is Artemis truly a multi-tenant service, and must one user belong to several organizations? Is a cross-organization platform administrator required? | Yes to all three: global identity, organization memberships with per-org roles, and an audited `platform_admin` role. Migrate existing data into one `Default` organization. | Phase 1 and every later schema |
| D2 — resolved | Which endpoint operating systems and transports must be supported first? | Linux and macOS, using a mixture of controller/engine-to-host SSH and agent-local execution for outbound-only hosts. Windows is out of initial scope. Test representative Debian/Ubuntu, RHEL-family, and the current plus previous macOS release unless a narrower matrix is supplied. | Phase 3 agent schema and Phase 5 execution transport |
| D3 | Which secret root is available in production: an environment/file key, HashiCorp Vault, a cloud KMS, or CyberArk? | Implement envelope encryption with a required deployment key first, plus a Vault adapter. Treat CyberArk and cloud KMS providers as later adapters. | Phase 0 secrets, Phase 7/8 credentials |
| D4 | Should remote scan engines connect outbound to Artemis, or may the controller connect inbound to engines? Can mTLS certificates be issued? | Outbound engine registration, polling/streaming, short-lived job leases, and mTLS where possible; no inbound listener requirement. | Phase 6 |
| D5 | Which integrations are required first? | Generic signed webhook/outbox, JSON/CEF syslog, Slack/Teams webhook, Jira, Splunk HEC, then ServiceNow/Elastic-specific adapters. | Phase 7 ordering |
| D6 | Which workload targets matter first? | Docker/OCI images with Trivy, then Kubernetes, AWS, Azure, and GCP. | Phase 8 ordering |
| D7 | How should HTTPS certificates be supplied for private deployments? | Put a reverse proxy in Compose, support user-provided certificates and public ACME, redirect HTTP, set secure cookies/HSTS, and keep Gunicorn HTTP-only on the internal network. | Phase 0 deployment hardening |
| D8 | What are the retention rules for scan evidence, software history, audit events, reports, and decommissioned assets? | Configurable per organization; suggested defaults: job logs 30 days, observations 13 months, audit events 2 years, reports 1 year, decommissioned asset records retained indefinitely unless explicitly purged. | Storage design in Phases 1–4 |
| D9 — resolved | Which endpoint changes may Artemis execute, and which require approval? | No secondary approval workflow. An authorized operator may directly execute package, service, reboot, agent-upgrade, identity/access, or fleet-wide work. Keep role authorization, launch confirmation, optional preview/canary controls, and a complete audit record. Finding responses remain informational until the operator explicitly starts an automation run. | Phases 4–5 |
| D10 | Is MIT the intended project license, and is automated deployment from CI desired? | Add the MIT license named in `pyproject.toml`; keep CI publish/deploy gated behind protected tags and explicit environment approval. | Phase 0 repository/CI |
| D11 — resolved | Should Artemis embed Ansible Runner or integrate with an existing AWX/Automation Controller? | There is no existing controller. Embed Runner behind an executor interface and omit the AWX adapter from the initial backlog. Preserve the interface seam without building unused integration code. | Phase 5 architecture |
| D12 — resolved | Where will playbooks live, and how are they promoted? | Initially accept ad-hoc playbook content for each run. Store the exact submitted content or bundle encrypted and content-addressed with its digest and job record. Add reusable Git-backed projects and immutable commit execution later without changing the executor contract. | Phase 5 content and supply chain |
| D13 — resolved | What fleet size and peak concurrency must the first release support? | Fewer than 100 endpoints. Validate 100 simultaneous agent connections, 10 concurrent automation jobs, and a full-fleet reconnect; keep all limits configurable. | Phases 2, 5, and 9 |
| D14 — resolved | Is remote-shell recording required, and may operators retain root shells? | Record session metadata only for now: actor, agent, start/end, duration, source, close reason, and exit status. Do not retain terminal input/output. Retain the current agent-process privilege, including root, with admin-only launch and prominent UI/audit labeling. | Phase 5 transport/security |

## Reconciled roadmap status

### Complete enough to remove from the remaining backlog

- Flask application factory and `api/models/services/scanners/tasks` structure.
- PostgreSQL/Alembic production path, Redis/Celery services, persisted scan jobs,
  Docker Compose, and environment-based configuration.
- JWT/cookie authentication, API keys, three ordinary roles, read-only write
  protection, authenticated Socket.IO commands, basic target validation, and
  initial cancellation APIs.
- `/api/v1`, generated OpenAPI/Swagger endpoints, webhook CRUD/delivery, React
  frontend, dashboard overhaul, and executive reporting.
- Initial endpoint agent inventory, local package/CVE correlation, telemetry,
  and remote shell.

### Partial implementations that must be completed

- Scanner modules exist, but `app.py` (1,449 lines), `vuln_scan.py` (2,297
  lines), `socketio_handlers.py` (956 lines), and the scheduler still contain
  compatibility/orchestration logic.
- Ad-hoc REST and site scans use Celery; Socket.IO port/vulnerability/
  fingerprint/auth scans, scheduled scans, NVD sync, and report scheduling
  still depend on in-process daemon/scheduler threads.
- PostgreSQL holds current application state, but top-level compatibility code
  still contains raw SQLite application operations. SQLite must remain only for
  the rebuildable NVD/CPE/ExploitDB feed cache.
- Scheduling supports cron, site exclusions, scanner rate options, and a basic
  vulnerability delta, but lacks durable schedule dispatch, time windows,
  concurrency policy, complete cancellation, and stable observation deltas.
- OpenAPI lists routes, but schemas, error contracts, permission annotations,
  and compatibility/version policy are incomplete.
- CI tests/builds the Python package, but does not type-check/build the frontend,
  exercise PostgreSQL/Redis, enforce a coverage floor, scan dependencies/images,
  or publish approved artifacts.
- `requirements.txt` exists but is stale and unpinned; `pyproject.toml` is the
  newer dependency source and must become authoritative.
- Logging has useful stdout and bounded UI history, but no structured event
  format, durable audit log, correlation IDs, or runtime rotation policy.

### Not implemented

- Organizations/tenant isolation.
- Rich asset lifecycle/groups/business context and inventory history.
- EPSS/KEV/vendor advisory/remediation intelligence.
- Fleet orchestration, ad-hoc Ansible jobs, maintenance workflows, and a
  low-latency agent control channel.
- Remote scan engines and failover.
- SIEM/ticketing/chat/SOAR adapters beyond generic webhooks.
- Container/Kubernetes/cloud inventory and vulnerability coverage.
- Encrypted/external credential vault.
- False-positive and risk-acceptance workflows.
- Request rate limiting and default HTTPS deployment.

### Coverage of the numbered roadmap

| Roadmap item | Plan destination |
|---|---|
| 1. Architecture refactor | P2 durable control plane; P9 legacy removal |
| 2. Authentication/multi-tenancy | P0 security baseline; P1 organization isolation |
| 3. REST API | P2.4 contract completion |
| 4. Testing/CI | P0.2–P0.3 |
| 5. Scheduled scans | P2.1–P2.3 |
| 6. Agent scanning | P3.3–P3.4; P5 agent transport and execution |
| 7. Vulnerability intelligence | P4.1–P4.3 |
| 8. Asset management | P3.1–P3.3 |
| 9. Fleet management/orchestration | P5 |
| 10–12. Reporting/dashboard/frontend | Maintain as released capabilities; extend in each feature phase |
| 13. Distributed engines | P6 |
| 14. Integrations | P7 |
| 15. Container/cloud | P8 |
| 16. Credential vault | P0.4 foundation; provider adapters in P7–P8 |
| 17. False positives | P4.4 |
| Quick wins | P0 hardening/CI, P2 cancellation/API, P9 operations/documentation |

## Target architecture rules

These rules apply to every phase:

1. PostgreSQL is the only system of record. SQLite is allowed only for public,
   rebuildable intelligence caches.
2. HTTP handlers validate/authorize and call services; services own use cases;
   Celery tasks own durable execution; scanner/provider adapters own external
   commands and APIs.
3. Every tenant-owned row has a non-null `organization_id`, every unique key
   includes it, every job/event carries it, and every read/write proves scope.
4. Prefer immutable observations plus derived current state over overwriting
   security evidence.
5. Scanner work is represented by a persisted job before dispatch. Socket.IO
   transports progress only; disconnecting a browser never controls job life.
6. Secrets are encrypted references, never ordinary serializer fields, logs,
   job options, or webhook payloads.
7. External providers implement a common adapter contract and use the outbox /
   retry machinery; provider-specific behavior does not enter core models.
8. All migrations are forward/backward data-tested on populated PostgreSQL.
   Use expand/backfill/contract migrations for non-null or uniqueness changes.

## Phase 0 — stabilize and harden the existing product

### P0.1 Land the current worktree

- Review and commit the remote shell, agent 1.3 upgrade, NVD metadata, and
  ExploitDB cache changes as coherent commits.
- Rebuild Compose, migrate a fresh and an existing database, upgrade one real
  agent, and exercise a terminal session and intelligence sync.
- Update `ROADMAP.md` and the test-count/coverage statements after the merge.

**Acceptance:** clean worktree; fresh and upgrade deployments pass; no missing
`settings` or `cve_searchsploit` errors; upgraded agent reports 1.3 plus
`remote_shell`.

### P0.2 Dependency and repository hygiene

- Make `pyproject.toml` the human-edited dependency source. Remove obsolete
  packages from `requirements.txt` and generate hashed production/dev lock
  files with one documented tool.
- Pin Python, Node, Nuclei, base images, and GitHub Actions to controlled update
  policies. Add Dependabot/Renovate and a scheduled dependency review.
- Add the confirmed license, `CONTRIBUTING.md`, security reporting policy,
  development setup, migration rules, and release/versioning policy.

**Tests:** clean environment installation from locks; Python package build;
frontend `npm ci`; license/dependency scanner.

### P0.3 CI and release gates

- Split CI into Python lint/test/coverage, frontend type-check/build/test,
  PostgreSQL migration/integration, Redis/Celery task integration, and Docker
  image build/smoke jobs.
- Test both a fresh migration and upgrade from the previous release database.
- Add coverage reporting and initially set the floor at the measured baseline;
  raise it per phase. Add scanner subprocess fixtures and agent CLI tests.
- On protected version tags, produce an immutable image/SBOM and signed release
  artifacts. Do not auto-deploy without D10 approval.

**Acceptance:** required checks fail on schema drift, frontend type errors,
tenant leaks, or a coverage regression; built image passes `/api/v1/health`.

### P0.4 Security and operations baseline

- Encrypt existing credentials with versioned envelope encryption. Backfill
  ciphertext, verify decryptability, then remove plaintext and filesystem
  `key_path` assumptions. Add secret-access audit events and rotation metadata.
- Add Redis-backed request limits with separate policies for login/setup,
  user/API writes, expensive queries, agent reports, and high-frequency shell
  polling. Return standard `429` responses with retry metadata.
- Add the HTTPS reverse-proxy profile chosen in D7, trusted proxy handling,
  secure/same-site cookies, HSTS, CSP, request-size limits, and CSRF review.
- Emit structured JSON logs with request/job/organization correlation IDs.
  Persist security-relevant `AuditEvent` rows. Configure Docker/runtime log
  rotation; use an optional rotating file handler only for non-container use.
- Apply an explicit permission matrix to every mutation. Credential, agent-key,
  settings, integration, and shell administration must be admin-only.

**Acceptance:** no plaintext credential remains; rate-limit tests are
deterministic; production refuses insecure secret/TLS configuration unless an
explicit development override is set; audit events cover login, secret reads,
role changes, scan starts/cancels, shell lifecycle, dispositions, and exports.

## Phase 1 — organization boundary and canonical resource identity

This phase must precede new enterprise models.

### P1.1 Identity and organization context

- Add `Organization`, `OrganizationMembership`, and invitations. Keep `User` as
  a global identity; move ordinary role assignment to membership. Add the D1
  platform role separately.
- Create a Default organization and membership for every existing user.
- Resolve the active organization from an explicit header/session selection,
  verify membership on every request and Socket.IO connection, and bind API
  keys to one organization. Include organization context in Celery signatures.
- Add organization CRUD/member/role endpoints and an organization switcher.

### P1.2 Tenant columns and resource normalization

- Add nullable `organization_id` to all application resources, backfill Default,
  add scoped indexes/uniques, then make it non-null. This includes assets,
  findings, scans, fingerprints, credentials, settings, schedules/history,
  sites, jobs, agents/reports/data/shells, webhooks/deliveries, reports/schedules,
  and risk snapshots.
- Change globally unique fields such as asset IP, site name, agent key metadata,
  credential name, and webhook ownership to organization-scoped uniqueness.
- Add `asset_id` foreign keys to port scans, fingerprints, findings, software,
  OS facts, and agent data. Backfill by `(organization_id, ip)`, switch services,
  then retire IP-only relationships.
- Split system-wide feed/runtime settings from organization branding, SMTP,
  policies, retention, and integration settings.

### P1.3 Enforced scoped data access

- Introduce one tenant-aware repository/query boundary and ban unscoped
  tenant-model queries in application code. Make missing context fail closed.
- Add PostgreSQL row-level security as defense in depth if D1 requires hostile
  tenant isolation; set and reset organization context safely per transaction.
- Scope filesystem artifacts beneath organization-specific paths and prevent
  path traversal/cross-org report downloads.

**Tests/acceptance:** a two-organization matrix covers every API method,
Socket.IO room, background task, report artifact, webhook, agent, and shell.
Cross-org IDs return 404 and produce no timing/data leak. A static check rejects
new unscoped tenant queries. Existing installations migrate into Default with
unchanged counts.

## Phase 2 — one durable job and API control plane

### P2.1 Unify all asynchronous work

- Expand `ScanJob` into a generic `Job` or extend its types for port, vuln,
  fingerprint, auth, site, scheduled scan, NVD/CPE/ExploitDB/EPSS/KEV sync,
  report generation/delivery, discovery, endpoint operation, Ansible run,
  integration, and engine work.
- Add immutable `JobEvent` records (`queued`, progress, structured log, result,
  retry, cancel, failure), progress counters, parent/child jobs, leases,
  idempotency keys, and retention.
- Move Socket.IO scan handlers to REST job creation plus job-event subscription.
  Remove `_spawn_scan_thread` and per-browser `active_scans`.
- Replace the web-process scheduler thread with Celery Beat invoking a
  singleton, database-backed “dispatch due work” task. Due scheduled scans and
  reports create jobs; they never execute inside the scheduler tick.

### P2.2 Cancellation and scanner lifecycle

- Pass a database/Redis cancellation predicate into every adapter. Launch Nmap,
  Nuclei, fingerprint helpers, and child tools in process groups; terminate,
  wait, then kill on timeout. Close SSH sessions cooperatively.
- Check cancellation between expanded CIDR targets and expensive enrichment
  batches. Mark partial evidence explicitly and make terminal transitions
  compare-and-set/idempotent.
- Reconcile orphaned `running` leases after worker loss and distinguish retryable
  infrastructure failures from deterministic scan failures.

### P2.3 Scheduling and execution-profile completion

- Model reusable scan execution profiles: allowed time windows/time zone, max hosts,
  exclusions, scanner rate, concurrency, credentials, engine pool, retry, and
  notification rules. Schedules reference versioned profiles.
- Validate cron/time zones and compute missed-run behavior explicitly (`skip`,
  `run_once`, or `catch_up`). Prevent duplicate dispatch with a unique schedule
  occurrence key.
- Replace summary-JSON deltas with comparisons of stable finding/asset/software
  observation identities. Expose new, resolved, reopened, and changed results.

### P2.4 API contract completion

- Standardize envelopes, pagination, filtering, sorting, errors, timestamps,
  idempotency headers, optimistic concurrency, and async `202 + job URL`
  responses across `/api/v1`.
- Define reusable request/response schemas and generate OpenAPI from those
  schemas rather than fallback docstrings. Annotate auth/roles and examples.
- Add versioned resource coverage for all supported UI actions; deprecate
  `/api` aliases and `/classic`, then remove them after a documented window.
- Expand webhook events to job state, finding lifecycle, endpoint-job failure,
  disposition approval, asset lifecycle, and integration failure. Add event
  IDs and replay/idempotency semantics.

**Tests/acceptance:** no scanner/sync/report function starts a daemon thread;
browser disconnect does not stop work; forced worker death is recovered;
cancellation kills the real fixture subprocess; schedules dispatch once; the
OpenAPI contract validates and every operation has schemas, roles, and errors.

## Phase 3 — real asset and agent management

### P3.1 Asset context and lifecycle

- Add criticality, environment, business owner/team, external ID, notes,
  lifecycle (`active`, `stale`, `decommissioned`), decommission reason/date,
  first/last-seen source, and manual-field provenance.
- Add organization-scoped tags, static groups, and saved/dynamic groups. Use
  normalized join tables, not JSON arrays. Add bulk edit/tag/decommission APIs.
- Ensure discovery never overwrites manual business metadata and never silently
  reactivates a decommissioned asset; create a review event instead.

### P3.2 Monitored-subnet discovery

- Add discovery scopes with CIDR allowlists, exclusions, engine, schedule,
  maximum size, and approval state. Discovery creates ordinary durable jobs.
- Perform bounded host discovery and upsert assets as `discovered`; record
  source and observation time. Alert on new hosts and decommissioned reappearance.
- Require explicit authorization for broad/public ranges and enforce global and
  organization scan allow/deny rules before dispatch.

### P3.3 Historical inventory

- Replace point-in-time package overwrite with inventory snapshots and package
  observations (`first_seen`, `last_seen`, version interval, installed/removed).
- Record port/service, OS, and identity changes with source and job/report IDs.
- Add asset timelines and software/port change views; expose retention controls.

### P3.4 Agent parity

- Version the agent report schema and add patch/update state, reboot-required,
  package-manager/vendor advisory identifiers, services, uptime, and resource
  health.
- Split platform collectors behind a common interface. Linux collectors cover
  `/proc`, systemd, apt/dpkg, dnf/rpm, and the kernel reboot indicator; macOS
  collectors cover `sysctl`/`ps`, launchd, system software updates, Homebrew
  when installed, and restart state. Missing optional tools produce an explicit
  unsupported value rather than a failed report.
- Add signed, typed agent work requests for inventory and endpoint operations;
  never encode automation as keystrokes sent through the unrestricted shell.
- Add agent rollout rings, minimum supported version, upgrade status, capability
  health, and a tested rollback-safe upgrade path.
- Package and test systemd installation on Linux and a launchd plist/package on
  macOS. Preserve outbound-only enrollment and ensure upgrade/restart behavior
  is atomic on both platforms.

**Acceptance:** users can group/tag/own/decommission assets; discovery is bounded
and auditable; historical queries show install/update/remove transitions; agent
and SSH inventory produce the same canonical observation schema.

## Phase 4 — canonical findings, intelligence, remediation, and exceptions

### P4.1 Canonical finding model

- Introduce global `VulnerabilityDefinition` and tenant-owned
  `FindingOccurrence`/`FindingObservation`. Preserve source evidence and stable
  identity across Nuclei, agent, SSH, container, and cloud sources.
- Migrate `vulnerabilities` and `cve_matches`, retain compatibility reads during
  backfill, then remove the Python-time merge and source-overwrite limitation.
- Track `open`, `resolved`, `reopened`, `suppressed`, and `accepted` separately
  from raw observations.

### P4.2 Vulnerability intelligence feeds

- Load FIRST EPSS from its daily bulk CSV; store score, percentile, model date,
  and history needed to explain prioritization.
- Load CISA KEV from the official JSON catalog; store date added, due date,
  ransomware flag, required action, and source revision.
- Preserve ExploitDB evidence and add normalized exploit evidence types. Derive
  maturity (`none`, `poc`, `weaponized`, `known_exploited`) from evidence with
  explicit rules rather than a single boolean.
- Add vendor-advisory adapters only for selected platforms. Store advisory URL,
  vendor severity, affected/fixed package versions, and retrieval provenance.
- Compute a transparent priority score from severity, EPSS, KEV, exploit
  maturity, asset criticality/exposure, and age; expose every factor.

### P4.3 Remediation guidance

- Generate vendor/package-specific fixed-version guidance from trusted advisory
  data. Include affected assets, reboot/restart notes, validation, and source
  links. Mark heuristic guidance clearly.
- Keep finding responses informational. An operator may explicitly start a
  Phase 5 ad-hoc run or later reusable template linked to that guidance; never
  place credentials or an executable remediation payload in a finding response.

### P4.4 False-positive and risk-acceptance workflow

- Add dispositions with type, scope (occurrence/asset/group/org), rationale,
  evidence, requester, approver, expiry, review date, and status.
- Add reusable suppression rules keyed by stable finding fingerprints. Continue
  ingesting raw observations while suppressing presentation/notifications.
- Require approval for risk acceptance/organization-wide suppression; expire
  and reopen automatically; audit all transitions. Add bulk workflows and
  effective-risk reporting.

**Tests/acceptance:** feed imports are idempotent and retain source dates;
priority factors are deterministic; a resolved finding reopens on new evidence;
suppression never deletes evidence; expired acceptance returns to open and
notifies; tenant boundaries apply to every disposition.

## Phase 5 — fleet management and Ansible orchestration

This phase intentionally excludes benchmark evaluation, control mappings,
configuration scoring, and pass/fail posture dashboards. Its purpose is to let
operators understand and safely operate their endpoints.

### Research conclusion

| Option | Role in Artemis | Decision |
|---|---|---|
| Embedded Ansible Runner | Execute operator-supplied or reusable content, capture structured events/artifacts, and support cancellation/isolation | Default and only initial execution backend |
| AWX/Automation Controller | Delegate launches to a separate automation control plane | Keep only an interface seam; no initial implementation because none is deployed |
| `ansible-pull` | Autonomous VCS pull and local execution on intermittently connected endpoints | Defer; it weakens immediate lease, event, and cancellation semantics |
| Custom Ansible connection plugin over the Artemis agent | Execute controller-side modules through the outbound agent tunnel | Defer until the persistent channel is proven; it is a separate file-transfer/privilege/cancellation project |

Use a hybrid transport: standard Ansible SSH from an execution node when the
host is reachable; signed agent-local execution for enrolled, outbound-only
hosts. Both must emit the same Artemis job-event contract.

### P5.1 Replace shell polling with a persistent agent channel

- Add a versioned, outbound agent WebSocket (`wss`) transport, authenticated
  with the enrolled agent identity and rotating short-lived credentials. Use
  heartbeats, sequence/acknowledgement numbers, bounded queues, reconnect with
  jitter, resume from the last acknowledged event, and explicit backpressure.
- Multiplex typed channels for presence, terminal input/output/resize, job
  leases, job events, artifact transfer, and cancellation. Every envelope has
  agent/job/session ID, protocol version, sequence, expiry, and idempotency key.
  Reject unknown, expired, replayed, or over-limit messages.
- Use a maintained, pinned Socket.IO/WebSocket client in the agent rather than
  implementing framing and reconnect behavior from scratch. Update Compose and
  reverse-proxy settings for WebSocket upgrades, long idle timeouts, and Redis
  fan-out across multiple web workers.
- Bridge browser terminal rooms through the existing authenticated Socket.IO
  layer. Stream agent output immediately instead of persisting it and waiting
  for the browser's 250 ms poll; coalesce small input frames for at most 10–20
  ms. Under D14, do not persist transcript chunks. Keep future encrypted I/O
  recording outside the initial implementation.
- Move transient fallback input/output from PostgreSQL to bounded Redis streams
  with a TTL no longer than the session plus five minutes. Purge existing shell
  chunk rows and retire their durable tables after the fallback migration;
  retain only `AgentShellSession` metadata in PostgreSQL.
- Keep the current HTTPS transport as a temporary fallback, but change it to
  server-held long polling for command delivery and adaptive output batching.
  Report active transport, round-trip latency, reconnect count, and queue depth
  on the agent detail page.
- Separate interactive terminal authorization from endpoint jobs. Enforce one
  operator lease, idle and absolute timeouts, explicit close, backpressure,
  and role checks. Persist D14 metadata but never terminal input or output.
  Clearly label that the session has the agent process's root privilege. Never
  use the terminal byte stream as an automation API.

**Why first:** today the browser polls every 250 ms and the active agent loop
waits 350 ms between HTTPS polls, with a database write/read cycle between
them. That imposes a visible latency floor before network and rendering time.

### P5.2 Establish the Ansible execution boundary

- Add an `AutomationExecutor` interface. Ship an embedded Ansible Runner
  implementation in a dedicated Celery queue. Do not implement an
  AWX/Automation Controller adapter now; only keep the executor boundary clean
  enough to add one later. Artemis remains the source of truth for fleet
  identity, authorization, job history, and operator experience.
- Build pinned Ansible execution-environment images with Ansible Builder.
  Reference images by digest and record the ansible-core, Runner, collection,
  system package, and Python dependency versions on every run. Do not install
  arbitrary collections into the Artemis web container.
- Execute each run in a rootless, resource-limited container with a unique
  private data directory, read-only project content, a bounded artifact path,
  and only required network/filesystem access. Destroy decrypted credentials
  and temporary inventory after completion.
- Map Runner status and structured `job_events` into `Job`/`JobEvent`: play,
  task, host, event type, changed/failed/unreachable/skipped counts, sanitized
  stdout, timestamps, and artifact references. Wire Runner cancellation into
  the normal Artemis job cancellation state machine.
- Initially accept an uploaded YAML file/bundle or pasted playbook for an
  ad-hoc run. Apply content/expanded-size limits, safe archive extraction,
  YAML parsing, `ansible-playbook --syntax-check`, and linting before dispatch.
  Authorized operators are intentionally allowed to use command/shell modules;
  isolation and audit are the boundary, not a module allowlist.
- Store submitted content encrypted and content-addressed, attach its SHA-256
  digest and exact normalized launch options to the immutable job record, and
  never fetch roles/collections dynamically during a run. Secrets use typed
  secret inputs and credential references rather than inline playbook values.
- Add reusable Git-backed `AutomationProject`, `ProjectRevision`, and
  `AutomationTemplate` resources later. Git runs resolve to an immutable commit
  SHA and templates define the playbook, execution environment, credential
  type, target scope, tags, timeout, forks, `serial`, failure threshold,
  preview support, and typed variable schema.
- Allowlist and pin execution images and bundled collections; verify image
  signatures where the registry supports them. Audit content digest/source,
  template/commit when applicable, variables, actor, and target snapshot for
  every launch.
- Add initial `AutomationContent`, `ExecutionEnvironment`, `JobTarget`, and
  `MaintenanceWindow` models. `AutomationContent` identifies pasted/uploaded
  content by digest and encrypted artifact reference. Add project/revision/
  template models only with the later Git phase. Add no separate approval model
  or endpoint. Reuse generic `Job`/`JobEvent` records and parent plus child batch
  jobs for campaigns rather than creating a second job system.

### P5.3 Inventory, credentials, and execution transports

- Generate an ephemeral Ansible inventory from Artemis assets, agents, groups,
  and tags at job launch. Use immutable Artemis IDs as inventory identities and
  source connection address/user/port only from controlled host variables.
  Save the selected target-ID snapshot so membership changes cannot alter a
  running job.
- Prefer inventory generation through a small Artemis inventory plugin once
  the schema stabilizes; start with a generated private inventory artifact to
  reduce plugin surface. Never persist passwords, private keys, or become
  secrets in inventory variables.
- For routable Linux and macOS endpoints, run from the controller or a remote
  execution engine over standard SSH. Discover/configure a supported Python 3
  interpreter and report macOS Full Disk Access or privilege limitations as
  actionable preflight failures. Resolve credentials just in time through the
  Phase 0 vault abstraction, verify host keys, scope credentials to groups/
  hosts, and redact secret values. WinRM/PSRP remains out of scope.
- For outbound-only enrolled agents, add a dedicated `agent_local` executor.
  Deliver a signed manifest containing the immutable job-content digest over
  the typed job channel. A pinned agent-side Ansible runtime runs that exact
  content against `localhost` with `ansible.builtin.local`, streams
  Runner-compatible events, honors cancellation, and deletes staging data.
  This capability must be separately advertised and rejects content whose
  signature or digest does not match the server-created job.
- Do not make `ansible-pull` the primary control plane: its VCS/cron pull model
  is useful for autonomous convergence but does not provide Artemis with the
  immediate leases, cancellation, structured event stream, and per-launch
  audit required here. It can be reconsidered later for disconnected sites.
- Do not initially build a custom Ansible connection plugin over the agent
  channel. Revisit that only if installing the pinned local runtime is
  unacceptable and the transport can correctly implement file transfer,
  privilege escalation, cancellation, and reconnect semantics.

### P5.4 Fleet workflows and operator experience

- Expand the Agents area into a fleet view: saved groups, tags, OS/version,
  agent/runtime version, last seen, active transport, latency, reboot-required,
  pending updates, last job, current job, and rollout ring. Keep asset linkage
  visible, but expose agent-only actions only from an enrolled agent.
- Add an ad-hoc launch wizard accepting pasted/uploaded content, typed secret
  inputs, ordinary variables, an execution environment, and a host/group
  snapshot. Offer check mode and redacted diff when supported, then a normal
  launch confirmation—not a separate approval. Canary selection, `serial`
  batch size, maximum failure percentage, maintenance window, pause between
  batches, cancel, and retry-failed-hosts are optional operator controls.
- Add the reusable project/template library after ad-hoc execution is stable.
  It uses the same launch screen and job contract; selecting a template merely
  replaces submitted content with a pinned project revision and variable schema.
- Provide host and task timelines with live real output—not a generic “waiting
  for activity” line. Summarize `ok`, `changed`, `failed`, `unreachable`, and
  `skipped`, while allowing drill-down to sanitized stdout and artifacts.
- Ship built-in, versioned Linux and macOS starter playbooks for fact refresh,
  package inventory, update preview, batched OS/Homebrew package update,
  controlled reboot with return-to-service validation, systemd/launchd service
  start/stop/restart, agent upgrade/rollback, and a bounded diagnostic bundle.
  Do not ship identity/access starters initially, although D9 allows authorized
  operators to submit such work ad hoc.
- Add patch campaigns as a workflow over templates: snapshot candidate hosts,
  preview, select/exclude, optional canary, staged rollout, reboot coordination,
  post-run fact refresh, and per-host outcome. Report operational state and
  job results; do not introduce configuration scores or benchmark results.
- Expose the same launch/status/cancel/event APIs for integrations. Enforce
  organization, group, template, credential, environment, concurrency, and
  maintenance-window authorization server-side, never only in the UI.
- Start with `POST /api/v1/automation/runs` for multipart/pasted content and
  launch options. Later add `/automation/projects`, `/automation/templates`,
  and `/automation/templates/{id}/launch`. Reuse shared `/jobs/{id}`,
  `/jobs/{id}/events`, and `/jobs/{id}/cancel`; there is no approval endpoint.
  Live delivery subscribes to authorized job rooms, while the REST event
  endpoint is the durable replay/fallback contract.

### P5.5 Tests and acceptance gates

- Protocol tests cover authentication, replay, expiry, ordering, duplicate
  delivery, reconnect/resume, backpressure, cancellation, and bounded buffers.
  An integration test proves terminal echo p95 below 150 ms on a local Compose
  network and verifies the HTTPS fallback remains functional.
- Runner contract tests use fixture playbooks for success, change, unreachable,
  failure, timeout, secret-bearing `no_log`, cancellation, and malformed event
  data. Assert that job events and host summaries survive worker restart.
- Inventory tests prove group/tag targeting, target snapshot immutability,
  credential redaction, host-key enforcement, and tenant isolation. Agent-local
  tests prove signature/content-digest verification and rejection of altered
  content. Run this matrix over representative Linux and macOS fixtures.
- End-to-end tests run ad-hoc submission → optional preview → launch → optional
  canary → serial rollout → fact refresh, including a failed canary that
  prevents later batches. Load tests use D13 targets and include 100-agent mass
  reconnect, slow consumer, and event fan-out.

**Acceptance:** an authorized operator can submit an ad-hoc playbook, select a
fleet group, optionally preview/canary/stage it, see task/host output live, and
cancel it without a second-person approval. The audit trail identifies who ran
which immutable content digest with which non-secret inputs. Routable SSH and
outbound-only agent targets on Linux and macOS produce the same central
job-event shape. Interactive shell echo meets the latency target without losing
output or recording terminal content.

### Recommended Phase 5 delivery packets

| Packet | Deliverable | Depends on |
|---|---|---|
| P5-A | Persistent agent channel, presence metrics, streamed terminal, HTTPS fallback | P2 jobs/events and P0 auth/audit |
| P5-B | Runner worker, execution environment, fixture playbook bundle, SSH inventory, live event UI | P5-A event contract and P0 vault |
| P5-C | Ad-hoc content/run APIs and UI, preview, optional canary/serial controls | P5-B |
| P5-D | Signed Linux/macOS agent-local runtime and identical central event mapping | P5-A–C and D2 |
| P5-E | Linux/macOS patch/reboot/service/agent-upgrade starters and campaign workflow | P5-C–D |
| P5-F | Git projects, immutable revisions, and reusable job templates | P5-C; intentionally later |

Each packet should be independently migratable, feature-flagged, documented,
and releasable. Do not wait for P5-E to ship the terminal latency improvement.

## Phase 6 — distributed scan engines

- Add `ScanEngine`, registration token/certificate, capability, engine pool,
  heartbeat, capacity, version, network labels, and status models.
- Package a scanner-engine service using the existing scanner adapters. It
  connects outbound, leases eligible jobs, streams job events, uploads bounded
  artifacts, renews leases, and reports health.
- Route site/automation jobs to engine pools using required capabilities and
  network scope. Enforce per-engine concurrency and organization authorization.
- Implement lease expiry, retry, and failover only for idempotent/restartable
  work. Never let two engines publish the same occurrence without a shared
  idempotency key.
- Add engine installation/upgrade, certificate rotation/revocation, diagnostics,
  health/capacity UI, and “test reachability” workflows.

**Acceptance:** a controller with no route to a target can dispatch through a
remote engine; engine loss requeues safely; an unauthorized engine cannot see
another pool/org job; version/capability mismatch prevents dispatch with a clear
error; health and job logs remain available centrally.

## Phase 7 — integrations and automation

- Add tenant-owned `Integration`, encrypted credential reference,
  `IntegrationRule`, `OutboxEvent`, and delivery/dead-letter records. Build one
  provider interface for validation, send/upsert/close, health, retryability,
  and rate limits.
- SIEM: JSON and CEF syslog first, then Splunk HEC and Elastic bulk. Include
  stable event IDs, schema version, tenant, finding/asset IDs, timestamps, and
  disposition state; redact secrets/evidence according to organization
  retention and redaction settings.
- Ticketing: Jira then ServiceNow under D5. Deduplicate by finding/rule, update
  existing tickets, close/comment on resolution, preserve backlinks, and honor
  exception state.
- Chat: Slack/Teams cards for high-value events with deep links and throttled
  summaries rather than one message per observation.
- SOAR: reuse signed webhooks with richer event types, replay, secret rotation,
  allowlisted destinations, and optional inbound acknowledgement endpoints.
- Add rule simulation, test delivery, per-integration health, metrics, audit,
  retry/dead-letter UI, and organization egress allowlists.

**Acceptance:** duplicate events do not create duplicate tickets; provider
timeouts retry without blocking scans; permanent failures dead-letter visibly;
secrets never appear in output; SSRF controls reject private/metadata endpoints
unless explicitly allowlisted.

## Phase 8 — container, Kubernetes, and cloud inventory/vulnerability coverage

### P8.1 Generalize targets and evidence

- Introduce a resource identity that can represent host/IP, OCI image digest,
  container, Kubernetes object/cluster, and cloud resource ARN/ID without
  forcing them into the IP-only `Asset` shape.
- Reuse canonical components/findings/observations, groups/tags, jobs, engines,
  dispositions, and reports. Store source-native identifiers and relationships.

### P8.2 OCI images

- Implement the D6 scanner adapter (recommended Trivy) behind a generic image
  scanner interface. Support registry credential references, digest pinning,
  SBOM ingestion, OS/library vulnerability findings, and provenance.
- Add registry/project scan profiles and CI API examples. Never persist pulled
  image layers beyond the configured worker cache retention.

### P8.3 Kubernetes

- Use scoped service-account/kubeconfig secret references. Inventory clusters,
  namespaces, workloads, images, nodes, and relationships. Correlate running
  workloads with image and node vulnerabilities.
- Support remote engines for private clusters and least-privilege inventory
  collection profiles.

### P8.4 Cloud

- Add provider adapters in D6 order with read-only, external-ID/workload-identity
  authentication. Inventory accounts/subscriptions/projects, compute instances,
  managed Kubernetes, and workload/image relationships without erasing
  provider evidence.
- Record collection coverage, denied APIs, regions, and stale resources so a
  partial inventory cannot appear complete.

**Acceptance:** identical image digests deduplicate; rescans create observations
and resolve absent findings; cloud/Kubernetes credentials are encrypted and
least-privilege; partial coverage is visible; all resources are tenant-scoped
and usable by reporting, exceptions, and integrations.

## Phase 9 — roadmap closure and enterprise release criteria

- Remove `app.py`, legacy `/classic`, duplicated raw SQLite state functions, and
  deprecated `/api` aliases after parity and the announced compatibility window.
- Make `vuln_scan.py`, `nvd_feeds.py`, `cpe_dict.py`, and `exploit_ref.py` a
  cohesive intelligence-cache package; no application ORM models may depend on
  it for writes.
- Add backup/restore and disaster-recovery procedures for PostgreSQL, Redis job
  semantics, object/report storage, organization encryption keys, and feed
  caches. Test restoration, not just backup creation.
- Add SLOs/metrics for API, queue latency, scan duration, engine/agent freshness,
  feed age, integration delivery, and scheduler lag. Add readiness/liveness and
  migration/worker version compatibility checks.
- Run threat modeling and security review for tenant isolation, SSRF, command
  execution, remote shell, secret storage, artifact paths, provider credentials,
  and update supply chain. Add abuse and load tests.
- Update `ROADMAP.md` from checkboxes to released capabilities with migration,
  operations, limitations, and support documentation.

**Release definition of done:** all enterprise data paths are tenant-isolated;
all long-running work is durable/cancellable; no plaintext secret or unscoped
artifact exists; supported upgrade/rollback and backup/restore paths are tested;
OpenAPI and UI use the same contracts; critical workflows have integration and
failure-path tests; production observability identifies a failed tenant/job/
engine/provider without enabling debug mode.

## Recommended execution sequence

Use one branch/PR per numbered packet and keep migrations independently
deployable. The critical path is:

`P0 baseline/security → P1 tenancy/identity → P2 jobs/API → P3 assets/agents →
P4 findings/intelligence/exceptions → P5 fleet/Ansible → P6 engines → P7
integrations → P8 cloud/container → P9 removal/GA`

After P1, feed ingestion and CI work can run in parallel with job-control work.
The P5 persistent agent channel can begin after P2 defines canonical jobs and
events; its inventory targeting depends on P3. After P4 establishes canonical
findings, integration and image-scanner adapters can proceed in parallel.
Distributed engine protocol work may begin after P2, but routing production
jobs through it must wait for tenant scoping and canonical job leases.

## External source constraints used by this plan

- FIRST publishes EPSS daily and recommends its bulk CSV for local/batch
  enrichment rather than API-wide mirroring:
  <https://www.first.org/epss/data.html>
- CISA KEV machine-readable feed:
  <https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>
- Ansible Runner is the supported embeddable interface and exposes structured
  events, status handlers, cancellation, artifacts, and process isolation:
  <https://ansible.readthedocs.io/projects/runner/en/stable/intro.html>
- Ansible Builder defines reproducible, versioned execution environments:
  <https://docs.ansible.com/projects/builder/en/stable/definition/>
- Ansible recommends inventory plugins over legacy inventory scripts for
  dynamic sources:
  <https://docs.ansible.com/projects/ansible/latest/inventory_guide/intro_dynamic_inventory.html>
- Standard connection plugins cover SSH and local execution; the local plugin
  executes as the user running Ansible:
  <https://docs.ansible.com/projects/ansible/latest/plugins/connection.html>
  and
  <https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/local_connection.html>
- Ansible-managed POSIX nodes require Python and an SSH account; interpreter
  paths must be recorded explicitly when discovery cannot resolve them:
  <https://docs.ansible.com/projects/ansible/latest/installation_guide/intro_installation.html>
- The official macOS guidance documents Full Disk Access limitations for SSH
  management, while `community.general` supplies Homebrew and launchd modules:
  <https://docs.ansible.com/projects/ansible/latest/reference_appendices/faq.html>,
  <https://docs.ansible.com/projects/ansible/latest/collections/community/general/homebrew_module.html>,
  and
  <https://docs.ansible.com/projects/ansible/latest/collections/community/general/launchd_module.html>
- Check/diff modes and execution controls such as `serial` and failure
  thresholds support preview and staged rollout safety:
  <https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_execution.html>
- `ansible-pull` is a VCS-to-local execution model, which is why this plan keeps
  it out of the primary centrally controlled job path:
  <https://docs.ansible.com/projects/ansible/latest/cli/ansible-pull.html>
