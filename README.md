# 🛡️ Artemis — Vulnerability Scanner

A web-based network vulnerability scanner and asset fingerprinting platform powered by Nmap, Nuclei, and a custom endpoint identification engine.

## Features

- **Port Scanning** — Nmap-based service discovery with CIDR range support
- **Endpoint Fingerprinting** — Identifies what's actually running on each port using:
  - HTTP header analysis (Server, X-Powered-By, custom headers)
  - HTML body pattern matching (91 technology signatures)
  - Favicon hash matching (MMH3, Shodan-compatible)
  - TLS certificate inspection (Subject CN/Org, SAN)
  - Service banner and CPE parsing
  - URL path probing for known endpoints
- **Vulnerability Scanning** — Nuclei-based with NVD enrichment (CVSS, CWE, references)
- **Agent Inventory Matching** — Agent package reports are CPE-normalized and matched against the local NVD cache
- **Asset Management** — Track scanned hosts, scan history, technology stacks
- **Operator Activity Log** — Recent backend history plus live WebSocket scan output

## Tech Stack

- **Backend:** Python, Flask, Flask-SocketIO
- **Scanning:** Nmap (python-nmap), Nuclei
- **Fingerprinting:** Custom engine with JSON signature database
- **Database:** SQLAlchemy with Alembic migrations; SQLite for local development
- **Jobs:** Celery with Redis-backed durable execution in production
- **Frontend:** Vanilla JS, Socket.IO

## Quick Start

### Docker Compose (full stack)

```bash
cp .env.example .env   # set SECRET_KEY and POSTGRES_PASSWORD
docker compose up -d --build
```

Open <http://localhost:5005> and create the admin account. This brings up the
web UI, a Celery worker, PostgreSQL, and Redis, with `nmap` and `nuclei`
bundled in the image. See [DEPLOY.md](DEPLOY.md) for details.

### Local development

```bash
python -m venv env
. env/bin/activate
python -m pip install -e '.[dev]'
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
python run.py
```

Local development executes queued jobs eagerly. Production requires PostgreSQL,
Redis, migrated schemas, and separate web and worker processes:

```bash
export FLASK_CONFIG=production
export DATABASE_URL=postgresql+psycopg://artemis:password@localhost/artemis
export CELERY_BROKER_URL=redis://localhost:6379/0
export CELERY_RESULT_BACKEND=redis://localhost:6379/1

python -m pip install -e '.[postgres]'
flask --app run.py db upgrade
celery -A artemis.celery_app:celery_app worker --loglevel=INFO
python run.py
```

Site scans and ad-hoc `POST /api/v1/scans` requests run on the durable Celery
queue; their state is exposed at `/api/v1/scan-jobs`.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for code structure and data
flows, and [docs/TESTING.md](docs/TESTING.md) for the test-suite map and commands.

## REST API

PostgreSQL is the system of record for all application state. The NVD / CPE /
ExploitDB feed cache is a local SQLite read-cache (`NVD_CACHE_PATH`), rebuilt by
sync — not the system of record.

Interactive docs and the machine-readable spec:

| URL | |
|-----|--|
| `/api/v1/docs` | Swagger UI (public) |
| `/api/v1/openapi.json` | OpenAPI 3.0 document (public) |
| `/api/v1/health` | dependency health (public) |

Authenticate with a bearer JWT (`POST /api/v1/auth/login`) or an `X-API-Key`
header. Agent endpoints use `X-Agent-Key`.

### Webhooks

Configure outbound webhooks under **Settings → Webhooks** or via
`/api/v1/webhooks`. Events: `scan.completed`, `vulnerability.discovered`,
`asset.discovered`, `agent.registered`, `agent.report.received`,
`site.scan.completed`. Each delivery is a signed POST carrying
`X-Artemis-Signature: sha256=<hmac_sha256(secret, body)>`, retried with
exponential backoff (up to 5 attempts); the delivery log is at
`/api/v1/webhooks/<id>/deliveries`.

## Fingerprint Signatures

The fingerprint engine includes 91 signatures across 38 categories:

| Category | Examples |
|----------|----------|
| Web Servers | Apache, nginx, IIS, Caddy, LiteSpeed |
| Firewalls | Palo Alto PAN-OS, FortiGate, Cisco ASA, pfSense, OPNsense |
| CMS | WordPress, Drupal, Joomla |
| Virtualization | VMware vCenter/ESXi, Proxmox VE |
| Management | Dell iDRAC, HPE iLO |
| Monitoring | Grafana, Kibana, Zabbix, Nagios, Prometheus |
| Databases | Elasticsearch, MongoDB, Redis, MySQL, PostgreSQL, MSSQL |
| Network | Cisco, MikroTik, Ubiquiti UniFi |
| Load Balancers | F5 BIG-IP, Citrix NetScaler, HAProxy |
| And more... | Jenkins, GitLab, Splunk, Keycloak, Portainer, etc. |

Signatures are stored in `fingerprint/signatures.json` and can be extended easily.
