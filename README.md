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
- **Asset Management** — Track scanned hosts, scan history, technology stacks
- **Real-time UI** — WebSocket-powered with live scan logs, multiple themes

## Tech Stack

- **Backend:** Python, Flask, Flask-SocketIO
- **Scanning:** Nmap (python-nmap), Nuclei
- **Fingerprinting:** Custom engine with JSON signature database
- **Database:** SQLAlchemy with Alembic migrations; SQLite for local development
- **Jobs:** Celery with Redis-backed durable execution in production
- **Frontend:** Vanilla JS, Socket.IO

## Quick Start

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

Site scans are the first workload on the durable queue. Their state is exposed at
`/api/v1/scan-jobs`; remaining interactive scan types are being migrated incrementally.

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
