# 🛡️ Cerebus — Vulnerability Scanner

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
- **Database:** SQLite
- **Frontend:** Vanilla JS, Socket.IO

## Quick Start

```bash
python -m venv env
. env/bin/activate
python -m pip install -r requirements.txt
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
python app.py
```

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
