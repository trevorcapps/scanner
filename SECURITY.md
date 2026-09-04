# Security Policy

## Supported versions

Artemis is pre-1.0. Security fixes are applied to the `master` branch and the
most recent tagged release only.

| Version | Supported |
|---------|-----------|
| `master` / latest tag | yes |
| older tags | no |

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Report privately through one of:

- GitHub's **"Report a vulnerability"** flow (Security tab → Advisories), or
- email the maintainer at `trevor.capps@gmail.com` with subject
  `ARTEMIS SECURITY`.

Please include:

- affected component and version / commit,
- a description of the issue and its impact,
- reproduction steps or a proof of concept,
- any known mitigations.

## What to expect

- Acknowledgement within 3 business days.
- An initial assessment and severity rating within 10 business days.
- Coordinated disclosure: we will agree on a disclosure timeline with you,
  typically 90 days or sooner once a fix is available.
- Credit in the release notes and advisory unless you prefer to remain
  anonymous.

## Scope

In scope: the Artemis web application, API, Celery workers, the endpoint agent,
the Docker images and Compose deployment, and the release/update supply chain.

Out of scope: findings that require a pre-existing compromise of the host,
denial of service through resource exhaustion on an unauthenticated endpoint
that is already rate-limited, and vulnerabilities in third-party scanners
(`nmap`, `nuclei`) — report those upstream.

## Handling of scan data

Artemis processes vulnerability and asset data for the operator's own estate.
Deployments are single-organization until the Phase 1 tenancy boundary lands;
until then, treat one Artemis instance as one trust domain.
