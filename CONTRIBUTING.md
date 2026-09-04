# Contributing to Artemis

## Development setup

Artemis is a Flask/SocketIO backend with a Celery worker and a React/Vite
frontend. PostgreSQL is the system of record; SQLite is used only for local
development, tests, and the rebuildable NVD/CPE/ExploitDB feed cache.

```bash
git clone <repo> && cd scanner
python -m venv env && . env/bin/activate
pip install -e '.[all]'          # postgres + wsgi + fingerprint + dev extras

cd frontend && npm ci && cd ..

cp .env.example .env             # set SECRET_KEY; DATABASE_URL defaults to sqlite
FLASK_APP=run.py flask db upgrade
python run.py                    # http://localhost:5005
```

For the full stack (web + worker + PostgreSQL + Redis) use Docker:

```bash
docker compose up -d --build
```

## Dependencies

`pyproject.toml` is the **only** human-edited dependency source. Add or bump a
runtime dependency there (in `dependencies` or the appropriate optional-extra),
then regenerate the lock files with [uv](https://docs.astral.sh/uv/):

```bash
. env/bin/activate
pip install uv
./scripts/lock-deps.sh            # writes requirements.lock + requirements-dev.lock
```

Commit `pyproject.toml` and both lock files together. CI installs from the lock
files; the Docker image installs the `pyproject` extras. Do not hand-edit the
`.lock` files. `requirements.txt` has been removed — it was stale and unpinned.

Dependabot (`.github/dependabot.yml`) opens weekly grouped PRs for pip, npm,
GitHub Actions, and Docker base images. Security updates are never held back.

## Database migrations

- Every schema change ships an Alembic migration in `migrations/versions/`.
- Migrations must be **forward and backward data-tested on populated
  PostgreSQL**. Use expand / backfill / contract steps for new non-null columns
  or uniqueness changes — never a single destructive `ALTER`.
- Tenant-owned tables carry a non-null `organization_id`; every unique key
  includes it (enforced from Phase 1 onward).
- Test both a fresh `flask db upgrade` and an upgrade from the previous release
  database before merging.

## Tests and linting

```bash
. env/bin/activate
ruff check artemis agent tests --select E9,F63,F7,F82
pytest --cov=artemis --cov=agent --cov-report=term-missing

cd frontend && npm run build && cd ..
```

CI runs the same checks plus PostgreSQL/Redis integration and a Docker image
smoke test. A coverage floor is enforced and raised per roadmap phase; new code
should not regress it.

## Coding conventions

- HTTP handlers validate and authorize, then call a service. Services own use
  cases. Celery tasks own durable execution. Scanner/provider adapters own
  external commands and APIs.
- Prefer immutable observations plus derived current state over overwriting
  security evidence.
- Secrets are encrypted references — never plain serializer fields, log lines,
  job options, or webhook payloads.
- Match the style, naming, and comment density of the surrounding code.

## Commit and PR hygiene

- One logical change per commit; conventional-commit style subjects
  (`feat:`, `fix:`, `chore:`, `docs:`).
- One branch/PR per roadmap packet; keep migrations independently deployable.
- PRs must pass all required checks. Describe schema changes, new env vars, and
  any migration ordering constraints in the PR body.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do not open a public issue for a vulnerability.
