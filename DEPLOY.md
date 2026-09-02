# Deploying Artemis with Docker Compose

The compose stack runs the whole application: the Flask/SocketIO web UI, a
Celery worker for scan jobs, PostgreSQL, and Redis. The bundled image also
includes the external scanners the app shells out to (`nmap`, `nuclei`).

## Prerequisites

- Docker Engine 24+ with the Compose plugin (`docker compose version`)
- Outbound internet access on the build host (pulls `nuclei` from GitHub)

## First run

```bash
cp .env.example .env

# Fill in the two required secrets:
python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" >> .env
$EDITOR .env        # set POSTGRES_PASSWORD (and optionally NVD_API_KEY)

docker compose up -d --build
```

Then open <http://localhost:5005>. On the first visit, with no users in the
database, Artemis runs in setup mode — create the admin account through the UI.

`WEB_PORT` in `.env` changes the published host port (container always listens
on 5005).

## Services

| Service    | Role                                                        |
|------------|-------------------------------------------------------------|
| `web`      | gunicorn + gevent-websocket serving `run:app`; runs `flask db upgrade` on start and hosts the scan scheduler thread |
| `worker`   | `celery -A artemis.celery_app:celery_app worker` — executes scan jobs |
| `postgres` | Application database (`postgres:16-alpine`), volume `pgdata` |
| `redis`    | Celery broker/result backend + SocketIO message queue, volume `redisdata` |

Volumes `artemis-data` (legacy sqlite NVD/CPE cache at `/data`),
`nuclei-templates`, and `nuclei-config` persist scanner state between runs.

## Common operations

```bash
docker compose logs -f web worker          # tail logs
docker compose exec web flask db upgrade   # re-run migrations
docker compose exec web bash               # shell in the app container
docker compose exec worker nuclei -update-templates   # refresh nuclei templates
docker compose down                        # stop (keeps volumes/data)
docker compose down -v                     # stop and delete all data
```

Rebuild after pulling new code:

```bash
docker compose up -d --build
```

## Networking / scan reachability

The default (bridge) setup reaches your LAN for **TCP connect scans** — traffic
is NAT'd out through the host — so a normal port scan of any routable address
works out of the box.

Layer-2 features (ARP/MAC discovery, SYN scans) need the scanner containers on
the host network. Enable that with the override:

```bash
# add to .env:
#   DB_HOST=127.0.0.1
#   REDIS_HOST=127.0.0.1
docker compose -f docker-compose.yml -f docker-compose.host.yml up -d --build
```

`docker-compose.host.yml` also pins Postgres/Redis to loopback. Do **not** just
add `network_mode: host` to a service by hand — it drops the container off the
compose network and it can no longer resolve the `postgres`/`redis` hostnames.

## Notes

- The `web` and `worker` containers get `NET_RAW`/`NET_ADMIN` and run as root so
  `nmap` can perform raw-socket scans and ARP/MAC discovery on reachable
  networks. Run the stack on a host and network segment you are authorized to
  scan from.
- `NUCLEI_VERSION` in `.env` pins the nuclei release; leave it empty to take the
  latest at image build time.
- To scale scan throughput, raise `CELERY_CONCURRENCY` (env) or run more worker
  replicas: `docker compose up -d --scale worker=3`.
- Production config requires Redis-backed Celery; the app refuses to start with
  eager/`memory://` execution when `FLASK_CONFIG=production`.
