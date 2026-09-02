# syntax=docker/dockerfile:1

###############################################################################
# Artemis vulnerability scanner — production image
#
# Bundles the Flask/SocketIO web app, the Celery worker code, and the external
# scanning tools it shells out to (nmap, nuclei). The same image runs both the
# "web" and "worker" services in docker-compose; the entrypoint selects the role.
###############################################################################

# --- Frontend build (React/Vite) -------------------------------------------
# Emits static/ui/ which Flask serves at "/". Kept in its own stage so a
# python-only change does not reinstall node modules.
FROM node:20-slim AS frontend
WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build
# -> /build/static/ui  (vite base '/static/ui/', outDir '../static/ui')

FROM python:3.12-slim-bookworm

# --- External scanning tools --------------------------------------------------
# nmap  : service/port discovery (python-nmap shells out to it)
# nuclei : template-based vulnerability scanning
ARG NUCLEI_VERSION=

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    MPLCONFIGDIR=/tmp/matplotlib \
    FLASK_APP=run.py \
    # Top-level scanner modules (device_type, nvd_feeds, fingerprint/, ...) are
    # not part of the installed `artemis` package. gunicorn adds CWD to sys.path
    # but the Celery prefork pool does not — pin it so every process can import.
    PYTHONPATH=/app

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        nmap \
        ca-certificates \
        curl \
        unzip \
        tini \
        libpq5 \
        libxml2 \
        libxslt1.1 \
        libmagic1 \
        postgresql-client; \
    rm -rf /var/lib/apt/lists/*

# Install nuclei from GitHub releases. When NUCLEI_VERSION is empty the latest
# release is resolved at build time.
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
        amd64) nuclei_arch=amd64 ;; \
        arm64) nuclei_arch=arm64 ;; \
        *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    version="${NUCLEI_VERSION}"; \
    if [ -z "$version" ]; then \
        version="$(curl -fsSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
            | grep -m1 '"tag_name"' | sed -E 's/.*"v?([^"]+)".*/\1/')"; \
    fi; \
    version="${version#v}"; \
    url="https://github.com/projectdiscovery/nuclei/releases/download/v${version}/nuclei_${version}_linux_${nuclei_arch}.zip"; \
    echo "Downloading $url"; \
    curl -fsSL -o /tmp/nuclei.zip "$url"; \
    unzip -o /tmp/nuclei.zip -d /usr/local/bin nuclei; \
    rm /tmp/nuclei.zip; \
    chmod +x /usr/local/bin/nuclei; \
    nuclei -version

WORKDIR /app

# --- Python dependencies -----------------------------------------------------
# The WSGI stack (gunicorn + gevent-websocket) is layered separately so it
# stays cached across application changes.
RUN pip install --no-cache-dir \
        "gunicorn>=21.2" \
        "gevent>=24.2" \
        "gevent-websocket>=0.10"

# --- Application code + package install -------------------------------------
COPY . .
# Built SPA from the frontend stage (host static/ui/ is .dockerignore'd).
COPY --from=frontend /build/static/ui ./static/ui
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends build-essential; \
    pip install --no-cache-dir -e '.[postgres]'; \
    apt-get purge -y --auto-remove build-essential; \
    rm -rf /var/lib/apt/lists/*

# Persistent data (legacy sqlite NVD/CPE cache) and nuclei templates.
RUN mkdir -p /data /root/nuclei-templates /root/.config/nuclei

EXPOSE 5005

ENTRYPOINT ["tini", "--", "/app/docker/entrypoint.sh"]
CMD ["web"]
