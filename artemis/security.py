"""Request correlation, transport hardening, and production config guards."""

import logging
import os
import time
import uuid

from flask import g, jsonify, request
from werkzeug.middleware.proxy_fix import ProxyFix

from artemis.services import crypto_service

logger = logging.getLogger("artemis.request")


class InsecureConfigError(RuntimeError):
    """Production is configured without a required security control."""


def _truthy(name):
    return os.environ.get(name, "").lower() in ("1", "true", "yes", "on")


def validate_production_config(app):
    """Refuse to serve production without secrets/TLS unless explicitly waived.

    Skipped for management commands (``flask db ...``, shell) — they never expose
    a socket and legitimately run before TLS/al the runtime env is in place.
    """
    if app.config.get("TESTING"):
        return
    import sys
    argv = " ".join(sys.argv)
    serving = ("gunicorn" in argv or "run:app" in argv
               or argv.rstrip().endswith("run.py") or _truthy("ARTEMIS_SERVING"))
    if not serving:
        # Management command (flask db, shell, ...) — never opens a socket.
        return
    if _truthy("ARTEMIS_ALLOW_INSECURE"):
        logger.warning(
            "ARTEMIS_ALLOW_INSECURE is set — production security checks are disabled"
        )
        return

    problems = []

    if not os.environ.get("SECRET_KEY"):
        problems.append(
            "SECRET_KEY must be provided by the environment in production "
            "(the generated .secret_key file fallback is development-only)"
        )

    if not crypto_service.is_configured():
        problems.append(
            "no secret-encryption key configured — set ARTEMIS_ENCRYPTION_KEY "
            "(generate one with: python -c 'from artemis.services.crypto_service "
            "import generate_key; print(generate_key())')"
        )

    if not app.config.get("PREFERRED_URL_SCHEME") == "https" and not _truthy(
        "ARTEMIS_BEHIND_TLS_PROXY"
    ):
        problems.append(
            "HTTPS is not asserted — terminate TLS at the bundled proxy and set "
            "ARTEMIS_BEHIND_TLS_PROXY=1, or set ARTEMIS_ALLOW_INSECURE=1 to override"
        )

    if problems:
        raise InsecureConfigError(
            "Refusing to start in production:\n  - " + "\n  - ".join(problems)
        )


def init_security(app):
    """Install correlation IDs, proxy handling, secure cookies, and headers."""
    behind_proxy = _truthy("ARTEMIS_BEHIND_TLS_PROXY") or bool(
        os.environ.get("ARTEMIS_TRUSTED_PROXY_HOPS")
    )
    if behind_proxy:
        hops = int(os.environ.get("ARTEMIS_TRUSTED_PROXY_HOPS", "1"))
        app.wsgi_app = ProxyFix(
            app.wsgi_app, x_for=hops, x_proto=hops, x_host=hops, x_port=hops
        )
        app.config["PREFERRED_URL_SCHEME"] = "https"

    secure_cookies = behind_proxy or app.config.get("PREFERRED_URL_SCHEME") == "https"
    app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
    app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")
    app.config["SESSION_COOKIE_SECURE"] = secure_cookies and not app.config.get("TESTING")
    # Cap request bodies (agent reports and playbook uploads set their own higher
    # limits at the route). 8 MiB covers normal API traffic.
    app.config.setdefault(
        "MAX_CONTENT_LENGTH", int(os.environ.get("ARTEMIS_MAX_CONTENT_LENGTH", str(8 * 1024 * 1024)))
    )

    hsts = _truthy("ARTEMIS_BEHIND_TLS_PROXY") or app.config.get("PREFERRED_URL_SCHEME") == "https"

    @app.before_request
    def _assign_request_id():
        incoming = request.headers.get("X-Request-ID", "")
        g.request_id = incoming[:64] if incoming else uuid.uuid4().hex
        g.request_start = time.monotonic()

    @app.after_request
    def _finish_request(response):
        response.headers.setdefault("X-Request-ID", getattr(g, "request_id", ""))
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        if hsts:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        response.headers.setdefault(
            "Content-Security-Policy",
            os.environ.get(
                "ARTEMIS_CSP",
                "default-src 'self'; img-src 'self' data:; "
                "style-src 'self' 'unsafe-inline'; "
                "connect-src 'self' ws: wss:; "
                "frame-ancestors 'none'; base-uri 'self'",
            ),
        )
        if request.path.startswith(("/api/", "/agent/")):
            started = getattr(g, "request_start", None)
            logger.info(
                "%s %s -> %s",
                request.method, request.path, response.status_code,
                extra={
                    "http_method": request.method,
                    "http_path": request.path,
                    "http_status": response.status_code,
                    "duration_ms": None if started is None else round((time.monotonic() - started) * 1000, 1),
                },
            )
        return response

    @app.errorhandler(413)
    def _too_large(_err):
        return jsonify({"error": "Request body too large"}), 413
