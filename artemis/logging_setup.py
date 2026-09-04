"""Structured JSON logging with request / job / organization correlation.

Container deployments log to stdout as line-delimited JSON and rely on the
Docker/runtime log driver for rotation. Non-container use can opt into a
size-based rotating file handler with ARTEMIS_LOG_FILE.
"""

import json
import logging
import logging.handlers
import os
import sys
import time

try:
    from flask import g, has_request_context
except Exception:  # pragma: no cover - flask always present in practice
    def has_request_context():
        return False
    g = None

_RESERVED = set(logging.makeLogRecord({}).__dict__) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)

        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = value

        if has_request_context() and g is not None:
            for attr, out in (
                ("request_id", "request_id"),
                ("job_id", "job_id"),
                ("organization_id", "org_id"),
            ):
                val = getattr(g, attr, None)
                if val is not None:
                    payload.setdefault(out, val)

        return json.dumps(payload, separators=(",", ":"), default=str)


class PlainFormatter(logging.Formatter):
    def __init__(self):
        super().__init__("%(asctime)s %(levelname)s %(name)s: %(message)s")


def _wanted_format():
    fmt = os.environ.get("ARTEMIS_LOG_FORMAT", "").lower()
    if fmt in ("json", "plain"):
        return fmt
    # Default to JSON when running under a container / non-tty.
    return "plain" if sys.stderr.isatty() else "json"


def configure_logging():
    """Idempotently install the root handler set."""
    root = logging.getLogger()
    if getattr(root, "_artemis_configured", False):
        return

    level = os.environ.get("ARTEMIS_LOG_LEVEL", "INFO").upper()
    root.setLevel(getattr(logging, level, logging.INFO))

    formatter = JsonFormatter() if _wanted_format() == "json" else PlainFormatter()

    for handler in list(root.handlers):
        root.removeHandler(handler)

    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(formatter)
    root.addHandler(stream)

    log_file = os.environ.get("ARTEMIS_LOG_FILE", "").strip()
    if log_file:
        rotating = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=int(os.environ.get("ARTEMIS_LOG_FILE_BYTES", str(10 * 1024 * 1024))),
            backupCount=int(os.environ.get("ARTEMIS_LOG_FILE_BACKUPS", "5")),
        )
        rotating.setFormatter(formatter)
        root.addHandler(rotating)

    # Quiet noisy third parties one notch.
    for noisy in ("werkzeug", "urllib3", "socketio", "engineio"):
        logging.getLogger(noisy).setLevel(
            os.environ.get("ARTEMIS_LOG_LEVEL_" + noisy.upper(), "WARNING")
        )

    root._artemis_configured = True
