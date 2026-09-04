"""Redis-backed fixed-window rate limiting with per-category policies.

A deterministic in-memory backend is used when no Redis URL is configured (tests,
local dev), so limit behaviour is identical and assertions are stable.
"""

import logging
import os
import threading
import time

from flask import current_app, g, jsonify, request

logger = logging.getLogger("artemis.ratelimit")

# category -> (max_requests, window_seconds)
DEFAULT_POLICIES = {
    "login": (10, 300),            # brute-force protection on auth/setup
    "write": (120, 60),            # ordinary user/API mutations
    "expensive": (12, 60),         # scans, reports, exports, feed syncs
    "agent_report": (30, 60),      # per-agent inventory posts
    "shell_poll": (150, 60),       # high-frequency remote-shell polling
}


def _policies():
    policies = dict(DEFAULT_POLICIES)
    override = os.environ.get("ARTEMIS_RATE_LIMITS", "").strip()
    for entry in filter(None, (e.strip() for e in override.split(","))):
        try:
            name, count, window = entry.split(":")
            policies[name] = (int(count), int(window))
        except ValueError:
            logger.warning("ignoring malformed ARTEMIS_RATE_LIMITS entry: %s", entry)
    return policies


class _MemoryBackend:
    def __init__(self):
        self._hits = {}
        self._lock = threading.Lock()

    def incr(self, key, window):
        now = int(time.time())
        bucket = now // window
        composite = f"{key}:{bucket}"
        with self._lock:
            count = self._hits.get(composite, 0) + 1
            self._hits[composite] = count
            # opportunistic cleanup
            if len(self._hits) > 4096:
                self._hits = {
                    k: v for k, v in self._hits.items()
                    if int(k.rsplit(":", 1)[1]) >= bucket - 1
                }
        reset = (bucket + 1) * window - now
        return count, reset

    def reset(self):
        with self._lock:
            self._hits.clear()


class _RedisBackend:
    def __init__(self, client):
        self._client = client

    def incr(self, key, window):
        now = int(time.time())
        bucket = now // window
        composite = f"artemis:rl:{key}:{bucket}"
        pipe = self._client.pipeline()
        pipe.incr(composite)
        pipe.expire(composite, window + 1)
        count, _ = pipe.execute()
        reset = (bucket + 1) * window - now
        return int(count), reset

    def reset(self):  # pragma: no cover - only used by tests via memory backend
        pass


_backend = None
_backend_lock = threading.Lock()


def _get_backend():
    global _backend
    if _backend is not None:
        return _backend
    with _backend_lock:
        if _backend is None:
            url = ""
            try:
                url = current_app.config.get("REDIS_URL", "")
            except RuntimeError:
                url = os.environ.get("REDIS_URL", "")
            if url:
                try:
                    import redis

                    _backend = _RedisBackend(redis.Redis.from_url(url))
                    logger.info("rate limiting backed by Redis")
                except Exception:  # noqa: BLE001
                    logger.exception("Redis unavailable for rate limiting; using memory backend")
                    _backend = _MemoryBackend()
            else:
                _backend = _MemoryBackend()
    return _backend


def reset_state():
    """Test helper: drop the backend and any counters."""
    global _backend
    with _backend_lock:
        if isinstance(_backend, _MemoryBackend):
            _backend.reset()
        _backend = None


def _client_id():
    user = getattr(g, "current_user", None)
    if user is not None:
        return f"u{user.id}"
    agent = getattr(g, "current_agent", None)
    if agent is not None:
        return f"a{getattr(agent, 'id', 'x')}"
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
    return "ip" + ip.split(",")[0].strip()


def check(category, identifier=None):
    """Return (allowed, retry_after_seconds, limit, remaining)."""
    count_max, window = _policies().get(category, DEFAULT_POLICIES["write"])
    ident = identifier or _client_id()
    count, reset = _get_backend().incr(f"{category}:{ident}", window)
    remaining = max(0, count_max - count)
    return count <= count_max, reset, count_max, remaining


def enforce(category, identifier=None):
    """Flask helper: return a 429 response when the caller is over budget."""
    allowed, retry_after, limit, remaining = check(category, identifier)
    if allowed:
        return None
    logger.warning("rate limit hit: category=%s id=%s", category, identifier or _client_id())
    response = jsonify({
        "error": "Rate limit exceeded",
        "category": category,
        "retry_after": retry_after,
    })
    response.status_code = 429
    response.headers["Retry-After"] = str(retry_after)
    response.headers["X-RateLimit-Limit"] = str(limit)
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    return response


def rate_limited(category):
    """Decorator form for individual view functions."""
    from functools import wraps

    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            blocked = enforce(category)
            if blocked is not None:
                return blocked
            return view(*args, **kwargs)

        return wrapper

    return decorator
