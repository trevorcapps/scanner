"""Bounded in-memory application log history for the operator UI.

The process log remains the durable operational record (stdout in containers or
the service manager journal).  This handler keeps only a small, bounded view
so a newly opened browser panel can show recent activity instead of waiting for
the next Socket.IO event.
"""

import logging
import threading
from collections import deque
from datetime import datetime, timezone


_MAX_RECORDS = 500
_records = deque(maxlen=_MAX_RECORDS)
_records_lock = threading.Lock()
_sequence = 0


class RecentLogHandler(logging.Handler):
    """Capture formatted records without changing normal logging output."""

    _artemis_recent_log_handler = True

    def emit(self, record):
        global _sequence
        try:
            message = record.getMessage()
        except Exception:
            self.handleError(record)
            return

        with _records_lock:
            _sequence += 1
            _records.append({
                'id': _sequence,
                'timestamp': datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
                'level': record.levelname.lower(),
                'logger': record.name,
                'message': message,
            })


def install_recent_log_handler(level=logging.INFO):
    """Install the singleton history handler on the root logger."""
    root = logging.getLogger()
    if root.level > level:
        root.setLevel(level)
    for handler in root.handlers:
        if getattr(handler, '_artemis_recent_log_handler', False):
            return handler
    handler = RecentLogHandler(level=level)
    root.addHandler(handler)
    return handler


def get_recent_logs(limit=200, minimum_level=None):
    """Return a copy of the newest records, oldest first."""
    limit = max(1, min(int(limit), _MAX_RECORDS))
    threshold = logging._nameToLevel.get((minimum_level or '').upper())
    with _records_lock:
        records = list(_records)
    if threshold is not None:
        records = [record for record in records
                   if logging._nameToLevel.get(record['level'].upper(), 0) >= threshold]
    return records[-limit:]


def clear_recent_logs():
    """Clear history. Intended for tests and the explicit operator action."""
    with _records_lock:
        _records.clear()
