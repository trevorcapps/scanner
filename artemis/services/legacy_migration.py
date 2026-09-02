"""One-time importer: pre-Postgres SQLite application rows -> Postgres.

Runs on boot from ``_init_database``. It is a no-op unless:
  * ``LEGACY_SQLITE_PATH`` points at an existing file with a ``scans``/``assets`` table,
  * the Postgres ``assets`` table is empty, and
  * the ``_pg_migrated`` sentinel setting is absent.

The legacy DB file is left untouched (its now-dead app tables are a short-term
rollback safety net); only the sentinel is written back, into Postgres.
"""

import os
import sqlite3
import logging
from datetime import datetime, timezone

from artemis.extensions import db
from artemis.models.asset import Asset
from artemis.models.scan import Scan
from artemis.models.fingerprint_model import Fingerprint
from artemis.models.vulnerability import Vulnerability
from artemis.models.cve_match import CveMatch
from artemis.models.software import InstalledSoftware
from artemis.models.asset_os import AssetOsDetails
from artemis.models.credential import Credential
from artemis.models.setting import Setting
from artemis.models.agent_data import AgentData

logger = logging.getLogger(__name__)

SENTINEL_KEY = '_pg_migrated'

# (sqlite table, model). Order matters only for readability — no FKs between these.
_TABLES = [
    ('assets', Asset),
    ('scans', Scan),
    ('fingerprints', Fingerprint),
    ('vulnerabilities', Vulnerability),
    ('cve_matches', CveMatch),
    ('installed_software', InstalledSoftware),
    ('asset_os_details', AssetOsDetails),
    ('credentials', Credential),
    ('agent_data', AgentData),
]


def _sqlite_tables(conn):
    return {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}


def _copy_table(conn, sqlite_table, model, present_tables):
    """Copy one table and commit it. Raises on failure (caller isolates)."""
    if sqlite_table not in present_tables:
        return 0
    cols = [r[1] for r in conn.execute(f"PRAGMA table_info({sqlite_table})")]
    model_cols = {c.name for c in model.__table__.columns} - {'id'}
    use = [c for c in cols if c in model_cols]
    if not use:
        return 0

    rows = conn.execute(f"SELECT {', '.join(use)} FROM {sqlite_table}").fetchall()
    if not rows:
        return 0

    db.session.bulk_insert_mappings(model, [dict(zip(use, r)) for r in rows])
    db.session.commit()
    return len(rows)


def _copy_settings(conn, present_tables):
    if 'settings' not in present_tables:
        return 0
    rows = conn.execute("SELECT key, value FROM settings").fetchall()
    copied = 0
    for key, value in rows:
        if key == SENTINEL_KEY:
            continue
        db.session.merge(Setting(key=key, value=value))
        copied += 1
    db.session.commit()
    return copied


def migrate_legacy_sqlite(app):
    path = app.config.get('LEGACY_SQLITE_PATH')
    if not path or path == ':memory:' or not os.path.isfile(path):
        return

    if db.session.get(Setting, SENTINEL_KEY) is not None:
        return
    if Asset.query.first() is not None:
        logger.info("Legacy migration: Postgres already has assets — recording sentinel, skipping copy")
        db.session.add(Setting(key=SENTINEL_KEY, value='skipped:pg-not-empty'))
        db.session.commit()
        return

    conn = sqlite3.connect(f'file:{path}?mode=ro', uri=True)
    try:
        present = _sqlite_tables(conn)
        if 'scans' not in present and 'assets' not in present:
            return

        summary = {}
        for sqlite_table, model in _TABLES:
            try:
                n = _copy_table(conn, sqlite_table, model, present)
                if n:
                    summary[sqlite_table] = n
            except Exception as e:
                db.session.rollback()
                logger.warning(f"Legacy migration: {sqlite_table} failed: {e}")

        try:
            n = _copy_settings(conn, present)
            if n:
                summary['settings'] = n
        except Exception as e:
            db.session.rollback()
            logger.warning(f"Legacy migration: settings failed: {e}")

        db.session.add(Setting(
            key=SENTINEL_KEY,
            value=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        ))
        db.session.commit()
        logger.info(f"Legacy migration complete: {summary or 'nothing to copy'}")
    finally:
        conn.close()
