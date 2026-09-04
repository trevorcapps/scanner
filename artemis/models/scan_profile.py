"""Reusable, versioned scan execution profiles.

A schedule references a profile *version*; profiles are append-only — editing one
creates a new version so a running or historical job always resolves the exact
settings it launched with.
"""

import json

from artemis.extensions import db
from artemis.models._tenant import TenantMixin

MISSED_RUN_POLICIES = ('skip', 'run_once', 'catch_up')


class ScanExecutionProfile(TenantMixin, db.Model):
    __tablename__ = 'scan_execution_profiles'
    __table_args__ = (
        db.UniqueConstraint('organization_id', 'name', 'version', name='uq_exec_profile_org_name_ver'),
    )

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False)
    version = db.Column(db.Integer, nullable=False, default=1)
    is_current = db.Column(db.Integer, nullable=False, default=1)

    # Execution windows
    timezone = db.Column(db.String(64), nullable=False, default='UTC')
    window_start = db.Column(db.String(5))    # "HH:MM" local; null = anytime
    window_end = db.Column(db.String(5))
    window_days_json = db.Column(db.Text)     # [0..6] Mon..Sun; null = every day

    # Scope + rate
    max_hosts = db.Column(db.Integer, nullable=False, default=256)
    excluded_targets_json = db.Column(db.Text)
    scanner_rate = db.Column(db.Integer)      # nuclei rate-limit / nmap timing hint
    concurrency = db.Column(db.Integer, nullable=False, default=1)

    # Wiring
    credential_ids_json = db.Column(db.Text)
    engine_pool = db.Column(db.String(64))
    retry_count = db.Column(db.Integer, nullable=False, default=1)
    notify_json = db.Column(db.Text)          # {"on_complete": bool, "on_new_vulns": bool, ...}

    created_at = db.Column(db.Text, nullable=False)
    created_by = db.Column(db.Integer)

    # --- helpers -------------------------------------------------------
    @staticmethod
    def _load(value, default):
        try:
            return json.loads(value) if value else default
        except (TypeError, ValueError):
            return default

    @property
    def excluded_targets(self):
        return self._load(self.excluded_targets_json, [])

    @property
    def window_days(self):
        return self._load(self.window_days_json, None)

    @property
    def credential_ids(self):
        return self._load(self.credential_ids_json, [])

    @property
    def notify(self):
        return self._load(self.notify_json, {})

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'version': self.version,
            'is_current': bool(self.is_current),
            'timezone': self.timezone,
            'window_start': self.window_start,
            'window_end': self.window_end,
            'window_days': self.window_days,
            'max_hosts': self.max_hosts,
            'excluded_targets': self.excluded_targets,
            'scanner_rate': self.scanner_rate,
            'concurrency': self.concurrency,
            'credential_ids': self.credential_ids,
            'engine_pool': self.engine_pool,
            'retry_count': self.retry_count,
            'notify': self.notify,
            'created_at': self.created_at,
            'created_by': self.created_by,
        }
