"""Ansible automation content, execution environments, and run targets (P5).

An automation run reuses the generic ``ScanJob`` / ``JobEvent`` records
(``job_type='ansible_run'``); these models hold the immutable inputs a run
resolves to, so the audit trail can always answer "who ran which exact content
with which non-secret inputs".
"""

import json

from artemis.extensions import db
from artemis.models._tenant import TenantMixin

CONTENT_KINDS = ('playbook', 'bundle')


class AutomationContent(TenantMixin, db.Model):
    """Pasted or uploaded content, identified by SHA-256 digest and stored as a
    sealed (encrypted) artifact. Immutable once created."""

    __tablename__ = 'automation_content'
    __table_args__ = (
        db.UniqueConstraint('organization_id', 'digest', name='uq_automation_content_org_digest'),
    )

    id = db.Column(db.Integer, primary_key=True)
    digest = db.Column(db.String(64), nullable=False, index=True)
    kind = db.Column(db.String(16), nullable=False, default='playbook')
    filename = db.Column(db.Text)
    size_bytes = db.Column(db.Integer, nullable=False, default=0)
    sealed_body = db.Column(db.Text, nullable=False)     # crypto_service envelope
    syntax_ok = db.Column(db.Integer, nullable=False, default=0)
    lint_summary_json = db.Column(db.Text)
    created_at = db.Column(db.Text, nullable=False)
    created_by = db.Column(db.Integer)

    def to_dict(self):
        try:
            lint = json.loads(self.lint_summary_json) if self.lint_summary_json else None
        except (TypeError, ValueError):
            lint = None
        return {
            'id': self.id, 'digest': self.digest, 'kind': self.kind,
            'filename': self.filename, 'size_bytes': self.size_bytes,
            'syntax_ok': bool(self.syntax_ok), 'lint': lint,
            'created_at': self.created_at, 'created_by': self.created_by,
        }

    def reveal(self):
        from artemis.services import crypto_service
        return crypto_service.open_envelope(self.sealed_body)


class ExecutionEnvironment(TenantMixin, db.Model):
    """A pinned Ansible execution-environment image reference."""

    __tablename__ = 'execution_environments'
    __table_args__ = (
        db.UniqueConstraint('organization_id', 'name', name='uq_exec_env_org_name'),
    )

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    image = db.Column(db.Text, nullable=False)           # registry ref, digest-pinned
    ansible_core_version = db.Column(db.String(32))
    runner_version = db.Column(db.String(32))
    collections_json = db.Column(db.Text)
    is_default = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.Text, nullable=False)

    def to_dict(self):
        try:
            collections = json.loads(self.collections_json) if self.collections_json else []
        except (TypeError, ValueError):
            collections = []
        return {
            'id': self.id, 'name': self.name, 'image': self.image,
            'ansible_core_version': self.ansible_core_version,
            'runner_version': self.runner_version, 'collections': collections,
            'is_default': bool(self.is_default), 'created_at': self.created_at,
        }


class MaintenanceWindow(TenantMixin, db.Model):
    __tablename__ = 'maintenance_windows'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    timezone = db.Column(db.String(64), nullable=False, default='UTC')
    window_start = db.Column(db.String(5))               # "HH:MM"
    window_end = db.Column(db.String(5))
    days_json = db.Column(db.Text)
    created_at = db.Column(db.Text, nullable=False)

    def to_dict(self):
        try:
            days = json.loads(self.days_json) if self.days_json else None
        except (TypeError, ValueError):
            days = None
        return {
            'id': self.id, 'name': self.name, 'timezone': self.timezone,
            'window_start': self.window_start, 'window_end': self.window_end,
            'days': days, 'created_at': self.created_at,
        }


class AutomationRun(TenantMixin, db.Model):
    """The immutable input snapshot for one automation run. The execution record
    is the generic ScanJob referenced by ``job_id``."""

    __tablename__ = 'automation_runs'

    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.String(36), db.ForeignKey('scan_jobs.id', ondelete='CASCADE'),
                       nullable=False, index=True)
    content_id = db.Column(db.Integer, db.ForeignKey('automation_content.id', ondelete='RESTRICT'),
                           nullable=False)
    content_digest = db.Column(db.String(64), nullable=False)
    execution_environment_id = db.Column(db.Integer)
    # Non-secret variables, verbatim. Secrets are credential references, resolved
    # just in time, never stored here.
    variables_json = db.Column(db.Text)
    credential_refs_json = db.Column(db.Text)
    # Immutable snapshot of the target IDs at launch, so membership changes
    # cannot alter a running job.
    target_snapshot_json = db.Column(db.Text, nullable=False)
    check_mode = db.Column(db.Integer, nullable=False, default=0)
    serial = db.Column(db.Integer)
    max_fail_percentage = db.Column(db.Integer)
    launch_options_json = db.Column(db.Text)
    launched_by = db.Column(db.Integer)
    created_at = db.Column(db.Text, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'job_id': self.job_id,
            'content_id': self.content_id,
            'content_digest': self.content_digest,
            'execution_environment_id': self.execution_environment_id,
            'variables': _loads(self.variables_json, {}),
            'credential_refs': _loads(self.credential_refs_json, []),
            'target_snapshot': _loads(self.target_snapshot_json, []),
            'check_mode': bool(self.check_mode),
            'serial': self.serial,
            'max_fail_percentage': self.max_fail_percentage,
            'launch_options': _loads(self.launch_options_json, {}),
            'launched_by': self.launched_by,
            'created_at': self.created_at,
        }


def _loads(value, default):
    try:
        return json.loads(value) if value else default
    except (TypeError, ValueError):
        return default
