"""Patch campaigns (P5-E): a workflow over automation runs.

A campaign snapshots candidate hosts, optionally previews and canaries, then
stages a rollout in serial batches with reboot coordination and a post-run fact
refresh. It reuses generic Job / JobEvent records (a parent job + one child job
per batch); this model only holds the campaign plan and per-host outcome.
"""

import json

from artemis.extensions import db
from artemis.models._tenant import TenantMixin

CAMPAIGN_STATES = ('planned', 'previewing', 'canary', 'rolling', 'paused',
                   'completed', 'failed', 'cancelled')


class PatchCampaign(TenantMixin, db.Model):
    __tablename__ = 'patch_campaigns'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    starter_id = db.Column(db.String(64))               # e.g. linux-package-update
    content_id = db.Column(db.Integer)
    status = db.Column(db.String(16), nullable=False, default='planned', index=True)

    candidate_ids_json = db.Column(db.Text, nullable=False, default='[]')
    excluded_ids_json = db.Column(db.Text, nullable=False, default='[]')
    canary_ids_json = db.Column(db.Text, nullable=False, default='[]')

    batch_size = db.Column(db.Integer, nullable=False, default=10)
    pause_between_batches = db.Column(db.Integer, nullable=False, default=0)   # seconds
    max_fail_percentage = db.Column(db.Integer, nullable=False, default=0)
    coordinate_reboot = db.Column(db.Integer, nullable=False, default=1)
    maintenance_window_id = db.Column(db.Integer)

    variables_json = db.Column(db.Text)
    per_host_json = db.Column(db.Text)                  # {asset_id: {status, job_id, at}}
    parent_job_id = db.Column(db.String(36))

    created_at = db.Column(db.Text, nullable=False)
    created_by = db.Column(db.Integer)
    started_at = db.Column(db.Text)
    completed_at = db.Column(db.Text)

    @staticmethod
    def _load(value, default):
        try:
            return json.loads(value) if value else default
        except (TypeError, ValueError):
            return default

    @property
    def candidate_ids(self):
        return self._load(self.candidate_ids_json, [])

    @property
    def excluded_ids(self):
        return self._load(self.excluded_ids_json, [])

    @property
    def canary_ids(self):
        return self._load(self.canary_ids_json, [])

    @property
    def target_ids(self):
        return [i for i in self.candidate_ids if i not in set(self.excluded_ids)]

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'starter_id': self.starter_id,
            'content_id': self.content_id,
            'status': self.status,
            'candidate_ids': self.candidate_ids,
            'excluded_ids': self.excluded_ids,
            'canary_ids': self.canary_ids,
            'target_ids': self.target_ids,
            'batch_size': self.batch_size,
            'pause_between_batches': self.pause_between_batches,
            'max_fail_percentage': self.max_fail_percentage,
            'coordinate_reboot': bool(self.coordinate_reboot),
            'maintenance_window_id': self.maintenance_window_id,
            'variables': self._load(self.variables_json, {}),
            'per_host': self._load(self.per_host_json, {}),
            'parent_job_id': self.parent_job_id,
            'created_at': self.created_at,
            'started_at': self.started_at,
            'completed_at': self.completed_at,
        }
