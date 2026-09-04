"""AgentData model — latest agent-reported packages / system info per asset.

Denormalized snapshot keyed by IP so the asset-detail view can render an
endpoint's inventory without walking the full AgentReport history.
"""

import json

from artemis.extensions import db
from artemis.models._tenant import TenantMixin


class AgentData(TenantMixin, db.Model):
    __tablename__ = 'agent_data'
    __table_args__ = (
        db.UniqueConstraint('organization_id', 'ip', name='uq_agent_data_org_ip'),
    )

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.Text, nullable=False, index=True)
    packages_json = db.Column(db.Text)
    package_count = db.Column(db.Integer, default=0)
    system_info_json = db.Column(db.Text)
    os_info_json = db.Column(db.Text)
    updated_at = db.Column(db.Text)

    @staticmethod
    def _decode(value, fallback):
        if not value:
            return fallback
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return fallback

    def to_dict(self):
        return {
            'packages': self._decode(self.packages_json, []),
            'package_count': self.package_count or 0,
            'system_info': self._decode(self.system_info_json, {}),
            'os_info': self._decode(self.os_info_json, {}),
            'updated_at': self.updated_at,
        }
