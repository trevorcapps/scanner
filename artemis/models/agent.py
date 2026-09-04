"""Agent model — registered remote agents."""

import json

from artemis.extensions import db
from artemis.models._tenant import TenantMixin


class Agent(TenantMixin, db.Model):
    __tablename__ = 'agents'

    id = db.Column(db.Integer, primary_key=True)
    agent_key = db.Column(db.Text, unique=True, nullable=False)
    name = db.Column(db.Text)
    hostname = db.Column(db.Text)
    ip = db.Column(db.Text)
    mac_address = db.Column(db.Text)
    os_info_json = db.Column(db.Text)
    last_checkin = db.Column(db.Text)
    checkin_interval = db.Column(db.Integer, default=21600)
    status = db.Column(db.Text, default='active')
    agent_version = db.Column(db.Text)
    system_info_json = db.Column(db.Text)
    capabilities_json = db.Column(db.Text)
    created_at = db.Column(db.Text)
    enabled = db.Column(db.Integer, default=1)

    @staticmethod
    def _decode(value):
        if not value:
            return {}
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return {}

    def to_dict(self, include_key=False):
        os_info = self._decode(self.os_info_json)
        system_info = self._decode(self.system_info_json)
        capabilities = self._decode(self.capabilities_json)
        if not isinstance(capabilities, list):
            capabilities = []
        result = {
            'id': self.id,
            'name': self.name,
            'hostname': self.hostname,
            'ip': self.ip,
            'mac_address': self.mac_address,
            'os': (os_info.get('pretty_name') or os_info.get('os_name') or
                   os_info.get('name') or os_info.get('platform') or ''),
            'os_info': os_info,
            'last_checkin': self.last_checkin,
            'checkin_interval': self.checkin_interval,
            'status': self.status,
            'version': self.agent_version,
            'agent_version': self.agent_version,
            'system_info': system_info,
            'capabilities': capabilities,
            'created_at': self.created_at,
            'enabled': self.enabled,
        }
        if include_key:
            result['agent_key'] = self.agent_key
        return result
