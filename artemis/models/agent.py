"""Agent model — registered remote agents."""

from artemis.extensions import db


class Agent(db.Model):
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
    created_at = db.Column(db.Text)
    enabled = db.Column(db.Integer, default=1)

    def to_dict(self):
        return {
            'id': self.id,
            'agent_key': self.agent_key,
            'name': self.name,
            'hostname': self.hostname,
            'ip': self.ip,
            'os_info_json': self.os_info_json,
            'last_checkin': self.last_checkin,
            'checkin_interval': self.checkin_interval,
            'status': self.status,
            'agent_version': self.agent_version,
            'system_info_json': self.system_info_json,
            'created_at': self.created_at,
            'enabled': self.enabled,
        }
