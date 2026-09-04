"""Asset model."""

from artemis.extensions import db
from artemis.models._tenant import TenantMixin


class Asset(TenantMixin, db.Model):
    __tablename__ = 'assets'
    __table_args__ = (
        db.UniqueConstraint('organization_id', 'ip', name='uq_asset_org_ip'),
    )

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.Text)
    hostname = db.Column(db.Text)
    reverse_dns = db.Column(db.Text)
    aliases_json = db.Column(db.Text)
    os_name = db.Column(db.Text)
    os_family = db.Column(db.Text)
    os_vendor = db.Column(db.Text)
    os_accuracy = db.Column(db.Text)
    device_type = db.Column(db.Text)
    mac_address = db.Column(db.Text)
    mac_vendor = db.Column(db.Text)
    first_seen = db.Column(db.Text)
    last_seen = db.Column(db.Text)
    scan_count = db.Column(db.Integer, default=1)

    def to_dict(self):
        import json
        aliases = []
        if self.aliases_json:
            try:
                aliases = json.loads(self.aliases_json)
            except (json.JSONDecodeError, TypeError):
                pass
        return {
            'id': self.id,
            'ip': self.ip,
            'hostname': self.hostname,
            'reverse_dns': self.reverse_dns,
            'aliases': aliases,
            'os_name': self.os_name,
            'os_family': self.os_family,
            'os_vendor': self.os_vendor,
            'os_accuracy': self.os_accuracy,
            'device_type': self.device_type,
            'mac_address': self.mac_address,
            'mac_vendor': self.mac_vendor,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'scan_count': self.scan_count,
        }
