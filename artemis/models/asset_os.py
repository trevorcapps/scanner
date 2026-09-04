"""Asset OS details model — from authenticated scans."""

import json

from artemis.extensions import db
from artemis.models._tenant import TenantMixin


class AssetOsDetails(TenantMixin, db.Model):
    __tablename__ = 'asset_os_details'
    __table_args__ = (
        db.UniqueConstraint('organization_id', 'ip', name='uq_asset_os_org_ip'),
    )

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.Text)
    distro = db.Column(db.Text)
    version = db.Column(db.Text)
    kernel = db.Column(db.Text)
    arch = db.Column(db.Text)
    os_family = db.Column(db.Text)
    os_id = db.Column(db.Text)
    pretty_name = db.Column(db.Text)
    scan_date = db.Column(db.Text)
    system_info_json = db.Column(db.Text)

    def to_dict(self):
        try:
            system_info = json.loads(self.system_info_json) if self.system_info_json else {}
        except (ValueError, TypeError):
            system_info = {}
        return {
            'distro': self.distro,
            'version': self.version,
            'kernel': self.kernel,
            'arch': self.arch,
            'os_family': self.os_family,
            'os_id': self.os_id,
            'pretty_name': self.pretty_name,
            'scan_date': self.scan_date,
            'system_info': system_info,
        }
