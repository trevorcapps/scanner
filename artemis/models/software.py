"""Installed software model."""

from artemis.extensions import db
from artemis.models._tenant import TenantMixin


class InstalledSoftware(TenantMixin, db.Model):
    __tablename__ = 'installed_software'

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.Text, index=True)
    package_name = db.Column(db.Text)
    package_version = db.Column(db.Text)
    cpe = db.Column(db.Text)
    scan_date = db.Column(db.Text)

    __table_args__ = (
        db.UniqueConstraint('organization_id', 'ip', 'package_name', name='uq_sw_org_ip_pkg'),
    )

    def to_dict(self):
        return {
            'name': self.package_name,
            'version': self.package_version,
            'cpe': self.cpe,
            'scan_date': self.scan_date,
        }
