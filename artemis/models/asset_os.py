"""Asset OS details model — from authenticated scans."""

from artemis.extensions import db


class AssetOsDetails(db.Model):
    __tablename__ = 'asset_os_details'

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.Text, unique=True)
    distro = db.Column(db.Text)
    version = db.Column(db.Text)
    kernel = db.Column(db.Text)
    arch = db.Column(db.Text)
    os_family = db.Column(db.Text)
    os_id = db.Column(db.Text)
    pretty_name = db.Column(db.Text)
    scan_date = db.Column(db.Text)

    def to_dict(self):
        return {
            'distro': self.distro,
            'version': self.version,
            'kernel': self.kernel,
            'arch': self.arch,
            'os_family': self.os_family,
            'os_id': self.os_id,
            'pretty_name': self.pretty_name,
            'scan_date': self.scan_date,
        }
