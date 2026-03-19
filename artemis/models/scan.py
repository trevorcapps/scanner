"""Scan model — port scan results."""

from artemis.extensions import db


class Scan(db.Model):
    __tablename__ = 'scans'

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.Text, index=True)
    protocol = db.Column(db.Text)
    port = db.Column(db.Integer)
    state = db.Column(db.Text)
    service = db.Column(db.Text)
    product = db.Column(db.Text)
    version = db.Column(db.Text)
    scan_date = db.Column(db.Text)

    def to_dict(self):
        return {
            'id': self.id,
            'ip': self.ip,
            'protocol': self.protocol,
            'port': self.port,
            'state': self.state,
            'service': self.service,
            'product': self.product,
            'version': self.version,
            'scan_date': self.scan_date,
        }
