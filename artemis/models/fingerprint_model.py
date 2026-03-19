"""Fingerprint model."""

from artemis.extensions import db


class Fingerprint(db.Model):
    __tablename__ = 'fingerprints'

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.Text, index=True)
    port = db.Column(db.Integer)
    protocol = db.Column(db.Text)
    signature_id = db.Column(db.Text)
    name = db.Column(db.Text)
    category = db.Column(db.Text)
    vendor = db.Column(db.Text)
    version = db.Column(db.Text)
    cpe = db.Column(db.Text)
    confidence = db.Column(db.Integer)
    evidence_json = db.Column(db.Text)
    tls_subject_cn = db.Column(db.Text)
    tls_subject_org = db.Column(db.Text)
    tls_issuer_org = db.Column(db.Text)
    tls_self_signed = db.Column(db.Integer)
    http_title = db.Column(db.Text)
    http_server = db.Column(db.Text)
    favicon_hash = db.Column(db.Integer)
    scan_date = db.Column(db.Text)

    __table_args__ = (
        db.UniqueConstraint('ip', 'port', 'protocol', 'signature_id',
                            name='uq_fp_ip_port_proto_sig'),
    )

    def to_dict(self):
        import json
        evidence = []
        if self.evidence_json:
            try:
                evidence = json.loads(self.evidence_json)
            except (json.JSONDecodeError, TypeError):
                pass
        return {
            'ip': self.ip,
            'port': self.port,
            'protocol': self.protocol,
            'signature_id': self.signature_id,
            'name': self.name,
            'category': self.category,
            'vendor': self.vendor,
            'version': self.version,
            'cpe': self.cpe,
            'confidence': self.confidence,
            'evidence': evidence,
            'tls_subject_cn': self.tls_subject_cn,
            'tls_subject_org': self.tls_subject_org,
            'tls_issuer_org': self.tls_issuer_org,
            'tls_self_signed': bool(self.tls_self_signed),
            'http_title': self.http_title,
            'http_server': self.http_server,
            'favicon_hash': self.favicon_hash,
            'scan_date': self.scan_date,
        }
