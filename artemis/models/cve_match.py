"""CVE match model — auth scan / vulscan results."""

from artemis.extensions import db


class CveMatch(db.Model):
    __tablename__ = 'cve_matches'

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.Text, index=True)
    cve_id = db.Column(db.Text)
    severity = db.Column(db.Text)
    cvss_score = db.Column(db.Float)
    description = db.Column(db.Text)
    affected_cpe = db.Column(db.Text)
    has_exploit = db.Column(db.Integer, default=0)
    exploit_ids = db.Column(db.Text)
    exploit_url = db.Column(db.Text)
    scan_date = db.Column(db.Text)

    __table_args__ = (
        db.UniqueConstraint('ip', 'cve_id', name='uq_cve_match_ip_cve'),
    )

    def to_dict(self):
        return {
            'ip': self.ip,
            'cve_id': self.cve_id,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'description': self.description,
            'affected_cpe': self.affected_cpe,
            'has_exploit': bool(self.has_exploit),
            'exploit_ids': self.exploit_ids or '',
            'exploit_url': self.exploit_url or '',
            'scan_date': self.scan_date,
        }
