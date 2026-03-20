"""AgentReport model — reports submitted by remote agents."""

from artemis.extensions import db


class AgentReport(db.Model):
    __tablename__ = 'agent_reports'

    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.Integer, nullable=False)
    report_type = db.Column(db.Text, default='full')
    report_json = db.Column(db.Text)
    packages_count = db.Column(db.Integer, default=0)
    ports_count = db.Column(db.Integer, default=0)
    vulns_matched = db.Column(db.Integer, default=0)
    received_at = db.Column(db.Text)

    def to_dict(self):
        return {
            'id': self.id,
            'agent_id': self.agent_id,
            'report_type': self.report_type,
            'report_json': self.report_json,
            'packages_count': self.packages_count,
            'ports_count': self.ports_count,
            'vulns_matched': self.vulns_matched,
            'received_at': self.received_at,
        }
