"""Report + ReportSchedule models — generated executive/technical reports."""

import json

from artemis.extensions import db


class Report(db.Model):
    """A single generated report artifact stored on the data volume."""

    __tablename__ = 'reports'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.Text, nullable=False)
    kind = db.Column(db.Text, default='executive')       # executive | technical | full
    fmt = db.Column(db.Text, default='pdf')              # pdf | html
    scope_json = db.Column(db.Text)                      # {"type": "environment"} | {"type":"site","id":N} | {"type":"filter",...}
    status = db.Column(db.Text, default='ready')         # ready | failed
    error = db.Column(db.Text)
    file_path = db.Column(db.Text)                       # absolute path under REPORTS_DIR
    size_bytes = db.Column(db.Integer, default=0)
    summary_json = db.Column(db.Text)                    # headline counts captured at generation time
    generated_by = db.Column(db.Integer)                 # user id (nullable)
    schedule_id = db.Column(db.Integer)                  # set when produced by a ReportSchedule
    created_at = db.Column(db.Text)

    def to_dict(self):
        try:
            scope = json.loads(self.scope_json) if self.scope_json else {}
        except (ValueError, TypeError):
            scope = {}
        try:
            summary = json.loads(self.summary_json) if self.summary_json else {}
        except (ValueError, TypeError):
            summary = {}
        return {
            'id': self.id,
            'title': self.title,
            'kind': self.kind,
            'format': self.fmt,
            'scope': scope,
            'status': self.status,
            'error': self.error,
            'size_bytes': self.size_bytes or 0,
            'summary': summary,
            'generated_by': self.generated_by,
            'schedule_id': self.schedule_id,
            'created_at': self.created_at,
        }


class ReportSchedule(db.Model):
    """A recurring report: generate on a cron and email it to recipients."""

    __tablename__ = 'report_schedules'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False)
    kind = db.Column(db.Text, default='executive')
    fmt = db.Column(db.Text, default='pdf')
    scope_json = db.Column(db.Text)
    cron_expression = db.Column(db.Text, nullable=False)  # standard 5-field cron
    recipients = db.Column(db.Text)                       # comma-separated email addresses
    enabled = db.Column(db.Integer, default=1)
    last_run = db.Column(db.Text)
    next_run = db.Column(db.Text)
    last_status = db.Column(db.Text)
    last_error = db.Column(db.Text)
    created_at = db.Column(db.Text)
    updated_at = db.Column(db.Text)

    def to_dict(self):
        try:
            scope = json.loads(self.scope_json) if self.scope_json else {}
        except (ValueError, TypeError):
            scope = {}
        return {
            'id': self.id,
            'name': self.name,
            'kind': self.kind,
            'format': self.fmt,
            'scope': scope,
            'cron_expression': self.cron_expression,
            'recipients': [r.strip() for r in (self.recipients or '').split(',') if r.strip()],
            'enabled': bool(self.enabled),
            'last_run': self.last_run,
            'next_run': self.next_run,
            'last_status': self.last_status,
            'last_error': self.last_error,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
        }
