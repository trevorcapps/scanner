"""Scheduler glue for recurring reports — evaluate cron, generate, email."""

import json
import logging
from datetime import datetime, timezone

from croniter import croniter

from artemis.extensions import db
from artemis.models.report import ReportSchedule

logger = logging.getLogger(__name__)


def next_cron(expr, base=None):
    """Next fire time for a 5-field cron expression, as an ISO-Z string."""
    base = base or datetime.now(timezone.utc).replace(tzinfo=None)
    try:
        return croniter(expr, base).get_next(datetime).strftime('%Y-%m-%dT%H:%M:%SZ')
    except (ValueError, KeyError) as e:
        logger.warning(f"Bad cron '{expr}': {e}")
        return None


def run_due_report_schedules(now_iso):
    due = ReportSchedule.query.filter(
        ReportSchedule.enabled == 1,
        ReportSchedule.next_run.isnot(None),
        ReportSchedule.next_run <= now_iso,
    ).all()
    for sched in due:
        _run_one(sched)
        sched.last_run = now_iso
        sched.next_run = next_cron(sched.cron_expression)
        sched.updated_at = now_iso
        db.session.commit()


def _run_one(sched):
    from artemis.services.executive_report_service import build_report
    from artemis.services.email_service import send_report_email

    try:
        scope = json.loads(sched.scope_json) if sched.scope_json else {'type': 'environment'}
        rec = build_report(scope, kind=sched.kind, fmt=sched.fmt, schedule_id=sched.id)
        if rec.status != 'ready':
            sched.last_status = 'failed'
            sched.last_error = rec.error or 'generation failed'
            return

        recipients = [r.strip() for r in (sched.recipients or '').split(',') if r.strip()]
        if not recipients:
            sched.last_status = 'generated (no recipients)'
            sched.last_error = None
            return

        send_report_email(recipients, sched.name, rec)
        sched.last_status = 'sent'
        sched.last_error = None
        logger.info(f"Report schedule '{sched.name}' delivered to {len(recipients)} recipient(s)")
    except Exception as e:
        logger.exception(f"Report schedule '{sched.name}' failed")
        sched.last_status = 'failed'
        sched.last_error = str(e)
