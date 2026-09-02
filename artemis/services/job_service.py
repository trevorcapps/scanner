"""Persistent scan-job creation, dispatch, and cancellation."""

import json
from datetime import datetime, timezone

from flask import current_app

from artemis.extensions import db
from artemis.models.scan_job import ScanJob


TERMINAL_STATES = {'success', 'failed', 'cancelled', 'dispatch_failed'}


class QueueDispatchError(RuntimeError):
    def __init__(self, message, job):
        super().__init__(message)
        self.job = job


def _now_iso():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def create_job(job_type, target=None, site_id=None, requested_by=None, options=None):
    job = ScanJob(
        job_type=job_type,
        target=target,
        site_id=site_id,
        requested_by=requested_by,
        options_json=json.dumps(options or {}),
        status='queued',
        created_at=_now_iso(),
    )
    db.session.add(job)
    db.session.commit()
    return job


def dispatch_site_scan(site, requested_by=None):
    """Persist a site scan before publishing it to Celery."""
    from artemis.tasks.scan_tasks import run_site_scan_job

    job = create_job(
        'site_scan',
        target=site.name,
        site_id=site.id,
        requested_by=requested_by,
        options={'scan_type': site.scan_type},
    )
    job.task_id = f'site-scan-{job.id}'
    site.last_status = 'queued'
    db.session.commit()

    try:
        run_site_scan_job.apply_async(args=[job.id], task_id=job.task_id)
    except Exception as exc:
        job.status = 'dispatch_failed'
        job.error_message = str(exc)
        job.completed_at = _now_iso()
        site.last_status = 'failed'
        db.session.commit()
        raise QueueDispatchError('Scan queue is unavailable', job) from exc

    return job


def cancel_job(job):
    if job.status in TERMINAL_STATES:
        return False

    was_running = job.status == 'running'
    job.status = 'cancel_requested' if was_running else 'cancelled'
    job.cancel_requested_at = _now_iso()
    if not was_running:
        job.completed_at = _now_iso()
    db.session.commit()

    if job.task_id:
        current_app.extensions['celery'].control.revoke(job.task_id, terminate=False)
    return True
