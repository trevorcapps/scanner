"""Persistent job creation, dispatch, events, and cancellation.

``ScanJob`` is the single durable record for every asynchronous unit of work;
``JobEvent`` is its immutable, ordered event log. Socket.IO only transports
these events — losing a browser never affects a job.
"""

import json
import logging
from datetime import datetime, timedelta, timezone

from flask import current_app

from artemis.extensions import db
from artemis.models.job_event import JobEvent
from artemis.models.scan_job import ScanJob

logger = logging.getLogger(__name__)

TERMINAL_STATES = {'success', 'failed', 'cancelled', 'dispatch_failed'}

# job_type values the generic /jobs endpoint accepts and can dispatch.
SCAN_JOB_TYPES = ('port', 'vuln', 'fingerprint', 'auth', 'full')

_RETENTION_DAYS = 30


class QueueDispatchError(RuntimeError):
    def __init__(self, message, job):
        super().__init__(message)
        self.job = job


def _now():
    return datetime.now(timezone.utc)


def _now_iso():
    return _now().strftime('%Y-%m-%dT%H:%M:%SZ')


# --------------------------------------------------------------------------- #
# Events
# --------------------------------------------------------------------------- #

def emit_event(job, kind, *, message=None, level=None, current=None, total=None,
               data=None, commit=True, broadcast=True):
    """Append one immutable JobEvent and (optionally) push it over Socket.IO."""
    seq = (db.session.query(db.func.coalesce(db.func.max(JobEvent.seq), 0))
           .filter(JobEvent.job_id == job.id).scalar()) + 1
    event = JobEvent(
        job_id=job.id, seq=seq, kind=kind, message=message, level=level,
        progress_current=current, progress_total=total,
        data_json=json.dumps(data) if data is not None else None,
        created_at=_now_iso(),
    )
    db.session.add(event)
    if current is not None:
        job.progress_current = current
    if total is not None:
        job.progress_total = total
    if commit:
        db.session.commit()

    if broadcast:
        try:
            from artemis.extensions import socketio
            socketio.emit('job_event', event.to_dict(), room=f'job:{job.id}')
        except Exception:  # noqa: BLE001 - transport must not break execution
            pass
    return event


def job_events(job, after_seq=0, limit=500):
    return (JobEvent.query.filter(JobEvent.job_id == job.id, JobEvent.seq > after_seq)
            .order_by(JobEvent.seq).limit(limit).all())


# --------------------------------------------------------------------------- #
# Creation / dispatch
# --------------------------------------------------------------------------- #

def create_job(job_type, target=None, site_id=None, requested_by=None, options=None,
               parent_job_id=None, idempotency_key=None):
    if idempotency_key:
        existing = ScanJob.query.filter_by(idempotency_key=idempotency_key).first()
        if existing:
            return existing
    job = ScanJob(
        job_type=job_type,
        target=target,
        site_id=site_id,
        requested_by=requested_by,
        parent_job_id=parent_job_id,
        idempotency_key=idempotency_key,
        options_json=json.dumps(options or {}),
        status='queued',
        created_at=_now_iso(),
        retention_until=(_now() + timedelta(days=_RETENTION_DAYS)).strftime('%Y-%m-%dT%H:%M:%SZ'),
    )
    db.session.add(job)
    db.session.commit()
    emit_event(job, 'queued', message=f'{job_type} job queued', broadcast=False)
    return job


def _publish(job, task, *, on_dispatch_fail=None):
    try:
        task.apply_async(args=[job.id], task_id=job.task_id)
    except Exception as exc:
        job.status = 'dispatch_failed'
        job.error_message = str(exc)
        job.completed_at = _now_iso()
        if on_dispatch_fail:
            on_dispatch_fail()
        emit_event(job, 'failure', message='dispatch failed', level='error')
        raise QueueDispatchError('Scan queue is unavailable', job) from exc


def dispatch_site_scan(site, requested_by=None):
    from artemis.tasks.scan_tasks import run_site_scan_job

    job = create_job('site_scan', target=site.name, site_id=site.id,
                     requested_by=requested_by, options={'scan_type': site.scan_type})
    job.task_id = f'site-scan-{job.id}'
    site.last_status = 'queued'
    db.session.commit()
    _publish(job, run_site_scan_job, on_dispatch_fail=lambda: setattr(site, 'last_status', 'failed'))
    return job


def dispatch_adhoc_scan(target, scan_type='port', options=None, requested_by=None,
                        parent_job_id=None, idempotency_key=None):
    from artemis.tasks.scan_tasks import run_adhoc_scan_job

    job = create_job('adhoc_scan', target=target, requested_by=requested_by,
                     parent_job_id=parent_job_id, idempotency_key=idempotency_key,
                     options={'scan_type': scan_type, **(options or {})})
    if job.status != 'queued':          # returned an existing idempotent job
        return job
    job.task_id = f'adhoc-scan-{job.id}'
    db.session.commit()
    _publish(job, run_adhoc_scan_job)
    return job


# --------------------------------------------------------------------------- #
# Lifecycle helpers used by tasks
# --------------------------------------------------------------------------- #

def mark_running(job, attempt=1, lease_seconds=1800):
    job.status = 'running'
    job.started_at = job.started_at or _now_iso()
    job.attempt = attempt
    job.error_message = None
    job.lease_expires_at = (_now() + timedelta(seconds=lease_seconds)).strftime('%Y-%m-%dT%H:%M:%SZ')
    db.session.commit()
    emit_event(job, 'started', message='job started', current=0)


def _already_terminal(job):
    if job.status in TERMINAL_STATES:
        logger.info('job %s already %s; ignoring transition', job.id, job.status)
        return True
    return False


def mark_result(job, result):
    if _already_terminal(job):
        return job
    if job.status == 'cancel_requested':
        return mark_cancelled(job)
    job.status = 'success'
    job.result_json = json.dumps(result)
    job.completed_at = _now_iso()
    job.lease_expires_at = None
    db.session.commit()
    emit_event(job, 'result', message='job completed', data=result)
    return job


def mark_failed(job, message):
    if _already_terminal(job):
        return job
    job.status = 'failed'
    job.error_message = str(message)[:2000]
    job.completed_at = _now_iso()
    job.lease_expires_at = None
    db.session.commit()
    emit_event(job, 'failure', message=str(message)[:500], level='error')
    return job


def mark_cancelled(job):
    if job.status in ('success', 'failed', 'dispatch_failed'):
        return job
    job.status = 'cancelled'
    job.completed_at = job.completed_at or _now_iso()
    job.lease_expires_at = None
    db.session.commit()
    emit_event(job, 'cancel', message='job cancelled')
    return job


def is_cancelling(job_id):
    status = db.session.query(ScanJob.status).filter(ScanJob.id == job_id).scalar()
    return status in ('cancel_requested', 'cancelled')


def reconcile_orphaned_leases():
    """Requeue jobs whose worker died (lease expired while still 'running')."""
    now = _now_iso()
    stale = ScanJob.query.filter(
        ScanJob.status == 'running',
        ScanJob.lease_expires_at.isnot(None),
        ScanJob.lease_expires_at < now,
    ).all()
    for job in stale:
        job.status = 'queued'
        job.lease_expires_at = None
        emit_event(job, 'retry', message='worker lost; job requeued', level='warning', commit=False)
    if stale:
        db.session.commit()
    return len(stale)


def cancel_job(job):
    if job.status in TERMINAL_STATES:
        return False

    was_running = job.status == 'running'
    job.status = 'cancel_requested' if was_running else 'cancelled'
    job.cancel_requested_at = _now_iso()
    if not was_running:
        job.completed_at = _now_iso()
    db.session.commit()
    emit_event(job, 'cancel', message='cancellation requested' if was_running else 'job cancelled')

    if job.task_id:
        try:
            current_app.extensions['celery'].control.revoke(job.task_id, terminate=False)
        except Exception:  # noqa: BLE001
            pass
    return True
