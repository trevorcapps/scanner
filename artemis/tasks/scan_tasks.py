"""Durable Celery tasks for scanner workloads.

Each task owns one ScanJob's execution: it takes the lease, streams JobEvents,
and records a terminal state. Browser disconnects never touch it.
"""

import json
import logging
from datetime import datetime, timezone

from celery import shared_task
from flask import current_app

from artemis.extensions import db
from artemis.models.scan_job import ScanJob
from artemis.services import job_service

logger = logging.getLogger(__name__)


def _now_iso():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _load_job(job_id):
    job = db.session.get(ScanJob, job_id)
    if not job:
        raise LookupError(f'Scan job {job_id} does not exist')
    from artemis.services.tenant import set_task_organization
    set_task_organization(job.organization_id)
    return job


@shared_task(
    bind=True, name='artemis.site_scan', max_retries=2, default_retry_delay=30,
    acks_late=True, reject_on_worker_lost=True,
)
def run_site_scan_job(self, job_id):
    """Execute one persisted site scan and retain its terminal state."""
    from artemis.models.site import Site
    from artemis.services.site_service import execute_site_scan

    job = _load_job(job_id)
    if job_service.is_cancelling(job.id):
        return job_service.mark_cancelled(job).to_dict()

    site = db.session.get(Site, job.site_id)
    if not site:
        return job_service.mark_failed(job, 'Site no longer exists').to_dict()

    job_service.mark_running(job, attempt=self.request.retries + 1)
    try:
        site_scan = execute_site_scan(current_app._get_current_object(), site, job=job)
        result = {
            'site_scan_id': site_scan.id,
            'status': site_scan.status,
            'targets_scanned': site_scan.targets_scanned,
            'targets_failed': site_scan.targets_failed,
            'ports_found': site_scan.ports_found,
            'vulns_found': site_scan.vulns_found,
        }
        if site_scan.status == 'cancelled':
            return job_service.mark_cancelled(job).to_dict()
        if site_scan.status == 'failed':
            return job_service.mark_failed(job, 'site scan failed').to_dict()
        return job_service.mark_result(job, result).to_dict()
    except Exception as exc:
        logger.exception('Site scan job %s failed', job.id)
        site.last_status = 'failed'
        if self.request.retries < self.max_retries:
            job.status = 'retrying'
            job.error_message = str(exc)
            db.session.commit()
            job_service.emit_event(job, 'retry', message=str(exc)[:300], level='warning')
            raise self.retry(exc=exc)
        job_service.mark_failed(job, exc)
        raise


@shared_task(bind=True, name='artemis.adhoc_scan', max_retries=1,
             default_retry_delay=30, acks_late=True, reject_on_worker_lost=True)
def run_adhoc_scan_job(self, job_id):
    """Execute a one-off target scan (port/vuln/fingerprint/auth/full)."""
    from types import SimpleNamespace
    from artemis.services.scheduler_service import _ScanCancelled, _run_scan

    job = _load_job(job_id)
    if job_service.is_cancelling(job.id):
        return job_service.mark_cancelled(job).to_dict()

    opts = job._decode(job.options_json) or {}
    job_service.mark_running(job, attempt=self.request.retries + 1)

    def log_cb(message, level='info'):
        job_service.emit_event(job, 'log', message=str(message)[:500], level=level)

    sched = SimpleNamespace(
        id=None,
        target=job.target,
        scan_type=opts.get('scan_type', 'port'),
        scan_options_json=json.dumps({k: v for k, v in opts.items() if k != 'scan_type'}),
        profile_id=opts.get('profile') or opts.get('templates') or '',
        credential_ids_json=json.dumps(opts.get('credential_ids', [])),
    )

    schedule_id = opts.get('schedule_id')
    start = datetime.now(timezone.utc)
    try:
        result = _run_scan(current_app._get_current_object(), sched,
                           cancel_predicate=lambda: job_service.is_cancelling(job.id),
                           log_callback=log_cb)
        if schedule_id:
            from artemis.services.scheduler_service import record_schedule_history
            record_schedule_history(schedule_id, result, 'success',
                                    int((datetime.now(timezone.utc) - start).total_seconds()))
        return job_service.mark_result(job, result).to_dict()
    except _ScanCancelled:
        return job_service.mark_cancelled(job).to_dict()
    except Exception as exc:
        logger.exception('Adhoc scan job %s failed', job.id)
        if schedule_id:
            from artemis.services.scheduler_service import record_schedule_history
            record_schedule_history(schedule_id, {'error': str(exc)}, 'failed',
                                    int((datetime.now(timezone.utc) - start).total_seconds()))
        job_service.mark_failed(job, exc)
        raise


@shared_task(name='artemis.dispatch_due_work')
def dispatch_due_work():
    """Celery Beat singleton: turn due schedules and expired leases into jobs.

    Replaces the in-web-process scheduler thread. It never executes a scan
    itself — it only creates durable jobs (or requeues orphans).
    """
    from artemis.services.scheduler_service import dispatch_due_scans
    from artemis.services.report_schedule_runner import run_due_report_schedules

    reconciled = job_service.reconcile_orphaned_leases()
    dispatched = dispatch_due_scans()
    now = _now_iso()
    try:
        run_due_report_schedules(now)
    except Exception:
        logger.exception('report schedule dispatch failed')
    logger.info('dispatch_due_work: %s scans dispatched, %s leases reconciled',
                dispatched, reconciled)
    return {'dispatched': dispatched, 'reconciled': reconciled}
