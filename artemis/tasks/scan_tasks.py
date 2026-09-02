"""Durable Celery tasks for scanner workloads."""

import json
import logging
from datetime import datetime, timezone

from celery import shared_task
from flask import current_app

from artemis.extensions import db
from artemis.models.scan_job import ScanJob

logger = logging.getLogger(__name__)


def _now_iso():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _set_job(job, **fields):
    for field, value in fields.items():
        setattr(job, field, value)
    db.session.commit()


@shared_task(
    bind=True,
    name='artemis.site_scan',
    max_retries=2,
    default_retry_delay=30,
    acks_late=True,
    reject_on_worker_lost=True,
)
def run_site_scan_job(self, job_id):
    """Execute one persisted site scan and retain its terminal state."""
    from artemis.models.site import Site
    from artemis.services.site_service import execute_site_scan

    job = db.session.get(ScanJob, job_id)
    if not job:
        raise LookupError(f'Scan job {job_id} does not exist')
    if job.status in ('cancel_requested', 'cancelled'):
        _set_job(job, status='cancelled', completed_at=_now_iso())
        return job.to_dict()

    site = db.session.get(Site, job.site_id)
    if not site:
        _set_job(job, status='failed', error_message='Site no longer exists', completed_at=_now_iso())
        return job.to_dict()

    _set_job(
        job,
        status='running',
        started_at=job.started_at or _now_iso(),
        attempt=self.request.retries + 1,
        error_message=None,
    )

    try:
        site_scan = execute_site_scan(current_app._get_current_object(), site, job=job)
        if site_scan.status == 'cancelled':
            status = 'cancelled'
        elif site_scan.status == 'failed':
            status = 'failed'
        else:
            status = 'success'
        result = {
            'site_scan_id': site_scan.id,
            'status': site_scan.status,
            'targets_scanned': site_scan.targets_scanned,
            'targets_failed': site_scan.targets_failed,
            'ports_found': site_scan.ports_found,
            'vulns_found': site_scan.vulns_found,
        }
        _set_job(
            job,
            status=status,
            result_json=json.dumps(result),
            completed_at=_now_iso(),
        )
        return job.to_dict()
    except Exception as exc:
        logger.exception('Site scan job %s failed', job.id)
        site.last_status = 'failed'
        if self.request.retries < self.max_retries:
            _set_job(job, status='retrying', error_message=str(exc))
            raise self.retry(exc=exc)
        _set_job(job, status='failed', error_message=str(exc), completed_at=_now_iso())
        raise


@shared_task(bind=True, name='artemis.adhoc_scan', max_retries=1,
             default_retry_delay=30, acks_late=True, reject_on_worker_lost=True)
def run_adhoc_scan_job(self, job_id):
    """Execute a one-off target scan requested via POST /api/v1/scans."""
    from types import SimpleNamespace
    from artemis.services.scheduler_service import _run_scan

    job = db.session.get(ScanJob, job_id)
    if not job:
        raise LookupError(f'Scan job {job_id} does not exist')
    if job.status in ('cancel_requested', 'cancelled'):
        _set_job(job, status='cancelled', completed_at=_now_iso())
        return job.to_dict()

    opts = job._decode(job.options_json) or {}
    _set_job(job, status='running', started_at=job.started_at or _now_iso(),
             attempt=self.request.retries + 1, error_message=None)

    sched = SimpleNamespace(
        id=None,
        target=job.target,
        scan_type=opts.get('scan_type', 'port'),
        scan_options_json=json.dumps({k: v for k, v in opts.items() if k != 'scan_type'}),
        profile_id=opts.get('profile') or opts.get('templates') or '',
        credential_ids_json=json.dumps(opts.get('credential_ids', [])),
    )

    try:
        result = _run_scan(current_app._get_current_object(), sched)
        _set_job(job, status='success', result_json=json.dumps(result),
                 completed_at=_now_iso())
        return job.to_dict()
    except Exception as exc:
        logger.exception('Adhoc scan job %s failed', job.id)
        _set_job(job, status='failed', error_message=str(exc), completed_at=_now_iso())
        raise
