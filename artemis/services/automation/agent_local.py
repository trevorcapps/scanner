"""The agent_local AutomationExecutor (P5-D).

For an outbound-only enrolled agent, a run is delivered as a signed manifest
carrying the immutable content digest. The agent verifies signature + digest,
runs the exact content against localhost with ``ansible.builtin.local``, and
streams Runner-compatible events back. This capability is advertised separately
(``ansible_local``) and content whose signature/digest does not match the
server-created job is rejected.
"""

import base64
import hashlib
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from artemis.extensions import db
from artemis.models.agent import Agent
from artemis.models.agent_work import AgentWork
from artemis.services.automation.executor import AutomationExecutor
from artemis.services.tenant import scoped

logger = logging.getLogger(__name__)

WORK_TTL_SECONDS = 3600
WORK_LEASE_SECONDS = 300
_SECRET_AAD = b'artemis-agent-work-secrets-v1'


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def agent_supports_local(agent):
    try:
        caps = json.loads(agent.capabilities_json or '[]')
    except (TypeError, ValueError):
        caps = []
    return 'ansible_local' in caps


def _secret_key(agent):
    return hashlib.sha256(f'artemis-work-secrets:{agent.agent_key}'.encode()).digest()


def _seal_secrets(agent, values):
    """Encrypt transient credential values for the enrolled agent.

    Only the ciphertext is persisted in AgentWork. The agent derives the same
    key from its enrolled identity and decrypts the values immediately before
    execution.
    """
    if not values:
        return None
    nonce = os.urandom(12)
    ciphertext = AESGCM(_secret_key(agent)).encrypt(
        nonce, json.dumps(values, separators=(',', ':')).encode(), _SECRET_AAD)
    return {
        'nonce_b64': base64.b64encode(nonce).decode('ascii'),
        'ciphertext_b64': base64.b64encode(ciphertext).decode('ascii'),
    }


def create_work(agent, *, job_id, kind, content_body=None, content_digest=None,
                variables=None, secret_variables=None, check_mode=False):
    payload = {
        'job_id': job_id,
        'kind': kind,
        'variables': variables or {},
        'check_mode': bool(check_mode),
    }
    if content_body is not None:
        payload['content_b64'] = _b64(content_body)
    if content_digest:
        payload['content_digest'] = content_digest
    secret_box = _seal_secrets(agent, secret_variables)
    if secret_box:
        payload['secret_box'] = secret_box

    work = AgentWork(
        agent_id=agent.id, job_id=job_id, kind=kind, status='queued',
        content_digest=content_digest,
        payload_json=json.dumps(payload),
        signature=AgentWork.sign(agent, payload),
        created_at=_now(),
        expires_at=(datetime.now(timezone.utc) + timedelta(seconds=WORK_TTL_SECONDS))
        .strftime('%Y-%m-%dT%H:%M:%SZ'),
    )
    db.session.add(work)
    db.session.commit()
    return work


def poll_work(agent):
    """Return the oldest undelivered work item for an agent (agent-authenticated)."""
    now = _now()
    expired = scoped(AgentWork).filter(AgentWork.agent_id == agent.id,
                                       AgentWork.status.in_(('queued', 'delivered')),
                                       AgentWork.expires_at < now).all()
    for stale in expired:
        stale.status = 'expired'
        stale.completed_at = now
        stale.reject_reason = 'work item expired'
        _finish_parent_job(stale, failed=True)

    # A delivered item is leased, not acknowledged. Requeue it after the lease
    # so an agent that dies after polling can resume the job.
    lease_cutoff = (datetime.now(timezone.utc) - timedelta(seconds=WORK_LEASE_SECONDS)) \
        .strftime('%Y-%m-%dT%H:%M:%SZ')
    scoped(AgentWork).filter(AgentWork.agent_id == agent.id,
                             AgentWork.status == 'delivered',
                             AgentWork.delivered_at < lease_cutoff).update(
        {'status': 'queued'}, synchronize_session=False)
    work = (scoped(AgentWork).filter(AgentWork.agent_id == agent.id,
                                     AgentWork.status == 'queued')
            .order_by(AgentWork.created_at).first())
    if not work:
        db.session.commit()
        return None
    work.status = 'delivered'
    work.delivered_at = now
    db.session.commit()
    return work.manifest()


def record_result(agent, work_id, data):
    work = scoped(AgentWork).filter(AgentWork.id == work_id,
                                    AgentWork.agent_id == agent.id).first()
    if not work:
        return None
    if work.status in ('succeeded', 'failed', 'rejected', 'expired', 'cancelled'):
        return work
    status = data.get('status', 'failed')
    if status == 'rejected':
        work.status = 'rejected'
        work.reject_reason = data.get('reason', '')[:500]
    elif status == 'cancelled':
        work.status = 'cancelled'
    else:
        work.status = 'succeeded' if status in ('succeeded', 'successful') else 'failed'
    work.completed_at = _now()
    work.result_json = json.dumps({k: v for k, v in data.items() if k != 'events'})

    from artemis.services import job_service
    job = db.session.get(__import__('artemis.models.scan_job', fromlist=['ScanJob']).ScanJob,
                         work.job_id) if work.job_id else None
    if job and job.status not in job_service.TERMINAL_STATES:
        for event in data.get('events', [])[:500]:
            job_service.emit_event(job, 'log', message=str(event)[:500])
        if work.status == 'succeeded':
            job_service.mark_result(job, work.result_json and json.loads(work.result_json) or {})
        elif work.status == 'cancelled' or job.status == 'cancel_requested':
            job_service.mark_cancelled(job)
        else:
            job_service.mark_failed(job, work.reject_reason or 'agent-local run failed')
        _finish_campaign(job, work.status)
    db.session.commit()
    return work


def get_work(agent, work_id):
    return scoped(AgentWork).filter(AgentWork.id == work_id,
                                    AgentWork.agent_id == agent.id).first()


class AgentLocalExecutor(AutomationExecutor):
    """Server-side executor that delegates to one enrolled agent."""

    name = 'agent-local'
    handles_credentials = True

    def __init__(self, agent):
        self.agent = agent

    def available(self):
        return agent_supports_local(self.agent)

    def run(self, *, playbook_body, inventory, variables, private_data_dir,
            event_handler, cancel_check=None, check_mode=False, options=None):
        import hashlib
        digest = hashlib.sha256(playbook_body.encode()).hexdigest()
        job_id = (options or {}).get('job_id')
        credential_refs = (options or {}).get('credential_refs') or []
        secret_variables = {}
        if credential_refs:
            from artemis.services.auth_scan_service import resolve_credential_secrets
            for ref in credential_refs:
                secrets = resolve_credential_secrets(ref, reason='automation_agent_local') or {}
                if secrets.get('password'):
                    secret_variables['ansible_password'] = secrets['password']
                if secrets.get('key_data'):
                    secret_variables['ansible_ssh_private_key'] = secrets['key_data']
        work = create_work(self.agent, job_id=job_id, kind='ansible_local',
                           content_body=playbook_body, content_digest=digest,
                           variables=variables, secret_variables=secret_variables,
                           check_mode=check_mode)
        # The agent picks this up out of band; the calling task returns
        # immediately and the job is finished by record_result().
        event_handler({'event': 'playbook_on_play_start',
                       'event_data': {'name': f'delegated to agent {self.agent.id}'}})
        return {'status': 'delegated', 'rc': None, 'stats': {}, 'work_id': work.id}


def _b64(text):
    return base64.b64encode(text.encode()).decode('ascii')


def _finish_parent_job(work, failed=False):
    """Fail an expired work item's parent while preserving cancellation state."""
    if not work.job_id:
        return
    from artemis.models.scan_job import ScanJob
    from artemis.services import job_service
    job = db.session.get(ScanJob, work.job_id)
    if job and job.status not in job_service.TERMINAL_STATES:
        if failed:
            if job.status == 'cancel_requested':
                job_service.mark_cancelled(job)
            else:
                job_service.mark_failed(job, 'agent-local work expired')
            _finish_campaign(job, 'failed')


def _finish_campaign(job, work_status):
    from artemis.models.automation import AutomationRun
    run = scoped(AutomationRun).filter(AutomationRun.job_id == job.id).first()
    if not run:
        return
    options = json.loads(run.launch_options_json or '{}')
    campaign_id = options.get('campaign_id')
    if not campaign_id:
        return
    from artemis.services.automation.campaign_service import record_batch_outcome
    outcome = {aid: ('success' if work_status == 'succeeded' else 'failed')
               for aid in json.loads(run.target_snapshot_json or '[]')}
    record_batch_outcome(campaign_id, job.id, outcome)
