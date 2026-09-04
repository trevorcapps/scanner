"""The agent_local AutomationExecutor (P5-D).

For an outbound-only enrolled agent, a run is delivered as a signed manifest
carrying the immutable content digest. The agent verifies signature + digest,
runs the exact content against localhost with ``ansible.builtin.local``, and
streams Runner-compatible events back. This capability is advertised separately
(``ansible_local``) and content whose signature/digest does not match the
server-created job is rejected.
"""

import json
import logging
import time
from datetime import datetime, timedelta, timezone

from artemis.extensions import db
from artemis.models.agent import Agent
from artemis.models.agent_work import AgentWork
from artemis.services.automation.executor import AutomationExecutor
from artemis.services.tenant import scoped

logger = logging.getLogger(__name__)

WORK_TTL_SECONDS = 3600


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def agent_supports_local(agent):
    try:
        caps = json.loads(agent.capabilities_json or '[]')
    except (TypeError, ValueError):
        caps = []
    return 'ansible_local' in caps


def create_work(agent, *, job_id, kind, content_body=None, content_digest=None,
                variables=None):
    payload = {
        'job_id': job_id,
        'kind': kind,
        'variables': variables or {},
    }
    if content_body is not None:
        payload['content_b64'] = _b64(content_body)
    if content_digest:
        payload['content_digest'] = content_digest

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
    scoped(AgentWork).filter(AgentWork.agent_id == agent.id,
                             AgentWork.status.in_(('queued', 'delivered')),
                             AgentWork.expires_at < now).update(
        {'status': 'expired'}, synchronize_session=False)
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
    status = data.get('status', 'failed')
    if status == 'rejected':
        work.status = 'rejected'
        work.reject_reason = data.get('reason', '')[:500]
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
        else:
            job_service.mark_failed(job, work.reject_reason or 'agent-local run failed')
    db.session.commit()
    return work


class AgentLocalExecutor(AutomationExecutor):
    """Server-side executor that delegates to one enrolled agent."""

    name = 'agent-local'

    def __init__(self, agent):
        self.agent = agent

    def available(self):
        return agent_supports_local(self.agent)

    def run(self, *, playbook_body, inventory, variables, private_data_dir,
            event_handler, cancel_check=None, check_mode=False, options=None):
        import hashlib
        digest = hashlib.sha256(playbook_body.encode()).hexdigest()
        job_id = (options or {}).get('job_id')
        work = create_work(self.agent, job_id=job_id, kind='ansible_local',
                           content_body=playbook_body, content_digest=digest,
                           variables=variables)
        # The agent picks this up out of band; the calling task returns
        # immediately and the job is finished by record_result().
        event_handler({'event': 'playbook_on_play_start',
                       'event_data': {'name': f'delegated to agent {self.agent.id}'}})
        return {'status': 'delegated', 'rc': None, 'stats': {}, 'work_id': work.id}


def _b64(text):
    import base64
    return base64.b64encode(text.encode()).decode('ascii')
