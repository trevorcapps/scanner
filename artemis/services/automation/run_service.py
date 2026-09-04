"""Launch and execute automation runs (P5-B/C).

A run resolves to: one immutable content digest, a target-ID snapshot, an
ephemeral inventory built from Artemis assets/agents/groups, just-in-time
credential resolution, and a generic ScanJob whose JobEvents mirror the Ansible
Runner event stream.
"""

import json
import logging
from datetime import datetime, timezone

from artemis.extensions import db
from artemis.models.asset import Asset
from artemis.models.automation import AutomationRun, ExecutionEnvironment
from artemis.services import audit_service, job_service
from artemis.services.automation import content_service
from artemis.services.automation.executor import ExecutorUnavailable, TempDataDir, get_executor
from artemis.services.tenant import current_org_id, scoped, scoped_get

logger = logging.getLogger(__name__)


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _resolve_targets(spec):
    """spec: {"asset_ids": [...], "group_ids": [...], "tags": [...]}. Returns
    a list of {id, address, user, port} host vars from controlled sources only."""
    from artemis.models.asset_group import AssetGroup
    from artemis.services.asset_lifecycle_service import group_members

    assets = {}
    for aid in spec.get('asset_ids', []):
        asset = scoped_get(Asset, aid)
        if asset:
            assets[asset.id] = asset
    for gid in spec.get('group_ids', []):
        if scoped_get(AssetGroup, gid):
            for asset in group_members(gid):
                assets[asset.id] = asset
    if spec.get('tags'):
        for tag in spec['tags']:
            for asset in scoped(Asset).filter(Asset.tags.any(name=tag)).all():
                assets[asset.id] = asset

    hosts = []
    for asset in assets.values():
        if asset.lifecycle == 'decommissioned':
            continue
        hosts.append({
            'id': asset.id,
            'address': asset.ip,
            'user': spec.get('user') or 'root',
            'port': spec.get('port') or 22,
        })
    return hosts


def build_inventory(hosts):
    """A private INI inventory. Immutable Artemis asset IDs are the identities;
    connection details come only from controlled host vars. No secrets here."""
    lines = ['[targets]']
    for host in hosts:
        lines.append(
            f"artemis_{host['id']} ansible_host={host['address']} "
            f"ansible_user={host['user']} ansible_port={host['port']}"
        )
    lines += ['', '[targets:vars]', 'ansible_python_interpreter=auto_silent']
    return '\n'.join(lines) + '\n'


def launch_run(*, content_raw=None, content_id=None, content_kind='playbook',
               filename=None, targets, variables=None, credential_refs=None,
               execution_environment_id=None, check_mode=False, serial=None,
               max_fail_percentage=None, launch_options=None, launched_by=None):
    executor = get_executor()

    if content_id:
        content = scoped_get(
            __import__('artemis.models.automation', fromlist=['AutomationContent']).AutomationContent,
            content_id)
        if not content:
            raise ValueError('content not found')
    else:
        content = content_service.accept_content(
            content_raw, kind=content_kind, filename=filename, created_by=launched_by)

    hosts = _resolve_targets(targets or {})
    if not hosts:
        raise ValueError('no eligible targets resolved')

    job = job_service.create_job('ansible_run', target=f'{len(hosts)} host(s)',
                                 requested_by=launched_by,
                                 options={'content_digest': content.digest,
                                          'check_mode': check_mode})
    job.task_id = f'ansible-{job.id}'
    db.session.flush()

    run = AutomationRun(
        job_id=job.id, content_id=content.id, content_digest=content.digest,
        execution_environment_id=execution_environment_id,
        variables_json=json.dumps(variables or {}),
        credential_refs_json=json.dumps(credential_refs or []),
        target_snapshot_json=json.dumps([h['id'] for h in hosts]),
        check_mode=1 if check_mode else 0, serial=serial,
        max_fail_percentage=max_fail_percentage,
        launch_options_json=json.dumps(launch_options or {}),
        launched_by=launched_by, created_at=_now(),
    )
    db.session.add(run)
    db.session.commit()

    audit_service.record('automation.launch', target_type='automation_run', target_id=run.id,
                         detail={'digest': content.digest, 'hosts': len(hosts),
                                 'check_mode': check_mode,
                                 'variables': list((variables or {}).keys())},
                         commit=True)

    if not executor.available():
        job_service.mark_failed(job, 'no automation executor available')
        return run, job

    from artemis.tasks.scan_tasks import run_automation_job
    try:
        run_automation_job.apply_async(args=[job.id], task_id=job.task_id)
    except Exception as exc:
        job_service.mark_failed(job, f'dispatch failed: {exc}')
    return run, job


def execute(job):
    """Called by the Celery task. Maps Runner events onto JobEvents."""
    run = scoped(AutomationRun).filter(AutomationRun.job_id == job.id).first()
    if not run:
        return job_service.mark_failed(job, 'automation run record missing')

    content = db.session.get(
        __import__('artemis.models.automation', fromlist=['AutomationContent']).AutomationContent,
        run.content_id)
    playbook_body = content.reveal()
    hosts = _resolve_targets({'asset_ids': json.loads(run.target_snapshot_json)})
    inventory = build_inventory(hosts)

    variables = json.loads(run.variables_json or '{}')
    _inject_credentials(variables, json.loads(run.credential_refs_json or '[]'))

    executor = get_executor()
    job_service.mark_running(job, lease_seconds=3600)

    counts = {'ok': 0, 'changed': 0, 'failed': 0, 'unreachable': 0, 'skipped': 0}

    def on_event(event):
        etype = event.get('event', '')
        data = event.get('event_data', {}) or {}
        if etype in ('runner_on_ok', 'runner_on_changed', 'runner_on_failed',
                     'runner_on_unreachable', 'runner_on_skipped'):
            key = etype.replace('runner_on_', '')
            counts[key] = counts.get(key, 0) + 1
            job_service.emit_event(
                job, 'log',
                message=f"{data.get('host', '?')}: {data.get('task', etype)} [{key}]",
                level='error' if key in ('failed', 'unreachable') else 'info',
                data={'host': data.get('host'), 'task': data.get('task'), 'result': key},
            )
        elif etype == 'playbook_on_play_start':
            job_service.emit_event(job, 'log', message=f"play: {data.get('name', '')}")

    try:
        with TempDataDir() as pdd:
            result = executor.run(
                playbook_body=playbook_body, inventory=inventory, variables=variables,
                private_data_dir=pdd, event_handler=on_event,
                cancel_check=lambda: job_service.is_cancelling(job.id),
                check_mode=bool(run.check_mode),
                options=json.loads(run.launch_options_json or '{}'),
            )
    except ExecutorUnavailable as exc:
        return job_service.mark_failed(job, str(exc))
    finally:
        variables.clear()  # destroy decrypted secrets

    summary = {'status': result.get('status'), 'rc': result.get('rc'),
               'host_summary': counts, 'stats': result.get('stats')}
    if result.get('status') == 'successful' and counts['failed'] == 0 and counts['unreachable'] == 0:
        return job_service.mark_result(job, summary)
    return job_service.mark_failed(job, json.dumps(summary))


def _inject_credentials(variables, refs):
    from artemis.services.auth_scan_service import resolve_credential_secrets
    for ref in refs:
        secrets = resolve_credential_secrets(ref, reason='automation_run')
        if not secrets:
            continue
        if secrets.get('password'):
            variables['ansible_password'] = secrets['password']
        if secrets.get('key_data'):
            variables['ansible_ssh_private_key'] = secrets['key_data']


# --- execution environments -------------------------------------------------
def list_environments():
    return scoped(ExecutionEnvironment).order_by(ExecutionEnvironment.name).all()


def create_environment(data, created_by=None):
    env = ExecutionEnvironment(
        name=(data.get('name') or 'default').strip(),
        image=data['image'],
        ansible_core_version=data.get('ansible_core_version'),
        runner_version=data.get('runner_version'),
        collections_json=json.dumps(data.get('collections', [])),
        is_default=1 if data.get('is_default') else 0,
        created_at=_now(),
    )
    db.session.add(env)
    db.session.commit()
    return env
