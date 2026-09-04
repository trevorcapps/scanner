"""Patch-campaign orchestration (P5-E)."""

import json
from datetime import datetime, timezone

from artemis.extensions import db
from artemis.models.asset import Asset
from artemis.models.campaign import PatchCampaign
from artemis.services import audit_service, job_service
from artemis.services.automation import starters
from artemis.services.automation.content_service import accept_content
from artemis.services.automation.run_service import launch_run
from artemis.services.tenant import current_org_id, scoped, scoped_get


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def create_campaign(data, created_by=None):
    starter_id = data.get('starter_id')
    content_id = data.get('content_id')
    if not (starter_id or content_id):
        raise ValueError('starter_id or content_id is required')
    if starter_id and not starters.STARTERS.get(starter_id):
        raise ValueError(f'unknown starter {starter_id}')

    candidates = _resolve_candidates(data.get('targets') or {})
    if not candidates:
        raise ValueError('no candidate hosts resolved')

    campaign = PatchCampaign(
        name=(data.get('name') or 'campaign').strip(),
        starter_id=starter_id, content_id=content_id,
        status='planned',
        candidate_ids_json=json.dumps(candidates),
        excluded_ids_json=json.dumps(data.get('excluded_ids') or []),
        canary_ids_json=json.dumps(data.get('canary_ids') or []),
        batch_size=int(data.get('batch_size', 10)),
        pause_between_batches=int(data.get('pause_between_batches', 0)),
        max_fail_percentage=int(data.get('max_fail_percentage', 0)),
        coordinate_reboot=1 if data.get('coordinate_reboot', True) else 0,
        maintenance_window_id=data.get('maintenance_window_id'),
        variables_json=json.dumps(data.get('variables') or {}),
        per_host_json=json.dumps({str(cid): {'status': 'pending'} for cid in candidates}),
        created_at=_now(), created_by=created_by,
    )
    db.session.add(campaign)
    db.session.commit()
    audit_service.record('campaign.create', target_type='patch_campaign', target_id=campaign.id,
                         detail={'starter': starter_id, 'candidates': len(candidates)}, commit=True)
    return campaign


def _resolve_candidates(spec):
    from artemis.models.asset_group import AssetGroup, AssetTag
    from artemis.services.asset_lifecycle_service import group_members
    ids = set()
    for aid in spec.get('asset_ids', []):
        if scoped_get(Asset, aid):
            ids.add(aid)
    for gid in spec.get('group_ids', []):
        if scoped_get(AssetGroup, gid):
            ids.update(a.id for a in group_members(gid))
    for tag in spec.get('tags', []):
        ids.update(a.id for a in scoped(Asset).filter(Asset.tags.any(AssetTag.name == tag)).all())
    live = {a.id for a in scoped(Asset).filter(
        Asset.id.in_(ids), Asset.lifecycle != 'decommissioned').all()}
    return sorted(live)


def _content_body(campaign):
    if campaign.starter_id:
        return starters.get_starter_body(campaign.starter_id)
    from artemis.models.automation import AutomationContent
    content = scoped_get(AutomationContent, campaign.content_id)
    return content.reveal() if content else None


def _launch_batch(campaign, asset_ids, *, check_mode=False, parent_job_id=None):
    body = _content_body(campaign)
    # Mark hosts running *before* dispatch so an eager task's terminal callback
    # can find the campaign.
    per_host = json.loads(campaign.per_host_json or '{}')
    for aid in asset_ids:
        per_host[str(aid)] = {'status': 'running', 'at': _now()}
    campaign.per_host_json = json.dumps(per_host)
    campaign_id = campaign.id
    db.session.commit()

    run, job = launch_run(
        content_raw=body, targets={'asset_ids': asset_ids},
        variables={**json.loads(campaign.variables_json or '{}'),
                   'batch_size': campaign.batch_size,
                   'max_fail_percentage': campaign.max_fail_percentage},
        check_mode=check_mode, serial=campaign.batch_size,
        max_fail_percentage=campaign.max_fail_percentage,
        launch_options={'campaign_id': campaign_id, 'parent_job_id': parent_job_id},
        launched_by=campaign.created_by,
    )
    return run, job


def preview(campaign_id):
    campaign = scoped_get(PatchCampaign, campaign_id)
    if not campaign:
        return None
    campaign.status = 'previewing'
    db.session.commit()
    _run, job = _launch_batch(campaign, campaign.target_ids, check_mode=True)
    return job


def start(campaign_id):
    """Kick off canary (if any) then hand the rest to advance()."""
    campaign = scoped_get(PatchCampaign, campaign_id)
    if not campaign or campaign.status in ('completed', 'cancelled'):
        return None
    campaign.started_at = campaign.started_at or _now()
    parent = job_service.create_job('campaign', target=campaign.name,
                                    requested_by=campaign.created_by,
                                    options={'campaign_id': campaign.id})
    campaign.parent_job_id = parent.id

    canary = campaign.canary_ids or campaign.target_ids[:1]
    campaign.status = 'canary' if campaign.canary_ids else 'rolling'
    db.session.commit()
    _run, job = _launch_batch(campaign, canary, parent_job_id=parent.id)
    return job


def advance(campaign_id):
    """Progress the campaign one batch. Stops if the failure threshold is hit."""
    campaign = scoped_get(PatchCampaign, campaign_id)
    if not campaign or campaign.status not in ('canary', 'rolling', 'paused'):
        return campaign

    per_host = json.loads(campaign.per_host_json or '{}')
    done_ok = {int(k) for k, v in per_host.items() if v.get('status') == 'success'}
    done_fail = {int(k) for k, v in per_host.items() if v.get('status') == 'failed'}
    running = {int(k) for k, v in per_host.items() if v.get('status') == 'running'}
    if running:
        return campaign   # wait for the current batch

    total = len(campaign.target_ids)
    if total and len(done_fail) * 100 // total > campaign.max_fail_percentage:
        campaign.status = 'failed'
        db.session.commit()
        audit_service.record('campaign.failed', target_type='patch_campaign',
                             target_id=campaign.id, detail={'failed': len(done_fail)}, commit=True)
        return campaign

    remaining = [i for i in campaign.target_ids if i not in done_ok and i not in done_fail]
    if not remaining:
        campaign.status = 'completed'
        campaign.completed_at = _now()
        db.session.commit()
        if campaign.starter_id and 'update' in campaign.starter_id:
            _post_run_fact_refresh(campaign)
        audit_service.record('campaign.completed', target_type='patch_campaign',
                             target_id=campaign.id, commit=True)
        return campaign

    campaign.status = 'rolling'
    batch = remaining[:campaign.batch_size]
    db.session.commit()
    _launch_batch(campaign, batch, parent_job_id=campaign.parent_job_id)
    return campaign


def record_batch_outcome(campaign_id, job_id, host_results):
    """Called from the automation job's terminal handler. host_results:
    {asset_id: 'success'|'failed'}."""
    campaign = scoped_get(PatchCampaign, campaign_id)
    if not campaign:
        return
    per_host = json.loads(campaign.per_host_json or '{}')
    for aid, status in host_results.items():
        per_host[str(aid)] = {'status': status, 'job_id': job_id, 'at': _now()}
    campaign.per_host_json = json.dumps(per_host)
    db.session.commit()
    advance(campaign.id)


def _post_run_fact_refresh(campaign):
    try:
        body = starters.get_starter_body('linux-fact-refresh')
        launch_run(content_raw=body, targets={'asset_ids': campaign.target_ids},
                   variables={}, launched_by=campaign.created_by)
    except Exception:  # noqa: BLE001
        pass


def cancel(campaign_id):
    campaign = scoped_get(PatchCampaign, campaign_id)
    if campaign and campaign.status not in ('completed', 'cancelled'):
        campaign.status = 'cancelled'
        db.session.commit()
    return campaign
