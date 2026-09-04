"""Asset business context, lifecycle, tags, and groups (P3.1)."""

import json
from datetime import datetime, timedelta, timezone

from artemis.extensions import db
from artemis.models.asset import CRITICALITY, LIFECYCLE_STATES, MANUAL_FIELDS, Asset
from artemis.models.asset_group import (
    AssetGroup,
    AssetGroupMember,
    AssetReviewEvent,
    AssetTag,
)
from artemis.services import audit_service
from artemis.services.tenant import current_org_id, scoped, scoped_get

STALE_AFTER_DAYS = 30


def _now_iso():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


# --------------------------------------------------------------------------- #
# Business context + lifecycle
# --------------------------------------------------------------------------- #

def update_business_context(asset_id, data):
    asset = scoped_get(Asset, asset_id)
    if not asset:
        return None
    if 'criticality' in data and data['criticality'] not in CRITICALITY:
        raise ValueError(f'criticality must be one of {CRITICALITY}')

    for field in MANUAL_FIELDS:
        if field in data:
            value = data[field]
            setattr(asset, field, value)
            if value not in (None, ''):
                asset.mark_manual(field)
    db.session.commit()
    audit_service.record('asset.update', target_type='asset', target_id=asset.id,
                         detail={'fields': [f for f in MANUAL_FIELDS if f in data]}, commit=True)
    return asset


def decommission(asset_id, reason, actor_id=None):
    asset = scoped_get(Asset, asset_id)
    if not asset:
        return None
    asset.lifecycle = 'decommissioned'
    asset.decommission_reason = reason
    asset.decommissioned_at = _now_iso()
    db.session.commit()
    audit_service.record('asset.decommission', target_type='asset', target_id=asset.id,
                         detail={'reason': reason}, commit=True)
    try:
        from artemis.services.webhook_service import emit
        emit('asset.decommissioned', {'asset_id': asset.id, 'ip': asset.ip, 'reason': reason})
    except Exception:  # noqa: BLE001
        pass
    return asset


def reactivate(asset_id):
    asset = scoped_get(Asset, asset_id)
    if not asset:
        return None
    asset.lifecycle = 'active'
    asset.decommission_reason = None
    asset.decommissioned_at = None
    for ev in AssetReviewEvent.query.filter_by(asset_id=asset.id, resolved_at=None,
                                               kind='decommissioned_reappeared'):
        ev.resolved_at = _now_iso()
    db.session.commit()
    audit_service.record('asset.reactivate', target_type='asset', target_id=asset.id, commit=True)
    return asset


def mark_stale_assets():
    """Move assets not seen in STALE_AFTER_DAYS from active -> stale."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=STALE_AFTER_DAYS)).strftime('%Y-%m-%dT%H:%M:%SZ')
    rows = scoped(Asset).filter(Asset.lifecycle == 'active',
                                Asset.last_seen.isnot(None), Asset.last_seen < cutoff).all()
    for asset in rows:
        asset.lifecycle = 'stale'
    if rows:
        db.session.commit()
    return len(rows)


def bulk_operation(op, asset_ids, **kwargs):
    """op ∈ {'tag', 'untag', 'set_context', 'decommission', 'add_to_group', 'remove_from_group'}."""
    assets = scoped(Asset).filter(Asset.id.in_(asset_ids)).all()
    touched = 0
    for asset in assets:
        if op == 'tag':
            add_tag(asset.id, kwargs['tag'])
        elif op == 'untag':
            remove_tag(asset.id, kwargs['tag'])
        elif op == 'set_context':
            update_business_context(asset.id, kwargs['context'])
        elif op == 'decommission':
            decommission(asset.id, kwargs.get('reason', 'bulk decommission'))
        elif op == 'add_to_group':
            add_to_group(kwargs['group_id'], asset.id)
        elif op == 'remove_from_group':
            remove_from_group(kwargs['group_id'], asset.id)
        touched += 1
    return touched


# --------------------------------------------------------------------------- #
# Tags
# --------------------------------------------------------------------------- #

def list_tags():
    return scoped(AssetTag).order_by(AssetTag.name).all()


def get_or_create_tag(name, color=None):
    name = name.strip()
    tag = scoped(AssetTag).filter(AssetTag.name == name).first()
    if not tag:
        tag = AssetTag(name=name, color=color, created_at=_now_iso())
        db.session.add(tag)
        db.session.flush()
    return tag


def add_tag(asset_id, name):
    asset = scoped_get(Asset, asset_id)
    if not asset:
        return None
    tag = get_or_create_tag(name)
    if tag not in asset.tags:
        asset.tags.append(tag)
        db.session.commit()
    return tag


def remove_tag(asset_id, name):
    asset = scoped_get(Asset, asset_id)
    tag = scoped(AssetTag).filter(AssetTag.name == name.strip()).first()
    if asset and tag and tag in asset.tags:
        asset.tags.remove(tag)
        db.session.commit()


# --------------------------------------------------------------------------- #
# Groups (static + dynamic)
# --------------------------------------------------------------------------- #

def list_groups():
    return scoped(AssetGroup).order_by(AssetGroup.name).all()


def create_group(name, *, kind='static', description=None, filter_spec=None, created_by=None):
    if kind not in ('static', 'dynamic'):
        raise ValueError('kind must be static or dynamic')
    group = AssetGroup(
        name=name.strip(), kind=kind, description=description,
        filter_json=json.dumps(filter_spec) if filter_spec else None,
        created_at=_now_iso(), created_by=created_by,
    )
    db.session.add(group)
    db.session.commit()
    return group


def add_to_group(group_id, asset_id):
    group = scoped_get(AssetGroup, group_id)
    if not group or group.kind != 'static':
        return None
    if not AssetGroupMember.query.filter_by(group_id=group_id, asset_id=asset_id).first():
        db.session.add(AssetGroupMember(group_id=group_id, asset_id=asset_id))
        db.session.commit()
    return group


def remove_from_group(group_id, asset_id):
    AssetGroupMember.query.filter_by(group_id=group_id, asset_id=asset_id).delete()
    db.session.commit()


def _dynamic_query(spec):
    q = scoped(Asset)
    if spec.get('environment'):
        q = q.filter(Asset.environment == spec['environment'])
    if spec.get('lifecycle'):
        q = q.filter(Asset.lifecycle == spec['lifecycle'])
    crit = spec.get('criticality')
    if crit:
        q = q.filter(Asset.criticality.in_(crit if isinstance(crit, list) else [crit]))
    if spec.get('device_type'):
        q = q.filter(Asset.device_type == spec['device_type'])
    if spec.get('tag'):
        q = q.filter(Asset.tags.any(AssetTag.name == spec['tag']))
    return q


def group_members(group_id):
    group = scoped_get(AssetGroup, group_id)
    if not group:
        return []
    if group.kind == 'dynamic':
        return _dynamic_query(group.filter_spec).all()
    return (scoped(Asset).join(AssetGroupMember, AssetGroupMember.asset_id == Asset.id)
            .filter(AssetGroupMember.group_id == group_id).all())


def list_review_events(unresolved_only=True):
    q = scoped(AssetReviewEvent)
    if unresolved_only:
        q = q.filter(AssetReviewEvent.resolved_at.is_(None))
    return q.order_by(AssetReviewEvent.created_at.desc()).all()
