"""Disposition + suppression workflow (P4.4)."""

import ipaddress
import json
from datetime import datetime, timezone

from artemis.extensions import db
from artemis.models.disposition import (
    DISPOSITION_SCOPES,
    DISPOSITION_TYPES,
    Disposition,
    SuppressionRule,
)
from artemis.models.finding import FindingOccurrence
from artemis.services import audit_service
from artemis.services.tenant import current_org_id, scoped, scoped_get


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


# --------------------------------------------------------------------------- #
# Dispositions
# --------------------------------------------------------------------------- #

def create_disposition(data, requested_by=None):
    dtype = data.get('type')
    scope = data.get('scope', 'occurrence')
    if dtype not in DISPOSITION_TYPES:
        raise ValueError(f'type must be one of {DISPOSITION_TYPES}')
    if scope not in DISPOSITION_SCOPES:
        raise ValueError(f'scope must be one of {DISPOSITION_SCOPES}')
    if not (data.get('rationale') or '').strip():
        raise ValueError('rationale is required')

    fingerprint = data.get('fingerprint')
    definition_id = data.get('definition_id')
    target_id = data.get('target_id')

    if target_id is not None:
        try:
            target_id = int(target_id)
        except (TypeError, ValueError) as exc:
            raise ValueError('target_id must be an integer') from exc

    if scope == 'occurrence':
        if not target_id:
            raise ValueError('target_id is required for occurrence scope')
        occ = scoped_get(FindingOccurrence, target_id)
        if not occ:
            raise ValueError('finding occurrence not found')
        fingerprint = occ.fingerprint
        definition_id = definition_id or occ.definition_id
    elif scope == 'asset' and target_id:
        from artemis.models.asset import Asset
        if not scoped_get(Asset, target_id):
            raise ValueError('asset not found')
    elif scope == 'group' and target_id:
        from artemis.models.asset_group import AssetGroup
        if not scoped_get(AssetGroup, target_id):
            raise ValueError('asset group not found')
    elif scope in ('asset', 'group'):
        raise ValueError(f'target_id is required for {scope} scope')

    disp = Disposition(
        disposition_type=dtype, scope=scope, target_id=target_id,
        fingerprint=fingerprint, definition_id=definition_id,
        rationale=data['rationale'].strip(),
        evidence_json=json.dumps(data['evidence']) if data.get('evidence') is not None else None,
        requested_by=requested_by,
        status='pending',
        created_at=_now(),
        expires_at=data.get('expires_at'),
        review_date=data.get('review_date'),
    )
    db.session.add(disp)
    db.session.flush()

    if not disp.needs_approval():
        _apply(disp, approver_id=requested_by, auto=True)
    db.session.commit()
    audit_service.record('disposition.create', target_type='disposition', target_id=disp.id,
                         detail={'type': dtype, 'scope': scope, 'auto_approved': not disp.needs_approval()},
                         commit=True)
    return disp


def decide(disposition_id, approve, approver_id):
    disp = scoped_get(Disposition, disposition_id)
    if not disp or disp.status != 'pending':
        return None
    if approve:
        _apply(disp, approver_id=approver_id, auto=False)
    else:
        disp.status = 'rejected'
        disp.approved_by = approver_id
        disp.approved_at = _now()
    db.session.commit()
    audit_service.record('disposition.decide', target_type='disposition', target_id=disp.id,
                         detail={'approved': approve}, commit=True)
    return disp


def _apply(disp, approver_id, auto):
    disp.status = 'approved'
    disp.approved_by = approver_id
    disp.approved_at = _now()
    # Reflect on the matching occurrences (status only — evidence untouched).
    target_status = 'accepted' if disp.disposition_type == 'risk_accepted' else 'suppressed'
    for occ in _matching_occurrences(disp):
        if occ.status in ('open', 'reopened'):
            occ.status = target_status

    # organization / group-wide dispositions also spawn a reusable rule.
    # A reusable rule without a selector matches every finding. Group rules
    # without a definition/fingerprint are represented by the current status
    # updates below, but must never become an unbounded organization rule.
    has_selector = bool(disp.definition_id or disp.fingerprint)
    if disp.scope == 'organization' or (disp.scope == 'group' and has_selector) \
            or (disp.disposition_type == 'false_positive' and has_selector):
        db.session.add(SuppressionRule(
            name=f'{disp.disposition_type}:{disp.definition_id or disp.scope}',
            definition_id=disp.definition_id, fingerprint=disp.fingerprint,
            reason=disp.rationale, disposition_id=disp.id, enabled=1,
            created_by=disp.approved_by, created_at=_now(), expires_at=disp.expires_at,
        ))


def _matching_occurrences(disp):
    q = scoped(FindingOccurrence)
    if disp.fingerprint:
        return q.filter(FindingOccurrence.fingerprint == disp.fingerprint).all()
    if disp.scope == 'asset' and disp.target_id:
        return q.filter(FindingOccurrence.asset_id == disp.target_id).all()
    if disp.scope == 'group' and disp.target_id:
        from artemis.models.asset_group import AssetGroupMember
        asset_ids = [row.asset_id for row in scoped(AssetGroupMember).filter(
            AssetGroupMember.group_id == disp.target_id).all()]
        return q.filter(FindingOccurrence.asset_id.in_(asset_ids)).all() if asset_ids else []
    if disp.definition_id:
        return q.filter(FindingOccurrence.definition_id == disp.definition_id).all()
    return []


def expire_due():
    """Approved dispositions past their expiry return to open and notify."""
    now = _now()
    reopened = 0
    for disp in scoped(Disposition).filter(
        Disposition.status == 'approved',
        Disposition.expires_at.isnot(None), Disposition.expires_at < now,
    ).all():
        disp.status = 'expired'
        for occ in _matching_occurrences(disp):
            if occ.status in ('suppressed', 'accepted'):
                occ.status = 'reopened'
                occ.reopened_at = now
                reopened += 1
        audit_service.record('disposition.expired', target_type='disposition',
                             target_id=disp.id, commit=False)
        _notify_expired(disp)
    for rule in scoped(SuppressionRule).filter(
        SuppressionRule.enabled == 1, SuppressionRule.expires_at.isnot(None),
        SuppressionRule.expires_at < now,
    ).all():
        rule.enabled = 0
    db.session.commit()
    return reopened


# --------------------------------------------------------------------------- #
# Suppression matching (presentation-time)
# --------------------------------------------------------------------------- #

def active_rules():
    now = _now()
    return scoped(SuppressionRule).filter(
        SuppressionRule.enabled == 1,
        db.or_(SuppressionRule.expires_at.is_(None), SuppressionRule.expires_at > now),
    ).all()


def is_suppressed(occ, rules=None):
    rules = rules if rules is not None else active_rules()
    for rule in rules:
        if rule.definition_id and rule.definition_id != occ.definition_id:
            continue
        if rule.fingerprint and rule.fingerprint != occ.fingerprint:
            continue
        if rule.component_pattern and rule.component_pattern not in (occ.component or ''):
            continue
        if rule.ip_pattern and not _ip_matches(rule.ip_pattern, occ.ip):
            continue
        return True
    return False


def _ip_matches(pattern, ip):
    if not ip:
        return False
    try:
        if '/' in pattern:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(pattern, strict=False)
        return pattern == ip
    except ValueError:
        return pattern == ip


def effective_risk():
    """Open findings minus suppressed/accepted, grouped by severity."""
    rules = active_rules()
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    suppressed = accepted = 0
    for occ in scoped(FindingOccurrence).filter(
        FindingOccurrence.status.in_(('open', 'reopened', 'suppressed', 'accepted'))
    ).all():
        if occ.status == 'accepted':
            accepted += 1
            continue
        if occ.status == 'suppressed' or is_suppressed(occ, rules):
            suppressed += 1
            continue
        sev = (occ.definition.severity if occ.definition else 'medium') or 'medium'
        counts[sev.lower()] = counts.get(sev.lower(), 0) + 1
    return {'effective': counts, 'suppressed': suppressed, 'accepted': accepted}


def _notify_expired(disp):
    try:
        from artemis.services.webhook_service import emit
        emit('disposition.approved', {'disposition_id': disp.id, 'status': 'expired',
                                      'definition_id': disp.definition_id})
    except Exception:  # noqa: BLE001
        pass
