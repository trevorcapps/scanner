"""Canonical finding ingestion and lifecycle (P4.1).

``ingest_finding`` is the single write path for every scanner source. It
upserts the global definition, the tenant occurrence (by stable fingerprint),
and appends an immutable observation. Lifecycle (open/resolved/reopened) is
derived from observations, not overwritten by whichever source ran last.
"""

import json
from datetime import datetime, timezone

from artemis.extensions import db
from artemis.models.asset import Asset
from artemis.models.finding import (
    FindingObservation,
    FindingOccurrence,
    VulnerabilityDefinition,
)
from artemis.services.tenant import current_org_id, scoped

# source -> confidence rank (higher wins when merging severity)
SOURCE_RANK = {'cloud': 5, 'container': 4, 'agent': 3, 'ssh': 3, 'nuclei': 2, 'import': 1}


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def upsert_definition(def_id, *, kind='cve', **fields):
    definition = db.session.get(VulnerabilityDefinition, def_id)
    if definition is None:
        definition = VulnerabilityDefinition(id=def_id, kind=kind)
        db.session.add(definition)
    for key, value in fields.items():
        if value is not None and hasattr(definition, key):
            setattr(definition, key, value)
    definition.updated_at = _now()
    return definition


def ingest_finding(*, definition_id, kind, ip, source, port=None, protocol=None,
                   component=None, severity=None, title=None, description=None,
                   cvss_score=None, cvss_vector=None, cwe_id=None, references=None,
                   published_date=None, matched_at=None, evidence=None, job_id=None,
                   observed_at=None):
    """Record one observation of one vulnerability on one asset. Returns the occurrence."""
    observed_at = observed_at or _now()
    upsert_definition(
        definition_id, kind=kind, title=title, description=description,
        severity=severity, cvss_score=cvss_score, cvss_vector=cvss_vector,
        cwe_id=cwe_id, published_date=published_date,
        references_json=json.dumps(references) if references else None,
    )

    fp = FindingOccurrence.make_fingerprint(definition_id, ip, port, protocol, component)
    occ = scoped(FindingOccurrence).filter(FindingOccurrence.fingerprint == fp).first()
    asset = scoped(Asset).filter(Asset.ip == ip).first()

    if occ is None:
        occ = FindingOccurrence(
            fingerprint=fp, definition_id=definition_id,
            asset_id=asset.id if asset else None, ip=ip, port=port,
            protocol=protocol, component=component, status='open',
            first_seen=observed_at, last_seen=observed_at,
            sources_json=json.dumps([source]),
        )
        db.session.add(occ)
        db.session.flush()
    else:
        occ.last_seen = observed_at
        if asset and occ.asset_id != asset.id:
            occ.asset_id = asset.id
        sources = set(json.loads(occ.sources_json or '[]'))
        sources.add(source)
        occ.sources_json = json.dumps(sorted(sources))
        if occ.status in ('resolved',):
            occ.status = 'reopened'
            occ.reopened_at = observed_at
            occ.resolved_at = None
        elif occ.status == 'reopened':
            pass  # stays reopened until it resolves again

    db.session.add(FindingObservation(
        occurrence_id=occ.id, source=source, job_id=job_id, observed_at=observed_at,
        present=1, severity=severity, matched_at=matched_at,
        evidence_json=json.dumps(evidence) if evidence is not None else None,
    ))
    try:
        from artemis.services.intel_service import rescore_occurrence
        rescore_occurrence(occ)
    except Exception:  # noqa: BLE001
        pass
    db.session.commit()
    return occ


def resolve_absent(ip, *, seen_definition_ids, source, job_id=None):
    """After a full scan of ``ip``, occurrences from this source not seen this
    run are recorded absent and (if no other source still sees them) resolved."""
    now = _now()
    resolved = 0
    open_occ = scoped(FindingOccurrence).filter(
        FindingOccurrence.ip == ip,
        FindingOccurrence.status.in_(('open', 'reopened')),
    ).all()
    for occ in open_occ:
        if occ.definition_id in seen_definition_ids:
            continue
        if source not in json.loads(occ.sources_json or '[]'):
            continue
        db.session.add(FindingObservation(
            occurrence_id=occ.id, source=source, job_id=job_id, observed_at=now, present=0,
        ))
        other_sources = [s for s in json.loads(occ.sources_json or '[]') if s != source]
        if not other_sources:
            occ.status = 'resolved'
            occ.resolved_at = now
            resolved += 1
            _webhook('finding.resolved', occ)
    db.session.commit()
    return resolved


def set_status(occurrence_id, status, *, reason=None):
    from artemis.models.finding import OCCURRENCE_STATUSES
    if status not in OCCURRENCE_STATUSES:
        raise ValueError(f'status must be one of {OCCURRENCE_STATUSES}')
    occ = scoped(FindingOccurrence).filter(FindingOccurrence.id == occurrence_id).first()
    if not occ:
        return None
    occ.status = status
    if status == 'resolved':
        occ.resolved_at = _now()
    db.session.commit()
    return occ


def list_findings(status=None, severity=None, kev_only=False, limit=200, ip=None,
                  include_suppressed=False):
    q = scoped(FindingOccurrence)
    if status:
        q = q.filter(FindingOccurrence.status == status)
    elif not include_suppressed:
        q = q.filter(FindingOccurrence.status.in_(('open', 'reopened')))
    if ip:
        q = q.filter(FindingOccurrence.ip == ip)
    if severity:
        q = q.join(VulnerabilityDefinition).filter(VulnerabilityDefinition.severity == severity)
    if kev_only:
        q = q.join(VulnerabilityDefinition).filter(VulnerabilityDefinition.kev == 1)
    rows = q.order_by(FindingOccurrence.priority_score.desc().nullslast(),
                      FindingOccurrence.last_seen.desc()).limit(min(limit, 2000)).all()
    if include_suppressed:
        return rows
    try:
        from artemis.services.disposition_service import active_rules, is_suppressed
        rules = active_rules()
        return [r for r in rows if not is_suppressed(r, rules)]
    except Exception:  # noqa: BLE001
        return rows


def _webhook(event, occ):
    try:
        from artemis.services.webhook_service import emit
        emit(event, {'occurrence_id': occ.id, 'definition_id': occ.definition_id,
                     'ip': occ.ip, 'status': occ.status})
    except Exception:  # noqa: BLE001
        pass
