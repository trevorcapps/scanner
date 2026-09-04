"""Maintain software observation intervals and the asset timeline (P3.3)."""

from datetime import datetime, timezone

from artemis.extensions import db
from artemis.models.asset import Asset
from artemis.models.inventory_history import AssetTimelineEvent, SoftwareObservation
from artemis.services.tenant import scoped


def _now_iso():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def record_event(asset_id, kind, *, summary=None, from_value=None, to_value=None,
                 source=None, job_id=None, report_id=None, detail=None):
    import json as _json
    event = AssetTimelineEvent(
        asset_id=asset_id, kind=kind, summary=summary,
        from_value=str(from_value) if from_value is not None else None,
        to_value=str(to_value) if to_value is not None else None,
        source=source, job_id=job_id, report_id=report_id,
        detail_json=_json.dumps(detail) if detail is not None else None,
        created_at=_now_iso(),
    )
    db.session.add(event)
    return event


def record_inventory(ip, packages, *, source='auth-scan', job_id=None):
    """Fold a fresh package list into the observation history for one asset.

    Emits package_installed / package_updated / package_removed timeline events.
    """
    asset = scoped(Asset).filter(Asset.ip == ip).first()
    if asset is None:
        return {'installed': 0, 'updated': 0, 'removed': 0}
    now = _now_iso()

    incoming = {p['name']: p for p in packages if p.get('name')}
    open_obs = {
        o.package_name: o
        for o in scoped(SoftwareObservation).filter(
            SoftwareObservation.asset_id == asset.id,
            SoftwareObservation.removed_at.is_(None),
        ).all()
    }

    installed = updated = removed = 0

    for name, pkg in incoming.items():
        version = pkg.get('version')
        current = open_obs.get(name)
        if current is None:
            db.session.add(SoftwareObservation(
                asset_id=asset.id, ip=ip, package_name=name, package_version=version,
                cpe=pkg.get('cpe'), source=source, job_id=job_id,
                first_seen=now, last_seen=now,
            ))
            record_event(asset.id, 'package_installed', summary=f'{name} {version or ""}'.strip(),
                         to_value=version, source=source, job_id=job_id)
            installed += 1
        elif current.package_version != version:
            current.removed_at = now
            db.session.add(SoftwareObservation(
                asset_id=asset.id, ip=ip, package_name=name, package_version=version,
                cpe=pkg.get('cpe'), source=source, job_id=job_id,
                first_seen=now, last_seen=now,
            ))
            record_event(asset.id, 'package_updated', summary=f'{name} {current.package_version} → {version}',
                         from_value=current.package_version, to_value=version,
                         source=source, job_id=job_id)
            updated += 1
        else:
            current.last_seen = now

    for name, obs in open_obs.items():
        if name not in incoming:
            obs.removed_at = now
            record_event(asset.id, 'package_removed', summary=name,
                         from_value=obs.package_version, source=source, job_id=job_id)
            removed += 1

    db.session.commit()
    return {'installed': installed, 'updated': updated, 'removed': removed}


def record_identity_change(ip, *, hostname=None, os_name=None, source='scan', job_id=None):
    asset = scoped(Asset).filter(Asset.ip == ip).first()
    if asset is None:
        return
    if hostname and asset.hostname and asset.hostname != hostname and 'hostname' not in asset.manual_fields:
        record_event(asset.id, 'hostname_changed', summary=f'{asset.hostname} → {hostname}',
                     from_value=asset.hostname, to_value=hostname, source=source, job_id=job_id)
    if os_name and asset.os_name and asset.os_name != os_name:
        record_event(asset.id, 'os_changed', summary=f'{asset.os_name} → {os_name}',
                     from_value=asset.os_name, to_value=os_name, source=source, job_id=job_id)
    db.session.commit()


def record_port_changes(ip, current_ports, *, source='scan', job_id=None):
    """current_ports: iterable of (port, protocol, service)."""
    from artemis.models.scan import Scan
    asset = scoped(Asset).filter(Asset.ip == ip).first()
    if asset is None:
        return
    previous = {
        (s.port, s.protocol)
        for s in scoped(Scan).filter(Scan.ip == ip, Scan.state == 'open').all()
    }
    incoming = {(p[0], p[1]) for p in current_ports}
    for port, proto in incoming - previous:
        record_event(asset.id, 'port_opened', summary=f'{port}/{proto}', to_value=str(port),
                     source=source, job_id=job_id)
    for port, proto in previous - incoming:
        record_event(asset.id, 'port_closed', summary=f'{port}/{proto}', from_value=str(port),
                     source=source, job_id=job_id)
    db.session.commit()


def asset_timeline(asset_id, limit=200, kinds=None):
    q = scoped(AssetTimelineEvent).filter(AssetTimelineEvent.asset_id == asset_id)
    if kinds:
        q = q.filter(AssetTimelineEvent.kind.in_(kinds))
    return q.order_by(AssetTimelineEvent.created_at.desc()).limit(limit).all()


def software_history(asset_id, package_name=None):
    q = scoped(SoftwareObservation).filter(SoftwareObservation.asset_id == asset_id)
    if package_name:
        q = q.filter(SoftwareObservation.package_name == package_name)
    return q.order_by(SoftwareObservation.package_name, SoftwareObservation.first_seen).all()


def prune_history(older_than_iso):
    removed = scoped(AssetTimelineEvent).filter(
        AssetTimelineEvent.created_at < older_than_iso).delete(synchronize_session=False)
    removed += scoped(SoftwareObservation).filter(
        SoftwareObservation.removed_at.isnot(None),
        SoftwareObservation.removed_at < older_than_iso).delete(synchronize_session=False)
    db.session.commit()
    return removed
