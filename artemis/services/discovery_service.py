"""Monitored-subnet discovery: scope CRUD, authorization, and bounded sweeps."""

import ipaddress
import json
from datetime import datetime, timezone

from artemis.extensions import db
from artemis.models.discovery import DiscoveryScope
from artemis.services import audit_service
from artemis.services.tenant import current_org_id, scoped, scoped_get

# A scope wider than this (host count across all CIDRs) needs explicit approval.
BROAD_HOST_THRESHOLD = 4096
# Hard ceiling regardless of the scope's own max_hosts.
ABSOLUTE_MAX_HOSTS = 65536


def _now_iso():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _networks(cidrs):
    nets = []
    for entry in cidrs:
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            continue
    return nets


def _host_count(cidrs):
    return sum(max(1, net.num_addresses - 2) for net in _networks(cidrs))


def is_public(cidrs):
    return any(not net.is_private for net in _networks(cidrs))


def requires_approval(scope):
    return is_public(scope.cidrs) or _host_count(scope.cidrs) > BROAD_HOST_THRESHOLD


def check_scan_allowed(target_ip):
    """Global + per-org allow/deny check applied before any dispatch.

    Deny wins. Rules are stored as JSON settings ``scan_allow`` / ``scan_deny``
    (lists of CIDRs); with no allow-list everything not denied is allowed.
    """
    from artemis.services.auth_scan_service import get_setting

    try:
        addr = ipaddress.ip_address(target_ip)
    except ValueError:
        return True

    deny = _networks(json.loads(get_setting('scan_deny', '[]') or '[]'))
    if any(addr in net for net in deny):
        return False
    allow = _networks(json.loads(get_setting('scan_allow', '[]') or '[]'))
    if allow and not any(addr in net for net in allow):
        return False
    return True


# --------------------------------------------------------------------------- #
# Scope CRUD
# --------------------------------------------------------------------------- #

def list_scopes():
    return scoped(DiscoveryScope).order_by(DiscoveryScope.name).all()


def get_scope(scope_id):
    return scoped_get(DiscoveryScope, scope_id)


def create_scope(data, created_by=None):
    cidrs = data.get('cidrs') or []
    if not cidrs or not _networks(cidrs):
        raise ValueError('at least one valid CIDR is required')
    if _host_count(cidrs) > ABSOLUTE_MAX_HOSTS:
        raise ValueError(f'scope exceeds the absolute limit of {ABSOLUTE_MAX_HOSTS} hosts')

    scope = DiscoveryScope(
        name=(data.get('name') or 'scope').strip(),
        cidrs_json=json.dumps(cidrs),
        exclusions_json=json.dumps(data.get('exclusions') or []),
        engine_pool=data.get('engine_pool'),
        cron_expression=data.get('cron_expression'),
        max_hosts=min(int(data.get('max_hosts', 1024)), ABSOLUTE_MAX_HOSTS),
        enabled=1 if data.get('enabled') else 0,
        created_at=_now_iso(), created_by=created_by,
    )
    scope.approval_state = 'pending' if requires_approval(scope) else 'approved'
    db.session.add(scope)
    db.session.commit()
    audit_service.record('discovery.scope.create', target_type='discovery_scope',
                         target_id=scope.id, detail={'cidrs': cidrs}, commit=True)
    return scope


def approve_scope(scope_id, approver_id, approve=True):
    scope = scoped_get(DiscoveryScope, scope_id)
    if not scope:
        return None
    scope.approval_state = 'approved' if approve else 'rejected'
    scope.approved_by = approver_id
    scope.approved_at = _now_iso()
    db.session.commit()
    audit_service.record('discovery.scope.approve', target_type='discovery_scope',
                         target_id=scope.id, detail={'approved': approve}, commit=True)
    return scope


# --------------------------------------------------------------------------- #
# Dispatch + execution
# --------------------------------------------------------------------------- #

def dispatch_discovery(scope_id, requested_by=None):
    from artemis.services.job_service import QueueDispatchError, create_job
    from artemis.tasks.scan_tasks import run_discovery_job

    scope = scoped_get(DiscoveryScope, scope_id)
    if not scope:
        raise ValueError('scope not found')
    if scope.approval_state != 'approved':
        raise PermissionError('discovery scope is not approved')

    job = create_job('discovery', target=scope.name, requested_by=requested_by,
                     options={'scope_id': scope.id})
    job.task_id = f'discovery-{job.id}'
    db.session.commit()
    try:
        run_discovery_job.apply_async(args=[job.id], task_id=job.task_id)
    except Exception as exc:
        job.status = 'dispatch_failed'
        job.error_message = str(exc)
        db.session.commit()
        raise QueueDispatchError('Scan queue is unavailable', job) from exc
    return job


def run_scope(scope, cancel_check=None, log=None):
    """Bounded liveness sweep. Upserts assets as `discovered`. Returns a summary."""
    from artemis.scanners.nmap_scanner import parse_scan, scan as nmap_scan
    from artemis.services.asset_service import store_asset_info

    def _log(msg):
        if log:
            log(msg)

    excluded = _networks(scope.exclusions)
    targets = []
    for net in _networks(scope.cidrs):
        for host in net.hosts():
            if any(host in ex for ex in excluded):
                continue
            targets.append(str(host))
            if len(targets) >= min(scope.max_hosts, ABSOLUTE_MAX_HOSTS):
                break
        if len(targets) >= scope.max_hosts:
            break

    new_hosts, seen = [], 0
    for chunk_start in range(0, len(targets), 256):
        if cancel_check and cancel_check():
            break
        chunk = targets[chunk_start:chunk_start + 256]
        _log(f'discovery sweep {chunk_start + 1}-{chunk_start + len(chunk)} of {len(targets)}')
        try:
            result = nmap_scan(','.join(chunk), options={'ports': '', 'discovery_only': True,
                                                         '_ping_only': True},
                               cancel_check=cancel_check)
            live = parse_scan(result) or []
        except Exception as exc:  # noqa: BLE001
            _log(f'sweep error: {exc}')
            continue
        for entry in live:
            ip = entry.get('ip') if isinstance(entry, dict) else entry
            if not ip or not check_scan_allowed(ip):
                continue
            seen += 1
            created = store_asset_info(ip, dns_info={}, source='discovery')
            if created:
                new_hosts.append(ip)

    scope.last_run = _now_iso()
    scope.last_status = 'success'
    db.session.commit()

    if new_hosts:
        try:
            from artemis.services.webhook_service import emit
            emit('asset.discovered', {'scope': scope.name, 'new_hosts': new_hosts})
        except Exception:  # noqa: BLE001
            pass
    return {'targets': len(targets), 'hosts_seen': seen, 'new_hosts': new_hosts}
