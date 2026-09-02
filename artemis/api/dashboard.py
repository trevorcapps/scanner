"""Dashboard aggregation API — one blueprint, all read-only, one payload per widget."""

import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from flask import Blueprint, request
from sqlalchemy import func

from artemis.extensions import db
from artemis.models.asset import Asset
from artemis.models.scan import Scan
from artemis.models.agent import Agent
from artemis.models.site import Site
from artemis.models.scheduled_scan import ScheduledScan
from artemis.models.scan_history import ScanHistory
from artemis.models.scan_job import ScanJob
from artemis.services.auth_service import login_required
from artemis.services.vuln_service import (
    get_unified_vulnerabilities, get_unified_vulnerability_summary,
)

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint('dashboard', __name__)

_SEVERITIES = ('critical', 'high', 'medium', 'low', 'info')
_RISK_WEIGHTS = {'critical': 10, 'high': 5, 'medium': 2, 'low': 1, 'info': 0}


def _subnet_of(ip):
    parts = (ip or '').split('.')
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return 'other'


def _vuln_counts_by_ip():
    """{ip: {critical, high, medium, low, info, total}} from the vulnerabilities table."""
    from artemis.models.vulnerability import Vulnerability
    rows = db.session.query(Vulnerability.ip, Vulnerability.severity, func.count()).group_by(
        Vulnerability.ip, Vulnerability.severity).all()
    out = defaultdict(lambda: {s: 0 for s in _SEVERITIES} | {'total': 0})
    for ip, sev, n in rows:
        sev = sev if sev in _SEVERITIES else 'info'
        out[ip][sev] += n
        out[ip]['total'] += n
    return out


@dashboard_bp.route('/dashboard/summary')
@login_required
def summary():
    """
    ---
    get:
      summary: Single-payload environment overview (replaces the old 5 fetches)
      tags: [Dashboard]
      responses:
        200: {description: Aggregate counts}
      security: [{bearerAuth: []}, {apiKeyAuth: []}]
    """
    open_ports = db.session.query(Scan.ip, Scan.port).filter(
        Scan.state == 'open').distinct().count()

    agents = dict(db.session.query(Agent.status, func.count()).group_by(Agent.status).all())
    jobs = dict(db.session.query(ScanJob.status, func.count()).group_by(ScanJob.status).all())
    vuln_summary = get_unified_vulnerability_summary()

    return {
        'assets': Asset.query.count(),
        'open_ports': int(open_ports),
        'agents': {
            'total': sum(agents.values()),
            'active': agents.get('active', 0),
            'stale': agents.get('stale', 0),
            'offline': agents.get('offline', 0),
        },
        'sites': Site.query.count(),
        'schedules_enabled': ScheduledScan.query.filter(ScheduledScan.enabled == 1).count(),
        'vulnerabilities': {
            'by_severity': vuln_summary['by_severity'],
            'total': vuln_summary['unique_cves'],
            'exploitable': vuln_summary['with_exploits'],
            'affected_hosts': vuln_summary['affected_hosts'],
        },
        'scan_jobs': jobs,
    }


@dashboard_bp.route('/dashboard/cvss-distribution')
@login_required
def cvss_distribution():
    """
    ---
    get:
      summary: CVSS score histogram (10 unit-wide buckets) over unified findings
      tags: [Dashboard]
      responses: {200: {description: Buckets}}
      security: [{bearerAuth: []}]
    """
    buckets = [0] * 10
    unscored = 0
    for v in get_unified_vulnerabilities():
        score = v.get('cvss_score')
        if score is None:
            unscored += 1
            continue
        idx = min(9, max(0, int(score)))
        buckets[idx] += 1
    return {
        'buckets': [{'range': f'{i}-{i + 1}', 'min': i, 'count': n} for i, n in enumerate(buckets)],
        'unscored': unscored,
        'total': sum(buckets) + unscored,
    }


@dashboard_bp.route('/dashboard/top-vulnerabilities')
@login_required
def top_vulnerabilities():
    """
    ---
    get:
      summary: Highest-priority findings
      tags: [Dashboard]
      parameters: [{in: query, name: limit, schema: {type: integer, default: 10}}]
      responses: {200: {description: Ranked findings}}
      security: [{bearerAuth: []}]
    """
    try:
        limit = max(1, min(50, int(request.args.get('limit', 10))))
    except (TypeError, ValueError):
        limit = 10

    vulns = get_unified_vulnerabilities()  # already sorted: exploit, cvss, severity
    vulns.sort(key=lambda v: (
        0 if v['has_exploit'] else 1,
        -(v.get('cvss_score') or 0),
        -len(v.get('affected_assets', [])),
    ))
    top = []
    for v in vulns[:limit]:
        top.append({
            'cve_id': v['cve_id'],
            'vuln_name': v['vuln_name'],
            'severity': v['severity'],
            'cvss_score': v.get('cvss_score'),
            'has_exploit': v['has_exploit'],
            'affected_assets': len(v.get('affected_assets', [])),
            'detection_sources': v.get('detection_sources', []),
        })
    return {'vulnerabilities': top}


@dashboard_bp.route('/dashboard/risk-heatmap')
@login_required
def risk_heatmap():
    """
    ---
    get:
      summary: device_type x severity matrix + per-asset risk scores
      tags: [Dashboard]
      responses: {200: {description: Heatmap matrix and asset risk list}}
      security: [{bearerAuth: []}]
    """
    counts = _vuln_counts_by_ip()
    assets = Asset.query.all()

    matrix = defaultdict(lambda: {s: 0 for s in _SEVERITIES[:4]})
    asset_risk = []
    for a in assets:
        dt = a.device_type or 'unknown'
        vc = counts.get(a.ip, {})
        score = sum(_RISK_WEIGHTS[s] * vc.get(s, 0) for s in _SEVERITIES)
        for s in _SEVERITIES[:4]:
            if vc.get(s, 0) > 0:
                matrix[dt][s] += 1
        asset_risk.append({
            'ip': a.ip, 'hostname': a.hostname, 'device_type': dt,
            'risk_score': score, 'vuln_counts': {s: vc.get(s, 0) for s in _SEVERITIES},
        })

    asset_risk.sort(key=lambda x: x['risk_score'], reverse=True)
    return {
        'rows': [
            {'device_type': dt, **{s: cells[s] for s in _SEVERITIES[:4]},
             'total': sum(cells.values())}
            for dt, cells in sorted(matrix.items(), key=lambda kv: -sum(kv[1].values()))
        ],
        'severities': list(_SEVERITIES[:4]),
        'assets': asset_risk[:25],
    }


@dashboard_bp.route('/dashboard/trends')
@login_required
def trends():
    """
    ---
    get:
      summary: Per-day scan / vulnerability activity from scan history
      tags: [Dashboard]
      parameters: [{in: query, name: days, schema: {type: integer, default: 30}}]
      responses: {200: {description: Daily series}}
      security: [{bearerAuth: []}]
    """
    try:
        days = max(1, min(365, int(request.args.get('days', 30))))
    except (TypeError, ValueError):
        days = 30
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime('%Y-%m-%d')

    day = func.substr(func.coalesce(ScanHistory.started_at, ScanHistory.completed_at), 1, 10)
    rows = db.session.query(
        day,
        func.count(),
        func.coalesce(func.sum(ScanHistory.hosts_scanned), 0),
        func.coalesce(func.sum(ScanHistory.vulns_found), 0),
        func.coalesce(func.sum(ScanHistory.new_vulns), 0),
    ).filter(day >= since).group_by(day).order_by(day).all()

    by_day = {r[0]: r for r in rows if r[0]}
    series = []
    base = datetime.now(timezone.utc) - timedelta(days=days - 1)
    for i in range(days):
        d = (base + timedelta(days=i)).strftime('%Y-%m-%d')
        r = by_day.get(d)
        series.append({
            'date': d,
            'scans': r[1] if r else 0,
            'hosts_scanned': int(r[2]) if r else 0,
            'vulns_found': int(r[3]) if r else 0,
            'new_vulns': int(r[4]) if r else 0,
        })
    return {'days': days, 'series': series}


@dashboard_bp.route('/dashboard/topology')
@login_required
def topology():
    """
    ---
    get:
      summary: Network graph — root / subnet / asset nodes with risk metadata
      tags: [Dashboard]
      responses: {200: {description: "{nodes, links}"}}
      security: [{bearerAuth: []}]
    """
    counts = _vuln_counts_by_ip()
    port_counts = dict(db.session.query(Scan.ip, func.count(func.distinct(Scan.port))).filter(
        Scan.state == 'open').group_by(Scan.ip).all())

    nodes = [{'id': 'root', 'type': 'root', 'label': 'network'}]
    links = []
    subnets = set()

    for a in Asset.query.all():
        sub = _subnet_of(a.ip)
        if sub not in subnets:
            subnets.add(sub)
            nodes.append({'id': sub, 'type': 'subnet', 'label': sub})
            links.append({'source': 'root', 'target': sub})
        vc = counts.get(a.ip, {})
        worst = next((s for s in _SEVERITIES if vc.get(s, 0) > 0), None)
        nodes.append({
            'id': a.ip, 'type': 'asset', 'label': a.hostname or a.ip,
            'ip': a.ip, 'hostname': a.hostname,
            'device_type': a.device_type or 'unknown',
            'port_count': int(port_counts.get(a.ip, 0)),
            'worst_severity': worst,
            'vuln_total': vc.get('total', 0),
        })
        links.append({'source': sub, 'target': a.ip})

    return {'nodes': nodes, 'links': links,
            'stats': {'assets': len(nodes) - len(subnets) - 1, 'subnets': len(subnets)}}


@dashboard_bp.route('/dashboard/scan-queue')
@login_required
def scan_queue():
    """
    ---
    get:
      summary: Scan-job queue status + recent jobs
      tags: [Dashboard]
      responses: {200: {description: Queue counts and recent jobs}}
      security: [{bearerAuth: []}]
    """
    counts = dict(db.session.query(ScanJob.status, func.count()).group_by(ScanJob.status).all())
    recent = ScanJob.query.order_by(ScanJob.created_at.desc()).limit(10).all()
    return {
        'counts': counts,
        'active': counts.get('queued', 0) + counts.get('running', 0) + counts.get('retrying', 0),
        'recent': [j.to_dict() for j in recent],
    }
