"""Executive / technical report generation.

Aggregates environment posture, renders a branded HTML document (Jinja2), and
optionally converts it to PDF with WeasyPrint. Charts are matplotlib figures
embedded as base64 data URIs so a report is a single self-contained file that
also survives being emailed as an attachment.
"""

import base64
import io
import json
import logging
import os
from collections import defaultdict
from datetime import datetime, timezone

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from jinja2 import Environment, FileSystemLoader, select_autoescape

from flask import current_app

from artemis.extensions import db
from artemis.models.report import Report
from artemis.models.asset import Asset
from artemis.models.scan import Scan
from artemis.services.auth_scan_service import get_setting
from artemis.services.vuln_service import (
    get_unified_vulnerabilities,
)

logger = logging.getLogger(__name__)

_SEVERITIES = ('critical', 'high', 'medium', 'low', 'info')
_RISK_WEIGHTS = {'critical': 10, 'high': 5, 'medium': 2, 'low': 1, 'info': 0}
_SEV_COLORS = {
    'critical': '#b91c1c', 'high': '#ea580c', 'medium': '#ca8a04',
    'low': '#2563eb', 'info': '#6b7280',
}
_TEMPLATES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'templates')


# --------------------------------------------------------------------------- #
# Branding
# --------------------------------------------------------------------------- #

def get_branding():
    """Report branding pulled from settings (all optional)."""
    return {
        'org_name': get_setting('report_org_name', '') or 'Artemis',
        'logo': get_setting('report_logo', '') or '',            # data: URI
        'accent': get_setting('report_accent_color', '') or '#7c3aed',
        'footer': get_setting('report_footer', '') or '',
        'confidentiality': get_setting('report_confidentiality', '') or 'CONFIDENTIAL',
    }


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #

def _scope_label(scope):
    t = (scope or {}).get('type', 'environment')
    if t == 'site':
        from artemis.models.site import Site
        s = db.session.get(Site, scope.get('id'))
        return f"Site: {s.name}" if s else f"Site #{scope.get('id')}"
    if t == 'filter':
        bits = []
        if scope.get('min_severity'):
            bits.append(f"severity ≥ {scope['min_severity']}")
        if scope.get('device_type'):
            bits.append(f"type = {scope['device_type']}")
        if scope.get('subnet'):
            bits.append(f"subnet {scope['subnet']}")
        return 'Filtered: ' + (', '.join(bits) if bits else 'all assets')
    return 'Entire environment'


def _scope_ips(scope):
    """The set of asset IPs in scope, or None for 'everything'."""
    t = (scope or {}).get('type', 'environment')
    if t == 'environment':
        return None
    if t == 'site':
        from artemis.models.site import Site
        from artemis.services.site_service import resolve_site_targets
        s = db.session.get(Site, scope.get('id'))
        if not s:
            return set()
        try:
            return set(resolve_site_targets(s))
        except Exception:
            return set()
    if t == 'filter':
        q = Asset.query
        if scope.get('device_type'):
            q = q.filter(Asset.device_type == scope['device_type'])
        ips = {a.ip for a in q.all()}
        if scope.get('subnet'):
            pref = scope['subnet'].split('/')[0].rsplit('.', 1)[0] + '.'
            ips = {ip for ip in ips if ip.startswith(pref)}
        return ips
    return None


# --------------------------------------------------------------------------- #
# Aggregation
# --------------------------------------------------------------------------- #

def _gather(scope, kind):
    ips = _scope_ips(scope)
    in_scope = (lambda ip: True) if ips is None else (lambda ip: ip in ips)

    min_sev = (scope or {}).get('min_severity')
    sev_floor = _SEVERITIES.index(min_sev) if min_sev in _SEVERITIES else len(_SEVERITIES) - 1

    all_vulns = get_unified_vulnerabilities()
    vulns = []
    for v in all_vulns:
        hosts = [a for a in v.get('affected_assets', []) if in_scope(a['ip'])]
        if not hosts:
            continue
        sev = v.get('severity', 'info')
        if sev in _SEVERITIES and _SEVERITIES.index(sev) > sev_floor:
            continue
        vv = dict(v)
        vv['affected_assets'] = hosts
        vv['host_count'] = len({h['ip'] for h in hosts})
        vulns.append(vv)

    by_sev = defaultdict(int)
    exploitable = 0
    affected = set()
    for v in vulns:
        by_sev[v.get('severity', 'info')] += 1
        if v.get('has_exploit'):
            exploitable += 1
        for h in v['affected_assets']:
            affected.add(h['ip'])

    risk_score = sum(_RISK_WEIGHTS.get(s, 0) * n for s, n in by_sev.items())

    assets_q = Asset.query if ips is None else Asset.query.filter(Asset.ip.in_(ips or ['']))
    assets = assets_q.all()

    # per-asset rollup for the technical section
    host_rows = []
    per_host = defaultdict(lambda: {s: 0 for s in _SEVERITIES} | {'exploit': 0, 'cves': []})
    for v in vulns:
        for h in v['affected_assets']:
            ph = per_host[h['ip']]
            ph[v.get('severity', 'info')] += 1
            if v.get('has_exploit'):
                ph['exploit'] += 1
            ph['cves'].append({
                'cve_id': v['cve_id'], 'severity': v.get('severity', 'info'),
                'cvss_score': v.get('cvss_score'), 'has_exploit': bool(v.get('has_exploit')),
                'name': v.get('vuln_name') or v.get('cve_id'),
            })
    open_ports = defaultdict(list)
    if kind in ('technical', 'full'):
        pq = db.session.query(Scan.ip, Scan.port, Scan.protocol, Scan.service, Scan.product, Scan.version)\
            .filter(Scan.state == 'open')
        for ip, port, proto, svc, prod, ver in pq.all():
            if in_scope(ip):
                open_ports[ip].append({'port': port, 'protocol': proto, 'service': svc,
                                       'product': prod, 'version': ver})
    for a in assets:
        ph = per_host.get(a.ip, {})
        score = sum(_RISK_WEIGHTS.get(s, 0) * ph.get(s, 0) for s in _SEVERITIES)
        host_rows.append({
            'ip': a.ip, 'hostname': a.hostname, 'os_name': a.os_name,
            'device_type': a.device_type or 'unknown',
            'counts': {s: ph.get(s, 0) for s in _SEVERITIES},
            'exploit': ph.get('exploit', 0),
            'risk_score': score,
            'open_ports': sorted(open_ports.get(a.ip, []), key=lambda p: (p['port'] or 0)),
            'cves': sorted(ph.get('cves', []),
                           key=lambda c: (-_RISK_WEIGHTS.get(c['severity'], 0),
                                          -(c['cvss_score'] or 0))),
        })
    host_rows.sort(key=lambda h: -h['risk_score'])

    top_vulns = sorted(
        vulns,
        key=lambda v: (v.get('has_exploit', False), _RISK_WEIGHTS.get(v.get('severity', 'info'), 0),
                       v.get('cvss_score') or 0, v.get('host_count', 0)),
        reverse=True,
    )[:15]

    # CVSS histogram
    cvss_buckets = [0] * 10
    for v in vulns:
        sc = v.get('cvss_score')
        if sc is not None:
            cvss_buckets[min(9, max(0, int(sc)))] += 1

    op_q = db.session.query(Scan.ip, Scan.port).filter(Scan.state == 'open').distinct()
    if ips is not None:
        op_q = op_q.filter(Scan.ip.in_(ips or ['']))
    open_port_total = op_q.count()

    # trend
    from artemis.services.risk_snapshot_service import get_snapshots
    trend = get_snapshots(days=90)

    return {
        'scope_label': _scope_label(scope),
        'kind': kind,
        'generated_at': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
        'totals': {
            'assets': len(assets),
            'affected_hosts': len(affected),
            'unique_cves': len(vulns),
            'exploitable': exploitable,
            'risk_score': risk_score,
            'by_severity': {s: by_sev.get(s, 0) for s in _SEVERITIES},
            'open_ports': open_port_total,
        },
        'top_vulns': [{
            'cve_id': v['cve_id'], 'name': v.get('vuln_name') or v['cve_id'],
            'severity': v.get('severity', 'info'), 'cvss_score': v.get('cvss_score'),
            'has_exploit': bool(v.get('has_exploit')), 'host_count': v.get('host_count', 0),
            'description': (v.get('description') or '')[:400],
            'sources': v.get('detection_sources', []),
            'remediation': _remediation_hint(v),
        } for v in top_vulns],
        'hosts': host_rows,
        'cvss_buckets': cvss_buckets,
        'trend': trend,
    }


def _remediation_hint(v):
    """Best-effort 'what to do' line for a finding."""
    cpe = (v.get('affected_cpe') or '')
    parts = cpe.split(':')
    if len(parts) > 4 and parts[3] and parts[4]:
        pkg = parts[4]
        return f"Update {pkg} to the vendor-patched release; re-scan to confirm."
    if v.get('detection_sources') and 'auth-scan' in v['detection_sources']:
        return "Apply the distribution security update for the affected package."
    return "Review the vendor advisory and apply the recommended fix or mitigation."


# --------------------------------------------------------------------------- #
# Charts  -> data URIs
# --------------------------------------------------------------------------- #

def _fig_to_uri(fig):
    buf = io.BytesIO()
    fig.savefig(buf, format='png', dpi=110, bbox_inches='tight', facecolor='white')
    plt.close(fig)
    return 'data:image/png;base64,' + base64.b64encode(buf.getvalue()).decode('ascii')


def _chart_severity(by_severity):
    labels = [s for s in _SEVERITIES if by_severity.get(s, 0) > 0]
    if not labels:
        return None
    sizes = [by_severity[s] for s in labels]
    fig, ax = plt.subplots(figsize=(4.2, 3.0))
    ax.pie(sizes, labels=[f"{s.title()} ({n})" for s, n in zip(labels, sizes)],
           colors=[_SEV_COLORS[s] for s in labels], startangle=90,
           textprops={'fontsize': 9}, wedgeprops={'width': 0.42})
    ax.set(aspect='equal')
    return _fig_to_uri(fig)


def _chart_cvss(buckets):
    if not any(buckets):
        return None
    fig, ax = plt.subplots(figsize=(5.4, 2.8))
    xs = list(range(10))
    colors = ['#6b7280'] * 4 + ['#2563eb'] * 3 + ['#ea580c'] * 2 + ['#b91c1c']
    ax.bar(xs, buckets, color=colors, width=0.8)
    ax.set_xticks(xs)
    ax.set_xticklabels([f"{i}" for i in xs], fontsize=8)
    ax.set_xlabel('CVSS base score', fontsize=9)
    ax.set_ylabel('Findings', fontsize=9)
    ax.spines[['top', 'right']].set_visible(False)
    return _fig_to_uri(fig)


def _chart_trend(trend):
    pts = [p for p in trend if p.get('date')]
    if len(pts) < 2:
        return None
    dates = [datetime.strptime(p['date'], '%Y-%m-%d') for p in pts]
    fig, ax = plt.subplots(figsize=(6.4, 2.8))
    for sev in ('critical', 'high', 'medium'):
        ax.plot(dates, [p.get(sev, 0) for p in pts], marker='o', markersize=2.5,
                linewidth=1.4, label=sev.title(), color=_SEV_COLORS[sev])
    ax.fill_between(dates, [p.get('critical', 0) for p in pts], color=_SEV_COLORS['critical'], alpha=0.10)
    ax.legend(fontsize=8, frameon=False, ncol=3, loc='upper left')
    ax.set_ylabel('Open findings', fontsize=9)
    ax.spines[['top', 'right']].set_visible(False)
    fig.autofmt_xdate(rotation=30)
    return _fig_to_uri(fig)


# --------------------------------------------------------------------------- #
# Render
# --------------------------------------------------------------------------- #

def _jinja():
    env = Environment(
        loader=FileSystemLoader(_TEMPLATES_DIR),
        autoescape=select_autoescape(['html', 'xml']),
    )
    env.filters['sevcolor'] = lambda s: _SEV_COLORS.get(s, '#6b7280')
    return env


def render_html(scope, kind):
    ctx = _gather(scope, kind)
    ctx['branding'] = get_branding()
    ctx['charts'] = {
        'severity': _chart_severity(ctx['totals']['by_severity']),
        'cvss': _chart_cvss(ctx['cvss_buckets']),
        'trend': _chart_trend(ctx['trend']),
    }
    ctx['severities'] = _SEVERITIES
    ctx['risk_band'] = _risk_band(ctx['totals']['risk_score'])
    return _jinja().get_template('report_document.html').render(**ctx), ctx


def _risk_band(score):
    if score >= 200:
        return ('Critical', '#b91c1c')
    if score >= 80:
        return ('High', '#ea580c')
    if score >= 25:
        return ('Elevated', '#ca8a04')
    if score > 0:
        return ('Moderate', '#2563eb')
    return ('Low', '#16a34a')


def html_to_pdf(html):
    """Convert report HTML to PDF bytes. Raises RuntimeError if WeasyPrint absent."""
    try:
        from weasyprint import HTML
    except Exception as e:  # ImportError or missing system libs
        raise RuntimeError(f"PDF export unavailable (WeasyPrint not installed: {e})")
    return HTML(string=html).write_pdf()


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

def build_report(scope, kind='executive', fmt='pdf', generated_by=None, schedule_id=None):
    """Generate a report, persist the file + a Report row, and return the row."""
    scope = scope or {'type': 'environment'}
    kind = kind if kind in ('executive', 'technical', 'full') else 'executive'
    fmt = fmt if fmt in ('pdf', 'html') else 'pdf'
    now = datetime.now(timezone.utc)
    stamp = now.strftime('%Y%m%d-%H%M%S')

    reports_dir = current_app.config['REPORTS_DIR']
    os.makedirs(reports_dir, exist_ok=True)

    rec = Report(
        title=f"{_scope_label(scope)} — {kind.title()} report",
        kind=kind, fmt=fmt, scope_json=json.dumps(scope),
        generated_by=generated_by, schedule_id=schedule_id,
        created_at=now.isoformat(), status='ready',
    )

    try:
        html, ctx = render_html(scope, kind)
        rec.summary_json = json.dumps(ctx['totals'])

        if fmt == 'pdf':
            data = html_to_pdf(html)
            ext = 'pdf'
        else:
            data = html.encode('utf-8')
            ext = 'html'

        fname = f"report-{kind}-{stamp}.{ext}"
        path = os.path.join(reports_dir, fname)
        with open(path, 'wb') as fh:
            fh.write(data)
        rec.file_path = path
        rec.size_bytes = len(data)
    except Exception as e:
        logger.exception("Report generation failed")
        rec.status = 'failed'
        rec.error = str(e)

    db.session.add(rec)
    db.session.commit()
    return rec
