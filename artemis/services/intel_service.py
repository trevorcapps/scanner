"""Vulnerability intelligence feeds (P4.2): EPSS, CISA KEV, exploit maturity,
and a transparent priority score.

Feeds write into the global ``VulnerabilityDefinition`` rows. They are
idempotent: re-importing the same feed revision changes nothing. Only
definitions Artemis already tracks (i.e. that appear in a finding) are updated,
so the table does not balloon to the full CVE universe.
"""

import csv
import gzip
import io
import json
import logging
import urllib.request
from datetime import datetime, timezone

from artemis.extensions import db
from artemis.models.finding import FindingOccurrence, VulnerabilityDefinition

logger = logging.getLogger(__name__)

EPSS_URL = 'https://epss.cyentia.com/epss_scores-current.csv.gz'
KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

_UA = {'User-Agent': 'Artemis-Scanner/2.0'}


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _tracked_cve_ids():
    rows = db.session.query(VulnerabilityDefinition.id).filter(
        VulnerabilityDefinition.kind == 'cve').all()
    return {r[0] for r in rows}


# --------------------------------------------------------------------------- #
# EPSS — FIRST bulk CSV
# --------------------------------------------------------------------------- #

def sync_epss(fetch=None):
    """Load FIRST's daily EPSS CSV; update tracked definitions only."""
    tracked = _tracked_cve_ids()
    if not tracked:
        return {'updated': 0, 'model_date': None}

    raw = fetch() if fetch else _download(EPSS_URL, gz=True)
    reader = csv.reader(io.StringIO(raw))
    model_date = None
    updated = 0
    for row in reader:
        if not row:
            continue
        if row[0].startswith('#'):
            # "#model_version:v2025.03.14,score_date:2026-09-03T00:00:00+0000"
            for part in row:
                if 'score_date' in part:
                    model_date = part.split('score_date:', 1)[1].strip()
            continue
        if row[0] == 'cve':
            continue
        cve, score, percentile = row[0], row[1], row[2] if len(row) > 2 else None
        if cve not in tracked:
            continue
        definition = db.session.get(VulnerabilityDefinition, cve)
        definition.epss_score = float(score)
        definition.epss_percentile = float(percentile) if percentile else None
        definition.epss_model_date = model_date
        definition.updated_at = _now()
        updated += 1
    db.session.commit()
    _rescore_affected(tracked)
    logger.info('EPSS sync: %s definitions updated (model %s)', updated, model_date)
    return {'updated': updated, 'model_date': model_date}


# --------------------------------------------------------------------------- #
# CISA KEV — official JSON catalog
# --------------------------------------------------------------------------- #

def sync_kev(fetch=None):
    tracked = _tracked_cve_ids()
    raw = fetch() if fetch else _download(KEV_URL)
    catalog = json.loads(raw)
    revision = catalog.get('catalogVersion') or catalog.get('dateReleased')
    listed = 0
    for item in catalog.get('vulnerabilities', []):
        cve = item.get('cveID')
        if cve not in tracked:
            continue
        definition = db.session.get(VulnerabilityDefinition, cve)
        definition.kev = 1
        definition.kev_date_added = item.get('dateAdded')
        definition.kev_due_date = item.get('dueDate')
        definition.kev_ransomware = 1 if str(item.get('knownRansomwareCampaignUse', '')).lower() == 'known' else 0
        definition.kev_required_action = item.get('requiredAction')
        definition.updated_at = _now()
        listed += 1
    db.session.commit()
    _rescore_affected(tracked)
    logger.info('KEV sync: %s tracked CVEs listed (catalog %s)', listed, revision)
    return {'listed': listed, 'revision': revision}


# --------------------------------------------------------------------------- #
# Exploit maturity — derived from evidence, not a single boolean
# --------------------------------------------------------------------------- #

def refresh_exploit_maturity(definition_id):
    """Derive `exploit_maturity` from all evidence for one definition.

    Rules (highest wins):
      known_exploited  — KEV listed
      weaponized       — a Metasploit module / weaponized ExploitDB entry
      poc              — any ExploitDB entry or public PoC reference
      none             — otherwise
    """
    definition = db.session.get(VulnerabilityDefinition, definition_id)
    if definition is None:
        return 'none'

    evidence = []
    if definition.kev:
        evidence.append({'type': 'kev', 'source': 'cisa'})

    if definition.kind == 'cve':
        try:
            from exploit_ref import lookup_exploits
            hit = lookup_exploits(definition_id)
            for eid, url in zip(hit.get('exploit_ids', []), hit.get('exploit_urls', [])):
                evidence.append({'type': 'exploitdb', 'id': eid, 'url': url})
        except Exception:  # noqa: BLE001
            pass

    if any(e['type'] == 'kev' for e in evidence):
        maturity = 'known_exploited'
    elif any(e.get('type') == 'metasploit' for e in evidence):
        maturity = 'weaponized'
    elif any(e['type'] == 'exploitdb' for e in evidence):
        maturity = 'poc'
    else:
        maturity = 'none'

    definition.exploit_maturity = maturity
    definition.exploit_evidence_json = json.dumps(evidence)
    definition.updated_at = _now()
    return maturity


# --------------------------------------------------------------------------- #
# Transparent priority score
# --------------------------------------------------------------------------- #

_SEVERITY_WEIGHT = {'critical': 1.0, 'high': 0.8, 'medium': 0.5, 'low': 0.2, 'info': 0.05}
_MATURITY_WEIGHT = {'known_exploited': 1.0, 'weaponized': 0.85, 'poc': 0.5, 'none': 0.0}
_CRIT_WEIGHT = {'critical': 1.0, 'high': 0.8, 'medium': 0.5, 'low': 0.3, 'unknown': 0.4}


def compute_priority(occ):
    """Return (score 0-100, factor breakdown). Every factor is exposed."""
    definition = occ.definition
    sev = (definition.severity or 'medium').lower() if definition else 'medium'
    epss = definition.epss_score if definition and definition.epss_score is not None else 0.0
    kev = 1.0 if definition and definition.kev else 0.0
    maturity = _MATURITY_WEIGHT.get(definition.exploit_maturity if definition else 'none', 0.0)

    asset_crit = 'unknown'
    exposed = 0.0
    if occ.asset_id:
        from artemis.models.asset import Asset
        asset = db.session.get(Asset, occ.asset_id)
        if asset:
            asset_crit = (asset.criticality or 'unknown')
            exposed = 1.0 if (asset.environment or '').lower() in ('prod', 'production', 'internet') else 0.4

    age_days = 0
    try:
        first = datetime.strptime(occ.first_seen, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - first).days
    except (TypeError, ValueError):
        pass
    age_factor = min(age_days / 90.0, 1.0)

    factors = {
        'severity': {'value': sev, 'weight': _SEVERITY_WEIGHT.get(sev, 0.5)},
        'epss': {'value': round(epss, 4), 'weight': epss},
        'kev': {'value': bool(kev), 'weight': kev},
        'exploit_maturity': {'value': definition.exploit_maturity if definition else 'none',
                             'weight': maturity},
        'asset_criticality': {'value': asset_crit, 'weight': _CRIT_WEIGHT.get(asset_crit, 0.4)},
        'exposure': {'value': exposed, 'weight': exposed},
        'age_days': {'value': age_days, 'weight': age_factor},
    }
    raw = (
        0.30 * factors['severity']['weight'] +
        0.20 * factors['epss']['weight'] +
        0.20 * factors['kev']['weight'] +
        0.10 * factors['exploit_maturity']['weight'] +
        0.12 * factors['asset_criticality']['weight'] +
        0.05 * factors['exposure']['weight'] +
        0.03 * factors['age_days']['weight']
    )
    return round(raw * 100, 1), factors


def rescore_occurrence(occ):
    score, factors = compute_priority(occ)
    occ.priority_score = score
    occ.priority_factors_json = json.dumps(factors)
    return score


def _rescore_affected(definition_ids):
    occs = FindingOccurrence.query.filter(
        FindingOccurrence.definition_id.in_(definition_ids),
        FindingOccurrence.status.in_(('open', 'reopened')),
    ).all()
    for occ in occs:
        rescore_occurrence(occ)
    if occs:
        db.session.commit()
    return len(occs)


def sync_all(fetch_epss=None, fetch_kev=None):
    result = {'epss': sync_epss(fetch=fetch_epss), 'kev': sync_kev(fetch=fetch_kev)}
    for def_id in _tracked_cve_ids():
        refresh_exploit_maturity(def_id)
    db.session.commit()
    _rescore_affected(_tracked_cve_ids())
    return result


def _download(url, gz=False):
    req = urllib.request.Request(url, headers=_UA)
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = resp.read()
    if gz:
        data = gzip.decompress(data)
    return data.decode('utf-8', errors='replace')
