"""Vulnerability scanning orchestration service.

System of record: Postgres via the ``Vulnerability`` / ``CveMatch`` /
``InstalledSoftware`` models. The one deliberate exception is the NVD enrichment
step in ``get_unified_vulnerabilities``, which reads the local SQLite NVD cache
(``NVD_CACHE_PATH``) — public, re-syncable feed data that is not the system of
record.
"""

import json
import sqlite3
import logging
import urllib.request
import urllib.error
import time
from datetime import datetime

from artemis.extensions import db
from artemis.models.vulnerability import Vulnerability
from artemis.models.cve_match import CveMatch
from artemis.models.software import InstalledSoftware
from artemis.services._db import upsert

logger = logging.getLogger(__name__)

# NVD API configuration
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_DELAY = 0.6


def _nvd_cache_path():
    try:
        from flask import current_app
        return current_app.config.get('NVD_CACHE_PATH') or current_app.config.get('DB_PATH')
    except Exception:
        return None


def fetch_nvd_data(cve_id):
    """Fetch CVE data from the live NVD API."""
    if not cve_id or not cve_id.upper().startswith('CVE-'):
        return None

    url = f"{NVD_API_BASE}?cveId={cve_id.upper()}"

    try:
        logger.info(f"Fetching NVD data for {cve_id}")
        req = urllib.request.Request(url, headers={'User-Agent': 'VulnScanner/1.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode('utf-8'))

        if not data.get('vulnerabilities'):
            return None

        cve_data = data['vulnerabilities'][0]['cve']

        cvss_score = None
        cvss_vector = None
        metrics = cve_data.get('metrics', {})

        for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
            if key in metrics:
                cvss_data = metrics[key][0]['cvssData']
                cvss_score = cvss_data.get('baseScore')
                cvss_vector = cvss_data.get('vectorString')
                break

        description = ''
        for desc in cve_data.get('descriptions', []):
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break

        cwe_id = None
        for weakness in cve_data.get('weaknesses', []):
            for desc in weakness.get('description', []):
                if desc.get('value', '').startswith('CWE-'):
                    cwe_id = desc.get('value')
                    break
            if cwe_id:
                break

        references = [{'url': ref.get('url', ''), 'source': ref.get('source', '')}
                      for ref in cve_data.get('references', [])[:5]]

        result = {
            'cvss_score': cvss_score, 'cvss_vector': cvss_vector,
            'description': description, 'cwe_id': cwe_id,
            'references': references, 'published_date': cve_data.get('published', ''),
        }

        time.sleep(NVD_API_DELAY)
        return result

    except urllib.error.HTTPError as e:
        logger.error(f"HTTP error fetching NVD data for {cve_id}: {e.code}")
        time.sleep(NVD_API_DELAY)
        return None
    except urllib.error.URLError as e:
        logger.error(f"URL error fetching NVD data for {cve_id}: {e.reason}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error for {cve_id}: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error fetching NVD data for {cve_id}: {e}")
        return None


def _severity_from_score(score):
    if score is None:
        return None
    if score >= 9.0:
        return 'critical'
    if score >= 7.0:
        return 'high'
    if score >= 4.0:
        return 'medium'
    return 'low'


def _emit_webhook(event, payload):
    try:
        from artemis.services.webhook_service import emit
        emit(event, payload)
    except Exception:
        logger.debug("webhook emit failed", exc_info=True)


def store_vulnerabilities(ip, vulnerabilities):
    """Store Nuclei findings, enriching CVEs with NVD data. Returns the stored dicts."""
    scan_date = datetime.now().isoformat()
    stored = []
    new_findings = []

    try:
        for vuln in vulnerabilities:
            existed = db.session.query(Vulnerability.id).filter_by(
                ip=ip, port=vuln['port'], protocol=vuln['protocol'],
                vuln_id=vuln['vuln_id']).first() is not None
            vuln_id = vuln['vuln_id']
            description = vuln['description']
            severity = vuln['severity']
            cvss_score = vuln.get('cvss_score')
            cvss_vector = None
            cwe_id = vuln.get('cwe_id')
            references_json = None
            published_date = None

            if vuln.get('references'):
                refs = [{'url': ref, 'source': 'nuclei'} for ref in vuln['references'] if ref]
                if refs:
                    references_json = json.dumps(refs)

            if vuln_id.upper().startswith('CVE-'):
                nvd_data = fetch_nvd_data(vuln_id)
                if nvd_data:
                    if nvd_data.get('description') and len(description) < 100:
                        description = nvd_data['description']
                    if cvss_score is None:
                        cvss_score = nvd_data.get('cvss_score')
                    cvss_vector = nvd_data.get('cvss_vector')
                    if not cwe_id:
                        cwe_id = nvd_data.get('cwe_id')
                    published_date = nvd_data.get('published_date')

                    if nvd_data.get('references'):
                        existing_refs = json.loads(references_json) if references_json else []
                        existing_urls = {r['url'] for r in existing_refs}
                        for ref in nvd_data['references']:
                            if ref['url'] not in existing_urls:
                                existing_refs.append(ref)
                        references_json = json.dumps(existing_refs)

                    severity = _severity_from_score(cvss_score) or severity

            row = upsert(Vulnerability,
                         {'ip': ip, 'port': vuln['port'], 'protocol': vuln['protocol'],
                          'vuln_id': vuln_id},
                         {'vuln_name': vuln['vuln_name'], 'severity': severity,
                          'description': description, 'cvss_score': cvss_score,
                          'cvss_vector': cvss_vector, 'cwe_id': cwe_id,
                          'references_json': references_json,
                          'published_date': published_date, 'scan_date': scan_date})
            stored.append(row)
            if not existed:
                new_findings.append({
                    'ip': ip, 'port': vuln['port'], 'protocol': vuln['protocol'],
                    'vuln_id': vuln_id, 'vuln_name': vuln['vuln_name'],
                    'severity': severity, 'cvss_score': cvss_score,
                })

        db.session.commit()
        result = [r.to_dict() for r in stored]
        logger.info(f"Stored/updated {len(result)} vulnerabilities for {ip}")
        for finding in new_findings:
            _emit_webhook('vulnerability.discovered', finding)
        return result
    except Exception as e:
        db.session.rollback()
        logger.error(f"Database error storing vulnerabilities: {e}")
        return []


def get_vulnerabilities(ip=None):
    """Retrieve vulnerabilities, optionally filtered by IP."""
    try:
        q = Vulnerability.query
        if ip:
            q = q.filter_by(ip=ip)
        q = q.order_by(Vulnerability.cvss_score.desc().nullslast(),
                       Vulnerability.scan_date.desc())
        return [v.to_dict() for v in q.all()]
    except Exception as e:
        logger.error(f"Database error retrieving vulnerabilities: {e}")
        return []


def get_vulnerability_counts_by_severity(ip):
    """Vulnerability counts by severity for a specific IP."""
    from sqlalchemy import func
    try:
        rows = db.session.query(Vulnerability.severity, func.count()).filter(
            Vulnerability.ip == ip).group_by(Vulnerability.severity).all()
        counts = {sev: n for sev, n in rows}
        return {
            'critical': counts.get('critical', 0), 'high': counts.get('high', 0),
            'medium': counts.get('medium', 0), 'low': counts.get('low', 0),
            'info': counts.get('info', 0), 'total': sum(counts.values()),
        }
    except Exception as e:
        logger.error(f"Database error getting severity counts: {e}")
        return {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'total': 0}


def _enrich_from_nvd_cache(unified):
    """Step 3: enrich unified findings from the local SQLite NVD cache."""
    path = _nvd_cache_path()
    if not path or path == ':memory:':
        return
    try:
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='nvd_cves'")
        if not cur.fetchone():
            conn.close()
            return

        for cve_id, entry in unified.items():
            if not cve_id.upper().startswith('CVE-'):
                continue
            cur.execute('''SELECT description, cvss_v2_score, cvss_v2_vector,
                           cvss_v3_score, cvss_v3_vector, published_date, last_modified,
                           source_json FROM nvd_cves WHERE cve_id = ?''', (cve_id,))
            nvd_row = cur.fetchone()
            if not nvd_row:
                continue

            if nvd_row['description'] and len(nvd_row['description']) > len(entry['description']):
                entry['description'] = nvd_row['description']
            if nvd_row['cvss_v3_score']:
                entry['cvss_v3_score'] = nvd_row['cvss_v3_score']
                entry['cvss_score'] = nvd_row['cvss_v3_score']
            if nvd_row['cvss_v2_score']:
                entry['cvss_v2_score'] = nvd_row['cvss_v2_score']
                if not entry['cvss_score']:
                    entry['cvss_score'] = nvd_row['cvss_v2_score']
            if nvd_row['cvss_v3_vector']:
                entry['cvss_vector'] = nvd_row['cvss_v3_vector']
            elif nvd_row['cvss_v2_vector'] and not entry['cvss_vector']:
                entry['cvss_vector'] = nvd_row['cvss_v2_vector']
            if nvd_row['published_date']:
                entry['published_date'] = nvd_row['published_date']
            if nvd_row['last_modified']:
                entry['last_modified'] = nvd_row['last_modified']

            if nvd_row['source_json']:
                try:
                    src = json.loads(nvd_row['source_json'])
                    if not entry['cwe_id']:
                        for weakness in src.get('weaknesses', []):
                            for desc in weakness.get('description', []):
                                if desc.get('value', '').startswith('CWE-'):
                                    entry['cwe_id'] = desc['value']
                                    break
                            if entry['cwe_id']:
                                break
                    existing_urls = {r.get('url') for r in entry['references']}
                    for ref in src.get('references', [])[:10]:
                        url = ref.get('url', '')
                        if url and url not in existing_urls:
                            entry['references'].append({'url': url, 'source': ref.get('source', 'NVD')})
                            existing_urls.add(url)
                except (json.JSONDecodeError, TypeError):
                    pass

            sev = _severity_from_score(entry['cvss_score'])
            if sev and (entry['cvss_score'] or 0) > 0:
                entry['severity'] = sev
        conn.close()
    except Exception as e:
        logger.debug(f"NVD enrichment error: {e}")


def get_unified_vulnerabilities(ip=None, source=None, has_exploit=None, search=None):
    """Unified vulnerabilities from all sources, deduplicated by CVE ID."""
    try:
        unified = {}

        # 1. Nuclei results (vulnerabilities table)
        vq = Vulnerability.query
        if ip:
            vq = vq.filter_by(ip=ip)
        for row in vq.all():
            vuln_id = row.vuln_id
            cve_id = vuln_id.upper() if vuln_id.upper().startswith('CVE-') else vuln_id
            references = []
            if row.references_json:
                try:
                    references = json.loads(row.references_json)
                except json.JSONDecodeError:
                    pass
            asset_key = f"{row.ip}:{row.port}/{row.protocol}"

            if cve_id in unified:
                entry = unified[cve_id]
                if asset_key not in [a['key'] for a in entry['affected_assets']]:
                    entry['affected_assets'].append({'key': asset_key, 'ip': row.ip,
                                                     'port': row.port, 'protocol': row.protocol})
                if 'nuclei' not in entry['detection_sources']:
                    entry['detection_sources'].append('nuclei')
                existing_urls = {r.get('url') for r in entry['references']}
                for ref in references:
                    if ref.get('url') and ref['url'] not in existing_urls:
                        entry['references'].append(ref)
                        existing_urls.add(ref['url'])
                if not entry.get('template_id'):
                    entry['template_id'] = vuln_id if not vuln_id.upper().startswith('CVE-') else ''
                if not entry.get('nuclei_scan_date'):
                    entry['nuclei_scan_date'] = row.scan_date
            else:
                unified[cve_id] = {
                    'cve_id': cve_id, 'vuln_name': row.vuln_name, 'severity': row.severity,
                    'description': row.description or '', 'cvss_score': row.cvss_score,
                    'cvss_v3_score': row.cvss_score, 'cvss_v2_score': None,
                    'cvss_vector': row.cvss_vector, 'cwe_id': row.cwe_id, 'references': references,
                    'published_date': row.published_date, 'last_modified': None,
                    'has_exploit': False, 'exploit_ids': '', 'exploit_url': '', 'affected_cpe': '',
                    'affected_assets': [{'key': asset_key, 'ip': row.ip, 'port': row.port,
                                         'protocol': row.protocol}],
                    'detection_sources': ['nuclei'],
                    'template_id': vuln_id if not vuln_id.upper().startswith('CVE-') else '',
                    'nuclei_scan_date': row.scan_date, 'scan_date': row.scan_date,
                }

        # 2. cve_matches table (auth scan / vulscan)
        cq = CveMatch.query
        if ip:
            cq = cq.filter_by(ip=ip)
        sw_ips = {r[0] for r in db.session.query(InstalledSoftware.ip).distinct().all()}
        for row in cq.all():
            cve_id = (row.cve_id or '').upper()
            if not cve_id:
                continue
            asset_key = f"{row.ip}:0/tcp"
            det_source = 'auth-scan' if row.ip in sw_ips else 'nvd-local'

            if cve_id in unified:
                entry = unified[cve_id]
                if asset_key not in [a['key'] for a in entry['affected_assets']]:
                    entry['affected_assets'].append({'key': asset_key, 'ip': row.ip,
                                                     'port': 0, 'protocol': 'tcp'})
                if det_source not in entry['detection_sources']:
                    entry['detection_sources'].append(det_source)
                if row.has_exploit:
                    entry['has_exploit'] = True
                    if row.exploit_ids and not entry['exploit_ids']:
                        entry['exploit_ids'] = row.exploit_ids
                    if row.exploit_url and not entry['exploit_url']:
                        entry['exploit_url'] = row.exploit_url
                if row.description and len(row.description) > len(entry.get('description', '')):
                    entry['description'] = row.description
                if row.affected_cpe and row.affected_cpe not in (entry.get('affected_cpe') or ''):
                    entry['affected_cpe'] = (entry.get('affected_cpe', '') + ', ' + row.affected_cpe).strip(', ')
            else:
                unified[cve_id] = {
                    'cve_id': cve_id, 'vuln_name': cve_id, 'severity': row.severity or 'medium',
                    'description': row.description or '', 'cvss_score': row.cvss_score,
                    'cvss_v3_score': row.cvss_score, 'cvss_v2_score': None, 'cvss_vector': None,
                    'cwe_id': None, 'references': [], 'published_date': None, 'last_modified': None,
                    'has_exploit': bool(row.has_exploit), 'exploit_ids': row.exploit_ids or '',
                    'exploit_url': row.exploit_url or '', 'affected_cpe': row.affected_cpe or '',
                    'affected_assets': [{'key': asset_key, 'ip': row.ip, 'port': 0, 'protocol': 'tcp'}],
                    'detection_sources': [det_source], 'template_id': '', 'nuclei_scan_date': None,
                    'scan_date': row.scan_date,
                }

        # 3. Enrich from the local NVD cache (SQLite)
        _enrich_from_nvd_cache(unified)

        # 4. Mark exploit-db as a detection source
        for entry in unified.values():
            if entry['has_exploit'] and 'exploit-db' not in entry['detection_sources']:
                entry['detection_sources'].append('exploit-db')

        results = list(unified.values())

        if source:
            results = [r for r in results if source in r['detection_sources']]
        if has_exploit is not None:
            results = [r for r in results if bool(r['has_exploit']) == bool(has_exploit)]
        if search:
            s = search.lower()
            results = [r for r in results if
                       s in r['cve_id'].lower() or s in (r['description'] or '').lower() or
                       s in (r['affected_cpe'] or '').lower() or s in (r['vuln_name'] or '').lower()]

        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        results.sort(key=lambda r: (
            0 if r['has_exploit'] else 1,
            -1 * (r['cvss_score'] or 0),
            severity_order.get(r['severity'], 5),
        ))

        for r in results:
            r['affected_assets'] = [{'ip': a['ip'], 'port': a['port'], 'protocol': a['protocol']}
                                    for a in r['affected_assets']]
        return results
    except Exception as e:
        logger.error(f"Database error in get_unified_vulnerabilities: {e}")
        return []


def get_unified_vulnerability_summary(ip=None):
    """Summary counts for unified vulnerabilities."""
    try:
        summary = {
            'total_findings': 0, 'unique_cves': 0, 'with_exploits': 0, 'affected_hosts': 0,
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
            'by_source': {'nuclei': 0, 'nvd-local': 0, 'nmap-vulscan': 0, 'auth-scan': 0, 'exploit-db': 0},
        }
        vulns = get_unified_vulnerabilities(ip=ip)
        summary['unique_cves'] = len(vulns)

        all_ips = set()
        total_findings = 0
        for v in vulns:
            sev = v.get('severity', 'info')
            summary['by_severity'][sev] = summary['by_severity'].get(sev, 0) + 1
            if v['has_exploit']:
                summary['with_exploits'] += 1
            for a in v['affected_assets']:
                all_ips.add(a['ip'])
                total_findings += 1
            for src in v['detection_sources']:
                if src in summary['by_source']:
                    summary['by_source'][src] += 1

        summary['total_findings'] = total_findings
        summary['affected_hosts'] = len(all_ips)
        return summary
    except Exception as e:
        logger.error(f"Error getting unified summary: {e}")
        return {
            'total_findings': 0, 'unique_cves': 0, 'with_exploits': 0, 'affected_hosts': 0,
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
            'by_source': {},
        }
