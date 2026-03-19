"""Vulnerability scanning orchestration service — extracted from vuln_scan.py."""

import json
import sqlite3
import logging
import urllib.request
import urllib.error
import time
from datetime import datetime

from artemis.utils.dns import ScanError

logger = logging.getLogger(__name__)

# NVD API configuration
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_DELAY = 0.6


def _get_db_path():
    try:
        from flask import current_app
        return current_app.config['DB_PATH']
    except Exception:
        import os
        return os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__)))), 'vuln_scan.db')


def fetch_nvd_data(cve_id):
    """Fetch CVE data from NVD API."""
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

        if 'cvssMetricV31' in metrics:
            cvss_data = metrics['cvssMetricV31'][0]['cvssData']
            cvss_score = cvss_data.get('baseScore')
            cvss_vector = cvss_data.get('vectorString')
        elif 'cvssMetricV30' in metrics:
            cvss_data = metrics['cvssMetricV30'][0]['cvssData']
            cvss_score = cvss_data.get('baseScore')
            cvss_vector = cvss_data.get('vectorString')
        elif 'cvssMetricV2' in metrics:
            cvss_data = metrics['cvssMetricV2'][0]['cvssData']
            cvss_score = cvss_data.get('baseScore')
            cvss_vector = cvss_data.get('vectorString')

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

        references = []
        for ref in cve_data.get('references', [])[:5]:
            references.append({
                'url': ref.get('url', ''),
                'source': ref.get('source', '')
            })

        published_date = cve_data.get('published', '')

        result = {
            'cvss_score': cvss_score,
            'cvss_vector': cvss_vector,
            'description': description,
            'cwe_id': cwe_id,
            'references': references,
            'published_date': published_date
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


def store_vulnerabilities(ip, vulnerabilities):
    """Store vulnerability scan results in the database, enriching CVEs with NVD data."""
    conn = sqlite3.connect(_get_db_path())
    cursor = conn.cursor()
    scan_date = datetime.now()

    try:
        stored_count = 0
        for vuln in vulnerabilities:
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

                    if cvss_score is not None:
                        if cvss_score >= 9.0:
                            severity = 'critical'
                        elif cvss_score >= 7.0:
                            severity = 'high'
                        elif cvss_score >= 4.0:
                            severity = 'medium'
                        else:
                            severity = 'low'

            cursor.execute('''INSERT OR REPLACE INTO vulnerabilities
                              (ip, port, protocol, vuln_id, vuln_name, severity, description,
                               cvss_score, cvss_vector, cwe_id, references_json, published_date, scan_date)
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                           (ip, vuln['port'], vuln['protocol'], vuln_id,
                            vuln['vuln_name'], severity, description,
                            cvss_score, cvss_vector, cwe_id, references_json, published_date, scan_date))
            if cursor.rowcount > 0:
                stored_count += 1
        conn.commit()
        logger.info(f"Stored/updated {stored_count} vulnerabilities for {ip}")
    except sqlite3.Error as e:
        logger.error(f"Database error storing vulnerabilities: {e}")
    finally:
        conn.close()


def get_vulnerabilities(ip=None):
    """Retrieve vulnerabilities from database, optionally filtered by IP."""
    conn = sqlite3.connect(_get_db_path())
    cursor = conn.cursor()

    try:
        if ip:
            cursor.execute('''SELECT ip, port, protocol, vuln_id, vuln_name, severity, description,
                              cvss_score, cvss_vector, cwe_id, references_json, published_date, scan_date
                              FROM vulnerabilities WHERE ip = ? ORDER BY cvss_score DESC, scan_date DESC''', (ip,))
        else:
            cursor.execute('''SELECT ip, port, protocol, vuln_id, vuln_name, severity, description,
                              cvss_score, cvss_vector, cwe_id, references_json, published_date, scan_date
                              FROM vulnerabilities ORDER BY cvss_score DESC, scan_date DESC''')

        results = cursor.fetchall()
        vulnerabilities = []
        for row in results:
            references = []
            if row[10]:
                try:
                    references = json.loads(row[10])
                except json.JSONDecodeError:
                    pass

            vulnerabilities.append({
                'ip': row[0], 'port': row[1], 'protocol': row[2],
                'vuln_id': row[3], 'vuln_name': row[4], 'severity': row[5],
                'description': row[6], 'cvss_score': row[7], 'cvss_vector': row[8],
                'cwe_id': row[9], 'references': references,
                'published_date': row[11], 'scan_date': row[12]
            })
        return vulnerabilities
    except sqlite3.Error as e:
        logger.error(f"Database error retrieving vulnerabilities: {e}")
        return []
    finally:
        conn.close()


def get_vulnerability_counts_by_severity(ip):
    """Get vulnerability counts by severity for a specific IP."""
    conn = sqlite3.connect(_get_db_path())
    cursor = conn.cursor()

    try:
        cursor.execute('''SELECT severity, COUNT(*) FROM vulnerabilities
                          WHERE ip = ? GROUP BY severity''', (ip,))
        counts = dict(cursor.fetchall())
        return {
            'critical': counts.get('critical', 0),
            'high': counts.get('high', 0),
            'medium': counts.get('medium', 0),
            'low': counts.get('low', 0),
            'info': counts.get('info', 0),
            'total': sum(counts.values())
        }
    except sqlite3.Error as e:
        logger.error(f"Database error getting severity counts: {e}")
        return {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'total': 0}
    finally:
        conn.close()


def get_unified_vulnerabilities(ip=None, source=None, has_exploit=None, search=None):
    """Get unified vulnerabilities from all sources, deduplicated by CVE ID.

    This is a large function extracted as-is from vuln_scan.py.
    """
    conn = sqlite3.connect(_get_db_path())
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    try:
        unified = {}

        # 1. Fetch from vulnerabilities table (Nuclei results)
        vuln_query = '''SELECT ip, port, protocol, vuln_id, vuln_name, severity, description,
                        cvss_score, cvss_vector, cwe_id, references_json, published_date, scan_date
                        FROM vulnerabilities'''
        vuln_params = []
        if ip:
            vuln_query += ' WHERE ip = ?'
            vuln_params.append(ip)

        cursor.execute(vuln_query, vuln_params)
        for row in cursor.fetchall():
            vuln_id = row['vuln_id']
            cve_id = vuln_id.upper() if vuln_id.upper().startswith('CVE-') else vuln_id

            references = []
            if row['references_json']:
                try:
                    references = json.loads(row['references_json'])
                except json.JSONDecodeError:
                    pass

            asset_key = f"{row['ip']}:{row['port']}/{row['protocol']}"

            if cve_id in unified:
                entry = unified[cve_id]
                if asset_key not in [a['key'] for a in entry['affected_assets']]:
                    entry['affected_assets'].append({
                        'key': asset_key, 'ip': row['ip'],
                        'port': row['port'], 'protocol': row['protocol']
                    })
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
                    entry['nuclei_scan_date'] = row['scan_date']
            else:
                unified[cve_id] = {
                    'cve_id': cve_id, 'vuln_name': row['vuln_name'],
                    'severity': row['severity'], 'description': row['description'] or '',
                    'cvss_score': row['cvss_score'], 'cvss_v3_score': row['cvss_score'],
                    'cvss_v2_score': None, 'cvss_vector': row['cvss_vector'],
                    'cwe_id': row['cwe_id'], 'references': references,
                    'published_date': row['published_date'], 'last_modified': None,
                    'has_exploit': False, 'exploit_ids': '', 'exploit_url': '',
                    'affected_cpe': '',
                    'affected_assets': [{'key': asset_key, 'ip': row['ip'],
                                         'port': row['port'], 'protocol': row['protocol']}],
                    'detection_sources': ['nuclei'],
                    'template_id': vuln_id if not vuln_id.upper().startswith('CVE-') else '',
                    'nuclei_scan_date': row['scan_date'], 'scan_date': row['scan_date'],
                }

        # 2. Fetch from cve_matches table
        cve_query = '''SELECT ip, cve_id, severity, cvss_score, description, affected_cpe,
                       has_exploit, exploit_ids, exploit_url, scan_date
                       FROM cve_matches'''
        cve_params = []
        if ip:
            cve_query += ' WHERE ip = ?'
            cve_params.append(ip)

        cursor.execute(cve_query, cve_params)
        for row in cursor.fetchall():
            cve_id = row['cve_id'].upper() if row['cve_id'] else ''
            if not cve_id:
                continue

            asset_key = f"{row['ip']}:0/tcp"

            det_source = 'nvd-local'
            cursor2 = conn.cursor()
            cursor2.execute('SELECT COUNT(*) FROM installed_software WHERE ip = ?', (row['ip'],))
            has_sw = cursor2.fetchone()[0] > 0
            if has_sw:
                det_source = 'auth-scan'

            if cve_id in unified:
                entry = unified[cve_id]
                if asset_key not in [a['key'] for a in entry['affected_assets']]:
                    entry['affected_assets'].append({
                        'key': asset_key, 'ip': row['ip'], 'port': 0, 'protocol': 'tcp'
                    })
                if det_source not in entry['detection_sources']:
                    entry['detection_sources'].append(det_source)
                if row['has_exploit']:
                    entry['has_exploit'] = True
                    if row['exploit_ids'] and not entry['exploit_ids']:
                        entry['exploit_ids'] = row['exploit_ids']
                    if row['exploit_url'] and not entry['exploit_url']:
                        entry['exploit_url'] = row['exploit_url']
                if row['description'] and len(row['description']) > len(entry.get('description', '')):
                    entry['description'] = row['description']
                if row['affected_cpe'] and row['affected_cpe'] not in (entry.get('affected_cpe') or ''):
                    existing = entry.get('affected_cpe', '')
                    entry['affected_cpe'] = (existing + ', ' + row['affected_cpe']).strip(', ')
            else:
                unified[cve_id] = {
                    'cve_id': cve_id, 'vuln_name': cve_id,
                    'severity': row['severity'] or 'medium',
                    'description': row['description'] or '',
                    'cvss_score': row['cvss_score'], 'cvss_v3_score': row['cvss_score'],
                    'cvss_v2_score': None, 'cvss_vector': None,
                    'cwe_id': None, 'references': [],
                    'published_date': None, 'last_modified': None,
                    'has_exploit': bool(row['has_exploit']),
                    'exploit_ids': row['exploit_ids'] or '',
                    'exploit_url': row['exploit_url'] or '',
                    'affected_cpe': row['affected_cpe'] or '',
                    'affected_assets': [{'key': asset_key, 'ip': row['ip'], 'port': 0, 'protocol': 'tcp'}],
                    'detection_sources': [det_source],
                    'template_id': '', 'nuclei_scan_date': None,
                    'scan_date': row['scan_date'],
                }

        # 3. Enrich with NVD local database
        try:
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='nvd_cves'")
            if cursor.fetchone():
                for cve_id, entry in unified.items():
                    if not cve_id.upper().startswith('CVE-'):
                        continue
                    cursor.execute('''SELECT cve_id, description, cvss_v2_score, cvss_v2_vector,
                                      cvss_v3_score, cvss_v3_vector, published_date, last_modified,
                                      source_json
                                      FROM nvd_cves WHERE cve_id = ?''', (cve_id,))
                    nvd_row = cursor.fetchone()
                    if nvd_row:
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
                                            val = desc.get('value', '')
                                            if val.startswith('CWE-'):
                                                entry['cwe_id'] = val
                                                break
                                        if entry['cwe_id']:
                                            break
                                existing_urls = {r.get('url') for r in entry['references']}
                                for ref in src.get('references', [])[:10]:
                                    url = ref.get('url', '')
                                    if url and url not in existing_urls:
                                        entry['references'].append({
                                            'url': url, 'source': ref.get('source', 'NVD')
                                        })
                                        existing_urls.add(url)
                            except (json.JSONDecodeError, TypeError):
                                pass

                        score = entry['cvss_score']
                        if score is not None:
                            if score >= 9.0:
                                entry['severity'] = 'critical'
                            elif score >= 7.0:
                                entry['severity'] = 'high'
                            elif score >= 4.0:
                                entry['severity'] = 'medium'
                            elif score > 0:
                                entry['severity'] = 'low'
        except Exception as e:
            logger.debug(f"NVD enrichment error: {e}")

        # 4. Mark exploit-db as detection source
        for cve_id, entry in unified.items():
            if entry['has_exploit'] and 'exploit-db' not in entry['detection_sources']:
                entry['detection_sources'].append('exploit-db')

        results = list(unified.values())

        # Apply filters
        if source:
            results = [r for r in results if source in r['detection_sources']]
        if has_exploit is not None:
            if has_exploit:
                results = [r for r in results if r['has_exploit']]
            else:
                results = [r for r in results if not r['has_exploit']]
        if search:
            search_lower = search.lower()
            results = [r for r in results if
                       search_lower in r['cve_id'].lower() or
                       search_lower in (r['description'] or '').lower() or
                       search_lower in (r['affected_cpe'] or '').lower() or
                       search_lower in (r['vuln_name'] or '').lower()]

        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        results.sort(key=lambda r: (
            0 if r['has_exploit'] else 1,
            -1 * (r['cvss_score'] or 0),
            severity_order.get(r['severity'], 5)
        ))

        for r in results:
            r['affected_assets'] = [{'ip': a['ip'], 'port': a['port'], 'protocol': a['protocol']}
                                     for a in r['affected_assets']]

        return results
    except sqlite3.Error as e:
        logger.error(f"Database error in get_unified_vulnerabilities: {e}")
        return []
    finally:
        conn.close()


def get_unified_vulnerability_summary(ip=None):
    """Get summary counts for unified vulnerabilities."""
    try:
        summary = {
            'total_findings': 0, 'unique_cves': 0, 'with_exploits': 0,
            'affected_hosts': 0,
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
            'by_source': {'nuclei': 0, 'nvd-local': 0, 'nmap-vulscan': 0, 'auth-scan': 0, 'exploit-db': 0}
        }

        vulns = get_unified_vulnerabilities(ip=ip)
        summary['unique_cves'] = len(vulns)

        all_ips = set()
        total_findings = 0
        for v in vulns:
            summary['by_severity'][v.get('severity', 'info')] = \
                summary['by_severity'].get(v.get('severity', 'info'), 0) + 1
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
            'total_findings': 0, 'unique_cves': 0, 'with_exploits': 0,
            'affected_hosts': 0,
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
            'by_source': {}
        }
