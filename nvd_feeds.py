"""NVD Feed download, import, and local CPE matching module for Cerebus.

Provides bulk CVE download from NVD API 2.0, local SQLite storage,
and version-aware CPE matching for offline vulnerability lookups.
"""

import os
import re
import json
import time
import sqlite3
import logging
import threading
import urllib.request
import urllib.error
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000

# Import DB_PATH from vuln_scan (lazy to avoid circular imports)
_db_path = None

def _get_db_path():
    global _db_path
    if _db_path is None:
        from vuln_scan import DB_PATH
        _db_path = DB_PATH
    return _db_path


def init_nvd_tables(db_path=None):
    """Create NVD-related tables if they don't exist."""
    path = db_path or _get_db_path()
    conn = sqlite3.connect(path)
    cursor = conn.cursor()

    cursor.execute('''CREATE TABLE IF NOT EXISTS nvd_cves (
        cve_id TEXT PRIMARY KEY,
        description TEXT,
        published_date TEXT,
        last_modified TEXT,
        cvss_v3_score REAL,
        cvss_v3_severity TEXT,
        cvss_v2_score REAL,
        cvss_v2_severity TEXT,
        source_json TEXT
    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS nvd_cpe_matches (
        id INTEGER PRIMARY KEY,
        cve_id TEXT NOT NULL,
        cpe23uri TEXT NOT NULL,
        vulnerable INTEGER DEFAULT 1,
        version_start TEXT,
        version_start_type TEXT,
        version_end TEXT,
        version_end_type TEXT,
        FOREIGN KEY (cve_id) REFERENCES nvd_cves(cve_id)
    )''')

    cursor.execute('''CREATE INDEX IF NOT EXISTS idx_nvd_cpe_cve
                      ON nvd_cpe_matches(cve_id)''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS idx_nvd_cpe_uri
                      ON nvd_cpe_matches(cpe23uri)''')
    # Index for vendor:product lookups (first 5 CPE fields)
    cursor.execute('''CREATE INDEX IF NOT EXISTS idx_nvd_cpe_product
                      ON nvd_cpe_matches(cpe23uri COLLATE NOCASE)''')

    conn.commit()
    conn.close()
    logger.info("NVD tables initialized")


def _extract_cve_fields(cve_item):
    """Extract fields from a single NVD API 2.0 CVE item."""
    cve = cve_item.get('cve', {})
    cve_id = cve.get('id', '')

    # Description (English)
    description = ''
    for d in cve.get('descriptions', []):
        if d.get('lang') == 'en':
            description = d.get('value', '')
            break

    published = cve.get('published', '')
    last_modified = cve.get('lastModified', '')

    # CVSS scores
    metrics = cve.get('metrics', {})
    cvss_v3_score = None
    cvss_v3_severity = None
    cvss_v2_score = None
    cvss_v2_severity = None

    for key in ['cvssMetricV31', 'cvssMetricV30']:
        if key in metrics and metrics[key]:
            d = metrics[key][0].get('cvssData', {})
            cvss_v3_score = d.get('baseScore')
            cvss_v3_severity = d.get('baseSeverity')
            break

    if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
        d = metrics['cvssMetricV2'][0].get('cvssData', {})
        cvss_v2_score = d.get('baseScore')
        cvss_v2_severity = d.get('baseSeverity')

    # CPE matches from configurations
    cpe_matches = []
    for config in cve.get('configurations', []):
        for node in config.get('nodes', []):
            _extract_cpe_from_node(node, cve_id, cpe_matches)

    return {
        'cve_id': cve_id,
        'description': description[:2000],
        'published_date': published,
        'last_modified': last_modified,
        'cvss_v3_score': cvss_v3_score,
        'cvss_v3_severity': cvss_v3_severity,
        'cvss_v2_score': cvss_v2_score,
        'cvss_v2_severity': cvss_v2_severity,
        'cpe_matches': cpe_matches,
    }


def _extract_cpe_from_node(node, cve_id, results):
    """Recursively extract CPE match criteria from a configuration node."""
    for match in node.get('cpeMatch', []):
        criteria = match.get('criteria', '')
        if not criteria:
            continue
        results.append({
            'cve_id': cve_id,
            'cpe23uri': criteria,
            'vulnerable': 1 if match.get('vulnerable', True) else 0,
            'version_start': match.get('versionStartIncluding') or match.get('versionStartExcluding'),
            'version_start_type': 'including' if match.get('versionStartIncluding') else ('excluding' if match.get('versionStartExcluding') else None),
            'version_end': match.get('versionEndIncluding') or match.get('versionEndExcluding'),
            'version_end_type': 'including' if match.get('versionEndIncluding') else ('excluding' if match.get('versionEndExcluding') else None),
        })

    # Handle nested children nodes (AND/OR logic in NVD)
    for child in node.get('children', []):
        _extract_cpe_from_node(child, cve_id, results)


def sync_nvd_database(socketio=None, api_key=None, full_sync=False, db_path=None):
    """Download CVEs from NVD API and store in local database.

    Args:
        socketio: Flask-SocketIO instance for progress events (optional)
        api_key: NVD API key for faster rate limits (optional)
        full_sync: If True, re-download everything; otherwise incremental
        db_path: Override database path

    This runs in a background thread. Emits 'nvd_sync_progress' events.
    """
    path = db_path or _get_db_path()
    init_nvd_tables(path)

    def emit(data):
        if socketio:
            socketio.emit('nvd_sync_progress', data)
        logger.info(f"NVD sync: {data.get('message', '')}")

    conn = sqlite3.connect(path)
    cursor = conn.cursor()

    try:
        # Determine start date for incremental sync
        last_sync = None
        if not full_sync:
            cursor.execute("SELECT value FROM settings WHERE key = 'nvd_last_sync'")
            row = cursor.fetchone()
            if row and row[0]:
                last_sync = row[0]

        # Build initial URL parameters
        params = [f'resultsPerPage={RESULTS_PER_PAGE}']
        if last_sync and not full_sync:
            params.append(f'lastModStartDate={last_sync}')
            params.append(f'lastModEndDate={datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")}')
            emit({'status': 'running', 'message': f'Incremental sync from {last_sync}', 'percent': 0})
        else:
            emit({'status': 'running', 'message': 'Full NVD sync starting...', 'percent': 0})

        headers = {'User-Agent': 'Cerebus-Scanner/1.0'}
        if api_key:
            headers['apiKey'] = api_key

        delay = 0.6 if api_key else 6.0
        start_index = 0
        total_results = None
        imported = 0
        batch_size = 500  # Commit every N CVEs

        while True:
            url = f"{NVD_CVE_API}?{'&'.join(params)}&startIndex={start_index}"

            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=60) as resp:
                    data = json.loads(resp.read().decode('utf-8'))
            except Exception as e:
                emit({'status': 'error', 'message': f'API error at index {start_index}: {e}'})
                logger.error(f"NVD API error: {e}")
                time.sleep(delay * 2)
                continue

            if total_results is None:
                total_results = data.get('totalResults', 0)
                emit({'status': 'running', 'message': f'Total CVEs to process: {total_results}', 'percent': 0, 'total': total_results})

            vulns = data.get('vulnerabilities', [])
            if not vulns:
                break

            for item in vulns:
                fields = _extract_cve_fields(item)

                # Store CVE (without full JSON to save space — store only if needed)
                cursor.execute('''INSERT OR REPLACE INTO nvd_cves
                    (cve_id, description, published_date, last_modified,
                     cvss_v3_score, cvss_v3_severity, cvss_v2_score, cvss_v2_severity, source_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)''',
                    (fields['cve_id'], fields['description'], fields['published_date'],
                     fields['last_modified'], fields['cvss_v3_score'], fields['cvss_v3_severity'],
                     fields['cvss_v2_score'], fields['cvss_v2_severity']))

                # Delete old CPE matches for this CVE then insert new ones
                cursor.execute('DELETE FROM nvd_cpe_matches WHERE cve_id = ?', (fields['cve_id'],))
                for cpe in fields['cpe_matches']:
                    cursor.execute('''INSERT INTO nvd_cpe_matches
                        (cve_id, cpe23uri, vulnerable, version_start, version_start_type,
                         version_end, version_end_type)
                        VALUES (?, ?, ?, ?, ?, ?, ?)''',
                        (cpe['cve_id'], cpe['cpe23uri'], cpe['vulnerable'],
                         cpe['version_start'], cpe['version_start_type'],
                         cpe['version_end'], cpe['version_end_type']))

                imported += 1

                if imported % batch_size == 0:
                    conn.commit()
                    percent = min(99, int(imported / max(total_results, 1) * 100))
                    emit({
                        'status': 'running',
                        'message': f'Imported {imported}/{total_results} CVEs...',
                        'percent': percent,
                        'imported': imported,
                        'total': total_results
                    })

            start_index += len(vulns)

            if start_index >= total_results:
                break

            time.sleep(delay)

        # Final commit
        conn.commit()

        # Update last sync timestamp
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
        cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('nvd_last_sync', ?)", (now_str,))
        conn.commit()

        # Get total count in DB
        cursor.execute("SELECT COUNT(*) FROM nvd_cves")
        total_in_db = cursor.fetchone()[0]

        emit({
            'status': 'complete',
            'message': f'Sync complete: {imported} CVEs processed, {total_in_db} total in database',
            'percent': 100,
            'imported': imported,
            'total_in_db': total_in_db
        })

    except Exception as e:
        logger.error(f"NVD sync error: {e}")
        emit({'status': 'error', 'message': f'Sync failed: {e}'})
    finally:
        conn.close()


def get_nvd_sync_status(db_path=None):
    """Get NVD database sync status."""
    path = db_path or _get_db_path()
    conn = sqlite3.connect(path)
    cursor = conn.cursor()
    try:
        # Check if tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='nvd_cves'")
        if not cursor.fetchone():
            return {'total_cves': 0, 'last_sync': None}

        cursor.execute("SELECT COUNT(*) FROM nvd_cves")
        total = cursor.fetchone()[0]

        cursor.execute("SELECT value FROM settings WHERE key = 'nvd_last_sync'")
        row = cursor.fetchone()
        last_sync = row[0] if row else None

        return {'total_cves': total, 'last_sync': last_sync}
    except Exception as e:
        logger.error(f"Error getting NVD sync status: {e}")
        return {'total_cves': 0, 'last_sync': None}
    finally:
        conn.close()


# ============== Local CPE Matching ==============

def _parse_version(version_str):
    """Parse a version string into comparable tuple of integers.
    
    Handles versions like '2.4.41', '7.0.0-beta1', '10.3.2.1', etc.
    Non-numeric suffixes are stripped.
    """
    if not version_str or version_str == '*' or version_str == '-':
        return None

    # Strip common suffixes
    version_str = re.split(r'[-+~_]', version_str)[0]
    parts = []
    for p in version_str.split('.'):
        # Extract leading digits
        m = re.match(r'^(\d+)', p)
        if m:
            parts.append(int(m.group(1)))
        else:
            break
    return tuple(parts) if parts else None


def _version_compare(v1, v2):
    """Compare two version tuples. Returns -1, 0, or 1."""
    if v1 is None or v2 is None:
        return 0
    for a, b in zip(v1, v2):
        if a < b:
            return -1
        if a > b:
            return 1
    # If equal so far, shorter version is "less" (e.g., 2.4 < 2.4.1)
    if len(v1) < len(v2):
        return -1
    if len(v1) > len(v2):
        return 1
    return 0


def _version_in_range(version, start, start_type, end, end_type):
    """Check if a version falls within the specified range."""
    v = _parse_version(version)
    if v is None:
        return True  # Can't determine — assume match

    if start:
        vs = _parse_version(start)
        if vs:
            cmp = _version_compare(v, vs)
            if start_type == 'including' and cmp < 0:
                return False
            if start_type == 'excluding' and cmp <= 0:
                return False

    if end:
        ve = _parse_version(end)
        if ve:
            cmp = _version_compare(v, ve)
            if end_type == 'including' and cmp > 0:
                return False
            if end_type == 'excluding' and cmp >= 0:
                return False

    return True


def _cpe_matches(cpe_pattern, cpe_target):
    """Check if a CPE target matches a CPE pattern (with wildcards).
    
    Both are cpe:2.3 formatted strings.
    Only compares part, vendor, product fields. Version is checked separately.
    """
    pattern_parts = cpe_pattern.split(':')
    target_parts = cpe_target.split(':')

    if len(pattern_parts) < 5 or len(target_parts) < 5:
        return False

    # Compare part (a/h/o), vendor, product
    for i in range(2, 5):
        pp = pattern_parts[i] if i < len(pattern_parts) else '*'
        tp = target_parts[i] if i < len(target_parts) else '*'
        if pp == '*' or tp == '*':
            continue
        if pp.lower() != tp.lower():
            return False

    return True


def match_cpes_local(cpe_list, db_path=None):
    """Match a list of CPE strings against the local NVD database.

    Args:
        cpe_list: list of CPE 2.3 strings to check

    Returns:
        list of dicts: [{cve_id, severity, cvss_score, description, affected_cpe}, ...]
    """
    path = db_path or _get_db_path()
    conn = sqlite3.connect(path)
    cursor = conn.cursor()

    # Check if NVD tables have data
    try:
        cursor.execute("SELECT COUNT(*) FROM nvd_cves")
        if cursor.fetchone()[0] == 0:
            logger.info("Local NVD database is empty, skipping local matching")
            conn.close()
            return None  # Signal to caller to use API fallback
    except sqlite3.OperationalError:
        conn.close()
        return None

    results = []
    seen_cves = set()

    try:
        for cpe_string in cpe_list:
            parts = cpe_string.split(':')
            if len(parts) < 6:
                continue

            vendor = parts[3]
            product = parts[4]
            version = parts[5] if len(parts) > 5 else '*'

            if vendor == '*' or product == '*':
                continue

            # Search for CPE matches in the database
            # Use LIKE for vendor:product prefix matching
            search_pattern = f"cpe:2.3:%:{vendor}:{product}:%"
            cursor.execute('''
                SELECT cm.cve_id, cm.cpe23uri, cm.vulnerable,
                       cm.version_start, cm.version_start_type,
                       cm.version_end, cm.version_end_type,
                       c.description, c.cvss_v3_score, c.cvss_v3_severity,
                       c.cvss_v2_score, c.cvss_v2_severity
                FROM nvd_cpe_matches cm
                JOIN nvd_cves c ON cm.cve_id = c.cve_id
                WHERE cm.cpe23uri LIKE ? AND cm.vulnerable = 1
            ''', (search_pattern,))

            for row in cursor.fetchall():
                cve_id = row[0]
                cpe_uri = row[1]
                v_start = row[3]
                v_start_type = row[4]
                v_end = row[5]
                v_end_type = row[6]

                # Skip if already seen this CVE for this CPE
                key = (cve_id, cpe_string)
                if key in seen_cves:
                    continue

                # Check if the CPE pattern matches
                if not _cpe_matches(cpe_uri, cpe_string):
                    continue

                # Check version range
                # If the DB entry has version ranges, use them
                if v_start or v_end:
                    if not _version_in_range(version, v_start, v_start_type, v_end, v_end_type):
                        continue
                else:
                    # No range specified — check if the CPE pattern has a specific version
                    pattern_parts = cpe_uri.split(':')
                    if len(pattern_parts) > 5 and pattern_parts[5] not in ('*', '-', ''):
                        # Exact version match required
                        if version != '*' and pattern_parts[5] != version:
                            continue

                seen_cves.add(key)

                cvss_score = row[8] or row[10]  # Prefer v3
                severity = 'unknown'
                if cvss_score is not None:
                    if cvss_score >= 9.0:
                        severity = 'critical'
                    elif cvss_score >= 7.0:
                        severity = 'high'
                    elif cvss_score >= 4.0:
                        severity = 'medium'
                    else:
                        severity = 'low'
                elif row[9]:
                    severity = row[9].lower()
                elif row[11]:
                    severity = row[11].lower()

                results.append({
                    'cve_id': cve_id,
                    'severity': severity,
                    'cvss_score': cvss_score,
                    'description': (row[7] or '')[:500],
                    'affected_cpe': cpe_string,
                })

    except Exception as e:
        logger.error(f"Local CPE matching error: {e}")
    finally:
        conn.close()

    logger.info(f"Local NVD matching: {len(results)} CVEs found for {len(cpe_list)} CPEs")
    return results
