"""NVD Feed download, import, and local CPE matching module for Artemis.

Downloads bulk NVD JSON feed files (gzipped) for fast CVE import,
with incremental updates via the 'modified' feed. Stores CVEs and
CPE match data in local SQLite for offline vulnerability lookups.
"""

import re
import json
import gzip
import time
import sqlite3
import hashlib
import logging
import urllib.request
import urllib.error
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# NVD bulk JSON feed base URL
NVD_FEED_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0"
FEED_YEARS = list(range(2002, 2027))  # 2002-2026

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
    cursor.execute('''CREATE INDEX IF NOT EXISTS idx_nvd_cpe_product
                      ON nvd_cpe_matches(cpe23uri COLLATE NOCASE)''')

    # Denormalized product -> vendor index, derived from nvd_cpe_matches by
    # build_cpe_product_index(). Lets the auth-scan CPE resolver name packages
    # accurately without a separate CPE-dictionary download.
    cursor.execute('''CREATE TABLE IF NOT EXISTS cpe_products (
        product TEXT NOT NULL,
        vendor TEXT NOT NULL,
        part TEXT NOT NULL,
        hits INTEGER DEFAULT 0,
        PRIMARY KEY (product, vendor, part)
    )''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS idx_cpe_products_product
                      ON cpe_products(product)''')

    conn.commit()
    conn.close()
    logger.info("NVD tables initialized")


def _extract_cve_fields(cve_item):
    """Extract fields from a single NVD API 2.0 CVE item."""
    cve = cve_item.get('cve', cve_item)  # Handle both {'cve': {...}} and direct cve object
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
            'version_start_type': (
                'including' if match.get('versionStartIncluding')
                else ('excluding' if match.get('versionStartExcluding') else None)
            ),
            'version_end': match.get('versionEndIncluding') or match.get('versionEndExcluding'),
            'version_end_type': (
                'including' if match.get('versionEndIncluding')
                else ('excluding' if match.get('versionEndExcluding') else None)
            ),
        })

    for child in node.get('children', []):
        _extract_cpe_from_node(child, cve_id, results)


def _fetch_meta(feed_name):
    """Fetch .meta file for a feed and return dict with sha256, lastModifiedDate, size."""
    url = f"{NVD_FEED_BASE}/{feed_name}.meta"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Artemis-Scanner/1.0'})
        with urllib.request.urlopen(req, timeout=30) as resp:
            text = resp.read().decode('utf-8')
        meta = {}
        for line in text.strip().split('\n'):
            if ':' in line:
                key, _, val = line.partition(':')
                meta[key.strip()] = val.strip()
        return meta
    except Exception as e:
        logger.warning(f"Failed to fetch meta for {feed_name}: {e}")
        return None


def _get_stored_hash(cursor, feed_name):
    """Get stored sha256 hash for a feed from settings table."""
    try:
        cursor.execute("SELECT value FROM settings WHERE key = ?", (f'nvd_feed_hash_{feed_name}',))
        row = cursor.fetchone()
        return row[0] if row else None
    except Exception:
        return None


def _store_hash(cursor, feed_name, sha256):
    """Store sha256 hash for a feed in settings table."""
    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                   (f'nvd_feed_hash_{feed_name}', sha256))


def _download_and_parse_feed(feed_name, emit_fn, conn, cursor, label=""):
    """Download a gzipped JSON feed, decompress, parse, and import CVEs.
    
    Returns number of CVEs imported, or -1 on error.
    """
    url = f"{NVD_FEED_BASE}/{feed_name}.json.gz"
    emit_fn({'status': 'running', 'message': f'Downloading {label or feed_name}...'})

    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Artemis-Scanner/1.0'})
        with urllib.request.urlopen(req, timeout=120) as resp:
            compressed = resp.read()
    except Exception as e:
        emit_fn({'status': 'running', 'message': f'Download failed for {feed_name}: {e}'})
        logger.error(f"Download failed for {feed_name}: {e}")
        return -1

    # Compute sha256 of compressed file for verification
    file_hash = hashlib.sha256(compressed).hexdigest().upper()

    # Decompress
    try:
        raw = gzip.decompress(compressed)
    except Exception as e:
        emit_fn({'status': 'running', 'message': f'Decompression failed for {feed_name}: {e}'})
        logger.error(f"Decompression failed for {feed_name}: {e}")
        return -1

    # Free compressed data
    del compressed

    # Parse JSON
    try:
        data = json.loads(raw)
    except Exception as e:
        emit_fn({'status': 'running', 'message': f'JSON parse failed for {feed_name}: {e}'})
        logger.error(f"JSON parse failed for {feed_name}: {e}")
        return -1

    del raw

    vulns = data.get('vulnerabilities', [])
    total = len(vulns)
    emit_fn({'status': 'running', 'message': f'Importing {total} CVEs from {label or feed_name}...'})

    imported = 0
    batch_cves = []
    batch_cpes = []
    batch_cve_ids = []

    for item in vulns:
        fields = _extract_cve_fields(item)
        if not fields['cve_id']:
            continue

        batch_cves.append((
            fields['cve_id'], fields['description'], fields['published_date'],
            fields['last_modified'], fields['cvss_v3_score'], fields['cvss_v3_severity'],
            fields['cvss_v2_score'], fields['cvss_v2_severity']
        ))
        batch_cve_ids.append(fields['cve_id'])

        for cpe in fields['cpe_matches']:
            batch_cpes.append((
                cpe['cve_id'], cpe['cpe23uri'], cpe['vulnerable'],
                cpe['version_start'], cpe['version_start_type'],
                cpe['version_end'], cpe['version_end_type']
            ))

        imported += 1

        # Batch insert every 2000 CVEs
        if len(batch_cves) >= 2000:
            _flush_batch(cursor, batch_cves, batch_cpes, batch_cve_ids)
            batch_cves.clear()
            batch_cpes.clear()
            batch_cve_ids.clear()
            conn.commit()

    # Flush remaining
    if batch_cves:
        _flush_batch(cursor, batch_cves, batch_cpes, batch_cve_ids)
        conn.commit()

    # Store the hash
    _store_hash(cursor, feed_name, file_hash)
    conn.commit()

    return imported


def _flush_batch(cursor, batch_cves, batch_cpes, batch_cve_ids):
    """Batch insert CVEs and CPE matches."""
    cursor.executemany('''INSERT OR REPLACE INTO nvd_cves
        (cve_id, description, published_date, last_modified,
         cvss_v3_score, cvss_v3_severity, cvss_v2_score, cvss_v2_severity)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', batch_cves)

    # Delete old CPE matches for these CVEs
    if batch_cve_ids:
        placeholders = ','.join(['?'] * len(batch_cve_ids))
        cursor.execute(f'DELETE FROM nvd_cpe_matches WHERE cve_id IN ({placeholders})', batch_cve_ids)

    if batch_cpes:
        cursor.executemany('''INSERT INTO nvd_cpe_matches
            (cve_id, cpe23uri, vulnerable, version_start, version_start_type,
             version_end, version_end_type)
            VALUES (?, ?, ?, ?, ?, ?, ?)''', batch_cpes)


def sync_nvd_database(socketio=None, api_key=None, full_sync=False, db_path=None):
    """Download CVEs from NVD bulk feeds and store in local database.

    Args:
        socketio: Flask-SocketIO instance for progress events (optional)
        api_key: NVD API key (unused for bulk feeds, kept for API compat)
        full_sync: If True, download all year feeds; otherwise just 'modified' feed
        db_path: Override database path
    """
    path = db_path or _get_db_path()
    init_nvd_tables(path)

    def emit(data):
        if socketio:
            socketio.emit('nvd_sync_progress', data)
        logger.info(f"NVD sync: {data.get('message', '')}")

    conn = sqlite3.connect(path)
    cursor = conn.cursor()

    # Enable WAL mode for better concurrent performance
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")

    try:
        start_time = time.time()
        total_imported = 0

        if full_sync:
            # Full sync: download all year feeds (2002-2026)
            feeds = [(f'nvdcve-2.0-{year}', str(year)) for year in FEED_YEARS]
            total_feeds = len(feeds)

            emit({'status': 'running', 'message': f'Full sync: {total_feeds} year feeds to process', 'percent': 0})

            for idx, (feed_name, label) in enumerate(feeds):
                percent = int((idx / total_feeds) * 100)

                # Check meta to see if feed changed (skip if hash matches)
                meta = _fetch_meta(feed_name)
                if meta:
                    stored_hash = _get_stored_hash(cursor, feed_name)
                    meta_hash = meta.get('sha256', '')
                    if stored_hash and stored_hash == meta_hash:
                        emit({'status': 'running',
                              'message': f'Year {label}: unchanged, skipping',
                              'percent': percent,
                              'year': label})
                        continue

                emit({'status': 'running',
                      'message': f'Processing year {label} ({idx+1}/{total_feeds})...',
                      'percent': percent,
                      'year': label})

                count = _download_and_parse_feed(feed_name, emit, conn, cursor, label=f'Year {label}')
                if count >= 0:
                    total_imported += count
                    emit({'status': 'running',
                          'message': f'Year {label}: {count} CVEs imported',
                          'percent': int(((idx + 1) / total_feeds) * 100),
                          'imported': total_imported,
                          'year': label})

        else:
            # Incremental sync: download only the 'modified' feed (last 8 days)
            feed_name = 'nvdcve-2.0-modified'
            emit({
                'status': 'running',
                'message': 'Downloading modified feed (last 8 days of changes)...',
                'percent': 10,
            })

            # Check meta
            meta = _fetch_meta(feed_name)
            if meta:
                stored_hash = _get_stored_hash(cursor, feed_name)
                meta_hash = meta.get('sha256', '')
                if stored_hash and stored_hash == meta_hash:
                    # Get total count
                    cursor.execute("SELECT COUNT(*) FROM nvd_cves")
                    total_in_db = cursor.fetchone()[0]
                    emit({'status': 'complete',
                          'message': f'No changes since last sync. {total_in_db:,} CVEs in database.',
                          'percent': 100, 'total_in_db': total_in_db})
                    conn.close()
                    return

            count = _download_and_parse_feed(feed_name, emit, conn, cursor, label='Modified feed')
            if count >= 0:
                total_imported = count

        # Update last sync timestamp
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
        cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('nvd_last_sync', ?)", (now_str,))
        conn.commit()

        # Refresh the product->vendor index used by the auth-scan CPE resolver.
        try:
            emit({'status': 'running', 'message': 'Rebuilding CPE product index...', 'percent': 98})
            build_cpe_product_index(path)
        except Exception as e:
            logger.warning(f"CPE product index rebuild skipped: {e}")

        # Get total count in DB
        cursor.execute("SELECT COUNT(*) FROM nvd_cves")
        total_in_db = cursor.fetchone()[0]

        elapsed = time.time() - start_time
        minutes = int(elapsed // 60)
        seconds = int(elapsed % 60)

        emit({
            'status': 'complete',
            'message': (
                f'Sync complete: {total_imported:,} CVEs processed in {minutes}m {seconds}s. '
                f'{total_in_db:,} total in database.'
            ),
            'percent': 100,
            'imported': total_imported,
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
    """Parse a version string into comparable tuple of integers."""
    if not version_str or version_str == '*' or version_str == '-':
        return None

    version_str = re.split(r'[-+~_]', version_str)[0]
    parts = []
    for p in version_str.split('.'):
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
    if len(v1) < len(v2):
        return -1
    if len(v1) > len(v2):
        return 1
    return 0


def _version_in_range(version, start, start_type, end, end_type):
    """Check if a version falls within the specified range."""
    v = _parse_version(version)
    if v is None:
        return True

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
    """Check if a CPE target matches a CPE pattern (with wildcards)."""
    pattern_parts = cpe_pattern.split(':')
    target_parts = cpe_target.split(':')

    if len(pattern_parts) < 5 or len(target_parts) < 5:
        return False

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

    try:
        cursor.execute("SELECT COUNT(*) FROM nvd_cves")
        if cursor.fetchone()[0] == 0:
            logger.info("Local NVD database is empty, skipping local matching")
            conn.close()
            return None
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

                key = (cve_id, cpe_string)
                if key in seen_cves:
                    continue

                if not _cpe_matches(cpe_uri, cpe_string):
                    continue

                if v_start or v_end:
                    if not _version_in_range(version, v_start, v_start_type, v_end, v_end_type):
                        continue
                else:
                    pattern_parts = cpe_uri.split(':')
                    if len(pattern_parts) > 5 and pattern_parts[5] not in ('*', '-', ''):
                        if version != '*' and pattern_parts[5] != version:
                            continue

                seen_cves.add(key)

                cvss_score = row[8] or row[10]
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


# ===========================================================================
# CPE resolution for the authenticated scanner
# ===========================================================================

import re as _re  # noqa: E402

# Packages whose distro name does not match the CPE product/vendor. Seeds the
# resolver; anything not here falls through to the cpe_products index.
_CPE_OVERRIDES = {
    'openssh': ('openbsd', 'openssh'),
    'openssh-server': ('openbsd', 'openssh'),
    'openssh-client': ('openbsd', 'openssh'),
    'openssh-sftp-server': ('openbsd', 'openssh'),
    'openssl': ('openssl', 'openssl'),
    'libssl1.1': ('openssl', 'openssl'),
    'libssl3': ('openssl', 'openssl'),
    'libssl': ('openssl', 'openssl'),
    'apache2': ('apache', 'http_server'),
    'apache2-bin': ('apache', 'http_server'),
    'httpd': ('apache', 'http_server'),
    'nginx': ('f5', 'nginx'),
    'nginx-core': ('f5', 'nginx'),
    'nginx-full': ('f5', 'nginx'),
    'curl': ('haxx', 'curl'),
    'libcurl4': ('haxx', 'libcurl'),
    'libcurl3': ('haxx', 'libcurl'),
    'libc6': ('gnu', 'glibc'),
    'libc-bin': ('gnu', 'glibc'),
    'glibc': ('gnu', 'glibc'),
    'bash': ('gnu', 'bash'),
    'sudo': ('sudo_project', 'sudo'),
    'sudo-ldap': ('sudo_project', 'sudo'),
    'vim': ('vim', 'vim'),
    'vim-common': ('vim', 'vim'),
    'vim-tiny': ('vim', 'vim'),
    'git': ('git-scm', 'git'),
    'perl': ('perl', 'perl'),
    'perl-base': ('perl', 'perl'),
    'python3': ('python', 'python'),
    'python3.9': ('python', 'python'),
    'python3.10': ('python', 'python'),
    'python3.11': ('python', 'python'),
    'python2.7': ('python', 'python'),
    'php': ('php', 'php'),
    'bind9': ('isc', 'bind'),
    'bind9-host': ('isc', 'bind'),
    'libbind9-161': ('isc', 'bind'),
    'named': ('isc', 'bind'),
    'samba': ('samba', 'samba'),
    'samba-common': ('samba', 'samba'),
    'libsmbclient': ('samba', 'samba'),
    'postgresql': ('postgresql', 'postgresql'),
    'mariadb-server': ('mariadb', 'mariadb'),
    'mysql-server': ('oracle', 'mysql'),
    'redis-server': ('redis', 'redis'),
    'redis': ('redis', 'redis'),
    'nodejs': ('nodejs', 'node.js'),
    'docker-ce': ('docker', 'docker'),
    'docker.io': ('docker', 'docker'),
    'containerd': ('linuxfoundation', 'containerd'),
    'runc': ('linuxfoundation', 'runc'),
    'zlib1g': ('zlib', 'zlib'),
    'libzstd1': ('facebook', 'zstd'),
    'libxml2': ('xmlsoft', 'libxml2'),
    'libpng16-16': ('libpng', 'libpng'),
    'libexpat1': ('libexpat_project', 'libexpat'),
    'libssh2-1': ('libssh2', 'libssh2'),
    'libssh-4': ('libssh', 'libssh'),
    'sqlite3': ('sqlite', 'sqlite'),
    'libsqlite3-0': ('sqlite', 'sqlite'),
    'libtiff5': ('libtiff', 'libtiff'),
    'libtiff6': ('libtiff', 'libtiff'),
    'libtiff-dev': ('libtiff', 'libtiff'),
    'libjpeg62-turbo': ('libjpeg-turbo', 'libjpeg-turbo'),
    'libjpeg-turbo8': ('libjpeg-turbo', 'libjpeg-turbo'),
    'libfreetype6': ('freetype', 'freetype'),
    'libwebp7': ('webmproject', 'libwebp'),
    'libpcre2-8-0': ('pcre2_project', 'pcre2'),
    'libpcre3': ('pcre', 'pcre'),
    'libgd3': ('libgd', 'libgd'),
    'libtasn1-6': ('gnu', 'libtasn1'),
    'libidn2-0': ('gnu', 'libidn2'),
    'libksba8': ('gnupg', 'libksba'),
    'libnghttp2-14': ('nghttp2', 'nghttp2'),
    'liblzma5': ('tukaani', 'xz'),
    'xz-utils': ('tukaani', 'xz'),
    'exim4': ('exim', 'exim'),
    'postfix': ('postfix', 'postfix'),
    'dovecot-core': ('dovecot', 'dovecot'),
    'tar': ('gnu', 'tar'),
    'wget': ('gnu', 'wget'),
    'gnutls-bin': ('gnu', 'gnutls'),
    'libgnutls30': ('gnu', 'gnutls'),
    'libgcrypt20': ('gnupg', 'libgcrypt'),
    'gnupg': ('gnupg', 'gnupg'),
    'sysstat': ('sysstat_project', 'sysstat'),
    'rsync': ('samba', 'rsync'),
    'cron': ('vixie', 'cron'),
    'util-linux': ('kernel', 'util-linux'),
}

_KERNEL_RE = _re.compile(r'^(?:linux-image|linux-headers|kernel|linux-modules)')


def _normalize_version(version_str):
    """Reduce a distro package version to a CPE-comparable dotted version.

    '1:2.4.1-3+deb11u1' -> '2.4.1' ; '9.2p1-2' -> '9.2' ;
    '3.0.11-1~deb12u2' -> '3.0.11' ; '7.88.1-10+deb12u5' -> '7.88.1'
    Returns '*' when nothing usable remains.
    """
    if not version_str:
        return '*'
    v = str(version_str).strip()
    # epoch
    if ':' in v:
        v = v.split(':', 1)[1]
    # distro revision — everything from the first '-'
    v = v.split('-', 1)[0]
    # openssh 'p1', 'rc1', 'beta', dfsg tags, git snapshots
    v = _re.split(r'[+~]', v, maxsplit=1)[0]
    m = _re.match(r'(\d+(?:\.\d+){0,3})', v)
    if not m:
        return '*'
    return m.group(1)


def _norm_product(name):
    n = name.lower().strip()
    n = _re.sub(r'[^a-z0-9._+-]', '', n)
    return n


def build_cpe_product_index(db_path=None):
    """(Re)build cpe_products from nvd_cpe_matches. Idempotent; a few seconds."""
    path = db_path or _get_db_path()
    if not path or path == ':memory:':
        return 0
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    try:
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='nvd_cpe_matches'")
        if not cur.fetchone():
            return 0
        cur.execute("SELECT COUNT(*) FROM nvd_cpe_matches")
        if cur.fetchone()[0] == 0:
            return 0

        cur.execute('''CREATE TABLE IF NOT EXISTS cpe_products (
            product TEXT NOT NULL, vendor TEXT NOT NULL, part TEXT NOT NULL,
            hits INTEGER DEFAULT 0, PRIMARY KEY (product, vendor, part))''')
        cur.execute('''CREATE INDEX IF NOT EXISTS idx_cpe_products_product
                       ON cpe_products(product)''')

        tally = {}
        cur.execute("SELECT DISTINCT cpe23uri FROM nvd_cpe_matches")
        for (uri,) in cur:
            parts = (uri or '').split(':')
            if len(parts) < 6 or not parts[0].startswith('cpe'):
                continue
            part, vendor, product = parts[2], parts[3], parts[4]
            if vendor in ('*', '-', '') or product in ('*', '-', ''):
                continue
            key = (product, vendor, part)
            tally[key] = tally.get(key, 0) + 1

        cur.execute("DELETE FROM cpe_products")
        cur.executemany(
            "INSERT INTO cpe_products (product, vendor, part, hits) VALUES (?, ?, ?, ?)",
            [(p, v, pt, n) for (p, v, pt), n in tally.items()],
        )
        conn.commit()
        logger.info(f"cpe_products index built: {len(tally)} product/vendor pairs")
        return len(tally)
    except Exception as e:
        logger.warning(f"build_cpe_product_index failed: {e}")
        return 0
    finally:
        conn.close()


def _lookup_vendor(cur, product):
    """Best vendor for a normalized product name from cpe_products. Returns
    (vendor, product, part) or None."""
    for candidate in _product_candidates(product):
        cur.execute(
            "SELECT vendor, product, part FROM cpe_products WHERE product = ? "
            "ORDER BY (part = 'a') DESC, hits DESC LIMIT 1",
            (candidate,),
        )
        row = cur.fetchone()
        if row:
            return row
    return None


def _product_candidates(product):
    seen = []

    def add(x):
        if x and x not in seen:
            seen.append(x)

    add(product)
    add(product.replace('-', '_'))
    add(product.replace('_', '-'))
    # strip lib prefix / -dev,-bin,-common,-core suffixes and soname digits
    stripped = _re.sub(r'^lib', '', product)
    stripped = _re.sub(r'[0-9.]+$', '', stripped)
    stripped = _re.sub(r'-(dev|bin|common|core|server|client|utils|tools|doc|data)$', '', stripped)
    add(stripped)
    add(stripped.replace('-', '_'))
    return seen


def resolve_cpe(product_name, version, os_family=None, db_path=None):
    """Resolve a distro package to a CPE 2.3 'a' string, best-effort.

    Order: curated override map -> local cpe_products index -> generated fallback.
    """
    version = _normalize_version(version)
    product = _norm_product(product_name)

    if _KERNEL_RE.match(product):
        return f"cpe:2.3:o:linux:linux_kernel:{version}:*:*:*:*:*:*:*"

    ov = _CPE_OVERRIDES.get(product) or _CPE_OVERRIDES.get(product.replace('_', '-'))
    if ov:
        return f"cpe:2.3:a:{ov[0]}:{ov[1]}:{version}:*:*:*:*:*:*:*"

    path = db_path or _get_db_path()
    if path and path != ':memory:':
        conn = sqlite3.connect(path)
        cur = conn.cursor()
        try:
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cpe_products'")
            if cur.fetchone():
                cur.execute("SELECT COUNT(*) FROM cpe_products")
                if cur.fetchone()[0] == 0:
                    conn.close()
                    build_cpe_product_index(path)
                    conn = sqlite3.connect(path)
                    cur = conn.cursor()
                hit = _lookup_vendor(cur, product)
                if hit:
                    vendor, prod, part = hit
                    return f"cpe:2.3:{part}:{vendor}:{prod}:{version}:*:*:*:*:*:*:*"
        except Exception as e:
            logger.debug(f"resolve_cpe index lookup failed: {e}")
        finally:
            conn.close()

    return f"cpe:2.3:a:{product}:{product}:{version}:*:*:*:*:*:*:*"
