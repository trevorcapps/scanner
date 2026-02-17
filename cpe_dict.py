"""CPE Dictionary module for fuzzy CPE matching.

Downloads the NVD CPE dictionary and provides fuzzy matching
to improve CPE accuracy beyond hardcoded vendor mappings.
"""

import os
import re
import json
import gzip
import sqlite3
import logging
import difflib
import urllib.request
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Use the CPE match feed (contains CPE URIs with titles)
CPE_DICT_URL = "https://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz"

# Lazy DB path
_db_path = None

def _get_db_path():
    global _db_path
    if _db_path is None:
        from vuln_scan import DB_PATH
        _db_path = DB_PATH
    return _db_path


def init_cpe_tables(db_path=None):
    """Create CPE dictionary table."""
    path = db_path or _get_db_path()
    conn = sqlite3.connect(path)
    cursor = conn.cursor()

    cursor.execute('''CREATE TABLE IF NOT EXISTS cpe_dictionary (
        id INTEGER PRIMARY KEY,
        cpe23uri TEXT UNIQUE,
        vendor TEXT,
        product TEXT,
        version TEXT,
        title TEXT
    )''')

    cursor.execute('''CREATE INDEX IF NOT EXISTS idx_cpe_dict_product
                      ON cpe_dictionary(product)''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS idx_cpe_dict_vendor
                      ON cpe_dictionary(vendor)''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS idx_cpe_dict_vp
                      ON cpe_dictionary(vendor, product)''')

    conn.commit()
    conn.close()


def sync_cpe_dictionary(socketio=None, db_path=None):
    """Download and import the NVD CPE dictionary.

    Parses the XML and extracts unique vendor:product:version combos.
    """
    path = db_path or _get_db_path()
    init_cpe_tables(path)

    def emit(msg):
        if socketio:
            socketio.emit('nvd_sync_progress', {'status': 'running', 'message': msg})
        logger.info(f"CPE sync: {msg}")

    emit("Downloading CPE dictionary...")

    try:
        req = urllib.request.Request(CPE_DICT_URL,
                                     headers={'User-Agent': 'Artemis-Scanner/1.0'})
        with urllib.request.urlopen(req, timeout=120) as resp:
            compressed = resp.read()
    except Exception as e:
        emit(f"CPE dictionary download failed: {e}")
        return False

    emit("Decompressing CPE dictionary...")
    try:
        raw = gzip.decompress(compressed)
        del compressed
    except Exception as e:
        emit(f"CPE dictionary decompression failed: {e}")
        return False

    emit("Parsing CPE dictionary (this may take a moment)...")
    xml_text = raw.decode('utf-8', errors='replace')
    del raw

    # Parse CPE entries using regex (faster than XML parser for this)
    # Pattern: <cpe-23:cpe23-item name="cpe:2.3:..."/>
    # And <title xml:lang="en">...</title>
    cpe_pattern = re.compile(r'<cpe-23:cpe23-item\s+name="([^"]+)"')
    title_pattern = re.compile(r'<title\s+xml:lang="en">([^<]+)</title>')

    conn = sqlite3.connect(path)
    cursor = conn.cursor()

    # Use WAL for performance
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")

    batch = []
    count = 0
    seen_products = set()

    # Process line by line to find cpe23-item entries
    lines = xml_text.split('\n')
    current_cpe = None
    current_title = None

    for line in lines:
        cpe_match = cpe_pattern.search(line)
        if cpe_match:
            # Save previous entry
            if current_cpe:
                _add_cpe_to_batch(batch, current_cpe, current_title, seen_products)
            current_cpe = cpe_match.group(1)
            current_title = None

        title_match = title_pattern.search(line)
        if title_match and current_cpe and current_title is None:
            current_title = title_match.group(1)

        if len(batch) >= 5000:
            _flush_cpe_batch(cursor, batch)
            count += len(batch)
            batch.clear()
            if count % 50000 == 0:
                emit(f"Imported {count:,} CPE entries...")
                conn.commit()

    # Final entry
    if current_cpe:
        _add_cpe_to_batch(batch, current_cpe, current_title, seen_products)

    if batch:
        _flush_cpe_batch(cursor, batch)
        count += len(batch)

    conn.commit()

    # Store sync timestamp
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('cpe_dict_last_sync', ?)",
                   (now_str,))
    conn.commit()
    conn.close()

    emit(f"CPE dictionary sync complete: {count:,} entries imported")
    return True


def _add_cpe_to_batch(batch, cpe_uri, title, seen_products):
    """Parse a CPE URI and add to batch."""
    parts = cpe_uri.split(':')
    if len(parts) < 6:
        return

    vendor = parts[3]
    product = parts[4]
    version = parts[5] if len(parts) > 5 else '*'

    # Only store application CPEs (type 'a'), skip OS and hardware
    if len(parts) > 2 and parts[2] not in ('a', '*'):
        return

    # Deduplicate by vendor:product:version
    key = f"{vendor}:{product}:{version}"
    if key in seen_products:
        return
    seen_products.add(key)

    batch.append((cpe_uri, vendor, product, version, title or ''))


def _flush_cpe_batch(cursor, batch):
    """Batch insert CPE entries."""
    cursor.executemany('''INSERT OR IGNORE INTO cpe_dictionary
        (cpe23uri, vendor, product, version, title)
        VALUES (?, ?, ?, ?, ?)''', batch)


def search_cpe(software_name, version=None, db_path=None):
    """Search for the best matching CPE for a software name + version.

    Uses exact match first, then fuzzy matching.

    Args:
        software_name: Software/package name (e.g., "OpenSSH", "nginx")
        version: Version string (optional)

    Returns:
        Best matching CPE string, or a generated one if no match found.
    """
    path = db_path or _get_db_path()
    conn = sqlite3.connect(path)
    cursor = conn.cursor()

    try:
        # Check if CPE dictionary exists
        cursor.execute("SELECT COUNT(*) FROM cpe_dictionary")
        if cursor.fetchone()[0] == 0:
            conn.close()
            return None  # No dictionary loaded

        # Normalize the software name
        name_lower = software_name.lower().strip()
        name_normalized = re.sub(r'[^a-z0-9]', '_', name_lower).strip('_')

        # Step 1: Exact product match
        cursor.execute('''SELECT DISTINCT vendor, product, version, cpe23uri
                          FROM cpe_dictionary
                          WHERE product = ?
                          ORDER BY version DESC LIMIT 20''', (name_normalized,))
        exact_matches = cursor.fetchall()

        if exact_matches:
            return _best_version_match(exact_matches, version)

        # Step 2: Try common name variations
        variations = [
            name_normalized,
            name_normalized.replace('-', '_'),
            name_normalized.replace('_', '-'),
            name_normalized.replace('-server', ''),
            name_normalized.replace('-client', ''),
        ]

        for var in variations:
            cursor.execute('''SELECT DISTINCT vendor, product, version, cpe23uri
                              FROM cpe_dictionary
                              WHERE product = ?
                              ORDER BY version DESC LIMIT 20''', (var,))
            matches = cursor.fetchall()
            if matches:
                return _best_version_match(matches, version)

        # Step 3: LIKE search for partial matches
        cursor.execute('''SELECT DISTINCT vendor, product, version, cpe23uri
                          FROM cpe_dictionary
                          WHERE product LIKE ?
                          ORDER BY version DESC LIMIT 50''', (f'%{name_normalized}%',))
        like_matches = cursor.fetchall()

        if like_matches:
            # Use fuzzy matching to find best product name match
            best_score = 0
            best_match = None
            for row in like_matches:
                score = difflib.SequenceMatcher(None, name_normalized, row[1]).ratio()
                if score > best_score:
                    best_score = score
                    best_match = row

            if best_match and best_score > 0.6:
                # Re-fetch all versions for this vendor:product
                cursor.execute('''SELECT vendor, product, version, cpe23uri
                                  FROM cpe_dictionary
                                  WHERE vendor = ? AND product = ?
                                  ORDER BY version DESC LIMIT 20''',
                               (best_match[0], best_match[1]))
                return _best_version_match(cursor.fetchall() or [best_match], version)

        return None

    except Exception as e:
        logger.debug(f"CPE search error for {software_name}: {e}")
        return None
    finally:
        conn.close()


def _best_version_match(matches, target_version):
    """Find the best version match from a list of CPE matches.

    Args:
        matches: List of (vendor, product, version, cpe23uri) tuples
        target_version: Target version string to match

    Returns:
        CPE URI string with the best version match
    """
    if not matches:
        return None

    if not target_version:
        # No version specified — return the CPE with wildcard version
        vendor, product = matches[0][0], matches[0][1]
        return f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*"

    # Clean target version
    clean_version = target_version.split('-')[0].split('+')[0]
    clean_version = clean_version.split(':')[-1]  # strip epoch

    # Try exact version match
    for row in matches:
        if row[2] == clean_version:
            return row[3]

    # Try prefix match (e.g., "8.2" matches "8.2p1")
    for row in matches:
        if row[2] and clean_version.startswith(row[2]):
            return row[3]
        if row[2] and row[2].startswith(clean_version):
            return row[3]

    # No exact match — construct CPE with the correct vendor:product and our version
    vendor, product = matches[0][0], matches[0][1]
    return f"cpe:2.3:a:{vendor}:{product}:{clean_version}:*:*:*:*:*:*:*"


def get_cpe_dict_status(db_path=None):
    """Get CPE dictionary sync status."""
    path = db_path or _get_db_path()
    try:
        conn = sqlite3.connect(path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM cpe_dictionary")
        total = cursor.fetchone()[0]
        cursor.execute("SELECT value FROM settings WHERE key = 'cpe_dict_last_sync'")
        row = cursor.fetchone()
        last_sync = row[0] if row else None
        conn.close()
        return {'total_cpes': total, 'last_sync': last_sync}
    except Exception:
        return {'total_cpes': 0, 'last_sync': None}
