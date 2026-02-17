"""Vulscan NSE script integration for Cerebus.

Integrates nmap's vulscan script for CVE detection during port scans.
"""

import os
import re
import logging
import json
import sqlite3
from datetime import datetime

logger = logging.getLogger(__name__)

# Path to vulscan directory (cloned alongside scanner)
VULSCAN_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vulscan')
VULSCAN_NSE = os.path.join(VULSCAN_PATH, 'vulscan.nse')


def is_vulscan_available():
    """Check if vulscan NSE script is available."""
    return os.path.isfile(VULSCAN_NSE)


def get_vulscan_nmap_args():
    """Get nmap arguments to enable vulscan.

    Returns:
        String of nmap arguments, or empty string if vulscan not available.
    """
    if not is_vulscan_available():
        return ''

    return (
        f'--script={VULSCAN_NSE} '
        f'--script-args "vulscandb=cve.csv,'
        f'vulscanoutput={{{{id}}}} ||| {{{{title}}}} ||| {{{{product}}}} ||| {{{{version}}}}\\n"'
    )


def parse_vulscan_output(nmap_result):
    """Parse vulscan script output from nmap results.

    Args:
        nmap_result: nmap scan result dict for a host

    Returns:
        List of dicts: [{cve_id, title, product, version, port, protocol}]
    """
    results = []

    try:
        for protocol in nmap_result.all_protocols():
            for port in nmap_result[protocol]:
                port_data = nmap_result[protocol][port]
                script_output = port_data.get('script', {})

                # vulscan output is in the 'vulscan' script key
                vulscan_text = script_output.get('vulscan', '')
                if not vulscan_text:
                    continue

                for line in vulscan_text.split('\n'):
                    line = line.strip()
                    if '|||' not in line:
                        continue

                    parts = [p.strip() for p in line.split('|||')]
                    if len(parts) < 2:
                        continue

                    cve_id = parts[0].strip()
                    title = parts[1] if len(parts) > 1 else ''
                    product = parts[2] if len(parts) > 2 else ''
                    version = parts[3] if len(parts) > 3 else ''

                    # Only keep CVE-prefixed entries
                    if not cve_id.upper().startswith('CVE-'):
                        continue

                    results.append({
                        'cve_id': cve_id.upper(),
                        'title': title[:500],
                        'product': product,
                        'version': version,
                        'port': port,
                        'protocol': protocol,
                        'source': 'nmap-vulscan',
                    })

    except Exception as e:
        logger.warning(f"Error parsing vulscan output: {e}")

    return results


def store_vulscan_results(ip, vulscan_results, db_path=None):
    """Store vulscan CVE matches in the cve_matches table.

    Args:
        ip: Target IP address
        vulscan_results: List of parsed vulscan result dicts
    """
    if not vulscan_results:
        return

    from vuln_scan import DB_PATH
    path = db_path or DB_PATH

    conn = sqlite3.connect(path)
    cursor = conn.cursor()
    scan_date = datetime.now().isoformat()

    try:
        stored = 0
        for r in vulscan_results:
            # Build a CPE-like identifier for the affected product
            affected_cpe = f"nmap-vulscan:{r.get('product', '')}:{r.get('version', '')}"

            cursor.execute('''INSERT OR IGNORE INTO cve_matches
                (ip, cve_id, severity, cvss_score, description, affected_cpe, scan_date)
                VALUES (?, ?, ?, ?, ?, ?, ?)''',
                (ip, r['cve_id'], 'unknown', None,
                 r.get('title', ''), affected_cpe, scan_date))
            if cursor.rowcount > 0:
                stored += 1

        conn.commit()
        logger.info(f"Stored {stored} vulscan CVE matches for {ip}")
    except Exception as e:
        logger.error(f"Error storing vulscan results for {ip}: {e}")
    finally:
        conn.close()
