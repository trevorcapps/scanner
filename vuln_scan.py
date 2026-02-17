import os
import nmap
import sqlite3
import socket
import subprocess
import ipaddress
import logging
import json
import time
import urllib.request
import urllib.error
import tempfile
import shutil
from datetime import datetime

from fingerprint.engine import FingerprintEngine, FingerprintResult
from fingerprint.fpx import scan_host as fpx_scan_host, check_installed as fpx_check_installed

# Database path - use absolute path relative to this script's location
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vuln_scan.db')

# Singleton fingerprint engine (loaded once, reused)
_fingerprint_engine = None

def get_fingerprint_engine():
    """Get or create the singleton FingerprintEngine."""
    global _fingerprint_engine
    if _fingerprint_engine is None:
        _fingerprint_engine = FingerprintEngine()
    return _fingerprint_engine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# NVD API configuration
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_DELAY = 0.6  # Rate limit: ~100 requests per 60 seconds without API key


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
            logger.warning(f"No NVD data found for {cve_id}")
            return None

        cve_data = data['vulnerabilities'][0]['cve']

        # Extract CVSS score (prefer v3.1, fallback to v3.0, then v2.0)
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

        # Extract description (prefer English)
        description = ''
        for desc in cve_data.get('descriptions', []):
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break

        # Extract CWE ID
        cwe_id = None
        for weakness in cve_data.get('weaknesses', []):
            for desc in weakness.get('description', []):
                if desc.get('value', '').startswith('CWE-'):
                    cwe_id = desc.get('value')
                    break
            if cwe_id:
                break

        # Extract references
        references = []
        for ref in cve_data.get('references', [])[:5]:  # Limit to 5 references
            references.append({
                'url': ref.get('url', ''),
                'source': ref.get('source', '')
            })

        # Get published date
        published_date = cve_data.get('published', '')

        result = {
            'cvss_score': cvss_score,
            'cvss_vector': cvss_vector,
            'description': description,
            'cwe_id': cwe_id,
            'references': references,
            'published_date': published_date
        }

        logger.info(f"Successfully fetched NVD data for {cve_id}: CVSS {cvss_score}")
        time.sleep(NVD_API_DELAY)  # Rate limiting
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


# Function to validate IP address or CIDR
def validate_ip(ip):
    """Validate that the input is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_cidr(cidr):
    """Validate that the input is a valid CIDR notation."""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def validate_target(target):
    """Validate that the input is a valid IP address or CIDR notation."""
    return validate_ip(target) or validate_cidr(target)


def expand_cidr(cidr, max_hosts=256):
    """Expand a CIDR notation to a list of IP addresses.

    Args:
        cidr: CIDR notation string (e.g., '10.1.0.0/24')
        max_hosts: Maximum number of hosts to return (default 256, i.e., /24)

    Returns:
        List of IP address strings
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        hosts = list(network.hosts())

        if len(hosts) > max_hosts:
            logger.warning(f"CIDR {cidr} has {len(hosts)} hosts, limiting to {max_hosts}")
            hosts = hosts[:max_hosts]

        return [str(ip) for ip in hosts]
    except ValueError as e:
        logger.error(f"Invalid CIDR notation {cidr}: {e}")
        return []


def is_cidr(target):
    """Check if target is CIDR notation (contains /)."""
    return '/' in target and validate_cidr(target)


# ============== DNS Lookup Functions ==============

def dns_lookup(ip):
    """Perform DNS lookups for an IP address.

    Returns a dict with hostname, reverse DNS, and any additional DNS info.
    """
    result = {
        'hostname': None,
        'reverse_dns': None,
        'aliases': [],
        'dns_names': []
    }

    try:
        # Reverse DNS lookup
        hostname, aliases, _ = socket.gethostbyaddr(ip)
        result['hostname'] = hostname
        result['reverse_dns'] = hostname
        result['aliases'] = list(aliases) if aliases else []
        logger.info(f"DNS lookup for {ip}: hostname={hostname}")
    except socket.herror as e:
        logger.debug(f"No reverse DNS for {ip}: {e}")
    except socket.gaierror as e:
        logger.debug(f"DNS lookup failed for {ip}: {e}")
    except Exception as e:
        logger.warning(f"Unexpected error in DNS lookup for {ip}: {e}")

    return result


def get_os_info_from_scan(scan_result):
    """Extract OS information from nmap scan result."""
    os_info = {
        'os_name': None,
        'os_family': None,
        'os_accuracy': None,
        'os_vendor': None,
        'device_type': None
    }

    try:
        # Try to get OS match info
        if hasattr(scan_result, 'get') and 'osmatch' in scan_result:
            os_matches = scan_result.get('osmatch', [])
            if os_matches and len(os_matches) > 0:
                best_match = os_matches[0]
                os_info['os_name'] = best_match.get('name', None)
                os_info['os_accuracy'] = best_match.get('accuracy', None)

                # Get OS class info
                os_classes = best_match.get('osclass', [])
                if os_classes and len(os_classes) > 0:
                    os_class = os_classes[0]
                    os_info['os_family'] = os_class.get('osfamily', None)
                    os_info['os_vendor'] = os_class.get('vendor', None)
                    os_info['device_type'] = os_class.get('type', None)

        # Try hostscript results
        if hasattr(scan_result, 'get') and 'hostscript' in scan_result:
            for script in scan_result.get('hostscript', []):
                if script.get('id') == 'smb-os-discovery':
                    output = script.get('output', '')
                    if 'OS:' in output:
                        # Extract OS from smb-os-discovery output
                        for line in output.split('\n'):
                            if line.strip().startswith('OS:'):
                                os_info['os_name'] = line.split('OS:')[1].strip()
                                break
    except Exception as e:
        logger.debug(f"Error extracting OS info: {e}")

    return os_info


class ScanError(Exception):
    """Custom exception for scan-related errors."""
    pass


# Function to scan a given IP address
def scan(ip, options=None):
    """Execute Nmap scan on the given IP address.

    Args:
        ip: Target IP address
        options: Dict with optional scan settings:
            - ports: Port range string (e.g., '1-1000', '22,80,443', '-' for all)
            - scan_speed: Timing template (T2, T3, T4, T5)
            - host_timeout: Timeout in seconds per host
    """
    if not validate_ip(ip):
        raise ScanError(f"Invalid IP address: {ip}")

    # Create a new PortScanner instance per scan (thread-safe)
    nm = nmap.PortScanner()

    # Build nmap arguments from options
    args = ['-sV']

    if options:
        # Add timing template
        scan_speed = options.get('scan_speed', 'T3')
        if scan_speed in ['T2', 'T3', 'T4', 'T5']:
            args.append(f'-{scan_speed}')

        # Add host timeout
        host_timeout = options.get('host_timeout', 300)
        try:
            host_timeout = max(30, min(3600, int(host_timeout)))
        except (ValueError, TypeError):
            host_timeout = 300
        args.append(f'--host-timeout {host_timeout}')
    else:
        args.append('--host-timeout 300')

    arguments = ' '.join(args)

    # Handle port specification separately (passed to scan method)
    port_spec = None
    if options and options.get('ports'):
        port_spec = options['ports'].strip()
        if port_spec == '-':
            port_spec = '1-65535'  # All ports

    try:
        logger.info(f"Starting scan for IP: {ip} with args: {arguments}, ports: {port_spec or 'default'}")
        if port_spec:
            nm.scan(ip, ports=port_spec, arguments=arguments)
        else:
            nm.scan(ip, arguments=arguments)

        if ip not in nm.all_hosts():
            raise ScanError(f"Host {ip} is unreachable or returned no results")

        logger.info(f"Scan completed for IP: {ip}")
        return nm[ip]
    except nmap.PortScannerError as e:
        logger.error(f"Nmap error scanning {ip}: {e}")
        raise ScanError(f"Nmap error: {e}")
    except Exception as e:
        logger.error(f"Unexpected error scanning {ip}: {e}")
        raise ScanError(f"Scan failed: {e}")

# Function to parse scan results
def parse_scan(scan_result):
    """Parse Nmap scan results into structured tuples."""
    parsed_results = []
    try:
        for protocol in scan_result.all_protocols():
            ports = scan_result[protocol].keys()
            for port in ports:
                service = scan_result[protocol][port]
                parsed_results.append((
                    protocol,
                    port,
                    service.get('state', 'unknown'),
                    service.get('name', 'unknown'),
                    service.get('product', ''),
                    service.get('version', '')
                ))
    except Exception as e:
        logger.error(f"Error parsing scan results: {e}")
    return parsed_results

# Function to initialize the database
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS scans (
                        id INTEGER PRIMARY KEY,
                        ip TEXT,
                        protocol TEXT,
                        port INTEGER,
                        state TEXT,
                        service TEXT,
                        product TEXT,
                        version TEXT,
                        scan_date TEXT)''')

    # Vulnerabilities table with unique constraint to prevent duplicates
    cursor.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities (
                        id INTEGER PRIMARY KEY,
                        ip TEXT,
                        port INTEGER,
                        protocol TEXT,
                        vuln_id TEXT,
                        vuln_name TEXT,
                        severity TEXT,
                        description TEXT,
                        cvss_score REAL,
                        cvss_vector TEXT,
                        cwe_id TEXT,
                        references_json TEXT,
                        published_date TEXT,
                        scan_date TEXT,
                        UNIQUE(ip, port, protocol, vuln_id))''')

    # Assets table for storing detailed host information
    cursor.execute('''CREATE TABLE IF NOT EXISTS assets (
                        id INTEGER PRIMARY KEY,
                        ip TEXT UNIQUE,
                        hostname TEXT,
                        reverse_dns TEXT,
                        aliases_json TEXT,
                        os_name TEXT,
                        os_family TEXT,
                        os_vendor TEXT,
                        os_accuracy TEXT,
                        device_type TEXT,
                        mac_address TEXT,
                        mac_vendor TEXT,
                        first_seen TEXT,
                        last_seen TEXT,
                        scan_count INTEGER DEFAULT 1)''')

    # Fingerprints table for storing endpoint identification data
    cursor.execute('''CREATE TABLE IF NOT EXISTS fingerprints (
                        id INTEGER PRIMARY KEY,
                        ip TEXT,
                        port INTEGER,
                        protocol TEXT,
                        signature_id TEXT,
                        name TEXT,
                        category TEXT,
                        vendor TEXT,
                        version TEXT,
                        cpe TEXT,
                        confidence INTEGER,
                        evidence_json TEXT,
                        tls_subject_cn TEXT,
                        tls_subject_org TEXT,
                        tls_issuer_org TEXT,
                        tls_self_signed INTEGER,
                        http_title TEXT,
                        http_server TEXT,
                        favicon_hash INTEGER,
                        scan_date TEXT,
                        UNIQUE(ip, port, protocol, signature_id))''')

    # Authenticated scan: OS details per asset
    cursor.execute('''CREATE TABLE IF NOT EXISTS asset_os_details (
                        id INTEGER PRIMARY KEY,
                        ip TEXT UNIQUE,
                        distro TEXT,
                        version TEXT,
                        kernel TEXT,
                        arch TEXT,
                        os_family TEXT,
                        os_id TEXT,
                        pretty_name TEXT,
                        scan_date TEXT)''')

    # Authenticated scan: installed software inventory
    cursor.execute('''CREATE TABLE IF NOT EXISTS installed_software (
                        id INTEGER PRIMARY KEY,
                        ip TEXT,
                        package_name TEXT,
                        package_version TEXT,
                        cpe TEXT,
                        scan_date TEXT,
                        UNIQUE(ip, package_name))''')

    # Authenticated scan: CVE matches from NVD
    cursor.execute('''CREATE TABLE IF NOT EXISTS cve_matches (
                        id INTEGER PRIMARY KEY,
                        ip TEXT,
                        cve_id TEXT,
                        severity TEXT,
                        cvss_score REAL,
                        description TEXT,
                        affected_cpe TEXT,
                        scan_date TEXT,
                        UNIQUE(ip, cve_id))''')

    # Credentials table for stored credential sets
    cursor.execute('''CREATE TABLE IF NOT EXISTS credentials (
                        id INTEGER PRIMARY KEY,
                        name TEXT UNIQUE NOT NULL,
                        cred_type TEXT NOT NULL,
                        username TEXT NOT NULL,
                        key_path TEXT,
                        password TEXT,
                        created_at TEXT,
                        updated_at TEXT)''')

    # Settings table for persistent key-value config
    cursor.execute('''CREATE TABLE IF NOT EXISTS settings (
                        key TEXT PRIMARY KEY,
                        value TEXT)''')

    # Create indexes for better query performance
    cursor.execute('''CREATE INDEX IF NOT EXISTS idx_scans_ip ON scans(ip)''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS idx_vulns_ip ON vulnerabilities(ip)''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS idx_vulns_unique ON vulnerabilities(ip, port, protocol, vuln_id)''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip)''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS idx_fingerprints_ip ON fingerprints(ip)''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS idx_fingerprints_port ON fingerprints(ip, port)''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS idx_installed_software_ip ON installed_software(ip)''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS idx_cve_matches_ip ON cve_matches(ip)''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS idx_asset_os_ip ON asset_os_details(ip)''')

    conn.commit()
    conn.close()

# Function to store scan results in the database
def store_scan(ip, scan_results):
    """Store port scan results in the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        stored_count = 0
        # Use same timestamp for all ports in this scan
        scan_date = datetime.now().isoformat()
        for result in scan_results:
            cursor.execute('''INSERT INTO scans (ip, protocol, port, state, service, product, version, scan_date)
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                              (ip, result[0], result[1], result[2], result[3], result[4], result[5], scan_date))
            stored_count += 1
        conn.commit()
        logger.info(f"Stored {stored_count} port scan results for {ip}")
    except sqlite3.Error as e:
        logger.error(f"Database error storing scan results for {ip}: {e}")
    finally:
        conn.close()


def store_asset_info(ip, dns_info=None, os_info=None, mac_address=None, mac_vendor=None):
    """Store or update asset information in the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    now = datetime.now().isoformat()

    try:
        # Check if asset exists
        cursor.execute('SELECT id, scan_count, first_seen FROM assets WHERE ip = ?', (ip,))
        existing = cursor.fetchone()

        hostname = dns_info.get('hostname') if dns_info else None
        reverse_dns = dns_info.get('reverse_dns') if dns_info else None
        aliases_json = json.dumps(dns_info.get('aliases', [])) if dns_info else None

        os_name = os_info.get('os_name') if os_info else None
        os_family = os_info.get('os_family') if os_info else None
        os_vendor = os_info.get('os_vendor') if os_info else None
        os_accuracy = os_info.get('os_accuracy') if os_info else None
        device_type = os_info.get('device_type') if os_info else None

        if existing:
            # Update existing asset
            asset_id, scan_count, first_seen = existing
            cursor.execute('''UPDATE assets SET
                hostname = COALESCE(?, hostname),
                reverse_dns = COALESCE(?, reverse_dns),
                aliases_json = COALESCE(?, aliases_json),
                os_name = COALESCE(?, os_name),
                os_family = COALESCE(?, os_family),
                os_vendor = COALESCE(?, os_vendor),
                os_accuracy = COALESCE(?, os_accuracy),
                device_type = COALESCE(?, device_type),
                mac_address = COALESCE(?, mac_address),
                mac_vendor = COALESCE(?, mac_vendor),
                last_seen = ?,
                scan_count = scan_count + 1
                WHERE ip = ?''',
                (hostname, reverse_dns, aliases_json, os_name, os_family,
                 os_vendor, os_accuracy, device_type, mac_address, mac_vendor, now, ip))
            logger.info(f"Updated asset info for {ip}")
        else:
            # Insert new asset
            cursor.execute('''INSERT INTO assets
                (ip, hostname, reverse_dns, aliases_json, os_name, os_family,
                 os_vendor, os_accuracy, device_type, mac_address, mac_vendor,
                 first_seen, last_seen, scan_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)''',
                (ip, hostname, reverse_dns, aliases_json, os_name, os_family,
                 os_vendor, os_accuracy, device_type, mac_address, mac_vendor, now, now))
            logger.info(f"Created new asset record for {ip}")

        conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Database error storing asset info for {ip}: {e}")
    finally:
        conn.close()


def get_asset_details(ip):
    """Retrieve full asset details including ports, vulnerabilities, and metadata."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        # Get asset info
        cursor.execute('''SELECT ip, hostname, reverse_dns, aliases_json,
                          os_name, os_family, os_vendor, os_accuracy, device_type,
                          mac_address, mac_vendor, first_seen, last_seen, scan_count
                          FROM assets WHERE ip = ?''', (ip,))
        asset_row = cursor.fetchone()

        asset = {
            'ip': ip,
            'hostname': None,
            'reverse_dns': None,
            'aliases': [],
            'os_name': None,
            'os_family': None,
            'os_vendor': None,
            'os_accuracy': None,
            'device_type': None,
            'mac_address': None,
            'mac_vendor': None,
            'first_seen': None,
            'last_seen': None,
            'scan_count': 0,
            'ports': [],
            'vulnerabilities': []
        }

        if asset_row:
            asset['hostname'] = asset_row[1]
            asset['reverse_dns'] = asset_row[2]
            try:
                asset['aliases'] = json.loads(asset_row[3]) if asset_row[3] else []
            except json.JSONDecodeError:
                asset['aliases'] = []
            asset['os_name'] = asset_row[4]
            asset['os_family'] = asset_row[5]
            asset['os_vendor'] = asset_row[6]
            asset['os_accuracy'] = asset_row[7]
            asset['device_type'] = asset_row[8]
            asset['mac_address'] = asset_row[9]
            asset['mac_vendor'] = asset_row[10]
            asset['first_seen'] = asset_row[11]
            asset['last_seen'] = asset_row[12]
            asset['scan_count'] = asset_row[13]

        # Get latest ports
        cursor.execute('''SELECT MAX(scan_date) FROM scans WHERE ip = ?''', (ip,))
        latest = cursor.fetchone()
        if latest and latest[0]:
            cursor.execute('''SELECT protocol, port, state, service, product, version
                              FROM scans WHERE ip = ? AND scan_date = ?''', (ip, latest[0]))
            for row in cursor.fetchall():
                asset['ports'].append({
                    'protocol': row[0],
                    'port': row[1],
                    'state': row[2],
                    'service': row[3],
                    'product': row[4],
                    'version': row[5]
                })

        # Get vulnerability counts
        vuln_counts = get_vulnerability_counts_by_severity(ip)
        asset['vuln_counts'] = vuln_counts

        # Get vulnerabilities
        asset['vulnerabilities'] = get_vulnerabilities(ip)

        # Get fingerprint data
        fp_summary = get_fingerprint_summary(ip)
        asset['fingerprints'] = fp_summary.get('technologies', [])
        asset['fingerprints_by_port'] = fp_summary.get('by_port', {})

        # Get authenticated scan data
        asset['auth_os'] = get_asset_os_details(ip)
        asset['installed_software'] = get_installed_software(ip)
        asset['cve_matches'] = get_cve_matches(ip)

        return asset
    except sqlite3.Error as e:
        logger.error(f"Database error getting asset details for {ip}: {e}")
        return None
    finally:
        conn.close()


# Function to get the latest scan for an IP
def get_latest_scan(ip):
    """Retrieve all ports from the most recent scan for an IP."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        # First, get the latest scan_date for this IP
        cursor.execute('''SELECT MAX(scan_date) FROM scans WHERE ip = ?''', (ip,))
        result = cursor.fetchone()
        latest_date = result[0] if result else None

        if not latest_date:
            return []

        # Then get all ports from that scan
        cursor.execute('''SELECT protocol, port, state, service, product, version
                          FROM scans WHERE ip = ? AND scan_date = ?''', (ip, latest_date))
        latest_scan = cursor.fetchall()
        logger.info(f"Retrieved {len(latest_scan)} ports from latest scan for {ip}")
        return latest_scan
    except sqlite3.Error as e:
        logger.error(f"Database error in get_latest_scan: {e}")
        return []
    finally:
        conn.close()

def get_previous_scan(ip, before_date):
    """Retrieve all ports from the scan before the given date for an IP."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        # Get the scan date before the given date
        cursor.execute('''SELECT MAX(scan_date) FROM scans
                          WHERE ip = ? AND scan_date < ?''', (ip, before_date))
        result = cursor.fetchone()
        previous_date = result[0] if result else None

        if not previous_date:
            return [], None

        # Get all ports from that scan
        cursor.execute('''SELECT protocol, port, state, service, product, version
                          FROM scans WHERE ip = ? AND scan_date = ?''', (ip, previous_date))
        previous_scan = cursor.fetchall()
        logger.info(f"Retrieved {len(previous_scan)} ports from previous scan for {ip}")
        return previous_scan, previous_date
    except sqlite3.Error as e:
        logger.error(f"Database error in get_previous_scan: {e}")
        return [], None
    finally:
        conn.close()


# Function to compare scans and track changes
def compare_scans(old_scan, new_scan):
    """Compare two scans and identify added, removed, and changed ports."""
    # Create dictionaries keyed by (protocol, port)
    old_ports = {(r[0], r[1]): r for r in old_scan}
    new_ports = {(r[0], r[1]): r for r in new_scan}

    changes = {
        'added': [new_ports[k] for k in new_ports if k not in old_ports],
        'removed': [old_ports[k] for k in old_ports if k not in new_ports],
        'changed': [
            {'old': old_ports[k], 'new': new_ports[k]}
            for k in old_ports
            if k in new_ports and old_ports[k] != new_ports[k]
        ]
    }

    total_changes = len(changes['added']) + len(changes['removed']) + len(changes['changed'])
    logger.info(f"Comparison found {total_changes} changes: "
                f"{len(changes['added'])} added, {len(changes['removed'])} removed, "
                f"{len(changes['changed'])} changed")
    return changes

def generate_report_from_existing(ip):
    """Generate a report from existing scan data without performing a new scan."""
    if not validate_ip(ip):
        raise ScanError(f"Invalid IP address: {ip}")

    # Get the latest scan data from the database
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        # First, get the latest scan_date for this IP
        cursor.execute('''SELECT MAX(scan_date) FROM scans WHERE ip = ?''', (ip,))
        result = cursor.fetchone()
        latest_date = result[0] if result else None

        if not latest_date:
            raise ScanError(f"No scan data found for {ip}")

        # Get all ports from the latest scan
        cursor.execute('''SELECT protocol, port, state, service, product, version
                          FROM scans WHERE ip = ? AND scan_date = ?''', (ip, latest_date))
        latest_scan = cursor.fetchall()

        if not latest_scan:
            logger.warning(f"No ports found in latest scan for {ip}")
            return [], {'added': [], 'removed': [], 'changed': [], 'latest_date': latest_date, 'previous_date': None}, []

        # Get the previous scan for comparison
        previous_scan, previous_date = get_previous_scan(ip, latest_date)

        # Get vulnerabilities for this IP
        vulnerabilities = get_vulnerabilities(ip)

        # Handle first scan case
        if not previous_scan:
            logger.info(f"Only one scan exists for {ip}, no previous data to compare")
            changes = {
                'added': latest_scan,
                'removed': [],
                'changed': [],
                'latest_date': latest_date,
                'previous_date': None
            }
            return latest_scan, changes, vulnerabilities

        # Compare with previous scan
        changes = compare_scans(previous_scan, latest_scan)
        changes['latest_date'] = latest_date
        changes['previous_date'] = previous_date

        return latest_scan, changes, vulnerabilities
    except sqlite3.Error as e:
        logger.error(f"Database error in generate_report_from_existing: {e}")
        raise ScanError(f"Database error: {e}")
    finally:
        conn.close()


# Function to generate a report of vulnerabilities
def generate_report(ip):
    """Generate a vulnerability report for the given IP."""
    if not validate_ip(ip):
        raise ScanError(f"Invalid IP address: {ip}")

    latest_scan = get_latest_scan(ip)

    # Perform the current scan
    current_scan_result = scan(ip)
    parsed_current_scan = parse_scan(current_scan_result)

    if not parsed_current_scan:
        logger.warning(f"No ports found in scan for {ip}")
        return parsed_current_scan, {'added': [], 'removed': [], 'changed': []}

    # Store the new scan results
    store_scan(ip, parsed_current_scan)

    # Handle first scan case
    if not latest_scan:
        logger.info(f"First scan for {ip}, no previous data to compare")
        return parsed_current_scan, {'added': parsed_current_scan, 'removed': [], 'changed': []}

    # Compare with previous scan
    changes = compare_scans(latest_scan, parsed_current_scan)

    return parsed_current_scan, changes


# ============== Vulnerability Scanning Functions ==============

def check_nuclei_installed():
    """Check if nuclei is installed and available."""
    try:
        result = subprocess.run(['nuclei', '-version'],
                               capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            logger.info(f"Nuclei version: {result.stdout.strip() or result.stderr.strip()}")
            return True
    except FileNotFoundError:
        logger.error("Nuclei is not installed. Install it from: https://github.com/projectdiscovery/nuclei")
    except subprocess.TimeoutExpired:
        logger.error("Nuclei version check timed out")
    except Exception as e:
        logger.error(f"Error checking nuclei: {e}")
    return False


def vuln_scan(ip, options=None, log_callback=None):
    """Execute Nuclei vulnerability scan on the given IP address.

    Args:
        ip: Target IP address
        options: Dict with optional scan settings:
            - vuln_timeout: Timeout in seconds per host (default 600)
            - severity: Comma-separated severity levels (default 'critical,high,medium')
            - templates: Specific template paths or tags (optional)
            - rate_limit: Requests per second (default 150)
        log_callback: Optional callback function to receive log messages
    """
    if not validate_ip(ip):
        raise ScanError(f"Invalid IP address: {ip}")

    if not check_nuclei_installed():
        raise ScanError("Nuclei is not installed. Please install it from https://github.com/projectdiscovery/nuclei")

    # Create a temporary file for JSON output
    output_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    output_file.close()

    try:
        # Build nuclei command
        cmd = [
            'nuclei',
            '-target', ip,
            '-jsonl',  # JSON Lines output
            '-output', output_file.name,
            '-verbose',  # Verbose output for better logging
            '-no-color',  # No ANSI colors
            '-stats',  # Show statistics
        ]

        # Parse options
        if options:
            # Timeout
            vuln_timeout = options.get('vuln_timeout', 600)
            try:
                vuln_timeout = max(60, min(3600, int(vuln_timeout)))
            except (ValueError, TypeError):
                vuln_timeout = 600
            cmd.extend(['-timeout', str(vuln_timeout)])

            # Severity filter
            severity = options.get('severity', 'critical,high,medium,low')
            if severity:
                cmd.extend(['-severity', severity])

            # Rate limit
            rate_limit = options.get('rate_limit', 150)
            try:
                rate_limit = max(10, min(1000, int(rate_limit)))
            except (ValueError, TypeError):
                rate_limit = 150
            cmd.extend(['-rate-limit', str(rate_limit)])

            # Specific templates or tags
            templates = options.get('templates')
            if templates:
                cmd.extend(['-tags', templates])
        else:
            cmd.extend(['-timeout', '600'])
            cmd.extend(['-severity', 'critical,high,medium,low'])
            cmd.extend(['-rate-limit', '150'])

        logger.info(f"Starting Nuclei vulnerability scan for IP: {ip}")
        logger.debug(f"Nuclei command: {' '.join(cmd)}")

        if log_callback:
            log_callback(f"Nuclei command: {' '.join(cmd)}")
            log_callback(f"Starting vulnerability scan with {options.get('severity', 'all')} severity levels...")

        # Run nuclei with real-time output capture
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )

        # Capture stderr in real-time for logging
        stderr_lines = []
        import select
        import time

        timeout = int(options.get('vuln_timeout', 600)) + 60 if options else 660
        start_time = time.time()

        while True:
            # Check for timeout
            if time.time() - start_time > timeout:
                process.kill()
                raise subprocess.TimeoutExpired(cmd, timeout)

            # Check if process is still running
            if process.poll() is not None:
                break

            # Read available stderr output
            try:
                if process.stderr:
                    line = process.stderr.readline()
                    if line:
                        line = line.strip()
                        stderr_lines.append(line)

                        # Filter and send relevant logs
                        if log_callback and line:
                            # Skip empty lines and progress bars
                            if line and not line.startswith('[') and 'templates' in line.lower():
                                log_callback(f"Nuclei: {line}")
                            elif 'loaded' in line.lower() or 'template' in line.lower():
                                log_callback(f"Nuclei: {line}")
                            elif any(keyword in line.lower() for keyword in ['info', 'low', 'medium', 'high', 'critical']):
                                log_callback(f"Nuclei finding: {line}")

                        logger.debug(f"Nuclei: {line}")
                else:
                    time.sleep(0.1)
            except Exception:
                time.sleep(0.1)

        # Get any remaining output
        remaining_stderr = process.stderr.read() if process.stderr else ""
        if remaining_stderr:
            stderr_lines.append(remaining_stderr.strip())
            if log_callback:
                for line in remaining_stderr.strip().split('\n'):
                    if line.strip():
                        log_callback(f"Nuclei: {line.strip()}")

        if process.returncode != 0:
            # Nuclei returns non-zero even on success sometimes, check for real errors
            stderr_output = '\n'.join(stderr_lines)
            if 'error' in stderr_output.lower() and 'templates' not in stderr_output.lower():
                logger.warning(f"Nuclei stderr: {stderr_output}")

        # Read results from output file
        results = []
        if os.path.exists(output_file.name) and os.path.getsize(output_file.name) > 0:
            with open(output_file.name, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            results.append(json.loads(line))
                        except json.JSONDecodeError as e:
                            logger.warning(f"Failed to parse nuclei output line: {e}")

        logger.info(f"Nuclei scan completed for {ip}: {len(results)} finding(s)")
        if log_callback:
            log_callback(f"Nuclei scan finished: {len(results)} vulnerability finding(s)")
        return results

    except subprocess.TimeoutExpired:
        logger.error(f"Nuclei scan timed out for {ip}")
        raise ScanError(f"Vulnerability scan timed out for {ip}")
    except Exception as e:
        logger.error(f"Unexpected error in nuclei scan for {ip}: {e}")
        raise ScanError(f"Vulnerability scan failed: {e}")
    finally:
        # Clean up temp file
        try:
            if os.path.exists(output_file.name):
                os.unlink(output_file.name)
        except Exception:
            pass


def parse_vuln_scan(nuclei_results):
    """Parse Nuclei vulnerability scan results.

    Nuclei outputs JSON with fields like:
    - template-id: Template identifier
    - info.name: Vulnerability name
    - info.severity: Severity level (critical, high, medium, low, info)
    - info.description: Vulnerability description
    - info.reference: List of reference URLs
    - matched-at: URL/endpoint that matched
    - host: Target host
    - port: Port (if applicable)
    - type: Protocol type (http, tcp, etc.)
    """
    vulnerabilities = []

    if not nuclei_results:
        return vulnerabilities

    try:
        for result in nuclei_results:
            # Extract info section
            info = result.get('info', {})

            # Extract port from matched-at URL or result
            port = 0
            protocol = 'tcp'
            matched_at = result.get('matched-at', '') or result.get('matched', '')

            # Try to extract port from matched URL
            if matched_at:
                import re
                # Match patterns like :8080/ or :443/
                port_match = re.search(r':(\d+)(?:/|$)', matched_at)
                if port_match:
                    port = int(port_match.group(1))
                elif matched_at.startswith('https://'):
                    port = 443
                elif matched_at.startswith('http://'):
                    port = 80

            # Get protocol from result type
            result_type = result.get('type', 'http')
            if result_type in ['tcp', 'udp']:
                protocol = result_type
            elif result_type == 'ssl':
                protocol = 'tcp'

            # Extract CVE ID if present in tags or template-id
            vuln_id = result.get('template-id', 'unknown')
            tags = info.get('tags', [])

            # Look for CVE in tags
            cve_id = None
            if isinstance(tags, list):
                for tag in tags:
                    if tag.upper().startswith('CVE-'):
                        cve_id = tag.upper()
                        break

            # Also check info.classification.cve-id
            classification = info.get('classification', {})
            if not cve_id and classification:
                cve_ids = classification.get('cve-id', [])
                if cve_ids and len(cve_ids) > 0:
                    cve_id = cve_ids[0] if isinstance(cve_ids, list) else cve_ids

            # Use CVE ID if found, otherwise use template-id
            if cve_id:
                vuln_id = cve_id

            # Get severity
            severity = info.get('severity', 'info').lower()
            if severity not in ['critical', 'high', 'medium', 'low', 'info']:
                severity = 'info'

            # Get description
            description = info.get('description', '')
            if not description:
                description = info.get('name', vuln_id)

            # Get references
            references = info.get('reference', [])
            if isinstance(references, str):
                references = [references]

            vuln = {
                'port': port,
                'protocol': protocol,
                'vuln_id': vuln_id,
                'vuln_name': info.get('name', vuln_id),
                'severity': severity,
                'description': description[:1000] if description else '',  # Truncate long descriptions
                'matched_at': matched_at,
                'template_id': result.get('template-id', ''),
                'tags': tags if isinstance(tags, list) else [],
                'references': references,
                'cvss_score': classification.get('cvss-score') if classification else None,
                'cwe_id': classification.get('cwe-id', [None])[0] if classification and classification.get('cwe-id') else None
            }

            vulnerabilities.append(vuln)

    except Exception as e:
        logger.error(f"Error parsing Nuclei results: {e}")

    return vulnerabilities


def store_vulnerabilities(ip, vulnerabilities):
    """Store vulnerability scan results in the database, enriching CVEs with NVD data."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    scan_date = datetime.now()

    try:
        stored_count = 0
        for vuln in vulnerabilities:
            vuln_id = vuln['vuln_id']
            description = vuln['description']
            severity = vuln['severity']

            # Use data from Nuclei if available
            cvss_score = vuln.get('cvss_score')
            cvss_vector = None
            cwe_id = vuln.get('cwe_id')
            references_json = None
            published_date = None

            # Convert Nuclei references to JSON if available
            if vuln.get('references'):
                refs = [{'url': ref, 'source': 'nuclei'} for ref in vuln['references'] if ref]
                if refs:
                    references_json = json.dumps(refs)

            # Fetch additional NVD data for CVEs (enriches with more details)
            if vuln_id.upper().startswith('CVE-'):
                nvd_data = fetch_nvd_data(vuln_id)
                if nvd_data:
                    # Use NVD description if Nuclei description is short/missing
                    if nvd_data.get('description') and len(description) < 100:
                        description = nvd_data['description']

                    # Use NVD CVSS if not already set by Nuclei
                    if cvss_score is None:
                        cvss_score = nvd_data.get('cvss_score')
                    cvss_vector = nvd_data.get('cvss_vector')

                    # Use NVD CWE if not set
                    if not cwe_id:
                        cwe_id = nvd_data.get('cwe_id')

                    published_date = nvd_data.get('published_date')

                    # Merge NVD references with Nuclei references
                    if nvd_data.get('references'):
                        existing_refs = json.loads(references_json) if references_json else []
                        existing_urls = {r['url'] for r in existing_refs}
                        for ref in nvd_data['references']:
                            if ref['url'] not in existing_urls:
                                existing_refs.append(ref)
                        references_json = json.dumps(existing_refs)

                    # Update severity based on CVSS score if available
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


def get_vulnerability_count_by_ip(ip):
    """Get count of vulnerabilities for a specific IP."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        cursor.execute('''SELECT COUNT(*) FROM vulnerabilities WHERE ip = ?''', (ip,))
        count = cursor.fetchone()[0]
        return count
    except sqlite3.Error as e:
        logger.error(f"Database error getting vulnerability count: {e}")
        return 0
    finally:
        conn.close()


def get_vulnerability_counts_by_severity(ip):
    """Get vulnerability counts by severity for a specific IP."""
    conn = sqlite3.connect(DB_PATH)
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


def get_vulnerabilities(ip=None):
    """Retrieve vulnerabilities from database, optionally filtered by IP."""
    conn = sqlite3.connect(DB_PATH)
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
                'ip': row[0],
                'port': row[1],
                'protocol': row[2],
                'vuln_id': row[3],
                'vuln_name': row[4],
                'severity': row[5],
                'description': row[6],
                'cvss_score': row[7],
                'cvss_vector': row[8],
                'cwe_id': row[9],
                'references': references,
                'published_date': row[11],
                'scan_date': row[12]
            })
        return vulnerabilities
    except sqlite3.Error as e:
        logger.error(f"Database error retrieving vulnerabilities: {e}")
        return []
    finally:
        conn.close()


def store_fpx_results(ip, fpx_results):
    """Store fingerprintx protocol-level identification results.

    Args:
        ip: Target IP address
        fpx_results: List of FpxResult objects from fingerprintx
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    scan_date = datetime.now().isoformat()

    try:
        stored_count = 0
        for fpx in fpx_results:
            sig_id = f"fpx-{fpx.service}"
            name = fpx.service.upper() if len(fpx.service) <= 5 else fpx.service.title()

            # Map fingerprintx service names to categories
            service_categories = {
                'ssh': 'remote-access', 'rdp': 'remote-access', 'vnc': 'remote-access',
                'telnet': 'remote-access',
                'http': 'web-server', 'https': 'web-server',
                'mysql': 'database', 'postgresql': 'database', 'mssql': 'database',
                'mongodb': 'database', 'redis': 'database', 'elasticsearch': 'database',
                'couchdb': 'database', 'cassandra': 'database', 'oracle': 'database',
                'influxdb': 'database', 'neo4j': 'database', 'memcached': 'database',
                'smtp': 'email', 'imap': 'email', 'pop3': 'email',
                'ftp': 'file-transfer', 'smb': 'file-transfer', 'rsync': 'file-transfer',
                'dns': 'dns', 'ldap': 'directory', 'snmp': 'network-management',
                'ntp': 'network-service', 'dhcp': 'network-service',
                'kafka': 'message-queue', 'mqtt': 'message-queue',
                'modbus': 'industrial', 'ipmi': 'management',
            }
            category = service_categories.get(fpx.service.lower(), 'service')

            # Map to vendor where obvious
            service_vendors = {
                'ssh': 'OpenBSD' if fpx.version and 'openssh' in (fpx.version or '').lower() else 'Various',
                'mysql': 'Oracle', 'mssql': 'Microsoft', 'postgresql': 'PostgreSQL',
                'mongodb': 'MongoDB', 'redis': 'Redis', 'elasticsearch': 'Elastic',
                'rdp': 'Microsoft', 'smb': 'Microsoft',
            }
            vendor = service_vendors.get(fpx.service.lower(), '')

            # Build evidence from metadata
            evidence = [f'fpx_protocol_handshake:{fpx.service}']
            if fpx.metadata:
                for k, v in fpx.metadata.items():
                    if v and isinstance(v, str) and len(v) < 200:
                        evidence.append(f'fpx_meta:{k}={v[:100]}')

            # Protocol handshake = high confidence
            confidence = 90

            cursor.execute('''INSERT OR REPLACE INTO fingerprints
                (ip, port, protocol, signature_id, name, category, vendor,
                 version, cpe, confidence, evidence_json,
                 tls_subject_cn, tls_subject_org, tls_issuer_org, tls_self_signed,
                 http_title, http_server, favicon_hash, scan_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (ip, fpx.port, fpx.transport,
                 sig_id, name, category, vendor,
                 fpx.version, None, confidence,
                 json.dumps(evidence),
                 None, None, None, 0,
                 '', '', None, scan_date))
            stored_count += 1

        conn.commit()
        logger.info(f"Stored {stored_count} fingerprintx results for {ip}")
    except sqlite3.Error as e:
        logger.error(f"Database error storing fpx results for {ip}: {e}")
    finally:
        conn.close()


def store_fingerprints(ip, fingerprint_results):
    """Store fingerprint results in the database.

    Args:
        ip: Target IP address
        fingerprint_results: List of FingerprintResult objects
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    scan_date = datetime.now().isoformat()

    try:
        stored_count = 0
        for fp_result in fingerprint_results:
            for match in fp_result.matches:
                if match.confidence < 10:
                    continue  # Skip very low confidence matches

                tls_info = fp_result.tls_info or {}
                http_info = fp_result.http_info or {}

                cursor.execute('''INSERT OR REPLACE INTO fingerprints
                    (ip, port, protocol, signature_id, name, category, vendor,
                     version, cpe, confidence, evidence_json,
                     tls_subject_cn, tls_subject_org, tls_issuer_org, tls_self_signed,
                     http_title, http_server, favicon_hash, scan_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (ip, fp_result.port, fp_result.protocol,
                     match.signature_id, match.name, match.category, match.vendor,
                     match.version, match.cpe, match.confidence,
                     json.dumps(match.evidence),
                     tls_info.get('subject_cn'), tls_info.get('subject_org'),
                     tls_info.get('issuer_org'),
                     1 if tls_info.get('self_signed') else 0,
                     http_info.get('title', ''), http_info.get('server', ''),
                     fp_result.favicon_hash, scan_date))
                stored_count += 1

        conn.commit()
        logger.info(f"Stored {stored_count} fingerprint matches for {ip}")
    except sqlite3.Error as e:
        logger.error(f"Database error storing fingerprints for {ip}: {e}")
    finally:
        conn.close()


def get_fingerprints(ip, port=None):
    """Retrieve fingerprint data for an IP, optionally filtered by port.

    Returns list of dicts with fingerprint match data.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        if port is not None:
            cursor.execute('''SELECT ip, port, protocol, signature_id, name, category, vendor,
                              version, cpe, confidence, evidence_json,
                              tls_subject_cn, tls_subject_org, tls_issuer_org, tls_self_signed,
                              http_title, http_server, favicon_hash, scan_date
                              FROM fingerprints
                              WHERE ip = ? AND port = ?
                              ORDER BY confidence DESC''', (ip, port))
        else:
            cursor.execute('''SELECT ip, port, protocol, signature_id, name, category, vendor,
                              version, cpe, confidence, evidence_json,
                              tls_subject_cn, tls_subject_org, tls_issuer_org, tls_self_signed,
                              http_title, http_server, favicon_hash, scan_date
                              FROM fingerprints
                              WHERE ip = ?
                              ORDER BY port, confidence DESC''', (ip,))

        results = []
        for row in cursor.fetchall():
            evidence = []
            try:
                evidence = json.loads(row[10]) if row[10] else []
            except json.JSONDecodeError:
                pass

            results.append({
                'ip': row[0],
                'port': row[1],
                'protocol': row[2],
                'signature_id': row[3],
                'name': row[4],
                'category': row[5],
                'vendor': row[6],
                'version': row[7],
                'cpe': row[8],
                'confidence': row[9],
                'evidence': evidence,
                'tls_subject_cn': row[11],
                'tls_subject_org': row[12],
                'tls_issuer_org': row[13],
                'tls_self_signed': bool(row[14]),
                'http_title': row[15],
                'http_server': row[16],
                'favicon_hash': row[17],
                'scan_date': row[18],
            })

        return results
    except sqlite3.Error as e:
        logger.error(f"Database error getting fingerprints for {ip}: {e}")
        return []
    finally:
        conn.close()


def get_fingerprint_summary(ip):
    """Get a summary of identified technologies for an IP.

    Returns dict with best match per port and overall tech stack.
    """
    fingerprints = get_fingerprints(ip)
    if not fingerprints:
        return {'technologies': [], 'by_port': {}}

    # Group by port, take best match per port
    by_port = {}
    all_techs = {}
    for fp in fingerprints:
        port = fp['port']
        if port not in by_port:
            by_port[port] = fp  # Already sorted by confidence DESC
        # Track unique technologies
        sig_id = fp['signature_id']
        if sig_id not in all_techs or fp['confidence'] > all_techs[sig_id]['confidence']:
            all_techs[sig_id] = fp

    # Sort technologies by confidence
    technologies = sorted(all_techs.values(), key=lambda t: t['confidence'], reverse=True)

    return {
        'technologies': technologies,
        'by_port': by_port,
    }


def get_vulnerability_summary():
    """Get a summary of vulnerabilities grouped by severity."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        cursor.execute('''SELECT severity, COUNT(*) FROM vulnerabilities GROUP BY severity''')
        severity_counts = dict(cursor.fetchall())

        cursor.execute('''SELECT COUNT(DISTINCT ip) FROM vulnerabilities''')
        affected_hosts = cursor.fetchone()[0]

        cursor.execute('''SELECT COUNT(*) FROM vulnerabilities''')
        total_vulns = cursor.fetchone()[0]

        return {
            'total': total_vulns,
            'affected_hosts': affected_hosts,
            'by_severity': {
                'critical': severity_counts.get('critical', 0),
                'high': severity_counts.get('high', 0),
                'medium': severity_counts.get('medium', 0),
                'low': severity_counts.get('low', 0),
                'info': severity_counts.get('info', 0)
            }
        }
    except sqlite3.Error as e:
        logger.error(f"Database error getting vulnerability summary: {e}")
        return {'total': 0, 'affected_hosts': 0, 'by_severity': {}}
    finally:
        conn.close()


# ============== Authenticated Scan Storage ==============

def store_auth_scan_results(ip, os_info, packages, cves):
    """Store results from an authenticated SSH scan."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    scan_date = datetime.now().isoformat()

    try:
        # Store OS details
        cursor.execute('''INSERT OR REPLACE INTO asset_os_details
            (ip, distro, version, kernel, arch, os_family, os_id, pretty_name, scan_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (ip, os_info.get('distro'), os_info.get('version'), os_info.get('kernel'),
             os_info.get('arch'), os_info.get('os_family'), os_info.get('os_id'),
             os_info.get('pretty_name'), scan_date))

        # Store packages
        for pkg in packages:
            cursor.execute('''INSERT OR REPLACE INTO installed_software
                (ip, package_name, package_version, cpe, scan_date)
                VALUES (?, ?, ?, ?, ?)''',
                (ip, pkg['name'], pkg['version'], pkg.get('cpe', ''), scan_date))

        # Store CVE matches
        for cve in cves:
            cursor.execute('''INSERT OR REPLACE INTO cve_matches
                (ip, cve_id, severity, cvss_score, description, affected_cpe, scan_date)
                VALUES (?, ?, ?, ?, ?, ?, ?)''',
                (ip, cve['cve_id'], cve['severity'], cve.get('cvss_score'),
                 cve.get('description', ''), cve.get('affected_cpe', ''), scan_date))

        conn.commit()
        logger.info(f"Stored auth scan: {ip} - OS: {os_info.get('distro')}, "
                     f"{len(packages)} packages, {len(cves)} CVEs")
    except sqlite3.Error as e:
        logger.error(f"Database error storing auth scan for {ip}: {e}")
    finally:
        conn.close()


def get_asset_os_details(ip):
    """Get authenticated OS details for an asset."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('''SELECT distro, version, kernel, arch, os_family, os_id, pretty_name, scan_date
                          FROM asset_os_details WHERE ip = ?''', (ip,))
        row = cursor.fetchone()
        if row:
            return {
                'distro': row[0], 'version': row[1], 'kernel': row[2],
                'arch': row[3], 'os_family': row[4], 'os_id': row[5],
                'pretty_name': row[6], 'scan_date': row[7]
            }
        return None
    finally:
        conn.close()


def get_installed_software(ip):
    """Get installed software inventory for an asset."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('''SELECT package_name, package_version, cpe, scan_date
                          FROM installed_software WHERE ip = ?
                          ORDER BY package_name''', (ip,))
        return [{'name': r[0], 'version': r[1], 'cpe': r[2], 'scan_date': r[3]}
                for r in cursor.fetchall()]
    finally:
        conn.close()


def get_cve_matches(ip):
    """Get CVE matches for an asset from authenticated scanning."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('''SELECT cve_id, severity, cvss_score, description, affected_cpe, scan_date
                          FROM cve_matches WHERE ip = ?
                          ORDER BY cvss_score DESC''', (ip,))
        return [{'cve_id': r[0], 'severity': r[1], 'cvss_score': r[2],
                 'description': r[3], 'affected_cpe': r[4], 'scan_date': r[5]}
                for r in cursor.fetchall()]
    finally:
        conn.close()


# ============== Credentials & Settings Management ==============

def get_all_credentials():
    """Get all stored credentials (passwords masked)."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('''SELECT id, name, cred_type, username, key_path, password, created_at, updated_at
                          FROM credentials ORDER BY name''')
        results = []
        for r in cursor.fetchall():
            results.append({
                'id': r[0], 'name': r[1], 'cred_type': r[2], 'username': r[3],
                'key_path': r[4] or '', 'password': r[5] or '',
                'created_at': r[6], 'updated_at': r[7]
            })
        return results
    finally:
        conn.close()


def get_credential(cred_id):
    """Get a single credential by ID (full, unmasked)."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('''SELECT id, name, cred_type, username, key_path, password
                          FROM credentials WHERE id = ?''', (cred_id,))
        r = cursor.fetchone()
        if r:
            return {
                'id': r[0], 'name': r[1], 'cred_type': r[2], 'username': r[3],
                'key_path': r[4] or '', 'password': r[5] or ''
            }
        return None
    finally:
        conn.close()


def save_credential(name, cred_type, username, key_path='', password='', cred_id=None):
    """Create or update a credential set."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    now = datetime.now().isoformat()
    try:
        if cred_id:
            cursor.execute('''UPDATE credentials SET name=?, cred_type=?, username=?,
                              key_path=?, password=?, updated_at=? WHERE id=?''',
                           (name, cred_type, username, key_path, password, now, cred_id))
        else:
            cursor.execute('''INSERT INTO credentials (name, cred_type, username, key_path, password, created_at, updated_at)
                              VALUES (?, ?, ?, ?, ?, ?, ?)''',
                           (name, cred_type, username, key_path, password, now, now))
        conn.commit()
        return cursor.lastrowid if not cred_id else cred_id
    except sqlite3.IntegrityError:
        raise ValueError(f"Credential name '{name}' already exists")
    finally:
        conn.close()


def delete_credential(cred_id):
    """Delete a credential by ID."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('DELETE FROM credentials WHERE id = ?', (cred_id,))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def get_setting(key, default=None):
    """Get a setting value."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
        row = cursor.fetchone()
        return row[0] if row else default
    finally:
        conn.close()


def set_setting(key, value):
    """Set a setting value."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (key, value))
        conn.commit()
    finally:
        conn.close()


def get_open_ports_for_ip(ip):
    """Get the list of open ports from the latest scan for an IP."""
    latest = get_latest_scan(ip)
    ports = []
    for row in latest:
        if row[2] == 'open':
            ports.append({'port': row[1], 'protocol': row[0], 'service': row[3]})
    return ports
