"""Authenticated SSH scanning module for Cerebus.

Connects to targets via SSH, detects OS, gathers installed software inventory,
generates CPE strings, and queries NVD API for CVE matches.
"""

import re
import json
import time
import logging
import urllib.request
import urllib.error
import paramiko

logger = logging.getLogger(__name__)

# NVD API v2 configuration
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_LIMIT_DELAY = 6.5  # 5 req/30s without key => ~6s between requests


def ssh_connect(host, port=22, username='root', password=None, key_path=None, timeout=15):
    """Create an SSH connection using paramiko.

    Returns a paramiko.SSHClient or raises an exception.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    kwargs = dict(hostname=host, port=port, username=username, timeout=timeout)

    if key_path:
        try:
            pkey = paramiko.RSAKey.from_private_key_file(key_path, password=password)
        except Exception:
            try:
                pkey = paramiko.Ed25519Key.from_private_key_file(key_path, password=password)
            except Exception:
                pkey = paramiko.ECDSAKey.from_private_key_file(key_path, password=password)
        kwargs['pkey'] = pkey
    elif password:
        kwargs['password'] = password
    else:
        # Try agent-based auth
        kwargs['allow_agent'] = True
        kwargs['look_for_keys'] = True

    client.connect(**kwargs)
    return client


def _exec(client, cmd, timeout=30):
    """Execute a command over SSH and return stdout as string."""
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    return stdout.read().decode('utf-8', errors='replace').strip()


def detect_os(client):
    """Detect OS details from a connected SSH session.

    Returns dict with distro, version, kernel, arch, os_family.
    """
    info = {
        'distro': None,
        'version': None,
        'kernel': None,
        'arch': None,
        'os_family': None,
        'os_id': None,
        'pretty_name': None,
    }

    # uname
    uname = _exec(client, 'uname -a')
    if uname:
        info['kernel'] = uname

    arch = _exec(client, 'uname -m')
    if arch:
        info['arch'] = arch.strip()

    # /etc/os-release
    os_release = _exec(client, 'cat /etc/os-release 2>/dev/null')
    if os_release:
        kv = {}
        for line in os_release.splitlines():
            if '=' in line:
                k, _, v = line.partition('=')
                kv[k.strip()] = v.strip().strip('"')
        info['distro'] = kv.get('NAME') or kv.get('ID', '')
        info['version'] = kv.get('VERSION_ID', '')
        info['os_id'] = kv.get('ID', '')
        info['pretty_name'] = kv.get('PRETTY_NAME', '')

        # Determine os_family
        os_id = (kv.get('ID', '') + ' ' + kv.get('ID_LIKE', '')).lower()
        if any(x in os_id for x in ['debian', 'ubuntu', 'raspbian', 'mint']):
            info['os_family'] = 'debian'
        elif any(x in os_id for x in ['rhel', 'centos', 'fedora', 'rocky', 'alma', 'oracle']):
            info['os_family'] = 'rhel'
        elif 'alpine' in os_id:
            info['os_family'] = 'alpine'
        elif 'arch' in os_id:
            info['os_family'] = 'arch'
        elif 'freebsd' in os_id:
            info['os_family'] = 'freebsd'
        elif 'suse' in os_id or 'opensuse' in os_id:
            info['os_family'] = 'rhel'  # uses rpm
    else:
        # Try FreeBSD
        freebsd_ver = _exec(client, 'freebsd-version 2>/dev/null')
        if freebsd_ver:
            info['distro'] = 'FreeBSD'
            info['version'] = freebsd_ver.strip()
            info['os_family'] = 'freebsd'
            info['os_id'] = 'freebsd'

    if not info['os_family']:
        # Fallback: check for package managers
        if _exec(client, 'which dpkg 2>/dev/null'):
            info['os_family'] = 'debian'
        elif _exec(client, 'which rpm 2>/dev/null'):
            info['os_family'] = 'rhel'
        elif _exec(client, 'which apk 2>/dev/null'):
            info['os_family'] = 'alpine'
        elif _exec(client, 'which pacman 2>/dev/null'):
            info['os_family'] = 'arch'
        elif _exec(client, 'which pkg 2>/dev/null'):
            info['os_family'] = 'freebsd'

    return info


def gather_packages(client, os_family):
    """Gather installed packages based on OS family.

    Returns list of dicts: [{name, version}, ...]
    """
    packages = []

    if os_family == 'debian':
        output = _exec(client, "dpkg-query -W -f '${Package} ${Version}\\n'", timeout=60)
        for line in output.splitlines():
            parts = line.strip().split(' ', 1)
            if len(parts) == 2:
                packages.append({'name': parts[0], 'version': parts[1]})
    elif os_family == 'rhel':
        output = _exec(client, "rpm -qa --queryformat '%{NAME} %{VERSION}-%{RELEASE}\\n'", timeout=60)
        for line in output.splitlines():
            parts = line.strip().split(' ', 1)
            if len(parts) == 2:
                packages.append({'name': parts[0], 'version': parts[1]})
    elif os_family == 'freebsd':
        output = _exec(client, 'pkg info 2>/dev/null', timeout=60)
        for line in output.splitlines():
            # Format: "name-version  description"
            parts = line.strip().split(None, 1)
            if parts:
                name_ver = parts[0]
                # Split on last hyphen to separate name from version
                idx = name_ver.rfind('-')
                if idx > 0:
                    packages.append({'name': name_ver[:idx], 'version': name_ver[idx+1:]})
    elif os_family == 'alpine':
        output = _exec(client, 'apk list --installed 2>/dev/null', timeout=60)
        for line in output.splitlines():
            # Format: "name-version-rX arch {origin} (license) [installed]"
            m = re.match(r'^(\S+?)-(\d\S*)\s', line)
            if m:
                packages.append({'name': m.group(1), 'version': m.group(2)})
    elif os_family == 'arch':
        output = _exec(client, 'pacman -Q 2>/dev/null', timeout=60)
        for line in output.splitlines():
            parts = line.strip().split(' ', 1)
            if len(parts) == 2:
                packages.append({'name': parts[0], 'version': parts[1]})

    return packages


def generate_cpe(pkg_name, pkg_version, os_info=None):
    """Generate a CPE 2.3 string for a package.

    Format: cpe:2.3:a:VENDOR:PRODUCT:VERSION:*:*:*:*:*:*:*
    """
    # Normalize name
    product = pkg_name.lower().replace(' ', '_')
    version = pkg_version.split('-')[0] if pkg_version else '*'  # strip release suffix
    version = version.split(':')[-1] if ':' in version else version  # strip epoch

    # Best-effort vendor mapping for common packages
    vendor_map = {
        'linux-image': 'linux', 'linux-headers': 'linux',
        'openssl': 'openssl', 'libssl': 'openssl',
        'openssh-server': 'openbsd', 'openssh-client': 'openbsd',
        'apache2': 'apache', 'httpd': 'apache',
        'nginx': 'nginx', 'curl': 'haxx', 'libcurl': 'haxx',
        'python3': 'python', 'python': 'python',
        'php': 'php', 'mysql-server': 'oracle', 'mariadb-server': 'mariadb',
        'postgresql': 'postgresql', 'redis-server': 'redis',
        'nodejs': 'nodejs', 'docker-ce': 'docker', 'docker.io': 'docker',
        'sudo': 'sudo_project', 'bash': 'gnu', 'glibc': 'gnu',
        'libc6': 'gnu', 'bind9': 'isc', 'named': 'isc',
        'samba': 'samba', 'vim': 'vim', 'git': 'git-scm',
    }

    vendor = vendor_map.get(product, product)

    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def query_nvd_cves_for_cpe(cpe_string, nvd_api_key=None):
    """Query NVD API v2 for CVEs matching a CPE string.

    Returns list of dicts: [{cve_id, severity, cvss_score, description, affected_cpe}, ...]
    """
    # Extract keyword from CPE for search (NVD cpeName match can be strict)
    # Use keywordSearch as fallback
    parts = cpe_string.split(':')
    if len(parts) < 6:
        return []

    product = parts[4]
    version = parts[5]
    if version == '*':
        return []

    results = []
    url = f"{NVD_CVE_API}?cpeName={urllib.request.quote(cpe_string)}&resultsPerPage=20"

    headers = {'User-Agent': 'Cerebus-Scanner/1.0'}
    if nvd_api_key:
        headers['apiKey'] = nvd_api_key

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode('utf-8'))

        for vuln_item in data.get('vulnerabilities', []):
            cve = vuln_item.get('cve', {})
            cve_id = cve.get('id', '')

            # CVSS
            cvss_score = None
            severity = 'unknown'
            metrics = cve.get('metrics', {})
            for key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if key in metrics and metrics[key]:
                    cvss_data = metrics[key][0].get('cvssData', {})
                    cvss_score = cvss_data.get('baseScore')
                    break

            if cvss_score is not None:
                if cvss_score >= 9.0:
                    severity = 'critical'
                elif cvss_score >= 7.0:
                    severity = 'high'
                elif cvss_score >= 4.0:
                    severity = 'medium'
                else:
                    severity = 'low'

            # Description
            desc = ''
            for d in cve.get('descriptions', []):
                if d.get('lang') == 'en':
                    desc = d.get('value', '')
                    break

            results.append({
                'cve_id': cve_id,
                'severity': severity,
                'cvss_score': cvss_score,
                'description': desc[:500],
                'affected_cpe': cpe_string,
            })

    except urllib.error.HTTPError as e:
        if e.code == 404:
            pass  # No matches
        else:
            logger.warning(f"NVD API HTTP {e.code} for {product}")
    except Exception as e:
        logger.warning(f"NVD API error for {product}: {e}")

    return results


def run_authenticated_scan(host, port=22, username='root', password=None, key_path=None,
                           nvd_api_key=None, log_callback=None, max_cve_lookups=50):
    """Run a full authenticated scan on a host.

    Returns dict with os_info, packages (list), cves (list).
    """
    def log(msg, level='info'):
        logger.info(msg)
        if log_callback:
            log_callback(msg, level)

    log(f'Connecting to {host}:{port} via SSH as {username}...')

    client = ssh_connect(host, port=port, username=username,
                         password=password, key_path=key_path)
    try:
        log(f'SSH connection established to {host}')

        # Detect OS
        log(f'Detecting OS on {host}...')
        os_info = detect_os(client)
        if os_info.get('pretty_name'):
            log(f'OS: {os_info["pretty_name"]}')
        elif os_info.get('distro'):
            log(f'OS: {os_info["distro"]} {os_info.get("version", "")}')

        if os_info.get('arch'):
            log(f'Arch: {os_info["arch"]}')
        if os_info.get('kernel'):
            log(f'Kernel: {os_info["kernel"][:80]}', 'debug')

        if not os_info.get('os_family'):
            log(f'Could not detect package manager on {host}', 'warning')
            return {'os_info': os_info, 'packages': [], 'cves': []}

        # Gather packages
        log(f'Gathering installed packages ({os_info["os_family"]})...')
        packages = gather_packages(client, os_info['os_family'])
        log(f'Found {len(packages)} installed packages', 'success')

        # Generate CPEs
        for pkg in packages:
            pkg['cpe'] = generate_cpe(pkg['name'], pkg['version'], os_info)

    finally:
        client.close()

    # Query NVD for CVE matches (outside SSH session)
    cves = []
    if packages:
        # Focus on well-known packages that are more likely to have CVEs
        priority_keywords = [
            'openssl', 'openssh', 'apache', 'nginx', 'curl', 'python', 'php',
            'mysql', 'mariadb', 'postgresql', 'redis', 'node', 'docker',
            'sudo', 'bash', 'glibc', 'libc6', 'bind', 'samba', 'vim', 'git',
            'linux-image', 'kernel', 'httpd', 'tomcat', 'java', 'perl', 'ruby',
            'libxml', 'libpng', 'zlib', 'sqlite', 'exim', 'postfix', 'dovecot',
        ]

        priority_pkgs = [p for p in packages if any(k in p['name'].lower() for k in priority_keywords)]
        other_pkgs = [p for p in packages if p not in priority_pkgs]
        scan_pkgs = (priority_pkgs + other_pkgs)[:max_cve_lookups]

        log(f'Querying NVD for CVEs on {len(scan_pkgs)} packages (priority: {len(priority_pkgs)})...')

        delay = 1.0 if nvd_api_key else NVD_RATE_LIMIT_DELAY
        checked = 0

        for pkg in scan_pkgs:
            if pkg['cpe'].split(':')[5] == '*':
                continue  # skip packages with no version
            try:
                matches = query_nvd_cves_for_cpe(pkg['cpe'], nvd_api_key=nvd_api_key)
                if matches:
                    log(f'  {pkg["name"]} {pkg["version"]}: {len(matches)} CVE(s) found', 'warning')
                    cves.extend(matches)
                checked += 1
                if checked < len(scan_pkgs):
                    time.sleep(delay)
            except Exception as e:
                log(f'  NVD query error for {pkg["name"]}: {e}', 'debug')

        log(f'NVD lookup complete: {len(cves)} total CVE matches', 'success' if not cves else 'warning')

    return {
        'os_info': os_info,
        'packages': packages,
        'cves': cves,
    }
