"""Authenticated SSH scanning module for Artemis.

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


def _first_line(text):
    for line in (text or '').splitlines():
        line = line.strip()
        if line:
            return line
    return None


def _parse_listening_ports(raw):
    """Parse `ss -tlnp` / `netstat -tlnp` output into a list of dicts.

    In both tools the local endpoint is the 4th whitespace field
    (``State Recv-Q Send-Q Local:Port …`` / ``Proto Recv-Q Send-Q Local …``).
    """
    ports = []
    seen = set()
    for line in (raw or '').splitlines():
        line = line.strip()
        if not line or line.lower().startswith(('netid', 'proto', 'active', 'state')):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3]
        addr, _, port = local.rpartition(':')
        if not port.isdigit():
            continue
        proc = ''
        m = re.search(r'users:\(\("([^"]+)"', line)          # ss
        if m:
            proc = m.group(1)
        else:
            m = re.search(r'(?:^|\s)\d+/(\S+)', line)          # netstat "1234/sshd"
            if m:
                proc = m.group(1)
        addr = addr.strip('[]') or '*'
        if addr in ('::', '0.0.0.0'):          # all interfaces — collapse v4/v6
            addr = '*'
        key = (int(port), addr)
        if key in seen:
            continue
        seen.add(key)
        ports.append({'port': int(port), 'protocol': 'tcp', 'address': addr, 'process': proc})
    return sorted(ports, key=lambda p: p['port'])


def _count_pending_updates(client, os_family):
    """Best-effort count of upgradable packages. Returns int or None."""
    try:
        if os_family == 'debian':
            out = _exec(client, "apt-get -s -o Debug::NoLocking=true upgrade 2>/dev/null | grep -c '^Inst '", timeout=45)
            return int(out) if out.isdigit() else None
        if os_family == 'alpine':
            out = _exec(client, "apk version -l '<' 2>/dev/null | grep -c '<'", timeout=30)
            return max(0, int(out) - 0) if out.isdigit() else None
        if os_family == 'rhel':
            out = _exec(client, "dnf -q check-update 2>/dev/null | grep -c '^[a-zA-Z0-9]' ; true", timeout=60)
            return int(out) if out.isdigit() else None
        if os_family == 'arch':
            out = _exec(client, "pacman -Qu 2>/dev/null | wc -l", timeout=30)
            return int(out) if out.isdigit() else None
    except Exception:
        pass
    return None


def collect_host_facts(client, os_info):
    """Enumerate everything cheap an authenticated session reveals about a host.

    Runs while the SSH session is open. Every probe is read-only, guarded, and
    short. Returns a dict of facts (also merges a few onto ``os_info``).
    """
    os_family = os_info.get('os_family')
    facts = {}

    # Identity
    hostname = _first_line(_exec(client, 'hostname -f 2>/dev/null || hostname 2>/dev/null || uname -n'))
    if hostname and hostname.lower() != 'localhost':
        facts['hostname'] = hostname
        os_info.setdefault('hostname', hostname)
    facts['kernel_release'] = _first_line(_exec(client, 'uname -r'))
    facts['kernel_full'] = os_info.get('kernel')

    # Platform / virtualisation
    virt = _first_line(_exec(client, 'systemd-detect-virt 2>/dev/null'))
    if virt and virt not in ('none', ''):
        facts['virtualization'] = virt
    elif _exec(client, 'test -f /.dockerenv && echo docker'):
        facts['virtualization'] = 'docker'

    # CPU / memory
    cpu_model = _first_line(_exec(
        client,
        "grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 "
        "|| sysctl -n hw.model 2>/dev/null"))
    if cpu_model:
        facts['cpu_model'] = cpu_model.strip()
    cpu_count = _first_line(_exec(client, 'nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null'))
    if cpu_count and cpu_count.isdigit():
        facts['cpu_count'] = int(cpu_count)
    mem_kb = _first_line(_exec(client, "grep -m1 MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}'"))
    if mem_kb and mem_kb.isdigit():
        facts['memory_mb'] = round(int(mem_kb) / 1024)

    # Uptime / boot / time
    uptime_raw = _exec(client, 'cat /proc/uptime 2>/dev/null')
    if uptime_raw:
        try:
            facts['uptime_seconds'] = int(float(uptime_raw.split()[0]))
        except (ValueError, IndexError):
            pass
    boot_time = _first_line(_exec(client, 'uptime -s 2>/dev/null'))
    if boot_time:
        facts['boot_time'] = boot_time
    tz = _first_line(_exec(
        client,
        "timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null"))
    if tz:
        facts['timezone'] = tz

    # Network — default route iface drives "primary" MAC/IP
    gw_line = _first_line(_exec(client, 'ip route show default 2>/dev/null || route -n get default 2>/dev/null'))
    primary_iface = None
    if gw_line:
        gm = re.search(r'via (\S+)', gw_line)
        if gm:
            facts['default_gateway'] = gm.group(1)
        im = re.search(r'dev (\S+)', gw_line)
        if im:
            primary_iface = im.group(1)

    macs = {}
    for entry in _exec(client, "grep -H . /sys/class/net/*/address 2>/dev/null").splitlines():
        path, _, mac = entry.partition(':')
        iface = path.rsplit('/', 2)[-2] if '/' in path else ''
        mac = mac.strip()
        if iface and iface != 'lo' and mac and mac != '00:00:00:00:00:00':
            macs[iface] = mac
    if macs:
        facts['mac_addresses'] = macs
        facts['primary_mac'] = macs.get(primary_iface) or next(iter(macs.values()))
        os_info.setdefault('primary_mac', facts['primary_mac'])

    ipv4 = re.findall(r'inet (\d+\.\d+\.\d+\.\d+)',
                      _exec(client, 'ip -o -4 addr show scope global 2>/dev/null || ifconfig 2>/dev/null'))
    ipv4 = [a for a in ipv4 if not a.startswith('127.')]
    if ipv4:
        facts['ipv4_addresses'] = sorted(set(ipv4))

    # Listening services (authenticated ground truth)
    listen_raw = _exec(client,
                       'ss -H -tlnp 2>/dev/null || ss -tln 2>/dev/null || netstat -tlnp 2>/dev/null',
                       timeout=20)
    listening = _parse_listening_ports(listen_raw)
    if listening:
        facts['listening_ports'] = listening

    # Sessions / hardening / updates
    who = _exec(client, 'who 2>/dev/null')
    if who:
        facts['logged_in_users'] = sorted({l.split()[0] for l in who.splitlines() if l.split()})
    selinux = _first_line(_exec(client, 'getenforce 2>/dev/null'))
    if selinux:
        facts['selinux'] = selinux
    pending = _count_pending_updates(client, os_family)
    if pending is not None:
        facts['pending_updates'] = pending

    return facts


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

    Delegates to nvd_feeds.resolve_cpe (curated map + local cpe_products index +
    version normalisation). Falls back to the legacy heuristic if that import
    fails (e.g. NVD module unavailable).
    """
    try:
        from nvd_feeds import resolve_cpe
        os_family = (os_info or {}).get('os_family')
        return resolve_cpe(pkg_name, pkg_version, os_family=os_family)
    except Exception:
        pass

    # --- legacy fallback ---
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

    headers = {'User-Agent': 'Artemis-Scanner/1.0'}
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
                           nvd_api_key=None, log_callback=None, max_cve_lookups=400):
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

        # Enumerate host facts (hostname, hardware, network, listening services…)
        log(f'Enumerating host details on {host}...')
        try:
            facts = collect_host_facts(client, os_info)
            os_info['system'] = facts
            summary = []
            if facts.get('hostname'):
                summary.append(f"hostname {facts['hostname']}")
            if facts.get('virtualization'):
                summary.append(facts['virtualization'])
            if facts.get('listening_ports'):
                summary.append(f"{len(facts['listening_ports'])} listening port(s)")
            if facts.get('pending_updates'):
                summary.append(f"{facts['pending_updates']} pending update(s)")
            if summary:
                log('Host details: ' + ', '.join(summary))
        except Exception as e:
            log(f'Host detail enumeration partial: {e}', 'debug')

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

    # Try to improve CPE accuracy using CPE dictionary (fuzzy matching)
    try:
        from cpe_dict import search_cpe
        improved = 0
        for pkg in packages:
            better_cpe = search_cpe(pkg['name'], pkg['version'])
            if better_cpe:
                pkg['cpe'] = better_cpe
                improved += 1
        if improved > 0:
            log(f'Improved {improved} CPEs via dictionary lookup', 'debug')
    except Exception as e:
        log(f'CPE dictionary lookup unavailable: {e}', 'debug')

    # Query NVD for CVE matches (outside SSH session)
    cves = []
    if packages:
        # Local matching is a single indexed query per CPE, so every versioned
        # package can go through it. `max_cve_lookups` only bounds the (slow,
        # rate-limited) API fallback.
        versioned = [p for p in packages if p['cpe'].split(':')[5] not in ('*', '')]

        # Try local NVD database first — over ALL versioned packages.
        try:
            from nvd_feeds import match_cpes_local
            cpe_list = [pkg['cpe'] for pkg in versioned]
            if cpe_list:
                log(f'Checking {len(cpe_list)} CPEs against local NVD database...')
                local_results = match_cpes_local(cpe_list)
                if local_results is not None:
                    cves = local_results
                    log(f'Local NVD match: {len(cves)} CVE(s) found', 'success' if not cves else 'warning')
                else:
                    log(f'Local NVD database empty, falling back to API...', 'info')
                    local_results = None  # Signal API fallback
            else:
                local_results = None
        except ImportError:
            log(f'Local NVD module not available, using API...', 'debug')
            local_results = None

        # Fall back to NVD API if local DB is empty — capped and priority-first.
        scan_pkgs = versioned[:max_cve_lookups]
        if local_results is None:
            log(f'Querying NVD API for CVEs on {len(scan_pkgs)} packages...')

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

    # Cross-reference CVEs with ExploitDB
    if cves:
        try:
            from exploit_ref import enrich_cves_with_exploits
            log(f'Cross-referencing {len(cves)} CVEs with ExploitDB...', 'info')
            cves = enrich_cves_with_exploits(cves)
            exploit_count = sum(1 for c in cves if c.get('has_exploit'))
            if exploit_count:
                log(f'⚠️ {exploit_count} CVE(s) have known public exploits!', 'warning')
        except Exception as e:
            log(f'ExploitDB cross-reference unavailable: {e}', 'debug')

    return {
        'os_info': os_info,
        'packages': packages,
        'cves': cves,
    }
