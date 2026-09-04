#!/usr/bin/env python3
"""Artemis Agent — lightweight host scanner that reports to Artemis server.

Usage:
    python3 artemis_agent.py --server https://artemis.example.com --key <api-key> [--interval 21600]
    python3 artemis_agent.py --server https://artemis.example.com --register [--name "My Server"]
    python3 artemis_agent.py --server https://artemis.example.com --key <api-key> --once
    python3 artemis_agent.py --deregister        # remove this agent from the server

Config file: /etc/artemis/agent.conf or ~/.artemis/agent.conf (JSON)

Zero external dependencies — stdlib only. Python 3.8+.
"""

import argparse
import base64
import fcntl
import json
import os
import platform
import pty
import re
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import termios
import threading
import time
import urllib.error
import urllib.request

__version__ = '1.3.0'
TELEMETRY_SCHEMA_VERSION = 2
AGENT_CAPABILITIES = ['remote_shell']

DEFAULT_INTERVAL = 21600  # 6 hours
CONFIG_PATHS = ['/etc/artemis/agent.conf', os.path.expanduser('~/.artemis/agent.conf')]


def load_config():
    """Load config from file."""
    for path in CONFIG_PATHS:
        if os.path.isfile(path):
            try:
                with open(path) as f:
                    return json.load(f)
            except Exception:
                pass
    return {}


def save_config(data):
    """Save config to the first writable path."""
    for path in CONFIG_PATHS:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w') as f:
                json.dump(data, f, indent=2)
            os.chmod(path, 0o600)
            return path
        except PermissionError:
            continue
    return None


def remove_config():
    """Delete every agent config file we can find. Returns removed paths."""
    removed = []
    for path in CONFIG_PATHS:
        try:
            os.remove(path)
            removed.append(path)
        except FileNotFoundError:
            pass
        except OSError as e:
            print(f"Could not remove {path}: {e}", file=sys.stderr)
    return removed


def get_os_info():
    """Collect OS information from /etc/os-release and platform."""
    info = {
        'platform': platform.system(),
        'kernel': platform.release(),
        'arch': platform.machine(),
        'python_version': platform.python_version(),
    }
    try:
        with open('/etc/os-release') as f:
            for line in f:
                line = line.strip()
                if '=' in line:
                    key, _, val = line.partition('=')
                    info[key.lower()] = val.strip('"')
    except FileNotFoundError:
        info['distro'] = platform.platform()
    return info


def get_hostname():
    return socket.gethostname()


def get_ips():
    """Get all IP and MAC addresses."""
    ips = []
    try:
        output = subprocess.check_output(['ip', '-j', 'addr'], stderr=subprocess.DEVNULL, timeout=10)
        data = json.loads(output)
        for iface in data:
            name = iface.get('ifname', '')
            mac = iface.get('address', '')
            for addr_info in iface.get('addr_info', []):
                ips.append({
                    'interface': name,
                    'address': addr_info.get('local', ''),
                    'family': addr_info.get('family', ''),
                    'mac': mac,
                })
    except Exception:
        # Fallback
        try:
            hostname = socket.gethostname()
            addr = socket.gethostbyname(hostname)
            ips.append({'interface': 'default', 'address': addr, 'family': 'inet'})
        except Exception:
            pass
    return ips


def get_primary_ip():
    """Get the primary (non-loopback) IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 53))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'


def get_packages():
    """Inventory installed packages."""
    packages = []
    # Try dpkg
    try:
        out = subprocess.check_output(
            ['dpkg-query', '-W', '-f', '${Package}\t${Version}\t${Architecture}\n'],
            stderr=subprocess.DEVNULL, timeout=30
        ).decode('utf-8', errors='replace')
        for line in out.strip().split('\n'):
            parts = line.split('\t')
            if len(parts) >= 2:
                packages.append({
                    'name': parts[0], 'version': parts[1],
                    'arch': parts[2] if len(parts) > 2 else '', 'manager': 'dpkg',
                })
        if packages:
            return packages
    except (FileNotFoundError, subprocess.SubprocessError):
        pass

    # Try rpm
    try:
        out = subprocess.check_output(
            ['rpm', '-qa', '--queryformat', '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n'],
            stderr=subprocess.DEVNULL, timeout=30
        ).decode('utf-8', errors='replace')
        for line in out.strip().split('\n'):
            parts = line.split('\t')
            if len(parts) >= 2:
                packages.append({
                    'name': parts[0], 'version': parts[1],
                    'arch': parts[2] if len(parts) > 2 else '', 'manager': 'rpm',
                })
        if packages:
            return packages
    except (FileNotFoundError, subprocess.SubprocessError):
        pass

    # Try apk
    try:
        out = subprocess.check_output(
            ['apk', 'list', '--installed'],
            stderr=subprocess.DEVNULL, timeout=30
        ).decode('utf-8', errors='replace')
        for line in out.strip().split('\n'):
            # format: name-version {arch} ...
            match = re.match(r'^(\S+)-(\d\S*)\s', line)
            if match:
                packages.append({'name': match.group(1), 'version': match.group(2), 'manager': 'apk'})
        if packages:
            return packages
    except (FileNotFoundError, subprocess.SubprocessError):
        pass

    # Try pacman
    try:
        out = subprocess.check_output(
            ['pacman', '-Q'],
            stderr=subprocess.DEVNULL, timeout=30
        ).decode('utf-8', errors='replace')
        for line in out.strip().split('\n'):
            parts = line.split()
            if len(parts) >= 2:
                packages.append({'name': parts[0], 'version': parts[1], 'manager': 'pacman'})
        if packages:
            return packages
    except (FileNotFoundError, subprocess.SubprocessError):
        pass

    return packages


def get_open_ports():
    """Get open listening ports."""
    ports = []
    # Try ss
    try:
        out = subprocess.check_output(
            ['ss', '-H', '-tulnp'],
            stderr=subprocess.DEVNULL, timeout=10
        ).decode('utf-8', errors='replace')
        for line in out.strip().split('\n'):
            parts = line.split()
            if len(parts) >= 5:
                protocol = parts[0].lower()
                local = parts[4]
                proc = parts[-1] if 'users:' in parts[-1] else ''
                port_text = local.rsplit(':', 1)[-1]
                if port_text.isdigit():
                    ports.append({
                        'port': int(port_text), 'listen': local,
                        'protocol': protocol, 'state': 'open', 'process': proc,
                    })
        return ports
    except (FileNotFoundError, subprocess.SubprocessError):
        pass

    # Try netstat
    try:
        out = subprocess.check_output(
            ['netstat', '-tlnp'],
            stderr=subprocess.DEVNULL, timeout=10
        ).decode('utf-8', errors='replace')
        for line in out.strip().split('\n')[2:]:  # skip headers
            parts = line.split()
            if len(parts) >= 4:
                local = parts[3]
                proc = parts[-1] if len(parts) > 6 else ''
                port_text = local.rsplit(':', 1)[-1]
                if port_text.isdigit():
                    ports.append({
                        'port': int(port_text), 'listen': local,
                        'protocol': parts[0].lower(), 'state': 'open', 'process': proc,
                    })
        return ports
    except (FileNotFoundError, subprocess.SubprocessError):
        pass

    return ports


def get_system_info():
    """Get uptime, load, and disk usage."""
    info = {}
    # Uptime
    try:
        with open('/proc/uptime') as f:
            uptime_secs = float(f.read().split()[0])
            info['uptime_seconds'] = int(uptime_secs)
    except Exception:
        pass

    # Load average
    try:
        load = os.getloadavg()
        info['load_avg'] = {'1m': load[0], '5m': load[1], '15m': load[2]}
    except Exception:
        pass

    # Disk usage
    try:
        out = subprocess.check_output(
            ['df', '-h', '--output=target,size,used,avail,pcent'],
            stderr=subprocess.DEVNULL, timeout=10
        ).decode('utf-8', errors='replace')
        disks = []
        for line in out.strip().split('\n')[1:]:
            parts = line.split()
            if len(parts) >= 5 and parts[0].startswith('/'):
                disks.append({
                    'mount': parts[0], 'size': parts[1],
                    'used': parts[2], 'avail': parts[3], 'pct': parts[4],
                })
        info['disks'] = disks
    except Exception:
        pass

    # Last package update
    for path in ['/var/log/apt/history.log', '/var/log/dnf.log', '/var/log/yum.log']:
        try:
            mtime = os.path.getmtime(path)
            info['last_package_update'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(mtime))
            break
        except Exception:
            pass

    return info


def _read_cpu_sample():
    with open('/proc/stat') as f:
        values = [int(value) for value in f.readline().split()[1:]]
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return sum(values), idle


def get_performance_telemetry():
    """Collect a short CPU sample and current memory pressure."""
    cpu = {'logical_count': os.cpu_count() or 1}
    try:
        total_a, idle_a = _read_cpu_sample()
        time.sleep(0.12)
        total_b, idle_b = _read_cpu_sample()
        delta = total_b - total_a
        cpu['usage_percent'] = round(100.0 * (1 - ((idle_b - idle_a) / delta)), 1) if delta else 0.0
    except (OSError, ValueError):
        pass

    memory = {}
    try:
        with open('/proc/meminfo') as f:
            values = {}
            for line in f:
                key, value = line.split(':', 1)
                values[key] = int(value.strip().split()[0]) * 1024
        total = values.get('MemTotal', 0)
        available = values.get('MemAvailable', values.get('MemFree', 0))
        used = max(0, total - available)
        memory = {
            'total_bytes': total,
            'available_bytes': available,
            'used_bytes': used,
            'used_percent': round((used / total) * 100, 1) if total else 0.0,
            'swap_total_bytes': values.get('SwapTotal', 0),
            'swap_free_bytes': values.get('SwapFree', 0),
        }
    except (OSError, ValueError):
        pass
    return {'cpu': cpu, 'memory': memory}


def get_process_telemetry():
    """Collect process-state totals and a bounded list of resource leaders."""
    summary = {'total': 0, 'running': 0, 'sleeping': 0, 'zombie': 0, 'threads': 0, 'top': []}
    try:
        out = subprocess.check_output(
            ['ps', '-eo', 'pid=,user=,stat=,comm=,%cpu=,%mem=,rss=,nlwp=', '--sort=-%cpu'],
            stderr=subprocess.DEVNULL, timeout=10,
        ).decode('utf-8', errors='replace')
        for line in out.splitlines():
            parts = line.split(None, 7)
            if len(parts) != 8:
                continue
            pid, user, state, command, cpu, memory, rss, threads = parts
            summary['total'] += 1
            summary['threads'] += int(threads) if threads.isdigit() else 0
            if state.startswith('R'):
                summary['running'] += 1
            elif state.startswith('Z'):
                summary['zombie'] += 1
            else:
                summary['sleeping'] += 1
            if len(summary['top']) < 12:
                summary['top'].append({
                    'pid': int(pid), 'user': user, 'state': state,
                    'command': command, 'cpu_percent': float(cpu),
                    'memory_percent': float(memory), 'rss_bytes': int(rss) * 1024,
                    'threads': int(threads) if threads.isdigit() else 0,
                })
    except (FileNotFoundError, subprocess.SubprocessError, ValueError):
        pass
    return summary


def get_network_telemetry():
    """Collect interface byte/packet counters and socket state totals."""
    interfaces = []
    try:
        with open('/proc/net/dev') as f:
            for line in f.readlines()[2:]:
                name, counters = line.split(':', 1)
                values = counters.split()
                interfaces.append({
                    'name': name.strip(),
                    'rx_bytes': int(values[0]), 'rx_packets': int(values[1]),
                    'rx_errors': int(values[2]), 'rx_dropped': int(values[3]),
                    'tx_bytes': int(values[8]), 'tx_packets': int(values[9]),
                    'tx_errors': int(values[10]), 'tx_dropped': int(values[11]),
                })
    except (OSError, ValueError, IndexError):
        pass

    sockets = {'tcp_established': 0, 'tcp_listening': 0, 'tcp_total': 0, 'udp_total': 0}
    for path, protocol in (('/proc/net/tcp', 'tcp'), ('/proc/net/tcp6', 'tcp'),
                           ('/proc/net/udp', 'udp'), ('/proc/net/udp6', 'udp')):
        try:
            with open(path) as f:
                rows = f.readlines()[1:]
            sockets[protocol + '_total'] += len(rows)
            if protocol == 'tcp':
                states = [row.split()[3] for row in rows if len(row.split()) > 3]
                sockets['tcp_established'] += states.count('01')
                sockets['tcp_listening'] += states.count('0A')
        except OSError:
            pass
    return {'interfaces': interfaces, 'sockets': sockets}


def get_storage_telemetry():
    """Collect root capacity and kernel block-device I/O counters."""
    storage = {'filesystems': [], 'io': []}
    try:
        usage = shutil.disk_usage('/')
        storage['filesystems'].append({
            'mount': '/', 'total_bytes': usage.total, 'used_bytes': usage.used,
            'free_bytes': usage.free,
            'used_percent': round((usage.used / usage.total) * 100, 1) if usage.total else 0.0,
        })
    except OSError:
        pass
    try:
        with open('/proc/diskstats') as f:
            for line in f:
                parts = line.split()
                if len(parts) < 14 or parts[2].startswith(('loop', 'ram')):
                    continue
                storage['io'].append({
                    'device': parts[2], 'reads_completed': int(parts[3]),
                    'bytes_read': int(parts[5]) * 512,
                    'writes_completed': int(parts[7]), 'bytes_written': int(parts[9]) * 512,
                    'io_time_ms': int(parts[12]),
                })
    except (OSError, ValueError):
        pass
    return storage


def get_service_status():
    """Check status of common services."""
    services = [
        'sshd', 'ssh', 'nginx', 'apache2', 'httpd', 'docker', 'postgresql',
        'mysql', 'mariadb', 'redis-server', 'redis', 'cron', 'fail2ban',
    ]
    result = []
    for svc in services:
        try:
            ret = subprocess.call(
                ['systemctl', 'is-active', '--quiet', svc],
                stderr=subprocess.DEVNULL, timeout=5
            )
            if ret == 0:
                result.append({'name': svc, 'status': 'active'})
            else:
                # Only include if it exists
                ret2 = subprocess.call(
                    ['systemctl', 'list-unit-files', f'{svc}.service'],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5
                )
                if ret2 == 0:
                    result.append({'name': svc, 'status': 'inactive'})
        except Exception:
            pass
    return result


def collect_report():
    """Collect full system report."""
    started = time.monotonic()
    collectors = {}

    def collect(name, callback, fallback):
        collector_started = time.monotonic()
        try:
            value = callback()
            collectors[name] = {
                'status': 'ok',
                'duration_ms': round((time.monotonic() - collector_started) * 1000, 1),
                'records': len(value) if isinstance(value, list) else None,
            }
            return value
        except Exception as exc:
            collectors[name] = {
                'status': 'error',
                'duration_ms': round((time.monotonic() - collector_started) * 1000, 1),
                'error': type(exc).__name__,
            }
            return fallback

    report = {
        'telemetry_schema_version': TELEMETRY_SCHEMA_VERSION,
        'agent_version': __version__,
        'capabilities': AGENT_CAPABILITIES,
        'report_type': 'full',
        'hostname': get_hostname(),
        'ip': get_primary_ip(),
        'os_info': collect('os', get_os_info, {}),
        'ips': collect('interfaces', get_ips, []),
        'packages': collect('packages', get_packages, []),
        'ports': collect('ports', get_open_ports, []),
        'system_info': collect('system', get_system_info, {}),
        'services': collect('services', get_service_status, []),
        'performance': collect('performance', get_performance_telemetry, {}),
        'processes': collect('processes', get_process_telemetry, {}),
        'network': collect('network', get_network_telemetry, {}),
        'storage': collect('storage', get_storage_telemetry, {}),
    }
    report['package_count'] = len(report['packages'])
    report['telemetry'] = {
        'collectors': collectors,
        'duration_ms': round((time.monotonic() - started) * 1000, 1),
        'collected_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    }
    report['collected_at'] = report['telemetry']['collected_at']
    return report


def api_request(server, endpoint, data=None, key=None, method='POST', quiet=False):
    """Make an authenticated JSON request to the Artemis server."""
    url = f"{server.rstrip('/')}/api/v1{endpoint}"
    body = json.dumps(data).encode() if data is not None else None
    headers = {'Content-Type': 'application/json'}
    if key:
        headers['X-Agent-Key'] = key

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if not quiet:
            response_body = e.read().decode() if e.fp else ''
            print(f"HTTP {e.code}: {response_body}", file=sys.stderr)
        return None
    except Exception as e:
        if not quiet:
            print(f"Error: {e}", file=sys.stderr)
        return None


def api_call(server, endpoint, data=None, key=None):
    """Backward-compatible POST helper for registration and reports."""
    return api_request(server, endpoint, data=data, key=key, method='POST')


class RemotePty:
    """One local shell attached to a POSIX pseudo-terminal."""

    def __init__(self, session_id, cols=120, rows=32):
        self.session_id = session_id
        self.pid = None
        self.fd = None
        self.exit_code = None
        self.start(cols, rows)

    def start(self, cols, rows):
        pid, fd = pty.fork()
        if pid == 0:
            shell = shutil.which('bash') or shutil.which('sh') or '/bin/sh'
            env = os.environ.copy()
            env.update({'TERM': 'xterm-256color', 'HISTFILE': '/dev/null', 'ARTEMIS_REMOTE_SHELL': '1'})
            os.execvpe(shell, [shell, '-l'], env)
        self.pid = pid
        self.fd = fd
        os.set_blocking(fd, False)
        self.resize(cols, rows)

    def resize(self, cols, rows):
        if self.fd is None:
            return
        size = struct.pack('HHHH', max(5, int(rows)), max(20, int(cols)), 0, 0)
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, size)

    def write(self, data):
        if self.fd is None or not data:
            return
        remaining = memoryview(data)
        deadline = time.monotonic() + 2
        while remaining:
            _, writable, _ = select.select([], [self.fd], [], 0.25)
            if not writable:
                if time.monotonic() >= deadline:
                    raise TimeoutError('PTY input timed out')
                continue
            try:
                written = os.write(self.fd, remaining)
            except BlockingIOError:
                continue
            remaining = remaining[written:]

    def read(self, maximum=64 * 1024):
        if self.fd is None:
            return b''
        output = bytearray()
        while len(output) < maximum:
            ready, _, _ = select.select([self.fd], [], [], 0)
            if not ready:
                break
            try:
                chunk = os.read(self.fd, min(8192, maximum - len(output)))
            except (BlockingIOError, OSError):
                break
            if not chunk:
                break
            output.extend(chunk)
        return bytes(output)

    def poll(self):
        if self.pid is None or self.exit_code is not None:
            return self.exit_code
        try:
            waited, status = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError:
            self.exit_code = 0
            return self.exit_code
        if waited:
            if os.WIFEXITED(status):
                self.exit_code = os.WEXITSTATUS(status)
            elif os.WIFSIGNALED(status):
                self.exit_code = -os.WTERMSIG(status)
            else:
                self.exit_code = 0
        return self.exit_code

    def close(self):
        if self.pid is not None and self.poll() is None:
            try:
                os.kill(self.pid, signal.SIGHUP)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 2
            while self.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            if self.poll() is None:
                try:
                    os.kill(self.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.poll()
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None
        return self.exit_code


def _send_shell_event(server, key, session_id, event, **fields):
    return api_request(
        server,
        '/agents/shell/output',
        {'session_id': session_id, 'event': event, **fields},
        key=key,
        method='POST',
        quiet=True,
    )


def remote_shell_loop(server, key, stop_event=None):
    """Poll for operator-owned sessions and bridge them to a local PTY."""
    stop_event = stop_event or threading.Event()
    shell = None
    pending_output = bytearray()
    finished = None
    while not stop_event.is_set():
        response = api_request(
            server, '/agents/shell/poll', key=key, method='GET', quiet=True,
        )
        remote = response.get('session') if response else None

        if finished is not None:
            same_session = remote and remote.get('id') == finished['session_id']
            if response is not None and not same_session:
                # The controller already accepted the final event, even if its
                # response was lost before the agent received it.
                finished = None
                pending_output.clear()
            else:
                if pending_output:
                    chunk = bytes(pending_output[:64 * 1024])
                    result = _send_shell_event(
                        server, key, finished['session_id'], 'output',
                        data=base64.b64encode(chunk).decode('ascii'),
                    )
                    if result is not None:
                        del pending_output[:len(chunk)]
                if not pending_output:
                    result = _send_shell_event(
                        server, key, finished['session_id'], finished['event'],
                        **finished['fields'],
                    )
                    if result is not None:
                        finished = None
                stop_event.wait(0.35)
                continue

        if response is not None and remote is None and shell is not None:
            shell.close()
            shell = None
            pending_output.clear()

        if remote and remote.get('status') == 'closing' and shell is None:
            _send_shell_event(server, key, remote['id'], 'closed')
        elif remote and (shell is None or shell.session_id != remote['id']):
            if shell is not None:
                shell.close()
                pending_output.clear()
            try:
                shell = RemotePty(remote['id'], remote.get('cols', 120), remote.get('rows', 32))
                _send_shell_event(server, key, remote['id'], 'started')
            except Exception as exc:
                finished = {
                    'session_id': remote['id'], 'event': 'error',
                    'fields': {'error': str(exc)},
                }
                shell = None

        if remote and shell is not None:
            if remote.get('status') == 'closing':
                pending_output.extend(shell.read())
                exit_code = shell.close()
                finished = {
                    'session_id': remote['id'], 'event': 'closed',
                    'fields': {'exit_code': exit_code},
                }
                shell = None
            else:
                try:
                    if remote.get('status') == 'requested':
                        _send_shell_event(server, key, remote['id'], 'started')
                    shell.resize(remote.get('cols', 120), remote.get('rows', 32))
                    for item in remote.get('inputs', []):
                        shell.write(base64.b64decode(item.get('data', ''), validate=True))
                    if len(pending_output) < 64 * 1024:
                        pending_output.extend(shell.read(64 * 1024 - len(pending_output)))
                    if pending_output:
                        chunk = bytes(pending_output[:64 * 1024])
                        result = _send_shell_event(
                            server, key, remote['id'], 'output',
                            data=base64.b64encode(chunk).decode('ascii'),
                        )
                        if result is not None:
                            del pending_output[:len(chunk)]
                    exit_code = shell.poll()
                    if exit_code is not None:
                        pending_output.extend(shell.read())
                        shell.close()
                        finished = {
                            'session_id': remote['id'], 'event': 'exited',
                            'fields': {'exit_code': exit_code},
                        }
                        shell = None
                except Exception as exc:
                    shell.close()
                    finished = {
                        'session_id': remote['id'], 'event': 'error',
                        'fields': {'error': str(exc)},
                    }
                    shell = None

        stop_event.wait(0.35 if shell is not None else 2.0)

    if shell is not None:
        shell.close()


def do_register(server, name=None):
    """Register this agent with the server."""
    data = {
        'hostname': get_hostname(),
        'ip': get_primary_ip(),
        'os_info': get_os_info(),
        'agent_version': __version__,
        'capabilities': AGENT_CAPABILITIES,
        'name': name or get_hostname(),
    }
    result = api_call(server, '/agents/register', data)
    if result and 'agent_key' in result:
        cfg = load_config()
        cfg['server'] = server
        cfg['key'] = result['agent_key']
        cfg['agent_id'] = result['agent_id']
        path = save_config(cfg)
        print(f"Registered! Agent ID: {result['agent_id']}")
        print(f"Agent key saved to: {path}")
        print(f"Key: {result['agent_key']}")
        return result['agent_key']
    else:
        print("Registration failed.", file=sys.stderr)
        return None


def do_report(server, key):
    """Collect and send a report."""
    print("Collecting system data...")
    report = collect_report()
    pkg_count = len(report.get('packages', []))
    port_count = len(report.get('ports', []))
    print(f"  Packages: {pkg_count}, Open ports: {port_count}")
    print(f"Sending report to {server}...")
    result = api_call(server, '/agents/report', report, key=key)
    if result:
        print(f"Report accepted (ID: {result.get('report_id')}). CVEs matched: {result.get('vulns_matched', 0)}")
        return True
    else:
        print("Report failed.", file=sys.stderr)
        return False


def do_deregister(server, key, keep_config=False):
    """Remove this agent from the server, then delete the local config."""
    if server and key:
        print(f"Deregistering from {server}...")
        result = api_call(server, '/agents/deregister', {}, key=key)
        if result and result.get('status') == 'deregistered':
            print(f"Server removed agent #{result.get('id')}.")
        else:
            print("Server did not confirm removal (continuing with local cleanup).",
                  file=sys.stderr)
    else:
        print("No server/key in config — skipping server deregistration.", file=sys.stderr)

    if keep_config:
        return True
    for path in remove_config():
        print(f"Removed {path}")
    return True


def main():
    parser = argparse.ArgumentParser(description='Artemis Agent')
    parser.add_argument('--server', help='Artemis server URL')
    parser.add_argument('--key', help='Agent API key')
    parser.add_argument('--register', action='store_true', help='Register this agent')
    parser.add_argument('--name', help='Agent friendly name (for registration)')
    parser.add_argument('--once', action='store_true', help='Run once and exit')
    parser.add_argument('--deregister', action='store_true',
                        help='Remove this agent from the server and delete local config')
    parser.add_argument('--keep-config', action='store_true',
                        help='With --deregister, leave the local config file in place')
    parser.add_argument('--interval', type=int, help=f'Report interval in seconds (default: {DEFAULT_INTERVAL})')
    parser.add_argument('--version', action='version', version=f'artemis-agent {__version__}')
    parser.add_argument('--disable-remote-shell', action='store_true',
                        help='Disable polling for admin-initiated remote shell sessions')
    args = parser.parse_args()

    cfg = load_config()
    server = args.server or cfg.get('server')
    key = args.key or cfg.get('key')
    interval = args.interval or cfg.get('interval', DEFAULT_INTERVAL)

    if args.deregister:
        do_deregister(server, key, keep_config=args.keep_config)
        return

    if not server:
        print("Error: --server required (or set in config file)", file=sys.stderr)
        sys.exit(1)

    if args.register:
        do_register(server, args.name)
        return

    if not key:
        print("Error: --key required (or register first with --register)", file=sys.stderr)
        sys.exit(1)

    if args.once:
        success = do_report(server, key)
        sys.exit(0 if success else 1)

    # Continuous mode
    print(f"Artemis Agent v{__version__} starting (interval: {interval}s)")
    shell_enabled = not args.disable_remote_shell and cfg.get('remote_shell_enabled', True)
    if shell_enabled:
        threading.Thread(target=remote_shell_loop, args=(server, key), daemon=True).start()
        print("Remote shell polling enabled")
    while True:
        try:
            do_report(server, key)
        except Exception as e:
            print(f"Report error: {e}", file=sys.stderr)
        time.sleep(interval)


if __name__ == '__main__':
    main()
