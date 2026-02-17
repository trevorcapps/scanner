"""
fingerprintx integration — protocol-level service identification.

Wraps the fingerprintx CLI binary (Go, by Praetorian) to perform actual
protocol handshakes against open ports. This identifies services that
HTTP-based fingerprinting can't reach: databases, SSH, RDP, SMTP,
LDAP, Kafka, Redis, Memcached, etc.

fingerprintx supports 51+ protocols including:
  Databases: MySQL, PostgreSQL, MSSQL, MongoDB, Redis, Elasticsearch,
             CouchDB, Cassandra, InfluxDB, Neo4j, Oracle
  Remote:    SSH, RDP, Telnet, VNC
  Mail:      SMTP, IMAP, POP3
  File:      FTP, SMB, Rsync
  Web:       HTTP, HTTPS (with Wappalyzer tech detection)
  Other:     DNS, LDAP, Kafka, MQTT, SNMP, NTP, Memcached, Modbus, IPMI
"""

import json
import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# Default paths to look for fingerprintx binary
FPX_SEARCH_PATHS = [
    os.path.expanduser('~/go/bin/fingerprintx'),
    '/usr/local/bin/fingerprintx',
    '/usr/bin/fingerprintx',
]


@dataclass
class FpxResult:
    """Result from fingerprintx for a single port."""
    ip: str
    port: int
    protocol: str  # tcp/udp
    service: str  # identified service name (e.g., "ssh", "mysql", "http")
    version: Optional[str] = None
    transport: str = 'tcp'
    metadata: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)

    def to_dict(self):
        d = {
            'ip': self.ip,
            'port': self.port,
            'protocol': self.protocol,
            'service': self.service,
            'transport': self.transport,
        }
        if self.version:
            d['version'] = self.version
        if self.metadata:
            d['metadata'] = self.metadata
        return d


def find_fingerprintx() -> Optional[str]:
    """Locate the fingerprintx binary."""
    # Try shutil.which first (respects PATH)
    path = shutil.which('fingerprintx')
    if path:
        return path

    # Check common install locations
    for p in FPX_SEARCH_PATHS:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p

    return None


def check_installed() -> bool:
    """Check if fingerprintx is installed and available."""
    path = find_fingerprintx()
    if path:
        logger.info(f"fingerprintx found at: {path}")
        return True
    logger.warning("fingerprintx not found. Install: go install github.com/praetorian-inc/fingerprintx/cmd/fingerprintx@latest")
    return False


def scan_targets(targets: list, timeout_ms: int = 3000, fast: bool = False,
                 udp: bool = False, log_callback=None) -> list:
    """Run fingerprintx against a list of ip:port targets.

    Args:
        targets: List of "ip:port" strings (e.g., ["10.1.0.1:22", "10.1.0.1:80"])
        timeout_ms: Timeout per probe in milliseconds (default 3000)
        fast: Use fast mode (only checks default service for port, no fallback)
        udp: Also run UDP plugins
        log_callback: Optional function(message) for progress logging

    Returns:
        List of FpxResult objects for identified services.
    """
    fpx_path = find_fingerprintx()
    if not fpx_path:
        logger.error("fingerprintx binary not found")
        if log_callback:
            log_callback("fingerprintx not installed — skipping protocol fingerprinting")
        return []

    if not targets:
        return []

    def log(msg):
        logger.info(msg)
        if log_callback:
            log_callback(msg)

    log(f"fingerprintx: scanning {len(targets)} target(s)")

    # Write targets to a temp file for -l flag (more reliable than -t for large lists)
    tmp_file = None
    try:
        tmp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
        for target in targets:
            tmp_file.write(target + '\n')
        tmp_file.close()

        # Build command
        cmd = [
            fpx_path,
            '-l', tmp_file.name,
            '--json',
            '-w', str(timeout_ms),
        ]
        if fast:
            cmd.append('--fast')
        if udp:
            cmd.append('--udp')

        log(f"fingerprintx command: {' '.join(cmd)}")

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(30, (len(targets) * timeout_ms // 1000) + 30),
        )

        results = []

        # Parse JSON lines from stdout
        if proc.stdout:
            for line in proc.stdout.strip().split('\n'):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    result = _parse_fpx_json(data)
                    if result:
                        results.append(result)
                        ver_str = f' v{result.version}' if result.version else ''
                        log(f"fingerprintx: {result.ip}:{result.port} → {result.service}{ver_str}")
                except json.JSONDecodeError as e:
                    logger.debug(f"fingerprintx: non-JSON output: {line}")

        # Log stderr (errors/warnings)
        if proc.stderr:
            for line in proc.stderr.strip().split('\n'):
                if line.strip():
                    logger.debug(f"fingerprintx stderr: {line}")

        if proc.returncode != 0:
            logger.warning(f"fingerprintx exited with code {proc.returncode}")

        log(f"fingerprintx: identified {len(results)}/{len(targets)} service(s)")
        return results

    except subprocess.TimeoutExpired:
        logger.error("fingerprintx timed out")
        if log_callback:
            log_callback("fingerprintx: scan timed out")
        return []
    except FileNotFoundError:
        logger.error(f"fingerprintx binary not found at {fpx_path}")
        return []
    except Exception as e:
        logger.error(f"fingerprintx error: {e}")
        if log_callback:
            log_callback(f"fingerprintx error: {e}")
        return []
    finally:
        if tmp_file and os.path.exists(tmp_file.name):
            try:
                os.unlink(tmp_file.name)
            except Exception:
                pass


def scan_host(ip: str, ports: list, timeout_ms: int = 3000,
              fast: bool = False, udp: bool = False,
              log_callback=None) -> list:
    """Convenience: scan all ports for a single host.

    Args:
        ip: Target IP address
        ports: List of dicts with 'port' and optionally 'protocol' keys
        timeout_ms: Timeout per probe in ms
        fast: Fast mode
        udp: Include UDP
        log_callback: Optional logging callback

    Returns:
        List of FpxResult objects.
    """
    targets = []
    for p in ports:
        port_num = p if isinstance(p, int) else p.get('port', 0)
        if port_num > 0:
            targets.append(f"{ip}:{port_num}")

    return scan_targets(targets, timeout_ms=timeout_ms, fast=fast,
                        udp=udp, log_callback=log_callback)


def _parse_fpx_json(data: dict) -> Optional[FpxResult]:
    """Parse a single fingerprintx JSON output line into FpxResult."""
    try:
        # fingerprintx JSON format:
        # {"ip":"x.x.x.x","port":22,"service":"ssh","transport":"tcp",
        #  "metadata":{"version":"OpenSSH 8.2p1",...}}
        ip = data.get('ip', data.get('host', ''))
        port = data.get('port', 0)
        service = data.get('service', '')
        transport = data.get('transport', 'tcp')
        metadata = data.get('metadata', {})

        if not ip or not port or not service:
            return None

        # Extract version from metadata
        version = None
        if isinstance(metadata, dict):
            version = metadata.get('version')
            if not version:
                # Some services put version in different metadata keys
                version = metadata.get('serverVersion')
                if not version:
                    version = metadata.get('banner', '')
                    # Try to extract version from banner
                    if version:
                        import re
                        ver_match = re.search(r'[\d]+\.[\d]+[\.\d]*', version)
                        if ver_match:
                            version = ver_match.group(0)
                        else:
                            version = None

        return FpxResult(
            ip=ip,
            port=port,
            protocol=transport,
            service=service,
            version=version,
            transport=transport,
            metadata=metadata if isinstance(metadata, dict) else {},
            raw=data,
        )
    except Exception as e:
        logger.debug(f"Error parsing fingerprintx JSON: {e}")
        return None
