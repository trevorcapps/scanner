"""JARM TLS fingerprinting wrapper for Artemis.

Uses the vendored Salesforce JARM scanner to generate TLS fingerprints
for identifying server software by TLS handshake behavior.
"""

import logging
import socket
import hashlib
import struct
import concurrent.futures
from typing import Optional, Dict, List, Tuple

logger = logging.getLogger(__name__)

# Known JARM hashes for common services
KNOWN_JARM_HASHES = {
    # nginx
    "27d40d40d29d40d1dc42d43d00041d4689ee210f1f09e22e273e9a2bae18e6": "nginx",
    "27d40d40d29d40d1dc42d43d00041d2aa5ce6a70de7ba95aef77a77b00a0af": "nginx",
    "29d29d15d29d29d21c29d29d29d29de7d922e5f22e54553e33a039e5f8493e": "nginx",
    # Apache
    "2ad2ad16d2ad2ad22c2ad2ad2ad2ad6a7bd3e76a556e04b5ab03434c2763e5": "Apache httpd",
    "2ad2ad0002ad2ad22c2ad2ad2ad2ade1a3c0d7ca6ad8388057924be83dfc6": "Apache httpd",
    # IIS
    "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1": "Microsoft IIS",
    "07d14d16d21d21d00042d41d00041de5fb3038b23b6e814fee33f0e42a1a35": "Microsoft IIS",
    # Cobalt Strike (C2 framework — high interest for security)
    "07d14d16d21d21d07c07d14d07d21d9b2f5869a6985368a9dec764186a9175": "Cobalt Strike",
    "07d14d16d21d21d07c42d43d000000f50d155305214cf247147c43c0f1a823": "Cobalt Strike",
    "21d10d00021d21d21c21d10d21d21d000000f50d155305214cf247147c43c0": "Cobalt Strike",
    # OpenSSH
    "00000000000000000000000000000000000000000000000000000000000000": "No TLS / Connection failed",
    # Cloudflare
    "27d3ed3ed0003ed1dc42d43d00041d6183ff1bfae51ebd88d70016d95d4a34": "Cloudflare",
    # Tor
    "29d21b20d29d29d21c41d21b21b41d494e0df9532e75299f15ba73156cee38": "Tor",
    # HAProxy
    "2ad2ad0002ad2ad0002ad2ad2ad2ade1a3c0d7ca6ad8388057924be83dfc6": "HAProxy",
}


def _scan_jarm(host: str, port: int, timeout: int = 10) -> Optional[str]:
    """Scan a single host:port and return JARM hash.

    Uses the vendored jarm_scanner module functions.
    Returns JARM hash string or None on failure.
    """
    try:
        # Import vendored jarm functions
        from fingerprint import jarm_scanner

        # JARM sends 10 probes with different TLS parameters
        jarm_details_list = [
            # (tls_version, ciphers, extensions, grease, ALPN, version_support, extension_order)
            ("tls1_2", "ALL", "no_support", "1_2_FORWARD", "no_support", "forward"),
            ("tls1_2", "ALL", "no_support", "1_2_REVERSE", "no_support", "reverse"),
            ("tls1_2", "ALL", "no_support", "1_2_TOP_HALF", "no_support", "forward"),
            ("tls1_2", "ALL", "no_support", "1_2_BOTTOM_HALF", "no_support", "forward"),
            ("tls1_2", "ALL", "no_support", "1_2_MIDDLE_OUT", "no_support", "forward"),
            ("tls1_1", "ALL", "no_support", "1_1_FORWARD", "no_support", "forward"),
            ("tls1_3", "ALL", "1_3_SUPPORT", "1_3_FORWARD", "1_3_SUPPORT", "forward"),
            ("tls1_3", "ALL", "1_3_SUPPORT", "1_3_REVERSE", "1_3_SUPPORT", "reverse"),
            ("tls1_3", "ALL", "no_support", "1_3_MIDDLE_OUT", "1_3_SUPPORT", "forward"),
            ("tls1_3", "ALL", "1_3_SUPPORT", "1_3_FORWARD", "no_support", "forward"),
        ]

        raw_results = []
        for probe_idx, details in enumerate(jarm_details_list):
            try:
                packet = jarm_scanner.packet_building(details)
                # Add SNI
                sni_ext = jarm_scanner.extension_server_name(host)
                # Build and send
                jarm_scanner.send_packet.__defaults__ = None  # Reset if needed

                # Use low-level socket to send probe
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((host, port))
                sock.sendall(packet)

                # Read response
                data = b""
                try:
                    while True:
                        chunk = sock.recv(1484)
                        if not chunk:
                            break
                        data += chunk
                        if len(data) > 100:
                            break
                except socket.timeout:
                    pass
                finally:
                    sock.close()

                ans = jarm_scanner.read_packet(data, details)
                raw_results.append(ans)
            except Exception:
                raw_results.append("|||")

        # Hash the results
        jarm_raw = ",".join(raw_results)
        return jarm_scanner.jarm_hash(jarm_raw)

    except Exception as e:
        logger.debug(f"JARM scan failed for {host}:{port}: {e}")
        return None


def scan_jarm_simple(host: str, port: int, timeout: int = 10) -> Optional[str]:
    """Simplified JARM scan using subprocess to call the vendored script.

    This is more reliable than trying to import individual functions.
    """
    import subprocess
    import os

    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'jarm_scanner.py')

    try:
        result = subprocess.run(
            ['python3', script_path, host, '-p', str(port)],
            capture_output=True, text=True, timeout=timeout * 12  # 10 probes
        )

        if result.returncode == 0:
            output = result.stdout.strip()
            # Output format: "host,port,jarm_hash"
            for line in output.split('\n'):
                parts = line.strip().split(',')
                if len(parts) >= 3:
                    jarm_hash = parts[-1].strip()
                    if len(jarm_hash) == 62:
                        return jarm_hash
        return None
    except subprocess.TimeoutExpired:
        logger.debug(f"JARM scan timed out for {host}:{port}")
        return None
    except Exception as e:
        logger.debug(f"JARM scan error for {host}:{port}: {e}")
        return None


def identify_jarm(jarm_hash: str) -> Optional[str]:
    """Look up a JARM hash against known signatures.

    Returns identified service name or None.
    """
    if not jarm_hash:
        return None
    return KNOWN_JARM_HASHES.get(jarm_hash)


def scan_host_tls_ports(host: str, ports: List[Dict], timeout: int = 10,
                         log_callback=None) -> List[Dict]:
    """Scan all TLS-capable ports on a host for JARM fingerprints.

    Args:
        host: Target IP/hostname
        ports: List of port dicts with 'port' and 'service' keys
        timeout: Timeout per probe in seconds
        log_callback: Optional callback for progress logging

    Returns:
        List of dicts: [{port, jarm_hash, identified_as}]
    """
    # Identify TLS-capable ports
    tls_ports = []
    tls_services = {'https', 'ssl', 'tls', 'imaps', 'smtps', 'pop3s', 'ldaps', 'ftps'}
    tls_port_numbers = {443, 8443, 993, 995, 465, 636, 989, 990}

    for p in ports:
        port_num = p.get('port', 0)
        service = (p.get('service', '') or '').lower()
        if port_num in tls_port_numbers or service in tls_services or 'ssl' in service or 'tls' in service:
            tls_ports.append(port_num)

    if not tls_ports:
        return []

    if log_callback:
        log_callback(f"JARM scanning {len(tls_ports)} TLS port(s) on {host}")

    results = []

    # Run JARM scans (sequentially to avoid socket issues)
    for port in tls_ports:
        if log_callback:
            log_callback(f"  JARM scanning {host}:{port}...")

        jarm_hash = scan_jarm_simple(host, port, timeout=timeout)

        if jarm_hash and jarm_hash != "0" * 62:
            identified = identify_jarm(jarm_hash)
            results.append({
                'port': port,
                'jarm_hash': jarm_hash,
                'identified_as': identified,
            })
            if log_callback:
                id_str = f" ({identified})" if identified else ""
                log_callback(f"  JARM {host}:{port}: {jarm_hash[:20]}...{id_str}")
        else:
            if log_callback:
                log_callback(f"  JARM {host}:{port}: no TLS response")

    return results
