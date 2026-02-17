"""
Fingerprint engine — probes endpoints and matches against signature database.

Techniques used:
  1. HTTP header analysis (Server, X-Powered-By, custom headers)
  2. HTML body pattern matching (regex against page content)
  3. Favicon hash matching (MD5/MMH3 of /favicon.ico)
  4. TLS certificate inspection (Subject CN, Org, SAN)
  5. Service banner / nmap product+version parsing
  6. URL path probing (known paths like /wp-login.php, /actuator/health)
"""

import hashlib
import json
import logging
import os
import re
import socket
import ssl
import struct
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

SIGNATURES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'signatures.json')


# ── Minimal MurmurHash3 (32-bit, x86) for favicon hashing ──────────────────

def _mmh3_32(data: bytes, seed: int = 0) -> int:
    """Pure-python MurmurHash3 32-bit implementation for favicon hashing.
    Returns a signed 32-bit integer (matching the mmh3 library convention).
    """
    length = len(data)
    nblocks = length // 4
    h1 = seed & 0xFFFFFFFF

    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    mask = 0xFFFFFFFF

    for i in range(nblocks):
        k1 = struct.unpack_from('<I', data, i * 4)[0]
        k1 = (k1 * c1) & mask
        k1 = ((k1 << 15) | (k1 >> 17)) & mask
        k1 = (k1 * c2) & mask

        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & mask
        h1 = (h1 * 5 + 0xE6546B64) & mask

    tail_idx = nblocks * 4
    k1 = 0
    tail_size = length & 3
    if tail_size >= 3:
        k1 ^= data[tail_idx + 2] << 16
    if tail_size >= 2:
        k1 ^= data[tail_idx + 1] << 8
    if tail_size >= 1:
        k1 ^= data[tail_idx]
        k1 = (k1 * c1) & mask
        k1 = ((k1 << 15) | (k1 >> 17)) & mask
        k1 = (k1 * c2) & mask
        h1 ^= k1

    h1 ^= length
    # fmix32
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & mask
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & mask
    h1 ^= h1 >> 16

    # Convert to signed 32-bit
    if h1 >= 0x80000000:
        h1 -= 0x100000000
    return h1


# ── Data classes ────────────────────────────────────────────────────────────

@dataclass
class FingerprintMatch:
    """A single matched signature with confidence and optional version."""
    signature_id: str
    name: str
    category: str
    vendor: str
    version: Optional[str] = None
    cpe: Optional[str] = None
    confidence: int = 0
    evidence: list = field(default_factory=list)

    def to_dict(self):
        d = {
            'signature_id': self.signature_id,
            'name': self.name,
            'category': self.category,
            'vendor': self.vendor,
            'confidence': self.confidence,
            'evidence': self.evidence,
        }
        if self.version:
            d['version'] = self.version
        if self.cpe:
            d['cpe'] = self.cpe
        return d


@dataclass
class FingerprintResult:
    """Full fingerprint result for an endpoint (ip:port)."""
    ip: str
    port: int
    protocol: str = 'tcp'
    matches: list = field(default_factory=list)  # List[FingerprintMatch]
    tls_info: dict = field(default_factory=dict)
    http_info: dict = field(default_factory=dict)
    raw_headers: dict = field(default_factory=dict)
    favicon_hash: Optional[int] = None
    errors: list = field(default_factory=list)

    @property
    def best_match(self) -> Optional[FingerprintMatch]:
        if not self.matches:
            return None
        return max(self.matches, key=lambda m: m.confidence)

    @property
    def technologies(self) -> list:
        """Return all matches sorted by confidence descending."""
        return sorted(self.matches, key=lambda m: m.confidence, reverse=True)

    def to_dict(self):
        d = {
            'ip': self.ip,
            'port': self.port,
            'protocol': self.protocol,
            'matches': [m.to_dict() for m in self.technologies],
            'errors': self.errors,
        }
        if self.tls_info:
            d['tls_info'] = self.tls_info
        if self.http_info:
            d['http_info'] = self.http_info
        if self.favicon_hash is not None:
            d['favicon_hash'] = self.favicon_hash
        return d


# ── Fingerprint Engine ──────────────────────────────────────────────────────

class FingerprintEngine:
    """Probes endpoints and matches against the signature database."""

    def __init__(self, signatures_path: str = None, timeout: int = 8):
        self.timeout = timeout
        self.signatures = []
        self._load_signatures(signatures_path or SIGNATURES_PATH)

    def _load_signatures(self, path: str):
        """Load signature database from JSON file."""
        try:
            with open(path, 'r') as f:
                data = json.load(f)
            self.signatures = data.get('signatures', [])
            logger.info(f"Loaded {len(self.signatures)} fingerprint signatures")
        except Exception as e:
            logger.error(f"Failed to load signatures from {path}: {e}")
            self.signatures = []

    # ── HTTP Probing ────────────────────────────────────────────────────

    def _http_probe(self, ip: str, port: int, use_tls: bool = False) -> dict:
        """Probe an HTTP(S) endpoint and return headers + body."""
        scheme = 'https' if use_tls else 'http'
        url = f'{scheme}://{ip}:{port}/'
        result = {
            'status_code': None,
            'headers': {},
            'body': '',
            'title': '',
            'redirect_url': None,
        }

        try:
            ctx = None
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'close',
            })

            # Use a custom opener that doesn't follow redirects so we can see the initial response
            class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None

            opener = urllib.request.build_opener(
                NoRedirectHandler,
                urllib.request.HTTPSHandler(context=ctx) if use_tls else urllib.request.HTTPHandler
            )

            with opener.open(req, timeout=self.timeout) as resp:
                result['status_code'] = resp.status
                result['headers'] = {k: v for k, v in resp.getheaders()}
                body_bytes = resp.read(512 * 1024)  # Read up to 512KB
                try:
                    result['body'] = body_bytes.decode('utf-8', errors='replace')
                except Exception:
                    result['body'] = body_bytes.decode('latin-1', errors='replace')

        except urllib.error.HTTPError as e:
            result['status_code'] = e.code
            result['headers'] = {k: v for k, v in e.headers.items()}
            try:
                body_bytes = e.read(512 * 1024)
                result['body'] = body_bytes.decode('utf-8', errors='replace')
            except Exception:
                pass
        except urllib.error.URLError as e:
            if hasattr(e, 'reason') and isinstance(e.reason, ssl.SSLError):
                # SSL error but redirect info might be in the error
                logger.debug(f"SSL error probing {url}: {e.reason}")
            else:
                logger.debug(f"URL error probing {url}: {e}")
            return result
        except Exception as e:
            logger.debug(f"Error probing {url}: {e}")
            return result

        # Extract title
        title_match = re.search(r'<title[^>]*>(.*?)</title>', result['body'], re.IGNORECASE | re.DOTALL)
        if title_match:
            result['title'] = title_match.group(1).strip()[:200]

        return result

    def _fetch_favicon(self, ip: str, port: int, use_tls: bool = False) -> Optional[int]:
        """Fetch /favicon.ico and return its MMH3 hash (Shodan-compatible)."""
        scheme = 'https' if use_tls else 'http'
        url = f'{scheme}://{ip}:{port}/favicon.ico'

        try:
            ctx = None
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                'Connection': 'close',
            })

            handler = urllib.request.HTTPSHandler(context=ctx) if use_tls else urllib.request.HTTPHandler()
            opener = urllib.request.build_opener(handler)

            with opener.open(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    data = resp.read(1024 * 1024)  # Max 1MB
                    if len(data) > 0:
                        # Shodan-style: base64 encode then MMH3
                        import base64
                        b64_data = base64.encodebytes(data)
                        return _mmh3_32(b64_data)
        except Exception as e:
            logger.debug(f"Favicon fetch failed for {url}: {e}")

        return None

    # ── TLS Inspection ──────────────────────────────────────────────────

    def _tls_inspect(self, ip: str, port: int) -> dict:
        """Connect with TLS and extract certificate details."""
        tls_info = {
            'subject_cn': None,
            'issuer_cn': None,
            'issuer_org': None,
            'subject_org': None,
            'san': [],
            'not_before': None,
            'not_after': None,
            'serial': None,
            'self_signed': False,
        }

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if not cert:
                        # Get binary cert if parsed isn't available (self-signed etc.)
                        der = ssock.getpeercert(binary_form=True)
                        if der:
                            tls_info['has_cert'] = True
                        return tls_info

                    # Extract subject fields
                    subject = dict(x[0] for x in cert.get('subject', ()))
                    issuer = dict(x[0] for x in cert.get('issuer', ()))

                    tls_info['subject_cn'] = subject.get('commonName')
                    tls_info['subject_org'] = subject.get('organizationName')
                    tls_info['issuer_cn'] = issuer.get('commonName')
                    tls_info['issuer_org'] = issuer.get('organizationName')
                    tls_info['not_before'] = cert.get('notBefore')
                    tls_info['not_after'] = cert.get('notAfter')
                    tls_info['serial'] = cert.get('serialNumber')

                    # Extract SAN
                    san = cert.get('subjectAltName', ())
                    tls_info['san'] = [value for typ, value in san if typ in ('DNS', 'IP Address')]

                    # Check if self-signed
                    tls_info['self_signed'] = (
                        subject.get('commonName') == issuer.get('commonName') and
                        subject.get('organizationName') == issuer.get('organizationName')
                    )

        except ssl.SSLError as e:
            logger.debug(f"TLS error for {ip}:{port}: {e}")
        except socket.timeout:
            logger.debug(f"TLS connection timeout for {ip}:{port}")
        except ConnectionRefusedError:
            logger.debug(f"Connection refused for TLS on {ip}:{port}")
        except Exception as e:
            logger.debug(f"TLS inspection error for {ip}:{port}: {e}")

        return tls_info

    # ── URL Path Probing ────────────────────────────────────────────────

    def _probe_path(self, ip: str, port: int, path: str, use_tls: bool = False) -> Optional[int]:
        """Probe a specific URL path, return HTTP status code or None."""
        scheme = 'https' if use_tls else 'http'
        url = f'{scheme}://{ip}:{port}{path}'

        try:
            ctx = None
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                'Connection': 'close',
            })

            handler = urllib.request.HTTPSHandler(context=ctx) if use_tls else urllib.request.HTTPHandler()
            opener = urllib.request.build_opener(handler)

            with opener.open(req, timeout=self.timeout) as resp:
                return resp.status

        except urllib.error.HTTPError as e:
            return e.code
        except Exception:
            return None

    # ── Signature Matching ──────────────────────────────────────────────

    def _match_signature(self, sig: dict, http_data: dict, tls_info: dict,
                         favicon_hash: Optional[int], nmap_data: dict) -> Optional[FingerprintMatch]:
        """Test one signature against collected data. Returns a match or None."""
        matches = sig.get('matches', {})
        confidence = 0
        evidence = []
        version = None
        hit_count = 0

        headers = http_data.get('headers', {})
        body = http_data.get('body', '')
        title = http_data.get('title', '')

        # ── Header matching ─────────────────────────────────────────────
        header_patterns = matches.get('headers', {})
        for header_name, pattern in header_patterns.items():
            for resp_header, resp_value in headers.items():
                if resp_header.lower() == header_name.lower():
                    if re.search(pattern, resp_value, re.IGNORECASE):
                        confidence += 40
                        hit_count += 1
                        evidence.append(f'header:{resp_header}={resp_value[:80]}')
                    break

        # ── HTML body pattern matching ──────────────────────────────────
        html_patterns = matches.get('html_patterns', [])
        html_hits = 0
        for pattern in html_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                html_hits += 1
                if html_hits <= 3:  # Don't add too many evidence items
                    evidence.append(f'html_match:{pattern[:50]}')
        if html_hits > 0:
            # More hits = more confidence, but diminishing returns
            confidence += min(20 + (html_hits * 12), 50)
            hit_count += html_hits

        # ── Favicon hash matching ───────────────────────────────────────
        favicon_hashes = matches.get('favicon_hashes', [])
        if favicon_hash is not None and favicon_hash in favicon_hashes:
            confidence += 50
            hit_count += 1
            evidence.append(f'favicon_hash:{favicon_hash}')

        # ── TLS cert org matching ───────────────────────────────────────
        tls_org_patterns = matches.get('tls_org_patterns', [])
        tls_orgs = ' '.join(filter(None, [
            tls_info.get('subject_org', ''),
            tls_info.get('issuer_org', ''),
            tls_info.get('subject_cn', ''),
        ]))
        for pattern in tls_org_patterns:
            if tls_orgs and re.search(pattern, tls_orgs, re.IGNORECASE):
                confidence += 35
                hit_count += 1
                evidence.append(f'tls_org:{pattern}')
                break

        # ── Banner / nmap service matching ──────────────────────────────
        banner_patterns = matches.get('banner_patterns', [])
        nmap_product = nmap_data.get('product', '')
        nmap_version = nmap_data.get('version', '')
        nmap_extra = nmap_data.get('extrainfo', '')
        nmap_service = nmap_data.get('service', '')
        banner_text = f'{nmap_product} {nmap_version} {nmap_extra}'.strip()

        for pattern in banner_patterns:
            if re.search(pattern, banner_text, re.IGNORECASE):
                confidence += 40
                hit_count += 1
                evidence.append(f'banner:{banner_text[:80]}')
                break

        nmap_services = matches.get('nmap_services', [])
        if nmap_service in nmap_services:
            confidence += 30
            hit_count += 1
            evidence.append(f'nmap_service:{nmap_service}')

        # ── Bail out if nothing matched ─────────────────────────────────
        if hit_count == 0:
            return None

        # ── Version extraction ──────────────────────────────────────────
        version_patterns = matches.get('version_patterns', {})

        # Try headers first
        header_version_patterns = version_patterns.get('headers', {})
        for header_name, pattern in header_version_patterns.items():
            for resp_header, resp_value in headers.items():
                if resp_header.lower() == header_name.lower():
                    m = re.search(pattern, resp_value, re.IGNORECASE)
                    if m:
                        version = m.group(1)
                        evidence.append(f'version_from_header:{version}')
                    break

        # Try HTML body
        if not version:
            html_version_patterns = version_patterns.get('html', [])
            for pattern in html_version_patterns:
                m = re.search(pattern, body, re.IGNORECASE)
                if m:
                    version = m.group(1)
                    evidence.append(f'version_from_html:{version}')
                    break

        # Try banner
        if not version:
            banner_version_patterns = version_patterns.get('banner', [])
            for pattern in banner_version_patterns:
                m = re.search(pattern, banner_text, re.IGNORECASE)
                if m:
                    version = m.group(1)
                    evidence.append(f'version_from_banner:{version}')
                    break

        # Try nmap version
        if not version and nmap_version:
            version = nmap_version

        # ── Compute final confidence ────────────────────────────────────
        base = sig.get('confidence_base', 50)
        # Scale: multiple detection methods increase confidence
        if hit_count >= 3:
            confidence += 15
        if hit_count >= 5:
            confidence += 10
        if version:
            confidence += 10

        # Normalize: confidence is raw points, scale relative to base
        # A single strong signal (40pts) with base 90 = 36% → too low
        # Instead: treat confidence as a percentage of "max possible"
        # and blend with base confidence
        raw_pct = min(confidence / 80, 1.0)  # 80 points = full confidence
        final_confidence = min(int(raw_pct * base), 100)

        # Build CPE string if we have a prefix and version
        cpe = None
        cpe_prefix = sig.get('cpe_prefix')
        if cpe_prefix:
            if version:
                cpe = f"{cpe_prefix}:{version}:*:*:*:*:*:*:*"
            else:
                cpe = f"{cpe_prefix}:*:*:*:*:*:*:*:*"

        return FingerprintMatch(
            signature_id=sig['id'],
            name=sig['name'],
            category=sig.get('category', 'unknown'),
            vendor=sig.get('vendor', 'unknown'),
            version=version,
            cpe=cpe,
            confidence=final_confidence,
            evidence=evidence,
        )

    # ── Main fingerprint method ─────────────────────────────────────────

    def fingerprint(self, ip: str, port: int, protocol: str = 'tcp',
                    nmap_service: str = '', nmap_product: str = '',
                    nmap_version: str = '', nmap_extrainfo: str = '',
                    log_callback=None) -> FingerprintResult:
        """Fingerprint a single endpoint using all available techniques.

        Args:
            ip: Target IP address
            port: Target port number
            protocol: Protocol (tcp/udp)
            nmap_service: Service name from nmap (e.g., 'http', 'ssh')
            nmap_product: Product name from nmap (e.g., 'Apache httpd')
            nmap_version: Version from nmap
            nmap_extrainfo: Extra info from nmap
            log_callback: Optional function(message) for progress logging

        Returns:
            FingerprintResult with all matches and collected data.
        """
        result = FingerprintResult(ip=ip, port=port, protocol=protocol)

        def log(msg):
            logger.info(msg)
            if log_callback:
                log_callback(msg)

        nmap_data = {
            'service': nmap_service,
            'product': nmap_product,
            'version': nmap_version,
            'extrainfo': nmap_extrainfo,
        }

        # Determine if this is likely an HTTP service
        http_services = {'http', 'https', 'http-proxy', 'https-alt', 'http-alt',
                         'ssl/http', 'ssl/https', 'http-mgmt'}
        is_http = (nmap_service.lower().replace('-', '').replace('/', '') in
                   {s.replace('-', '').replace('/', '') for s in http_services}
                   or port in {80, 443, 8080, 8443, 8000, 8888, 9090, 3000, 5000, 8081})
        is_tls = (port == 443 or 'ssl' in nmap_service.lower() or 'https' in nmap_service.lower()
                  or port in {8443, 9443, 4443})

        http_data = {'headers': {}, 'body': '', 'title': ''}
        tls_info = {}
        favicon_hash = None

        # ── Step 1: TLS inspection (if applicable) ──────────────────────
        if is_tls or port in {443, 8443, 9443, 4443}:
            log(f'Fingerprint: TLS inspection on {ip}:{port}')
            tls_info = self._tls_inspect(ip, port)
            result.tls_info = tls_info

        # ── Step 2: HTTP probing ────────────────────────────────────────
        if is_http:
            # Try HTTPS first if we think it's TLS
            if is_tls:
                log(f'Fingerprint: HTTPS probe on {ip}:{port}')
                http_data = self._http_probe(ip, port, use_tls=True)
            else:
                log(f'Fingerprint: HTTP probe on {ip}:{port}')
                http_data = self._http_probe(ip, port, use_tls=False)
                # If HTTP fails, try HTTPS (some ports serve HTTPS on non-standard ports)
                if not http_data.get('status_code'):
                    log(f'Fingerprint: Retrying as HTTPS on {ip}:{port}')
                    http_data = self._http_probe(ip, port, use_tls=True)
                    if http_data.get('status_code'):
                        is_tls = True
                        # Also grab TLS info if we haven't yet
                        if not tls_info:
                            tls_info = self._tls_inspect(ip, port)
                            result.tls_info = tls_info

            result.http_info = {
                'status_code': http_data.get('status_code'),
                'title': http_data.get('title', ''),
                'server': http_data.get('headers', {}).get('Server', ''),
            }
            result.raw_headers = http_data.get('headers', {})

            # ── Step 3: Favicon hash ────────────────────────────────────
            if http_data.get('status_code'):
                log(f'Fingerprint: Fetching favicon for {ip}:{port}')
                favicon_hash = self._fetch_favicon(ip, port, use_tls=is_tls)
                result.favicon_hash = favicon_hash

        # ── Step 4: Match against all signatures ────────────────────────
        log(f'Fingerprint: Matching against {len(self.signatures)} signatures')
        for sig in self.signatures:
            try:
                match = self._match_signature(sig, http_data, tls_info, favicon_hash, nmap_data)
                if match and match.confidence > 0:
                    result.matches.append(match)
            except Exception as e:
                logger.debug(f"Error matching signature {sig.get('id')}: {e}")

        # ── Step 5: URL path probing for top candidates ─────────────────
        if is_http and result.matches:
            # Only probe paths for the top 5 candidates to limit requests
            top_matches = sorted(result.matches, key=lambda m: m.confidence, reverse=True)[:5]
            for match in top_matches:
                sig = next((s for s in self.signatures if s['id'] == match.signature_id), None)
                if not sig:
                    continue
                url_paths = sig.get('matches', {}).get('url_paths', [])
                for path in url_paths[:2]:  # Max 2 paths per signature
                    status = self._probe_path(ip, port, path, use_tls=is_tls)
                    if status and status < 404:
                        match.confidence = min(match.confidence + 10, 100)
                        match.evidence.append(f'url_path:{path}={status}')
                        log(f'Fingerprint: Path probe {path} returned {status} for {match.name}')

        # Sort final results
        result.matches.sort(key=lambda m: m.confidence, reverse=True)

        # Log summary
        if result.matches:
            best = result.best_match
            log(f'Fingerprint result for {ip}:{port}: {best.name}'
                f'{" v" + best.version if best.version else ""}'
                f' ({best.confidence}% confidence, {best.category})')
        else:
            log(f'Fingerprint: No matches for {ip}:{port} (service: {nmap_service})')

        return result

    def fingerprint_all_ports(self, ip: str, ports: list, log_callback=None) -> list:
        """Fingerprint all open ports for a host.

        Args:
            ip: Target IP address
            ports: List of dicts with keys: port, protocol, service, product, version, extrainfo
            log_callback: Optional logging callback

        Returns:
            List of FingerprintResult for each port.
        """
        results = []
        for port_info in ports:
            try:
                result = self.fingerprint(
                    ip=ip,
                    port=port_info.get('port', 0),
                    protocol=port_info.get('protocol', 'tcp'),
                    nmap_service=port_info.get('service', ''),
                    nmap_product=port_info.get('product', ''),
                    nmap_version=port_info.get('version', ''),
                    nmap_extrainfo=port_info.get('extrainfo', ''),
                    log_callback=log_callback,
                )
                results.append(result)
            except Exception as e:
                logger.error(f"Error fingerprinting {ip}:{port_info.get('port')}: {e}")

        return results
