"""Nuclei vulnerability scanner wrapper — extracted from vuln_scan.py."""

import os
import re
import json
import time
import logging
import subprocess
import tempfile

from artemis.utils.validation import validate_ip, validate_hostname
from artemis.utils.dns import ScanError

logger = logging.getLogger(__name__)


def check_nuclei_installed():
    """Check if nuclei is installed and available."""
    try:
        result = subprocess.run(['nuclei', '-version'],
                                capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            logger.info(f"Nuclei version: {result.stdout.strip() or result.stderr.strip()}")
            return True
    except FileNotFoundError:
        logger.error("Nuclei is not installed.")
    except subprocess.TimeoutExpired:
        logger.error("Nuclei version check timed out")
    except Exception as e:
        logger.error(f"Error checking nuclei: {e}")
    return False


def vuln_scan(ip, options=None, log_callback=None):
    """Execute Nuclei vulnerability scan on the given IP address.

    Args:
        ip: Target IP address
        options: Dict with optional scan settings
        log_callback: Optional callback function to receive log messages
    """
    if not validate_ip(ip) and not validate_hostname(ip):
        raise ScanError(f"Invalid target: {ip}")

    if not check_nuclei_installed():
        raise ScanError("Nuclei is not installed. Please install it from https://github.com/projectdiscovery/nuclei")

    output_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    output_file.close()

    try:
        cmd = [
            'nuclei',
            '-target', ip,
            '-jsonl',
            '-output', output_file.name,
            '-verbose',
            '-no-color',
            '-stats',
        ]

        if options:
            vuln_timeout = options.get('vuln_timeout', 600)
            try:
                vuln_timeout = max(60, min(3600, int(vuln_timeout)))
            except (ValueError, TypeError):
                vuln_timeout = 600
            cmd.extend(['-timeout', str(vuln_timeout)])

            severity = options.get('severity', 'critical,high,medium,low')
            if severity:
                cmd.extend(['-severity', severity])

            rate_limit = options.get('rate_limit', 150)
            try:
                rate_limit = max(10, min(1000, int(rate_limit)))
            except (ValueError, TypeError):
                rate_limit = 150
            cmd.extend(['-rate-limit', str(rate_limit)])

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
            severity = options.get('severity', 'all') if options else 'all'
            log_callback(f"Starting vulnerability scan with {severity} severity levels...")

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )

        stderr_lines = []
        timeout = int(options.get('vuln_timeout', 600)) + 60 if options else 660
        start_time = time.time()

        while True:
            if time.time() - start_time > timeout:
                process.kill()
                raise subprocess.TimeoutExpired(cmd, timeout)

            if process.poll() is not None:
                break

            try:
                if process.stderr:
                    line = process.stderr.readline()
                    if line:
                        line = line.strip()
                        stderr_lines.append(line)
                        # Forward every line of nuclei's live output to the
                        # trace window so scans can be troubleshot in-place.
                        if log_callback and line:
                            log_callback(f"nuclei: {line}")
                        logger.debug(f"Nuclei: {line}")
                else:
                    time.sleep(0.1)
            except Exception:
                time.sleep(0.1)

        remaining_stderr = process.stderr.read() if process.stderr else ""
        if remaining_stderr:
            stderr_lines.append(remaining_stderr.strip())
            if log_callback:
                for line in remaining_stderr.strip().split('\n'):
                    if line.strip():
                        log_callback(f"Nuclei: {line.strip()}")

        if process.returncode != 0:
            stderr_output = '\n'.join(stderr_lines)
            if 'error' in stderr_output.lower() and 'templates' not in stderr_output.lower():
                logger.warning(f"Nuclei stderr: {stderr_output}")

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
        try:
            if os.path.exists(output_file.name):
                os.unlink(output_file.name)
        except Exception:
            pass


def parse_vuln_scan(nuclei_results):
    """Parse Nuclei vulnerability scan results."""
    vulnerabilities = []

    if not nuclei_results:
        return vulnerabilities

    try:
        for result in nuclei_results:
            info = result.get('info', {})

            port = 0
            protocol = 'tcp'
            matched_at = result.get('matched-at', '') or result.get('matched', '')

            if matched_at:
                port_match = re.search(r':(\d+)(?:/|$)', matched_at)
                if port_match:
                    port = int(port_match.group(1))
                elif matched_at.startswith('https://'):
                    port = 443
                elif matched_at.startswith('http://'):
                    port = 80

            result_type = result.get('type', 'http')
            if result_type in ['tcp', 'udp']:
                protocol = result_type
            elif result_type == 'ssl':
                protocol = 'tcp'

            vuln_id = result.get('template-id', 'unknown')
            tags = info.get('tags', [])

            cve_id = None
            if isinstance(tags, list):
                for tag in tags:
                    if tag.upper().startswith('CVE-'):
                        cve_id = tag.upper()
                        break

            classification = info.get('classification', {})
            if not cve_id and classification:
                cve_ids = classification.get('cve-id', [])
                if cve_ids and len(cve_ids) > 0:
                    cve_id = cve_ids[0] if isinstance(cve_ids, list) else cve_ids

            if cve_id:
                vuln_id = cve_id

            severity = info.get('severity', 'info').lower()
            if severity not in ['critical', 'high', 'medium', 'low', 'info']:
                severity = 'info'

            description = info.get('description', '')
            if not description:
                description = info.get('name', vuln_id)

            references = info.get('reference', [])
            if isinstance(references, str):
                references = [references]

            vuln = {
                'port': port,
                'protocol': protocol,
                'vuln_id': vuln_id,
                'vuln_name': info.get('name', vuln_id),
                'severity': severity,
                'description': description[:1000] if description else '',
                'matched_at': matched_at,
                'template_id': result.get('template-id', ''),
                'tags': tags if isinstance(tags, list) else [],
                'references': references,
                'cvss_score': classification.get('cvss-score') if classification else None,
                'cwe_id': (
                    classification.get('cwe-id', [None])[0]
                    if classification and classification.get('cwe-id') else None
                ),
            }

            vulnerabilities.append(vuln)

    except Exception as e:
        logger.error(f"Error parsing Nuclei results: {e}")

    return vulnerabilities
