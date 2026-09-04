"""Nmap scanner wrapper — extracted from vuln_scan.py.

Runs the ``nmap`` binary directly (rather than through python-nmap's blocking
``PortScanner.scan``) so that nmap's own progress output can be streamed to the
live trace window while the scan runs. Results are collected from an XML output
file and parsed with python-nmap so the return shape is unchanged.
"""

import logging
import os
import shlex
import shutil
import subprocess
import tempfile

import nmap

from artemis.utils.validation import validate_ip, validate_hostname
from artemis.utils.dns import ScanError

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _build_args(options):
    """Build the nmap argument list (excluding target and output flags)."""
    args = ['-sV']

    scan_speed = 'T3'
    host_timeout = 300
    if options:
        candidate_speed = options.get('scan_speed', 'T3')
        if candidate_speed in ('T2', 'T3', 'T4', 'T5'):
            scan_speed = candidate_speed
        try:
            host_timeout = max(30, min(3600, int(options.get('host_timeout', 300))))
        except (ValueError, TypeError):
            host_timeout = 300

    args.append(f'-{scan_speed}')
    # An explicit unit is required — a bare number is interpreted as
    # milliseconds by nmap, which makes every host time out instantly.
    args.append('--host-timeout')
    args.append(f'{host_timeout}s')

    # Skip host discovery by default. Users scan targets they have explicitly
    # entered, and ICMP/ping probes are frequently dropped (firewalls, Docker
    # bridge networking), which otherwise makes nmap report the host as down
    # and scan nothing. Set options['host_discovery'] = True to re-enable pings.
    if not (options and options.get('host_discovery')):
        args.append('-Pn')

    if options and options.get('vulscan'):
        vulscan_path = os.path.join(BASE_DIR, 'vulscan', 'vulscan.nse')
        if os.path.isfile(vulscan_path):
            args.append(f'--script={vulscan_path}')
            args.append('--script-args')
            args.append('vulscandb=cve.csv')
            logger.info("Vulscan NSE enabled for this scan")
        else:
            logger.warning("Vulscan requested but vulscan.nse not found")

    return args


def _port_spec(options):
    if options and options.get('ports'):
        spec = str(options['ports']).strip()
        return '1-65535' if spec == '-' else spec
    return None


def scan(ip, options=None, log_callback=None, cancel_check=None):
    """Execute an Nmap scan on the given target (IP address or hostname).

    Args:
        ip: Target IP address or hostname
        options: Dict with optional scan settings (ports, scan_speed,
            host_timeout, vulscan)
        log_callback: Optional ``callable(str)`` that receives each line of
            nmap's live output.
        cancel_check: Optional ``callable() -> bool``; when it returns True the
            running nmap process is terminated.

    Returns:
        A python-nmap host result dict (as returned by ``PortScanner[host]``).
    """
    if not validate_ip(ip) and not validate_hostname(ip):
        raise ScanError(f"Invalid target: {ip}")

    nmap_bin = shutil.which('nmap')
    if not nmap_bin:
        raise ScanError("nmap is not installed or not on PATH")

    args = _build_args(options)
    port_spec = _port_spec(options)

    xml_fd, xml_path = tempfile.mkstemp(prefix='artemis-nmap-', suffix='.xml')
    os.close(xml_fd)

    cmd = [nmap_bin, '-v', '--stats-every', '2s', '-oX', xml_path]
    cmd.extend(args)
    if port_spec:
        cmd.extend(['-p', port_spec])
    cmd.append(ip)

    printable = ' '.join(shlex.quote(part) for part in cmd)
    logger.info(f"Running nmap: {printable}")
    if log_callback:
        log_callback(f"$ {printable}")

    from artemis.scanners._process import ProcessCancelled, ProcessTimeout, run_streaming

    tail = []
    try:
        def _line(line):
            tail.append(line)
            if len(tail) > 40:
                tail.pop(0)
            if log_callback:
                log_callback(f"nmap: {line}")

        try:
            returncode, _ = run_streaming(
                cmd, cancel_check=cancel_check, line_callback=_line,
                timeout=(options or {}).get('_max_seconds'),
            )
        except FileNotFoundError:
            raise ScanError("nmap is not installed or not on PATH")
        except ProcessCancelled:
            if log_callback:
                log_callback("nmap: terminated (scan cancelled)")
            raise ScanError("Scan cancelled")
        except ProcessTimeout:
            raise ScanError("Nmap scan timed out")

        if not os.path.exists(xml_path) or os.path.getsize(xml_path) == 0:
            detail = tail[-1] if tail else f"nmap exited with code {returncode}"
            raise ScanError(f"Nmap produced no output: {detail}")

        with open(xml_path) as fh:
            xml_output = fh.read()

        nm = nmap.PortScanner()
        try:
            nm.analyse_nmap_xml_scan(nmap_xml_output=xml_output)
        except nmap.PortScannerError as e:
            raise ScanError(f"Failed to parse nmap output: {e}")

        all_hosts = nm.all_hosts()
        if ip in all_hosts:
            scan_key = ip
        elif all_hosts:
            scan_key = all_hosts[0]
        else:
            if returncode != 0:
                detail = tail[-1] if tail else f"exit code {returncode}"
                raise ScanError(f"Nmap error: {detail}")
            raise ScanError(f"Host {ip} is unreachable or returned no results")

        logger.info(f"Scan completed for target: {ip} (nmap exit {returncode})")
        if log_callback:
            log_callback(f"nmap: finished (exit {returncode})")
        return nm[scan_key]
    finally:
        try:
            os.unlink(xml_path)
        except OSError:
            pass


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
        if hasattr(scan_result, 'get') and 'osmatch' in scan_result:
            os_matches = scan_result.get('osmatch', [])
            if os_matches and len(os_matches) > 0:
                best_match = os_matches[0]
                os_info['os_name'] = best_match.get('name', None)
                os_info['os_accuracy'] = best_match.get('accuracy', None)

                os_classes = best_match.get('osclass', [])
                if os_classes and len(os_classes) > 0:
                    os_class = os_classes[0]
                    os_info['os_family'] = os_class.get('osfamily', None)
                    os_info['os_vendor'] = os_class.get('vendor', None)
                    os_info['device_type'] = os_class.get('type', None)

        if hasattr(scan_result, 'get') and 'hostscript' in scan_result:
            for script in scan_result.get('hostscript', []):
                if script.get('id') == 'smb-os-discovery':
                    output = script.get('output', '')
                    if 'OS:' in output:
                        for line in output.split('\n'):
                            if line.strip().startswith('OS:'):
                                os_info['os_name'] = line.split('OS:')[1].strip()
                                break
    except Exception as e:
        logger.debug(f"Error extracting OS info: {e}")

    return os_info


def extract_host_info_from_scan(scan_result):
    """Extract hostname, MAC address, and vendor from nmap scan result."""
    from device_type import lookup_mac_vendor

    info = {
        'hostname': None,
        'mac_address': None,
        'mac_vendor': None,
    }

    try:
        if not hasattr(scan_result, 'get'):
            return info

        hostnames = scan_result.get('hostnames', [])
        if hostnames:
            for hn in hostnames:
                name = hn.get('name', '')
                if name:
                    info['hostname'] = name
                    break

        addresses = scan_result.get('addresses', {})
        mac = addresses.get('mac')
        if mac:
            info['mac_address'] = mac
            vendor_dict = scan_result.get('vendor', {})
            if mac in vendor_dict:
                info['mac_vendor'] = vendor_dict[mac]

        if info['mac_address'] and not info['mac_vendor']:
            info['mac_vendor'] = lookup_mac_vendor(info['mac_address'])

    except Exception as e:
        logger.debug(f"Error extracting host info from scan: {e}")

    return info
