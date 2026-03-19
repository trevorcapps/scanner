"""Nmap scanner wrapper — extracted from vuln_scan.py."""

import os
import logging

import nmap

from artemis.utils.validation import validate_ip, validate_hostname
from artemis.utils.dns import ScanError

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def scan(ip, options=None):
    """Execute Nmap scan on the given target (IP address or hostname).

    Args:
        ip: Target IP address or hostname
        options: Dict with optional scan settings:
            - ports: Port range string (e.g., '1-1000', '22,80,443', '-' for all)
            - scan_speed: Timing template (T2, T3, T4, T5)
            - host_timeout: Timeout in seconds per host
            - vulscan: Enable vulscan NSE script
    """
    if not validate_ip(ip) and not validate_hostname(ip):
        raise ScanError(f"Invalid target: {ip}")

    nm = nmap.PortScanner()

    args = ['-sV']

    if options:
        scan_speed = options.get('scan_speed', 'T3')
        if scan_speed in ['T2', 'T3', 'T4', 'T5']:
            args.append(f'-{scan_speed}')

        host_timeout = options.get('host_timeout', 300)
        try:
            host_timeout = max(30, min(3600, int(host_timeout)))
        except (ValueError, TypeError):
            host_timeout = 300
        args.append(f'--host-timeout {host_timeout}')
    else:
        args.append('--host-timeout 300')

    # Add vulscan NSE script if enabled
    if options and options.get('vulscan'):
        vulscan_path = os.path.join(BASE_DIR, 'vulscan', 'vulscan.nse')
        if os.path.isfile(vulscan_path):
            args.append(f'--script={vulscan_path}')
            args.append('--script-args "vulscandb=cve.csv"')
            logger.info("Vulscan NSE enabled for this scan")
        else:
            logger.warning("Vulscan requested but vulscan.nse not found")

    arguments = ' '.join(args)

    port_spec = None
    if options and options.get('ports'):
        port_spec = options['ports'].strip()
        if port_spec == '-':
            port_spec = '1-65535'

    try:
        logger.info(f"Starting scan for IP: {ip} with args: {arguments}, ports: {port_spec or 'default'}")
        if port_spec:
            nm.scan(ip, ports=port_spec, arguments=arguments)
        else:
            nm.scan(ip, arguments=arguments)

        all_hosts = nm.all_hosts()
        if ip in all_hosts:
            scan_key = ip
        elif all_hosts:
            scan_key = all_hosts[0]
        else:
            raise ScanError(f"Host {ip} is unreachable or returned no results")

        logger.info(f"Scan completed for target: {ip}")
        return nm[scan_key]
    except nmap.PortScannerError as e:
        logger.error(f"Nmap error scanning {ip}: {e}")
        raise ScanError(f"Nmap error: {e}")
    except Exception as e:
        logger.error(f"Unexpected error scanning {ip}: {e}")
        raise ScanError(f"Scan failed: {e}")


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
