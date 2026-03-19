"""Celery tasks for async scanning.

These tasks are only functional when Celery is configured.
When Celery is not available, the app falls back to threading (see api/ handlers).
"""

import logging

logger = logging.getLogger(__name__)

# Try to import celery; if unavailable, tasks are defined but non-functional
try:
    from celery import shared_task

    @shared_task(bind=True, max_retries=2)
    def run_port_scan(self, target, options=None):
        """Run a port scan as a Celery task."""
        from artemis.scanners.nmap_scanner import scan, parse_scan
        from artemis.services.scan_service import store_scan
        from artemis.services.asset_service import store_asset_info
        from artemis.scanners.nmap_scanner import get_os_info_from_scan, extract_host_info_from_scan
        from artemis.utils.dns import dns_lookup

        scan_result = scan(target, options=options)
        scan_data = parse_scan(scan_result)

        os_info = get_os_info_from_scan(scan_result)
        host_info = extract_host_info_from_scan(scan_result)
        dns_info = dns_lookup(target)

        if host_info.get('hostname') and not dns_info.get('hostname'):
            dns_info['hostname'] = host_info['hostname']

        store_asset_info(target, dns_info=dns_info, os_info=os_info,
                         mac_address=host_info.get('mac_address'),
                         mac_vendor=host_info.get('mac_vendor'))

        if scan_data:
            store_scan(target, scan_data)

        return {'ip': target, 'ports': len(scan_data), 'success': True}

    @shared_task(bind=True, max_retries=2)
    def run_vuln_scan(self, target, options=None):
        """Run a Nuclei vulnerability scan as a Celery task."""
        from artemis.scanners.nuclei_scanner import vuln_scan, parse_vuln_scan
        from artemis.services.vuln_service import store_vulnerabilities

        results = vuln_scan(target, options=options)
        vulnerabilities = parse_vuln_scan(results)

        if vulnerabilities:
            store_vulnerabilities(target, vulnerabilities)

        return {'ip': target, 'vulns': len(vulnerabilities), 'success': True}

except ImportError:
    logger.debug("Celery not available — scan tasks will use threading fallback")

    def run_port_scan(target, options=None):
        raise RuntimeError("Celery not configured. Use threading fallback.")

    def run_vuln_scan(target, options=None):
        raise RuntimeError("Celery not configured. Use threading fallback.")
