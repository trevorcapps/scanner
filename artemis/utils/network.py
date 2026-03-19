"""Network utilities."""

import re
import ipaddress
import logging

logger = logging.getLogger(__name__)


def sanitize_filename(ip):
    """Sanitize IP address for safe use in filenames."""
    return re.sub(r'[^0-9.]', '_', ip)


def expand_cidr(cidr, max_hosts=256):
    """Expand a CIDR notation to a list of IP addresses.

    Args:
        cidr: CIDR notation string (e.g., '10.1.0.0/24')
        max_hosts: Maximum number of hosts to return

    Returns:
        List of IP address strings
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        hosts = list(network.hosts())

        if len(hosts) > max_hosts:
            logger.warning(f"CIDR {cidr} has {len(hosts)} hosts, limiting to {max_hosts}")
            hosts = hosts[:max_hosts]

        return [str(ip) for ip in hosts]
    except ValueError as e:
        logger.error(f"Invalid CIDR notation {cidr}: {e}")
        return []
