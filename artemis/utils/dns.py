"""DNS lookup functions."""

import socket
import logging

from artemis.utils.validation import validate_ip, validate_hostname

logger = logging.getLogger(__name__)


class ScanError(Exception):
    """Custom exception for scan-related errors."""
    pass


def dns_lookup(ip):
    """Perform DNS lookups for an IP address.

    Returns a dict with hostname, reverse DNS, and any additional DNS info.
    """
    result = {
        'hostname': None,
        'reverse_dns': None,
        'aliases': [],
        'dns_names': []
    }

    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip)
        result['hostname'] = hostname
        result['reverse_dns'] = hostname
        result['aliases'] = list(aliases) if aliases else []
        logger.info(f"DNS lookup for {ip}: hostname={hostname}")
    except socket.herror as e:
        logger.debug(f"No reverse DNS for {ip}: {e}")
    except socket.gaierror as e:
        logger.debug(f"DNS lookup failed for {ip}: {e}")
    except Exception as e:
        logger.warning(f"Unexpected error in DNS lookup for {ip}: {e}")

    return result


def resolve_target(target):
    """Resolve a hostname to an IP address.

    Prefers IPv4 addresses. Returns the resolved IP string.
    Raises ScanError if resolution fails.
    """
    try:
        results = socket.getaddrinfo(target, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ipv4 = [r for r in results if r[0] == socket.AF_INET]
        if ipv4:
            ip = ipv4[0][4][0]
        elif results:
            ip = results[0][4][0]
        else:
            raise ScanError(f"Could not resolve hostname: {target}")
        logger.info(f"Resolved hostname {target} -> {ip}")
        return ip
    except socket.gaierror as e:
        raise ScanError(f"Could not resolve hostname: {target} ({e})")
    except Exception as e:
        raise ScanError(f"Could not resolve hostname: {target} ({e})")


def resolve_ip_param(value):
    """Resolve a hostname parameter to an IP address. Returns IP string.
    Raises ValueError if invalid."""
    if not value:
        raise ValueError("Target is required")
    value = value.strip()
    if validate_ip(value):
        return value
    if validate_hostname(value):
        return resolve_target(value)
    raise ValueError("Invalid target (IP, CIDR, or hostname)")
