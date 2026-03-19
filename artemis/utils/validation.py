"""IP, CIDR, hostname validation utilities."""

import re
import ipaddress


def validate_ip(ip):
    """Validate that the input is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_cidr(cidr):
    """Validate that the input is a valid CIDR notation."""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def validate_hostname(hostname):
    """Validate that the input is a plausible domain name or FQDN."""
    if not hostname or not isinstance(hostname, str):
        return False
    if len(hostname) > 253:
        return False
    h = hostname.rstrip('.')
    if not h:
        return False
    pattern = re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
        r'(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    )
    return bool(pattern.match(h))


def is_cidr(target):
    """Check if target is CIDR notation (contains /)."""
    return '/' in target and validate_cidr(target)


def is_hostname(target):
    """Check if target looks like a hostname (not an IP or CIDR)."""
    if validate_ip(target) or is_cidr(target):
        return False
    return validate_hostname(target)


def validate_target(target):
    """Validate that the input is a valid IP address, CIDR notation, or hostname."""
    return validate_ip(target) or validate_cidr(target) or validate_hostname(target)


def expand_cidr(cidr, max_hosts=256):
    """Expand a CIDR notation to a list of IP addresses."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        hosts = list(network.hosts())
        if len(hosts) > max_hosts:
            hosts = hosts[:max_hosts]
        return [str(ip) for ip in hosts]
    except ValueError:
        return []
