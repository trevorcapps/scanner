"""Device type classification module for Cerebus.

Combines multiple signals (nmap OS detection, MAC OUI vendor, port/service
heuristics, fingerprint data) to classify assets into device types.
"""

import logging
from mac_vendor_lookup import MacLookup, InvalidMacError

logger = logging.getLogger(__name__)

# Canonical device types
DEVICE_TYPES = [
    'router', 'computer', 'printer', 'firewall', 'switch',
    'iot', 'media device', 'phone', 'server', 'game console',
    'storage', 'access point', 'unknown'
]

DEVICE_TYPE_ICONS = {
    'router': '📡',
    'computer': '🖥️',
    'printer': '🖨️',
    'firewall': '🔥',
    'switch': '🔀',
    'iot': '🏠',
    'media device': '📺',
    'phone': '📱',
    'server': '🗄️',
    'game console': '🎮',
    'storage': '💾',
    'access point': '📶',
    'unknown': '❓',
}

# Singleton MAC lookup instance
_mac_lookup = None

def _get_mac_lookup():
    global _mac_lookup
    if _mac_lookup is None:
        _mac_lookup = MacLookup()
    return _mac_lookup


def lookup_mac_vendor(mac_address):
    """Look up vendor name from a MAC address. Returns None on failure."""
    if not mac_address:
        return None
    try:
        return _get_mac_lookup().lookup(mac_address)
    except (InvalidMacError, KeyError, Exception) as e:
        logger.debug(f"MAC vendor lookup failed for {mac_address}: {e}")
        return None


# ---- Signal 1: nmap OS class device type mapping ----
_NMAP_TYPE_MAP = {
    'general purpose': 'computer',
    'router': 'router',
    'switch': 'switch',
    'firewall': 'firewall',
    'printer': 'printer',
    'print server': 'printer',
    'wap': 'access point',
    'wireless': 'access point',
    'storage-misc': 'storage',
    'storage': 'storage',
    'webcam': 'iot',
    'media device': 'media device',
    'phone': 'phone',
    'voip phone': 'phone',
    'voip adapter': 'phone',
    'game console': 'game console',
    'remote management': 'server',
    'specialized': 'iot',
    'bridge': 'switch',
    'broadband router': 'router',
    'proxy server': 'server',
    'terminal server': 'server',
    'load balancer': 'server',
    'power-device': 'iot',
    'pda': 'phone',
    'hub': 'switch',
}


def classify_from_nmap_os(os_info):
    """Classify device type from nmap OS detection data.

    Args:
        os_info: dict with keys like device_type, os_family, os_vendor, os_name

    Returns:
        (device_type, confidence) or (None, 0)
    """
    if not os_info:
        return None, 0

    nmap_type = (os_info.get('device_type') or '').lower().strip()
    if nmap_type and nmap_type in _NMAP_TYPE_MAP:
        return _NMAP_TYPE_MAP[nmap_type], 90

    # Infer from OS name/family
    os_name = (os_info.get('os_name') or '').lower()
    os_family = (os_info.get('os_family') or '').lower()

    if any(w in os_name for w in ['pfsense', 'opnsense', 'fortios', 'fortigate', 'asa', 'palo alto']):
        return 'firewall', 80
    if any(w in os_name for w in ['ios', 'routeros', 'mikrotik', 'junos', 'vyos']):
        return 'router', 80
    if 'printer' in os_name or 'jetdirect' in os_name:
        return 'printer', 80
    if any(w in os_name for w in ['freenas', 'truenas', 'synology', 'qnap', 'unraid']):
        return 'storage', 80
    if any(w in os_name for w in ['roku', 'chromecast', 'fire tv', 'apple tv', 'sonos']):
        return 'media device', 80
    if any(w in os_name for w in ['android', 'ios']) and 'phone' in os_name:
        return 'phone', 70
    if any(w in os_name for w in ['playstation', 'xbox', 'nintendo', 'switch']):
        return 'game console', 80

    # Generic OS → computer
    if os_family in ('linux', 'windows', 'macos', 'freebsd', 'openbsd', 'netbsd'):
        return 'computer', 50  # low confidence — could be server

    return None, 0


# ---- Signal 2: MAC vendor mapping ----
_VENDOR_TYPE_MAP = {
    # Networking
    'cisco': 'router', 'juniper': 'router', 'mikrotik': 'router',
    'ubiquiti': 'access point', 'aruba': 'access point', 'ruckus': 'access point',
    'tp-link': 'router', 'netgear': 'router', 'd-link': 'router',
    'linksys': 'router', 'asus': 'computer', 'acer': 'computer',
    # Printers
    'hewlett packard': 'printer', 'hp inc': 'printer',
    'brother': 'printer', 'canon': 'printer', 'epson': 'printer',
    'xerox': 'printer', 'lexmark': 'printer', 'ricoh': 'printer',
    'kyocera': 'printer', 'konica minolta': 'printer',
    # Computers
    'apple': 'computer', 'dell': 'computer', 'lenovo': 'computer',
    'intel': 'computer', 'gigabyte': 'computer', 'msi': 'computer',
    'microsoft': 'computer', 'asustek': 'computer',
    # Storage / NAS
    'synology': 'storage', 'qnap': 'storage', 'western digital': 'storage',
    'buffalo': 'storage', 'drobo': 'storage',
    # IoT
    'nest': 'iot', 'ring': 'iot', 'wyze': 'iot', 'ecobee': 'iot',
    'philips hue': 'iot', 'tuya': 'iot', 'shelly': 'iot',
    'espressif': 'iot',
    # Media
    'sonos': 'media device', 'roku': 'media device',
    'amazon': 'media device',  # fire tv / echo
    # Game consoles
    'sony interactive': 'game console', 'nintendo': 'game console',
    # Phones
    'samsung': 'phone', 'xiaomi': 'phone', 'huawei': 'phone',
    'oneplus': 'phone', 'google': 'computer',
    # Firewalls
    'fortinet': 'firewall', 'palo alto': 'firewall',
    'sonicwall': 'firewall', 'watchguard': 'firewall',
    'sophos': 'firewall', 'barracuda': 'firewall',
}


def classify_from_mac_vendor(mac_vendor):
    """Classify device type from MAC OUI vendor string.

    Args:
        mac_vendor: Vendor string (e.g. "Cisco Systems, Inc.")

    Returns:
        (device_type, confidence) or (None, 0)
    """
    if not mac_vendor:
        return None, 0

    vendor_lower = mac_vendor.lower()
    for keyword, dtype in _VENDOR_TYPE_MAP.items():
        if keyword in vendor_lower:
            return dtype, 40  # moderate — vendor doesn't guarantee device type
    return None, 0


# ---- Signal 3: Port / service heuristics ----

def classify_from_ports(open_ports):
    """Classify device type from open port/service list.

    Args:
        open_ports: list of dicts with keys: port, service, product

    Returns:
        (device_type, confidence) or (None, 0)
    """
    if not open_ports:
        return None, 0

    port_numbers = {p.get('port') for p in open_ports}
    services = {(p.get('service') or '').lower() for p in open_ports}
    products = ' '.join((p.get('product') or '').lower() for p in open_ports)

    # Strong printer signals
    printer_ports = {631, 9100, 515}  # IPP, JetDirect, LPD
    if printer_ports & port_numbers:
        return 'printer', 60

    # Routing protocols
    if 179 in port_numbers:  # BGP
        return 'router', 60

    # SIP / VoIP
    if {5060, 5061} & port_numbers:
        return 'phone', 50

    # NAS indicators
    if 5000 in port_numbers and ('synology' in products or 'diskstation' in products):
        return 'storage', 70
    if 8080 in port_numbers and 'qnap' in products:
        return 'storage', 70

    # Media devices typically have limited ports
    if port_numbers <= {7000, 7100, 8008, 8443, 1400, 3689} and len(port_numbers) <= 4:
        if 'airplay' in services or 'daap' in services or 1400 in port_numbers:
            return 'media device', 50

    # Many services → likely a server
    if len(port_numbers) > 10:
        return 'server', 30

    return None, 0


# ---- Signal 4: Fingerprint engine results ----

def classify_from_fingerprints(fingerprints):
    """Classify from fingerprint engine results.

    Args:
        fingerprints: list of fingerprint dicts with keys: name, category, vendor

    Returns:
        (device_type, confidence) or (None, 0)
    """
    if not fingerprints:
        return None, 0

    for fp in fingerprints:
        cat = (fp.get('category') or '').lower()
        name = (fp.get('name') or '').lower()

        if 'firewall' in cat or 'firewall' in name:
            return 'firewall', 70
        if 'printer' in cat or 'printer' in name:
            return 'printer', 70
        if 'nas' in cat or 'storage' in cat:
            return 'storage', 70
        if 'router' in cat or 'router' in name:
            return 'router', 70
        if 'switch' in cat:
            return 'switch', 70

    return None, 0


def classify_device(os_info=None, mac_vendor=None, open_ports=None, fingerprints=None):
    """Combine all signals to classify a device.

    Priority: nmap OS > fingerprints > MAC vendor > port heuristics

    Returns:
        str: device type (one of DEVICE_TYPES)
    """
    signals = []

    dtype, conf = classify_from_nmap_os(os_info)
    if dtype:
        signals.append((dtype, conf, 'nmap_os'))

    dtype, conf = classify_from_fingerprints(fingerprints)
    if dtype:
        signals.append((dtype, conf, 'fingerprint'))

    dtype, conf = classify_from_mac_vendor(mac_vendor)
    if dtype:
        signals.append((dtype, conf, 'mac_vendor'))

    dtype, conf = classify_from_ports(open_ports)
    if dtype:
        signals.append((dtype, conf, 'ports'))

    if not signals:
        return 'unknown'

    # Sort by confidence descending, pick highest
    signals.sort(key=lambda s: s[1], reverse=True)
    best = signals[0]

    logger.debug(f"Device classification signals: {signals} → {best[0]}")
    return best[0]


def get_device_icon(device_type):
    """Get emoji icon for a device type."""
    return DEVICE_TYPE_ICONS.get(device_type, '❓')
