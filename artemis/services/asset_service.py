"""Asset CRUD & device classification service.

System of record: Postgres via the ``Asset`` / ``AgentData`` models.
"""

import json
import logging
from datetime import datetime

from artemis.extensions import db
from artemis.models.asset import Asset
from artemis.models.agent_data import AgentData

logger = logging.getLogger(__name__)


def _emit_webhook(event, payload):
    try:
        from artemis.services.webhook_service import emit
        emit(event, payload)
    except Exception:
        logger.debug("webhook emit failed", exc_info=True)


def store_asset_info(ip, dns_info=None, os_info=None, mac_address=None, mac_vendor=None,
                     source='scan'):
    """Create or update an asset row. Non-None fields overwrite; others are kept.

    Returns True when a new asset row was created, else False.
    """
    now = datetime.now().isoformat()
    dns_info = dns_info or {}
    os_info = os_info or {}

    updates = {
        'hostname': dns_info.get('hostname'),
        'reverse_dns': dns_info.get('reverse_dns'),
        'aliases_json': json.dumps(dns_info['aliases']) if dns_info.get('aliases') is not None else None,
        'os_name': os_info.get('os_name'),
        'os_family': os_info.get('os_family'),
        'os_vendor': os_info.get('os_vendor'),
        'os_accuracy': os_info.get('os_accuracy'),
        'device_type': os_info.get('device_type'),
        'mac_address': mac_address,
        'mac_vendor': mac_vendor,
    }

    try:
        asset = Asset.query.filter_by(ip=ip).first()
        created = asset is None
        if created:
            asset = Asset(ip=ip, first_seen=now, scan_count=0,
                          first_seen_source=source, lifecycle='active')
            db.session.add(asset)
        elif asset.lifecycle == 'decommissioned':
            # A decommissioned host reappeared — never silently reactivate it.
            _record_review(asset, 'decommissioned_reappeared', {'ip': ip, 'seen_at': now})
            asset.last_seen = now
            asset.last_seen_source = source
            db.session.commit()
            return False

        # Discovery-sourced fields never clobber operator-owned values.
        asset.apply_discovery(**{k: v for k, v in updates.items() if k != 'aliases_json'})
        if updates.get('aliases_json') is not None:
            asset.aliases_json = updates['aliases_json']
        asset.last_seen = now
        asset.last_seen_source = source
        asset.scan_count = (asset.scan_count or 0) + 1
        if asset.lifecycle == 'stale':
            asset.lifecycle = 'active'
        db.session.commit()
        if created:
            _emit_webhook('asset.discovered', {
                'ip': ip, 'hostname': asset.hostname, 'os_name': asset.os_name,
                'device_type': asset.device_type, 'first_seen': asset.first_seen,
            })
        return created
    except Exception as e:
        db.session.rollback()
        logger.error(f"Database error storing asset info for {ip}: {e}")
        return False


def _record_review(asset, kind, detail):
    from artemis.models.asset_group import AssetReviewEvent
    db.session.add(AssetReviewEvent(
        asset_id=asset.id, kind=kind, detail_json=json.dumps(detail),
        created_at=datetime.now().isoformat(),
    ))


def get_asset_details(ip):
    """Full asset detail: metadata + ports + vulns + fingerprints + auth-scan data."""
    from artemis.services.vuln_service import get_vulnerability_counts_by_severity, get_vulnerabilities
    from artemis.services.fingerprint_service import get_fingerprint_summary
    from artemis.services.auth_scan_service import get_asset_os_details, get_installed_software, get_cve_matches
    from artemis.models.scan import Scan
    from sqlalchemy import func

    try:
        row = Asset.query.filter_by(ip=ip).first()

        asset = {
            'ip': ip, 'hostname': None, 'reverse_dns': None, 'aliases': [],
            'os_name': None, 'os_family': None, 'os_vendor': None,
            'os_accuracy': None, 'device_type': None,
            'mac_address': None, 'mac_vendor': None,
            'first_seen': None, 'last_seen': None, 'scan_count': 0,
            'ports': [], 'vulnerabilities': [],
        }

        if row:
            asset.update({
                'hostname': row.hostname, 'reverse_dns': row.reverse_dns,
                'os_name': row.os_name, 'os_family': row.os_family,
                'os_vendor': row.os_vendor, 'os_accuracy': row.os_accuracy,
                'device_type': row.device_type, 'mac_address': row.mac_address,
                'mac_vendor': row.mac_vendor, 'first_seen': row.first_seen,
                'last_seen': row.last_seen, 'scan_count': row.scan_count,
            })
            try:
                asset['aliases'] = json.loads(row.aliases_json) if row.aliases_json else []
            except (json.JSONDecodeError, TypeError):
                asset['aliases'] = []

        latest = db.session.query(func.max(Scan.scan_date)).filter(Scan.ip == ip).scalar()
        if latest:
            for s in Scan.query.filter_by(ip=ip, scan_date=latest).all():
                asset['ports'].append({
                    'protocol': s.protocol, 'port': s.port, 'state': s.state,
                    'service': s.service, 'product': s.product, 'version': s.version,
                })

        asset['vuln_counts'] = get_vulnerability_counts_by_severity(ip)
        asset['vulnerabilities'] = get_vulnerabilities(ip)

        fp_summary = get_fingerprint_summary(ip)
        asset['fingerprints'] = fp_summary.get('technologies', [])
        asset['fingerprints_by_port'] = fp_summary.get('by_port', {})

        asset['auth_os'] = get_asset_os_details(ip)
        asset['installed_software'] = get_installed_software(ip)
        asset['cve_matches'] = get_cve_matches(ip)
        asset['agent_data'] = _get_agent_data(ip)

        return asset
    except Exception as e:
        logger.error(f"Database error getting asset details for {ip}: {e}")
        return None


def _get_agent_data(ip):
    """Latest agent-reported system data for an asset, or None."""
    try:
        row = AgentData.query.filter_by(ip=ip).first()
        return row.to_dict() if row else None
    except Exception:
        return None


def delete_asset(ip):
    """Purge an asset and every row keyed to its IP across the scan pipeline."""
    from artemis.models.scan import Scan
    from artemis.models.fingerprint_model import Fingerprint
    from artemis.models.vulnerability import Vulnerability
    from artemis.models.cve_match import CveMatch
    from artemis.models.software import InstalledSoftware
    from artemis.models.asset_os import AssetOsDetails

    removed = {}
    try:
        for model in (Scan, Fingerprint, Vulnerability, CveMatch,
                      InstalledSoftware, AssetOsDetails, AgentData, Asset):
            removed[model.__tablename__] = model.query.filter_by(ip=ip).delete()
        db.session.commit()
        logger.info(f"Deleted asset {ip}: {removed}")
        return removed
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting asset {ip}: {e}")
        raise


def update_device_type(ip):
    """Re-classify device type for an asset using all available signals."""
    import sys
    import os
    scanner_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if scanner_dir not in sys.path:
        sys.path.insert(0, scanner_dir)
    from device_type import classify_device
    from artemis.services.scan_service import get_open_ports_for_ip
    from artemis.services.fingerprint_service import get_fingerprints

    try:
        asset = Asset.query.filter_by(ip=ip).first()
        if not asset:
            return None

        os_info = {
            'os_name': asset.os_name, 'os_family': asset.os_family,
            'os_vendor': asset.os_vendor, 'os_accuracy': asset.os_accuracy,
            'device_type': asset.device_type,
        }

        device_type = classify_device(
            os_info=os_info,
            mac_vendor=asset.mac_vendor,
            open_ports=get_open_ports_for_ip(ip),
            fingerprints=get_fingerprints(ip),
        )

        asset.device_type = device_type
        db.session.commit()
        logger.info(f"Updated device type for {ip}: {device_type}")
        return device_type
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating device type for {ip}: {e}")
        return None
