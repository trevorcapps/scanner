"""Authenticated scanning orchestration + credential/settings storage.

System of record: Postgres via the ``AssetOsDetails`` / ``InstalledSoftware`` /
``CveMatch`` / ``Credential`` / ``Setting`` models.
"""

import json
import logging
from datetime import datetime

from artemis.extensions import db
from artemis.models.asset_os import AssetOsDetails
from artemis.models.software import InstalledSoftware
from artemis.models.cve_match import CveMatch
from artemis.models.credential import Credential
from artemis.models.setting import Setting
from artemis.services._db import upsert

logger = logging.getLogger(__name__)


def store_auth_scan_results(ip, os_info, packages, cves, detection_source='auth-scan'):
    """Store results from authenticated or agent-based inventory.

    Persists OS + system facts + software + CVE matches, and folds the
    newly-learned identity (hostname, MAC, OS) back onto the ``assets`` row so
    an authenticated scan enriches the asset the same way a port scan does.
    """
    scan_date = datetime.now().isoformat()
    system = os_info.get('system') or {}
    try:
        upsert(AssetOsDetails, {'ip': ip}, {
            'distro': os_info.get('distro'), 'version': os_info.get('version'),
            'kernel': os_info.get('kernel'), 'arch': os_info.get('arch'),
            'os_family': os_info.get('os_family'), 'os_id': os_info.get('os_id'),
            'pretty_name': os_info.get('pretty_name'), 'scan_date': scan_date,
            'system_info_json': json.dumps(system) if system else None,
        })
        for pkg in packages:
            upsert(InstalledSoftware, {'ip': ip, 'package_name': pkg['name']}, {
                'package_version': pkg['version'], 'cpe': pkg.get('cpe', ''),
                'scan_date': scan_date,
            })
        for cve in cves:
            upsert(CveMatch, {'ip': ip, 'cve_id': cve['cve_id']}, {
                'severity': cve['severity'], 'cvss_score': cve.get('cvss_score'),
                'description': cve.get('description', ''),
                'affected_cpe': cve.get('affected_cpe', ''),
                'has_exploit': 1 if cve.get('has_exploit') else 0,
                'exploit_ids': cve.get('exploit_ids', ''),
                'exploit_url': cve.get('exploit_url', ''),
                'detection_source': detection_source,
                'scan_date': scan_date,
            })
        db.session.commit()
        logger.info("Stored %s inventory: %s - OS: %s, %s packages, %s CVEs",
                    detection_source, ip, os_info.get('distro'), len(packages), len(cves))
    except Exception as e:
        db.session.rollback()
        logger.error(f"Database error storing auth scan for {ip}: {e}")
        return

    _enrich_asset_from_auth(ip, os_info, system)

    # Historical inventory: observation intervals + timeline (P3.3).
    try:
        from artemis.services.inventory_service import record_inventory
        record_inventory(ip, [{'name': p['name'], 'version': p.get('version'),
                               'cpe': p.get('cpe')} for p in packages],
                         source='agent' if detection_source == 'agent' else 'auth-scan')
    except Exception:
        logger.exception("inventory history update failed for %s", ip)

    # Canonical findings (P4.1) — CVE matches become finding occurrences.
    try:
        from artemis.services.finding_service import ingest_finding, resolve_absent
        src = 'agent' if detection_source == 'agent' else 'ssh'
        seen = set()
        for cve in cves:
            seen.add(cve['cve_id'])
            ingest_finding(
                definition_id=cve['cve_id'], kind='cve', ip=ip, source=src,
                component=cve.get('affected_cpe'), severity=cve.get('severity'),
                cvss_score=cve.get('cvss_score'), description=cve.get('description'),
                observed_at=scan_date,
                evidence={'affected_cpe': cve.get('affected_cpe'),
                          'has_exploit': bool(cve.get('has_exploit'))},
            )
        if seen:
            resolve_absent(ip, seen_definition_ids=seen, source=src)
    except Exception:
        logger.exception("canonical finding ingest failed for %s", ip)


def _enrich_asset_from_auth(ip, os_info, system):
    """Fold authenticated findings back onto the ``assets`` row + reclassify."""
    from artemis.services.asset_service import store_asset_info, update_device_type

    os_name = os_info.get('pretty_name') or os_info.get('distro')
    hostname = system.get('hostname') or os_info.get('hostname')
    mac = system.get('primary_mac') or os_info.get('primary_mac')
    mac_vendor = None
    if mac:
        try:
            from device_type import lookup_mac_vendor
            mac_vendor = lookup_mac_vendor(mac)
        except Exception:
            pass

    try:
        store_asset_info(
            ip,
            dns_info={'hostname': hostname} if hostname else None,
            os_info={'os_name': os_name, 'os_family': os_info.get('os_family')},
            mac_address=mac, mac_vendor=mac_vendor,
        )
        update_device_type(ip)
    except Exception as e:
        logger.warning(f"Asset enrichment from auth scan failed for {ip}: {e}")


def get_asset_os_details(ip):
    row = AssetOsDetails.query.filter_by(ip=ip).first()
    return row.to_dict() if row else None


def get_installed_software(ip):
    return [s.to_dict() for s in InstalledSoftware.query.filter_by(ip=ip)
            .order_by(InstalledSoftware.package_name).all()]


def get_cve_matches(ip):
    return [c.to_dict() for c in CveMatch.query.filter_by(ip=ip)
            .order_by(CveMatch.has_exploit.desc(), CveMatch.cvss_score.desc()).all()]


# --------------- Credentials ---------------

def _credential_dict(c, full=True):
    d = c.to_dict()
    if not full:
        d.pop('created_at', None)
        d.pop('updated_at', None)
    return d


def get_all_credentials():
    return [_credential_dict(c) for c in Credential.query.order_by(Credential.name).all()]


def get_credential(cred_id):
    """Safe (secret-free) view of one credential."""
    c = db.session.get(Credential, cred_id)
    return _credential_dict(c, full=False) if c else None


def resolve_credential_secrets(cred_id, *, reason='auth_scan'):
    """Return {username, cred_type, password, key_data} with real secret values.

    Every call writes a ``secret.read`` audit event. Use only at the point a
    scanner actually needs to authenticate.
    """
    from artemis.services import audit_service

    c = db.session.get(Credential, cred_id)
    if not c:
        return None
    try:
        payload = {
            'id': c.id,
            'name': c.name,
            'username': c.username,
            'cred_type': c.cred_type,
            'password': c.reveal_secret() if c.cred_type == 'ssh_password' else (c.reveal_secret() or None),
            'key_data': c.reveal_private_key() if c.cred_type == 'ssh_key' else None,
        }
        audit_service.record(
            audit_service.SECRET_READ, target_type='credential', target_id=c.id,
            detail={'name': c.name, 'reason': reason},
        )
        return payload
    except Exception:
        audit_service.record(
            audit_service.SECRET_READ, outcome='failure',
            target_type='credential', target_id=c.id, detail={'reason': reason},
        )
        raise


def save_credential(name, cred_type, username, key_path='', password='', cred_id=None,
                    private_key=None):
    """Create or update a credential set. Returns its id."""
    from artemis.services import audit_service, crypto_service

    if not crypto_service.is_configured():
        raise ValueError(
            "Secret encryption is not configured; set ARTEMIS_ENCRYPTION_KEY before storing credentials"
        )

    now = datetime.now().isoformat()
    try:
        creating = not cred_id
        if cred_id:
            c = db.session.get(Credential, cred_id)
            if not c:
                raise ValueError(f"Credential {cred_id} not found")
        else:
            if Credential.query.filter_by(name=name).first():
                raise ValueError(f"Credential name '{name}' already exists")
            c = Credential(created_at=now)
            db.session.add(c)

        c.name, c.cred_type, c.username = name, cred_type, username
        c.key_path = key_path or None
        c.updated_at = now
        # Only overwrite secrets when a new value is supplied (blank == keep).
        if password:
            c.set_secret(password)
        if private_key:
            c.set_private_key(private_key)

        db.session.flush()
        audit_service.record(
            audit_service.SECRET_WRITE, target_type='credential', target_id=c.id,
            detail={'name': name, 'created': creating},
        )
        db.session.commit()
        return c.id
    except ValueError:
        db.session.rollback()
        raise
    except Exception as e:
        db.session.rollback()
        logger.error(f"Database error saving credential: {e}")
        raise


def delete_credential(cred_id):
    deleted = Credential.query.filter_by(id=cred_id).delete()
    db.session.commit()
    return deleted > 0


# --------------- Settings ---------------

def get_setting(key, default=None):
    try:
        row = db.session.get(Setting, key)
        return row.value if row else default
    except Exception as e:
        logger.error(f"Database error reading setting {key}: {e}")
        return default


def set_setting(key, value):
    try:
        upsert(Setting, {'key': key}, {'value': value})
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Database error writing setting {key}: {e}")
