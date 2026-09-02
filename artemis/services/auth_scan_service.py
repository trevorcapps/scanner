"""Authenticated scanning orchestration + credential/settings storage.

System of record: Postgres via the ``AssetOsDetails`` / ``InstalledSoftware`` /
``CveMatch`` / ``Credential`` / ``Setting`` models.
"""

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


def store_auth_scan_results(ip, os_info, packages, cves):
    """Store results from an authenticated SSH scan."""
    scan_date = datetime.now().isoformat()
    try:
        upsert(AssetOsDetails, {'ip': ip}, {
            'distro': os_info.get('distro'), 'version': os_info.get('version'),
            'kernel': os_info.get('kernel'), 'arch': os_info.get('arch'),
            'os_family': os_info.get('os_family'), 'os_id': os_info.get('os_id'),
            'pretty_name': os_info.get('pretty_name'), 'scan_date': scan_date,
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
                'scan_date': scan_date,
            })
        db.session.commit()
        logger.info(f"Stored auth scan: {ip} - OS: {os_info.get('distro')}, "
                    f"{len(packages)} packages, {len(cves)} CVEs")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Database error storing auth scan for {ip}: {e}")


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
    d = {
        'id': c.id, 'name': c.name, 'cred_type': c.cred_type, 'username': c.username,
        'key_path': c.key_path or '', 'password': c.password or '',
    }
    if full:
        d['created_at'] = c.created_at
        d['updated_at'] = c.updated_at
    return d


def get_all_credentials():
    return [_credential_dict(c) for c in Credential.query.order_by(Credential.name).all()]


def get_credential(cred_id):
    c = db.session.get(Credential, cred_id)
    return _credential_dict(c, full=False) if c else None


def save_credential(name, cred_type, username, key_path='', password='', cred_id=None):
    """Create or update a credential set. Returns its id."""
    now = datetime.now().isoformat()
    try:
        if cred_id:
            c = db.session.get(Credential, cred_id)
            if not c:
                raise ValueError(f"Credential {cred_id} not found")
            c.name, c.cred_type, c.username = name, cred_type, username
            c.key_path, c.password, c.updated_at = key_path, password, now
        else:
            if Credential.query.filter_by(name=name).first():
                raise ValueError(f"Credential name '{name}' already exists")
            c = Credential(name=name, cred_type=cred_type, username=username,
                           key_path=key_path, password=password,
                           created_at=now, updated_at=now)
            db.session.add(c)
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
