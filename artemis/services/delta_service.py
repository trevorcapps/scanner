"""Stable observation deltas for a target set.

Instead of diffing opaque summary JSON, we compare the *identities* of the
current findings and installed software against a prior baseline and classify
each as new / resolved / reopened / changed. Identity keys:

  finding  -> (ip, port, protocol, vuln_id)
  cve      -> (ip, cve_id)
  software -> (ip, package_name)  with version as the mutable attribute
"""

from artemis.models.cve_match import CveMatch
from artemis.models.software import InstalledSoftware
from artemis.models.vulnerability import Vulnerability
from artemis.services.tenant import scoped


def _finding_index(ips):
    out = {}
    for v in scoped(Vulnerability).filter(Vulnerability.ip.in_(ips)).all():
        out[(v.ip, v.port, v.protocol, v.vuln_id)] = {
            'name': v.vuln_name, 'severity': v.severity, 'status': getattr(v, 'status', 'open'),
        }
    for c in scoped(CveMatch).filter(CveMatch.ip.in_(ips)).all():
        out[(c.ip, None, None, c.cve_id)] = {
            'name': c.cve_id, 'severity': getattr(c, 'severity', None), 'status': 'open',
        }
    return out


def _software_index(ips):
    return {
        (s.ip, s.package_name): s.package_version
        for s in scoped(InstalledSoftware).filter(InstalledSoftware.ip.in_(ips)).all()
    }


def compute_delta(ips, baseline):
    """Compare the live state of ``ips`` against a ``baseline`` snapshot dict
    (as returned by :func:`snapshot`). Returns the classified change set."""
    current_f = _finding_index(ips)
    base_f = baseline.get('findings', {}) if baseline else {}

    new, resolved, reopened, changed = [], [], [], []
    for key, cur in current_f.items():
        skey = '|'.join('' if p is None else str(p) for p in key)
        prev = base_f.get(skey)
        if prev is None:
            new.append({'key': skey, **cur})
        elif prev.get('status') == 'resolved' and cur.get('status') != 'resolved':
            reopened.append({'key': skey, **cur})
        elif prev.get('severity') != cur.get('severity'):
            changed.append({'key': skey, 'from': prev.get('severity'), 'to': cur.get('severity')})
    for skey, prev in base_f.items():
        key = tuple(None if p == '' else p for p in skey.split('|'))
        if not any('|'.join('' if x is None else str(x) for x in k) == skey for k in current_f):
            resolved.append({'key': skey, **prev})

    current_s = _software_index(ips)
    base_s = baseline.get('software', {}) if baseline else {}
    sw_installed, sw_removed, sw_updated = [], [], []
    for (ip, pkg), ver in current_s.items():
        skey = f'{ip}|{pkg}'
        if skey not in base_s:
            sw_installed.append({'ip': ip, 'package': pkg, 'version': ver})
        elif base_s[skey] != ver:
            sw_updated.append({'ip': ip, 'package': pkg, 'from': base_s[skey], 'to': ver})
    for skey in base_s:
        ip, pkg = skey.split('|', 1)
        if (ip, pkg) not in current_s:
            sw_removed.append({'ip': ip, 'package': pkg})

    return {
        'new_vulns': len(new),
        'resolved_vulns': len(resolved),
        'reopened_vulns': len(reopened),
        'changed_vulns': len(changed),
        'findings': {'new': new, 'resolved': resolved, 'reopened': reopened, 'changed': changed},
        'software': {'installed': sw_installed, 'removed': sw_removed, 'updated': sw_updated},
    }


def snapshot(ips):
    """Capture the current identity index for later delta comparison."""
    findings = {
        '|'.join('' if p is None else str(p) for p in k): v
        for k, v in _finding_index(ips).items()
    }
    software = {f'{ip}|{pkg}': ver for (ip, pkg), ver in _software_index(ips).items()}
    return {'findings': findings, 'software': software}
