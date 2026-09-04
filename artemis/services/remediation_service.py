"""Remediation guidance for a finding (P4.3).

Guidance is *informational*. It never contains credentials or an executable
payload — an operator explicitly starts a Phase 5 automation run against it. It
is computed on read from the definition, its advisory/reference data, and the
affected assets. Anything not backed by a trusted advisory is clearly marked
``heuristic``.
"""

import json
import re

from artemis.extensions import db
from artemis.models.asset import Asset
from artemis.models.finding import FindingOccurrence, VulnerabilityDefinition
from artemis.models.inventory_history import SoftwareObservation
from artemis.services.tenant import scoped

_FIXED_VERSION_RE = re.compile(r'fixed in (?:version )?([0-9][\w.\-+~:]*)', re.I)
_UPGRADE_RE = re.compile(r'upgrade to (?:version )?([0-9][\w.\-+~:]*)', re.I)


def _reboot_hint(definition, component):
    text = f'{definition.title or ""} {definition.description or ""} {component or ""}'.lower()
    if any(k in text for k in ('kernel', 'glibc', 'systemd', 'libc', 'openssl')):
        return 'A reboot (or full service restart) is required for this change to take effect.'
    if any(k in text for k in ('nginx', 'apache', 'httpd', 'sshd', 'openssh')):
        return 'Restart the affected service after upgrading.'
    return 'Restart the affected process or service after upgrading.'


def _fixed_version(definition):
    """Best-effort fixed version from advisory text / references. Heuristic."""
    haystacks = [definition.description or '']
    for ref in json.loads(definition.references_json or '[]'):
        if isinstance(ref, dict):
            haystacks.append(ref.get('url', ''))
        else:
            haystacks.append(str(ref))
    for text in haystacks:
        for rx in (_FIXED_VERSION_RE, _UPGRADE_RE):
            m = rx.search(text)
            if m:
                return m.group(1)
    return None


def build_guidance(occurrence_id):
    occ = scoped(FindingOccurrence).filter(FindingOccurrence.id == occurrence_id).first()
    if occ is None:
        return None
    definition = occ.definition or db.session.get(VulnerabilityDefinition, occ.definition_id)

    # every open occurrence of the same definition = the assets to fix
    affected = scoped(FindingOccurrence).filter(
        FindingOccurrence.definition_id == occ.definition_id,
        FindingOccurrence.status.in_(('open', 'reopened')),
    ).all()
    affected_assets = []
    for other in affected:
        asset = db.session.get(Asset, other.asset_id) if other.asset_id else None
        affected_assets.append({
            'occurrence_id': other.id, 'ip': other.ip,
            'hostname': asset.hostname if asset else None,
            'component': other.component,
            'criticality': asset.criticality if asset else None,
        })

    package = None
    installed_version = None
    if occ.component:
        package = occ.component.split(':')[-1] if ':' in occ.component else occ.component
        obs = scoped(SoftwareObservation).filter(
            SoftwareObservation.ip == occ.ip,
            SoftwareObservation.package_name == package,
            SoftwareObservation.removed_at.is_(None),
        ).first()
        installed_version = obs.package_version if obs else None

    fixed = _fixed_version(definition) if definition else None
    trusted = bool(definition and definition.kev and definition.kev_required_action)

    steps = []
    if trusted:
        steps.append({'text': definition.kev_required_action, 'source': 'cisa-kev', 'heuristic': False})
    if fixed and package:
        steps.append({'text': f'Upgrade {package} to {fixed} or later.',
                      'source': 'advisory-text', 'heuristic': not trusted})
    elif package:
        steps.append({'text': f'Upgrade {package} to the latest patched release from your OS vendor.',
                      'source': 'derived', 'heuristic': True})
    else:
        steps.append({'text': 'Apply the vendor patch or mitigation for this vulnerability.',
                      'source': 'derived', 'heuristic': True})
    steps.append({'text': _reboot_hint(definition, occ.component) if definition else
                  'Restart the affected service afterwards.', 'source': 'derived', 'heuristic': True})

    validation = (f'Re-run the scan that found this ({", ".join(json.loads(occ.sources_json or "[]"))}) '
                  f'and confirm the finding resolves.')

    return {
        'occurrence_id': occ.id,
        'definition_id': occ.definition_id,
        'title': (definition.title if definition else occ.definition_id),
        'package': package,
        'installed_version': installed_version,
        'fixed_version': fixed,
        'fixed_version_is_heuristic': not trusted,
        'steps': steps,
        'reboot_required': any('reboot' in s['text'].lower() for s in steps),
        'validation': validation,
        'affected_assets': affected_assets,
        'sources': [r for r in json.loads(definition.references_json or '[]')] if definition else [],
        'note': ('This guidance is informational. To apply it, start an automation '
                 'run from the Fleet area — Artemis never embeds credentials or a '
                 'runnable payload in a finding.'),
    }
