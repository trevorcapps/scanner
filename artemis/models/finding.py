"""Canonical finding model (P4.1).

- ``VulnerabilityDefinition`` — global, shared: one row per CVE / template /
  advisory identity, carrying intelligence (CVSS, EPSS, KEV, exploit maturity).
- ``FindingOccurrence`` — tenant-owned: this vulnerability *on this asset/port*.
  Stable identity across sources; tracks lifecycle status separately from raw
  observations.
- ``FindingObservation`` — tenant-owned, immutable: one row each time a source
  (nuclei / agent / ssh / container / cloud) saw the occurrence, with its
  source-native evidence preserved verbatim.
"""

import hashlib
import json

from artemis.extensions import db
from artemis.models._tenant import TenantMixin

OCCURRENCE_STATUSES = ('open', 'resolved', 'reopened', 'suppressed', 'accepted')
EXPLOIT_MATURITY = ('none', 'poc', 'weaponized', 'known_exploited')


class VulnerabilityDefinition(db.Model):
    """Global, deduplicated vulnerability identity + intelligence. Not tenant-scoped."""

    __tablename__ = 'vulnerability_definitions'

    # Natural key: "CVE-2024-1234" or "nuclei:template-id" or "advisory:VENDOR:ID"
    id = db.Column(db.String(128), primary_key=True)
    kind = db.Column(db.String(16), nullable=False)   # cve | template | advisory
    title = db.Column(db.Text)
    description = db.Column(db.Text)
    severity = db.Column(db.String(16))
    cvss_score = db.Column(db.Float)
    cvss_vector = db.Column(db.Text)
    cwe_id = db.Column(db.String(32))
    published_date = db.Column(db.Text)
    references_json = db.Column(db.Text)

    # --- intelligence (populated by P4.2 feeds) ---
    epss_score = db.Column(db.Float)
    epss_percentile = db.Column(db.Float)
    epss_model_date = db.Column(db.Text)
    kev = db.Column(db.Integer, nullable=False, default=0)
    kev_date_added = db.Column(db.Text)
    kev_due_date = db.Column(db.Text)
    kev_ransomware = db.Column(db.Integer, nullable=False, default=0)
    kev_required_action = db.Column(db.Text)
    exploit_maturity = db.Column(db.String(16), nullable=False, default='none')
    exploit_evidence_json = db.Column(db.Text)

    updated_at = db.Column(db.Text)

    def to_dict(self):
        return {
            'id': self.id,
            'kind': self.kind,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'cvss_vector': self.cvss_vector,
            'cwe_id': self.cwe_id,
            'published_date': self.published_date,
            'references': _loads(self.references_json, []),
            'epss': {
                'score': self.epss_score, 'percentile': self.epss_percentile,
                'model_date': self.epss_model_date,
            } if self.epss_score is not None else None,
            'kev': {
                'listed': bool(self.kev), 'date_added': self.kev_date_added,
                'due_date': self.kev_due_date, 'ransomware': bool(self.kev_ransomware),
                'required_action': self.kev_required_action,
            } if self.kev else None,
            'exploit_maturity': self.exploit_maturity,
            'exploit_evidence': _loads(self.exploit_evidence_json, []),
            'updated_at': self.updated_at,
        }


class FindingOccurrence(TenantMixin, db.Model):
    __tablename__ = 'finding_occurrences'
    __table_args__ = (
        db.UniqueConstraint('organization_id', 'fingerprint', name='uq_finding_occ_org_fp'),
    )

    id = db.Column(db.Integer, primary_key=True)
    # Stable identity hash of (definition, asset ip, port, protocol, component).
    fingerprint = db.Column(db.String(64), nullable=False, index=True)
    definition_id = db.Column(
        db.String(128), db.ForeignKey('vulnerability_definitions.id', ondelete='CASCADE'),
        nullable=False, index=True,
    )
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id', ondelete='CASCADE'), index=True)
    ip = db.Column(db.Text, index=True)
    port = db.Column(db.Integer)
    protocol = db.Column(db.String(8))
    component = db.Column(db.Text)                    # affected package / service / path

    status = db.Column(db.String(16), nullable=False, default='open', index=True)
    first_seen = db.Column(db.Text, nullable=False)
    last_seen = db.Column(db.Text, nullable=False)
    resolved_at = db.Column(db.Text)
    reopened_at = db.Column(db.Text)
    # Highest-confidence source that has ever reported this occurrence.
    sources_json = db.Column(db.Text)
    # Transparent priority score + its factors (P4.2).
    priority_score = db.Column(db.Float)
    priority_factors_json = db.Column(db.Text)

    definition = db.relationship('VulnerabilityDefinition', lazy='joined')
    observations = db.relationship('FindingObservation', backref='occurrence',
                                   cascade='all, delete-orphan', lazy='dynamic')

    @staticmethod
    def make_fingerprint(definition_id, ip, port, protocol, component=None):
        raw = f'{definition_id}|{ip}|{port or ""}|{protocol or ""}|{component or ""}'
        return hashlib.sha256(raw.encode()).hexdigest()

    def to_dict(self, include_definition=True):
        data = {
            'id': self.id,
            'fingerprint': self.fingerprint,
            'definition_id': self.definition_id,
            'asset_id': self.asset_id,
            'ip': self.ip,
            'port': self.port,
            'protocol': self.protocol,
            'component': self.component,
            'status': self.status,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'resolved_at': self.resolved_at,
            'reopened_at': self.reopened_at,
            'sources': _loads(self.sources_json, []),
            'priority_score': self.priority_score,
            'priority_factors': _loads(self.priority_factors_json, {}),
        }
        if include_definition and self.definition is not None:
            data['definition'] = self.definition.to_dict()
        return data


class FindingObservation(TenantMixin, db.Model):
    __tablename__ = 'finding_observations'
    __table_args__ = (
        db.Index('ix_finding_obs_occ_at', 'occurrence_id', 'observed_at'),
    )

    id = db.Column(db.Integer, primary_key=True)
    occurrence_id = db.Column(
        db.Integer, db.ForeignKey('finding_occurrences.id', ondelete='CASCADE'),
        nullable=False, index=True,
    )
    source = db.Column(db.String(16), nullable=False)   # nuclei | agent | ssh | container | cloud
    job_id = db.Column(db.String(36))
    observed_at = db.Column(db.Text, nullable=False)
    present = db.Column(db.Integer, nullable=False, default=1)   # 0 = observed absent
    severity = db.Column(db.String(16))
    matched_at = db.Column(db.Text)
    evidence_json = db.Column(db.Text)                  # source-native evidence, verbatim

    def to_dict(self):
        return {
            'id': self.id,
            'occurrence_id': self.occurrence_id,
            'source': self.source,
            'job_id': self.job_id,
            'observed_at': self.observed_at,
            'present': bool(self.present),
            'severity': self.severity,
            'matched_at': self.matched_at,
            'evidence': _loads(self.evidence_json, None),
        }


def _loads(value, default):
    try:
        return json.loads(value) if value else default
    except (TypeError, ValueError):
        return default
