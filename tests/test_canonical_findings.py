"""P4.1 canonical findings: shared definitions, stable occurrence identity across
sources, immutable observations, and lifecycle (open/resolved/reopened)."""

import unittest

from artemis import create_app
from artemis.extensions import db
from artemis.models.asset import Asset
from artemis.models.finding import (
    FindingObservation,
    FindingOccurrence,
    VulnerabilityDefinition,
)
from artemis.services import finding_service as fs
from artemis.services.auth_service import create_user


class CanonicalFindingTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app("testing", start_background_services=False)
        self.ctx = self.app.app_context()
        self.ctx.push()
        db.drop_all()
        db.create_all()
        create_user("admin", "password-123", role="admin")
        from artemis.services.org_service import ensure_default_organization
        from artemis.services.tenant import use_organization
        self.oid = ensure_default_organization().id
        db.session.commit()
        self._org = use_organization(self.oid)
        self._org.__enter__()
        db.session.add(Asset(ip="10.0.0.1", lifecycle="active", first_seen="2026-01-01"))
        db.session.commit()

    def tearDown(self):
        self._org.__exit__(None, None, None)
        db.drop_all()
        self.ctx.pop()

    def test_two_sources_one_occurrence_two_observations(self):
        fs.ingest_finding(definition_id="CVE-2024-1000", kind="cve", ip="10.0.0.1",
                          source="nuclei", port=443, protocol="tcp", severity="high")
        fs.ingest_finding(definition_id="CVE-2024-1000", kind="cve", ip="10.0.0.1",
                          source="ssh", port=443, protocol="tcp", severity="high")

        self.assertEqual(FindingOccurrence.query.count(), 1)
        occ = FindingOccurrence.query.one()
        self.assertEqual(sorted(occ.to_dict()["sources"]), ["nuclei", "ssh"])
        self.assertEqual(FindingObservation.query.filter_by(occurrence_id=occ.id).count(), 2)
        self.assertEqual(VulnerabilityDefinition.query.count(), 1)

    def test_resolve_then_reopen_on_new_evidence(self):
        fs.ingest_finding(definition_id="CVE-2024-2000", kind="cve", ip="10.0.0.1",
                          source="nuclei", port=80, protocol="tcp", severity="medium")
        # a later scan of the host no longer sees it -> resolved
        fs.resolve_absent("10.0.0.1", seen_definition_ids=set(), source="nuclei")
        occ = FindingOccurrence.query.one()
        self.assertEqual(occ.status, "resolved")
        self.assertIsNotNone(occ.resolved_at)

        # it comes back
        fs.ingest_finding(definition_id="CVE-2024-2000", kind="cve", ip="10.0.0.1",
                          source="nuclei", port=80, protocol="tcp", severity="medium")
        occ = FindingOccurrence.query.one()
        self.assertEqual(occ.status, "reopened")
        self.assertIsNone(occ.resolved_at)

    def test_observations_are_append_only(self):
        occ = fs.ingest_finding(definition_id="CVE-2024-3000", kind="cve", ip="10.0.0.1",
                                source="nuclei", severity="low",
                                evidence={"template": "x", "raw": "banner"})
        first_count = FindingObservation.query.count()
        fs.ingest_finding(definition_id="CVE-2024-3000", kind="cve", ip="10.0.0.1",
                          source="nuclei", severity="critical")   # severity changed upstream
        self.assertEqual(FindingObservation.query.count(), first_count + 1)
        # the first observation's evidence is untouched
        first_obs = FindingObservation.query.order_by(FindingObservation.id).first()
        self.assertEqual(first_obs.evidence_json and "banner" in first_obs.evidence_json, True)

    def test_scanner_storage_dual_writes_canonical(self):
        from artemis.services.vuln_service import store_vulnerabilities
        store_vulnerabilities("10.0.0.1", [{
            "port": 8080, "protocol": "tcp", "vuln_id": "CVE-2021-44228",
            "vuln_name": "Log4Shell", "severity": "critical",
            "description": "rce", "references": ["https://x"],
        }])
        self.assertEqual(FindingOccurrence.query.filter_by(ip="10.0.0.1").count(), 1)

    def test_api_list_and_status(self):
        occ = fs.ingest_finding(definition_id="CVE-2024-4000", kind="cve", ip="10.0.0.1",
                                source="nuclei", severity="high")
        occ_id = occ.id
        from artemis.services.auth_service import create_access_token
        from artemis.models.user import User
        tok = create_access_token(db.session.get(User, 1))
        client = self.app.test_client()
        h = {"Authorization": f"Bearer {tok}"}
        listing = client.get("/api/v1/findings", headers=h).get_json()
        self.assertEqual(listing["count"], 1)
        r = client.put(f"/api/v1/findings/{occ_id}/status", headers=h, json={"status": "accepted"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(db.session.get(FindingOccurrence, occ_id).status, "accepted")


if __name__ == "__main__":
    unittest.main()
