"""P4.2 vulnerability intelligence: EPSS + KEV feed ingestion (idempotent,
tracked-only), exploit-maturity derivation, and the transparent priority score."""

import json
import unittest

from artemis import create_app
from artemis.extensions import db
from artemis.models.asset import Asset
from artemis.models.finding import FindingOccurrence, VulnerabilityDefinition
from artemis.services import finding_service as fs
from artemis.services import intel_service as intel
from artemis.services.auth_service import create_user

EPSS_CSV = (
    "#model_version:v2025.01.01,score_date:2026-09-03T00:00:00+0000\n"
    "cve,epss,percentile\n"
    "CVE-2021-44228,0.97400,0.99990\n"
    "CVE-2099-0001,0.00100,0.10000\n"
)

KEV_JSON = json.dumps({
    "catalogVersion": "2026.09.03",
    "vulnerabilities": [
        {"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10", "dueDate": "2021-12-24",
         "knownRansomwareCampaignUse": "Known", "requiredAction": "Patch"},
        {"cveID": "CVE-2099-9999", "dateAdded": "2099-01-01"},
    ],
})


class VulnIntelTests(unittest.TestCase):
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
        db.session.add(Asset(ip="10.0.0.1", lifecycle="active", criticality="critical",
                             environment="prod", first_seen="2026-01-01"))
        db.session.commit()
        # one tracked finding
        fs.ingest_finding(definition_id="CVE-2021-44228", kind="cve", ip="10.0.0.1",
                          source="nuclei", severity="critical")

    def tearDown(self):
        self._org.__exit__(None, None, None)
        db.drop_all()
        self.ctx.pop()

    def test_epss_updates_only_tracked_definitions(self):
        result = intel.sync_epss(fetch=lambda: EPSS_CSV)
        self.assertEqual(result["updated"], 1)
        self.assertIsNone(db.session.get(VulnerabilityDefinition, "CVE-2099-0001"))  # untracked
        d = db.session.get(VulnerabilityDefinition, "CVE-2021-44228")
        self.assertAlmostEqual(d.epss_score, 0.974, places=3)
        self.assertEqual(d.epss_model_date, "2026-09-03T00:00:00+0000")

    def test_epss_is_idempotent(self):
        intel.sync_epss(fetch=lambda: EPSS_CSV)
        again = intel.sync_epss(fetch=lambda: EPSS_CSV)
        self.assertEqual(again["updated"], 1)  # updates, but value unchanged
        self.assertEqual(VulnerabilityDefinition.query.count(), 1)

    def test_kev_sets_flags_and_maturity(self):
        intel.sync_kev(fetch=lambda: KEV_JSON)
        d = db.session.get(VulnerabilityDefinition, "CVE-2021-44228")
        self.assertTrue(d.kev)
        self.assertTrue(d.kev_ransomware)
        self.assertEqual(d.kev_required_action, "Patch")
        intel.refresh_exploit_maturity("CVE-2021-44228")
        db.session.commit()
        self.assertEqual(db.session.get(VulnerabilityDefinition, "CVE-2021-44228").exploit_maturity,
                         "known_exploited")

    def test_priority_score_exposes_every_factor(self):
        intel.sync_epss(fetch=lambda: EPSS_CSV)
        intel.sync_kev(fetch=lambda: KEV_JSON)
        occ = FindingOccurrence.query.one()
        score, factors = intel.compute_priority(occ)
        self.assertGreater(score, 60)
        self.assertEqual(set(factors), {"severity", "epss", "kev", "exploit_maturity",
                                        "asset_criticality", "exposure", "age_days"})
        self.assertTrue(factors["kev"]["value"])
        self.assertEqual(factors["asset_criticality"]["value"], "critical")

    def test_sync_all_rescoring_persists_on_occurrence(self):
        intel.sync_all(fetch_epss=lambda: EPSS_CSV, fetch_kev=lambda: KEV_JSON)
        occ = FindingOccurrence.query.one()
        self.assertIsNotNone(occ.priority_score)
        self.assertIn("epss", json.loads(occ.priority_factors_json))

    def test_intel_status_api(self):
        intel.sync_epss(fetch=lambda: EPSS_CSV)
        from artemis.services.auth_service import create_access_token
        from artemis.models.user import User
        tok = create_access_token(db.session.get(User, 1))
        r = self.app.test_client().get("/api/v1/intel/status",
                                       headers={"Authorization": f"Bearer {tok}"}).get_json()
        self.assertEqual(r["epss"]["scored"], 1)


if __name__ == "__main__":
    unittest.main()
