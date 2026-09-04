"""P4.3 remediation guidance: informational only, advisory-backed when possible,
heuristic clearly marked, and no credentials / runnable payload."""

import unittest

from artemis import create_app
from artemis.extensions import db
from artemis.models.asset import Asset
from artemis.services import finding_service as fs
from artemis.services import intel_service as intel
from artemis.services.auth_service import create_user
from artemis.services.remediation_service import build_guidance


class RemediationTests(unittest.TestCase):
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
        db.session.add(Asset(ip="10.0.0.1", hostname="web1", criticality="high",
                             lifecycle="active", first_seen="2026-01-01"))
        db.session.commit()

    def tearDown(self):
        self._org.__exit__(None, None, None)
        db.drop_all()
        self.ctx.pop()

    def test_kev_action_is_trusted_not_heuristic(self):
        occ = fs.ingest_finding(definition_id="CVE-2021-44228", kind="cve", ip="10.0.0.1",
                                source="nuclei", severity="critical",
                                component="pkg:log4j-core")
        intel.sync_kev(fetch=lambda: '{"catalogVersion":"x","vulnerabilities":['
                       '{"cveID":"CVE-2021-44228","dateAdded":"2021-12-10",'
                       '"requiredAction":"Update to 2.17.1"}]}')
        db.session.commit()
        g = build_guidance(occ.id)
        trusted_steps = [s for s in g["steps"] if not s["heuristic"]]
        self.assertTrue(trusted_steps)
        self.assertEqual(trusted_steps[0]["source"], "cisa-kev")

    def test_heuristic_guidance_is_marked(self):
        occ = fs.ingest_finding(definition_id="CVE-2024-9999", kind="cve", ip="10.0.0.1",
                                source="ssh", severity="high", component="pkg:openssl")
        g = build_guidance(occ.id)
        self.assertTrue(g["fixed_version_is_heuristic"])
        self.assertTrue(all(s["heuristic"] for s in g["steps"]))

    def test_guidance_has_no_secret_or_payload(self):
        occ = fs.ingest_finding(definition_id="CVE-2024-1", kind="cve", ip="10.0.0.1",
                                source="nuclei", severity="medium")
        g = build_guidance(occ.id)
        blob = str(g).lower()
        for banned in ("password", "private key", "ansible", "playbook:", "ssh -i", "curl "):
            self.assertNotIn(banned, blob)
        self.assertIn("informational", g["note"])

    def test_affected_assets_listed(self):
        for ip in ("10.0.0.1", "10.0.0.2"):
            if ip == "10.0.0.2":
                db.session.add(Asset(ip=ip, lifecycle="active", first_seen="2026-01-01"))
                db.session.commit()
            fs.ingest_finding(definition_id="CVE-2024-2", kind="cve", ip=ip,
                              source="nuclei", severity="high")
        occ = fs.ingest_finding(definition_id="CVE-2024-2", kind="cve", ip="10.0.0.1",
                                source="nuclei", severity="high")
        g = build_guidance(occ.id)
        self.assertEqual({a["ip"] for a in g["affected_assets"]}, {"10.0.0.1", "10.0.0.2"})

    def test_api_endpoint(self):
        occ = fs.ingest_finding(definition_id="CVE-2024-3", kind="cve", ip="10.0.0.1",
                                source="nuclei", severity="low")
        from artemis.models.user import User
        from artemis.services.auth_service import create_access_token
        tok = create_access_token(db.session.get(User, 1))
        r = self.app.test_client().get(f"/api/v1/findings/{occ.id}/remediation",
                                       headers={"Authorization": f"Bearer {tok}"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("steps", r.get_json()["remediation"])


if __name__ == "__main__":
    unittest.main()
