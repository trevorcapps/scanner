"""P4.4 false-positive / risk-acceptance workflow: approval gating, suppression
without evidence loss, auto-expiry + reopen, and effective-risk reporting."""

import unittest

from artemis import create_app
from artemis.extensions import db
from artemis.models.disposition import Disposition, SuppressionRule
from artemis.models.finding import FindingObservation, FindingOccurrence
from artemis.services import disposition_service as svc
from artemis.services import finding_service as fs
from artemis.services.auth_service import create_user


class DispositionTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app("testing", start_background_services=False)
        self.ctx = self.app.app_context()
        self.ctx.push()
        db.drop_all()
        db.create_all()
        self.u = create_user("admin", "password-123", role="admin")
        from artemis.services.org_service import ensure_default_organization
        from artemis.services.tenant import use_organization
        self.oid = ensure_default_organization().id
        db.session.commit()
        self._org = use_organization(self.oid)
        self._org.__enter__()
        self.occ = fs.ingest_finding(definition_id="CVE-2024-1", kind="cve", ip="10.0.0.1",
                                     source="nuclei", severity="high",
                                     evidence={"raw": "banner-proof"})

    def tearDown(self):
        self._org.__exit__(None, None, None)
        db.drop_all()
        self.ctx.pop()

    def test_false_positive_occurrence_auto_applies(self):
        disp = svc.create_disposition({"type": "false_positive", "scope": "occurrence",
                                       "target_id": self.occ.id, "rationale": "not exploitable"},
                                      requested_by=self.u.id)
        self.assertEqual(disp.status, "approved")
        self.assertEqual(db.session.get(FindingOccurrence, self.occ.id).status, "suppressed")
        # evidence is untouched
        self.assertTrue(FindingObservation.query.filter(
            FindingObservation.evidence_json.like('%banner-proof%')).count())

    def test_risk_acceptance_requires_approval(self):
        disp = svc.create_disposition({"type": "risk_accepted", "scope": "occurrence",
                                       "target_id": self.occ.id, "rationale": "accepted till Q3",
                                       "expires_at": "2000-01-01T00:00:00Z"},
                                      requested_by=self.u.id)
        self.assertEqual(disp.status, "pending")
        self.assertEqual(db.session.get(FindingOccurrence, self.occ.id).status, "open")

        svc.decide(disp.id, True, self.u.id)
        self.assertEqual(db.session.get(FindingOccurrence, self.occ.id).status, "accepted")

    def test_expired_disposition_reopens_and_notifies(self):
        disp = svc.create_disposition({"type": "risk_accepted", "scope": "occurrence",
                                       "target_id": self.occ.id, "rationale": "temp",
                                       "expires_at": "2000-01-01T00:00:00Z"},
                                      requested_by=self.u.id)
        svc.decide(disp.id, True, self.u.id)
        reopened = svc.expire_due()
        self.assertEqual(reopened, 1)
        self.assertEqual(db.session.get(Disposition, disp.id).status, "expired")
        self.assertEqual(db.session.get(FindingOccurrence, self.occ.id).status, "reopened")

    def test_org_wide_suppression_rule_hides_from_list_but_keeps_ingesting(self):
        fs.ingest_finding(definition_id="CVE-2024-2", kind="cve", ip="10.0.0.2",
                          source="nuclei", severity="medium")
        disp = svc.create_disposition({"type": "false_positive", "scope": "organization",
                                       "definition_id": "CVE-2024-2", "rationale": "known FP scanner bug"},
                                      requested_by=self.u.id)
        self.assertEqual(disp.status, "pending")          # org-wide needs approval
        svc.decide(disp.id, True, self.u.id)
        self.assertTrue(SuppressionRule.query.count())

        # a fresh scan still records the observation ...
        fs.ingest_finding(definition_id="CVE-2024-2", kind="cve", ip="10.0.0.2",
                          source="nuclei", severity="medium")
        self.assertTrue(FindingObservation.query.join(FindingOccurrence).filter(
            FindingOccurrence.definition_id == "CVE-2024-2").count() >= 2)
        # ... but the finding is not in the default list
        ids = {f.definition_id for f in fs.list_findings()}
        self.assertNotIn("CVE-2024-2", ids)
        self.assertIn("CVE-2024-2", {f.definition_id for f in fs.list_findings(include_suppressed=True)})

    def test_effective_risk_excludes_accepted_and_suppressed(self):
        svc.create_disposition({"type": "false_positive", "scope": "occurrence",
                                "target_id": self.occ.id, "rationale": "fp"}, requested_by=self.u.id)
        risk = svc.effective_risk()
        self.assertEqual(risk["effective"]["high"], 0)
        self.assertGreaterEqual(risk["suppressed"] + risk["accepted"], 1)

    def test_bulk_and_decision_api(self):
        from artemis.models.user import User
        from artemis.services.auth_service import create_access_token
        occ2 = fs.ingest_finding(definition_id="CVE-2024-3", kind="cve", ip="10.0.0.3",
                                 source="nuclei", severity="low")
        tok = create_access_token(db.session.get(User, 1))
        h = {"Authorization": f"Bearer {tok}"}
        r = self.app.test_client().post("/api/v1/dispositions/bulk", headers=h, json={
            "type": "wont_fix", "rationale": "legacy box", "occurrence_ids": [self.occ.id, occ2.id]})
        self.assertEqual(len(r.get_json()["created"]), 2)


if __name__ == "__main__":
    unittest.main()
