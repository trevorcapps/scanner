"""P5-E starter playbooks and patch campaigns: staged rollout with canary,
failure-threshold stop, and per-host outcome tracking."""

import json
import unittest

from artemis import create_app
from artemis.extensions import db
from artemis.models.asset import Asset
from artemis.models.campaign import PatchCampaign
from artemis.services.auth_service import create_access_token, create_user
from artemis.services.automation import campaign_service, starters
from artemis.services.automation.executor import AutomationExecutor, set_executor


class _Executor(AutomationExecutor):
    name = "seq"

    def __init__(self):
        self.results = []   # list of "successful"/"failed" per call

    def available(self):
        return True

    def run(self, *, playbook_body, inventory, variables, private_data_dir,
            event_handler, cancel_check=None, check_mode=False, options=None):
        status = self.results.pop(0) if self.results else "successful"
        event_handler({"event": "runner_on_ok", "event_data": {"host": "x"}})
        return {"status": status, "rc": 0 if status == "successful" else 2,
                "stats": {"ok": 1, "failed": 0 if status == "successful" else 1}}


class CampaignTests(unittest.TestCase):
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
        self.ids = []
        for i in range(6):
            a = Asset(ip=f"10.0.0.{i + 1}", lifecycle="active", first_seen="2026-01-01")
            db.session.add(a)
            db.session.flush()
            self.ids.append(a.id)
        db.session.commit()
        self.ex = _Executor()
        set_executor(self.ex)

    def tearDown(self):
        from artemis.services.automation.executor import reset_executor
        reset_executor()
        self._org.__exit__(None, None, None)
        db.drop_all()
        self.ctx.pop()

    def test_starters_registry_and_bodies(self):
        listed = {s["id"] for s in starters.list_starters()}
        self.assertIn("linux-package-update", listed)
        self.assertIn("hosts: targets", starters.get_starter_body("linux-fact-refresh"))

    def test_campaign_excludes_and_targets(self):
        c = campaign_service.create_campaign({
            "name": "sep", "starter_id": "linux-package-update",
            "targets": {"asset_ids": self.ids}, "excluded_ids": [self.ids[0]],
            "batch_size": 2, "canary_ids": [self.ids[1]],
        }, created_by=self.u.id)
        self.assertEqual(len(c.target_ids), 5)
        self.assertNotIn(self.ids[0], c.target_ids)

    def test_full_rollout_completes(self):
        c = campaign_service.create_campaign({
            "name": "roll", "starter_id": "linux-package-update",
            "targets": {"asset_ids": self.ids}, "batch_size": 2,
            "canary_ids": [self.ids[0]],
        }, created_by=self.u.id)
        campaign_service.start(c.id)          # canary batch runs + advance() chains
        c = db.session.get(PatchCampaign, c.id)
        self.assertEqual(c.status, "completed")
        per_host = json.loads(c.per_host_json)
        self.assertTrue(all(v["status"] == "success" for v in per_host.values()))

    def test_failure_threshold_stops_the_campaign(self):
        self.ex.results = ["failed", "failed", "failed", "failed", "failed", "failed"]
        c = campaign_service.create_campaign({
            "name": "bad", "starter_id": "linux-package-update",
            "targets": {"asset_ids": self.ids}, "batch_size": 2,
            "max_fail_percentage": 10, "canary_ids": [self.ids[0]],
        }, created_by=self.u.id)
        campaign_service.start(c.id)
        c = db.session.get(PatchCampaign, c.id)
        self.assertEqual(c.status, "failed")

    def test_preview_uses_check_mode(self):
        seen = {}
        real_run = self.ex.run

        def spy(**kw):
            seen["check_mode"] = kw["check_mode"]
            return real_run(**kw)

        self.ex.run = spy
        c = campaign_service.create_campaign({
            "name": "prev", "starter_id": "linux-update-preview",
            "targets": {"asset_ids": self.ids},
        }, created_by=self.u.id)
        campaign_service.preview(c.id)
        self.assertTrue(seen["check_mode"])

    def test_api_flow(self):
        h = {"Authorization": f"Bearer {create_access_token(self.u)}"}
        r = self.app.test_client().post("/api/v1/automation/campaigns", headers=h, json={
            "name": "api", "starter_id": "linux-fact-refresh",
            "targets": {"asset_ids": self.ids},
        })
        self.assertEqual(r.status_code, 201)
        cid = r.get_json()["campaign"]["id"]
        s = self.app.test_client().post(f"/api/v1/automation/campaigns/{cid}/start", headers=h)
        self.assertEqual(s.status_code, 200)


if __name__ == "__main__":
    unittest.main()
