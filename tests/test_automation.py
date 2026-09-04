"""P5-B/C ansible automation: executor boundary, content validation +
content-addressing, ephemeral inventory, run job + event mapping, audit."""

import json
import unittest
from contextlib import contextmanager

from artemis import create_app
from artemis.extensions import db
from artemis.models.asset import Asset
from artemis.models.audit_event import AuditEvent
from artemis.models.automation import AutomationContent, AutomationRun
from artemis.models.scan_job import ScanJob
from artemis.services.auth_service import create_access_token, create_user
from artemis.services.automation import content_service
from artemis.services.automation.executor import AutomationExecutor, set_executor

PLAYBOOK = """- hosts: targets
  gather_facts: false
  tasks:
    - name: touch a file
      ansible.builtin.command: /bin/true
"""

BAD_PLAYBOOK = "just a string, not a play list"


class FakeExecutor(AutomationExecutor):
    name = "fake"

    def __init__(self, status="successful"):
        self.status = status
        self.last_inventory = None

    def available(self):
        return True

    def run(self, *, playbook_body, inventory, variables, private_data_dir,
            event_handler, cancel_check=None, check_mode=False, options=None):
        self.last_inventory = inventory
        event_handler({"event": "playbook_on_play_start", "event_data": {"name": "p"}})
        event_handler({"event": "runner_on_ok", "event_data": {"host": "artemis_1", "task": "touch"}})
        return {"status": self.status, "rc": 0 if self.status == "successful" else 2,
                "stats": {"ok": 1, "changed": 0, "failed": 0}}


class AutomationTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app("testing", start_background_services=False)
        self.ctx = self.app.app_context()
        self.ctx.push()
        db.drop_all()
        db.create_all()
        self.u = create_user("admin", "password-123", role="admin")
        self.reader = create_user("reader", "password-123", role="readonly")
        from artemis.services.org_service import ensure_default_organization
        from artemis.services.tenant import use_organization
        self.oid = ensure_default_organization().id
        db.session.commit()
        self._org = use_organization(self.oid)
        self._org.__enter__()
        db.session.add(Asset(ip="10.0.0.1", hostname="h1", lifecycle="active", first_seen="2026-01-01"))
        db.session.commit()
        self.asset_id = Asset.query.one().id
        set_executor(FakeExecutor())
        self.client = self.app.test_client()

    def tearDown(self):
        from artemis.services.automation.executor import reset_executor
        reset_executor()
        self._org.__exit__(None, None, None)
        db.drop_all()
        self.ctx.pop()

    def _h(self, tok=None):
        return {"Authorization": f"Bearer {tok or create_access_token(self.u)}"}

    def test_content_is_validated_and_content_addressed(self):
        c1 = content_service.accept_content(PLAYBOOK, created_by=self.u.id)
        c2 = content_service.accept_content(PLAYBOOK, created_by=self.u.id)
        self.assertEqual(c1.id, c2.id)                       # idempotent by digest
        self.assertEqual(len(c1.digest), 64)
        self.assertTrue(c1.syntax_ok)
        self.assertTrue(c1.sealed_body.startswith("enc:v1:"))
        self.assertEqual(c1.reveal(), PLAYBOOK)

    def test_bad_playbook_rejected(self):
        with self.assertRaises(content_service.ContentError):
            content_service.accept_content(BAD_PLAYBOOK)

    def test_run_launches_job_and_maps_events(self):
        r = self.client.post("/api/v1/automation/runs", headers=self._h(), json={
            "content": PLAYBOOK,
            "targets": {"asset_ids": [self.asset_id]},
            "variables": {"pkg": "nginx"},
        })
        self.assertEqual(r.status_code, 202)
        job_id = r.get_json()["job"]["id"]

        job = db.session.get(ScanJob, job_id)
        self.assertEqual(job.status, "success")          # eager celery ran it
        kinds = [e.kind for e in job.events.all()]
        self.assertIn("log", kinds)
        run = AutomationRun.query.one()
        self.assertEqual(run.target_snapshot_json, json.dumps([self.asset_id]))
        self.assertEqual(run.to_dict()["variables"], {"pkg": "nginx"})   # non-secret, stored

    def test_saved_content_can_be_listed_and_launched(self):
        content = content_service.accept_content(PLAYBOOK, created_by=self.u.id)
        listed = self.client.get("/api/v1/automation/content", headers=self._h())
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.get_json()["content"][0]["id"], content.id)

        launched = self.client.post("/api/v1/automation/runs", headers=self._h(), json={
            "content_id": content.id,
            "targets": {"asset_ids": [self.asset_id]},
        })
        self.assertEqual(launched.status_code, 202)
        self.assertEqual(db.session.get(ScanJob, launched.get_json()["job"]["id"]).status, "success")

    def test_content_can_be_saved_without_launching(self):
        response = self.client.post("/api/v1/automation/content", headers=self._h(), json={
            "content": PLAYBOOK,
            "filename": "saved.yml",
        })
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.get_json()["content"]["filename"], "saved.yml")
        self.assertEqual(AutomationContent.query.count(), 1)

    def test_audit_records_digest_and_nonsecret_inputs(self):
        self.client.post("/api/v1/automation/runs", headers=self._h(), json={
            "content": PLAYBOOK, "targets": {"asset_ids": [self.asset_id]},
            "variables": {"batch": 5},
        })
        ev = AuditEvent.query.filter_by(action="automation.launch").one()
        detail = json.loads(ev.detail_json)
        self.assertEqual(detail["hosts"], 1)
        self.assertEqual(detail["variables"], ["batch"])
        self.assertEqual(len(detail["digest"]), 64)

    def test_readonly_cannot_launch(self):
        r = self.client.post("/api/v1/automation/runs",
                             headers=self._h(create_access_token(self.reader)),
                             json={"content": PLAYBOOK, "targets": {"asset_ids": [self.asset_id]}})
        self.assertEqual(r.status_code, 403)

    def test_failed_run_marks_job_failed(self):
        set_executor(FakeExecutor(status="failed"))
        r = self.client.post("/api/v1/automation/runs", headers=self._h(), json={
            "content": PLAYBOOK, "targets": {"asset_ids": [self.asset_id]}})
        job = db.session.get(ScanJob, r.get_json()["job"]["id"])
        self.assertEqual(job.status, "failed")

    def test_executor_unavailable_is_reported(self):
        from artemis.services.automation.executor import NullExecutor
        set_executor(NullExecutor())
        status = self.client.get("/api/v1/automation/executor", headers=self._h()).get_json()
        self.assertFalse(status["available"])
        r = self.client.post("/api/v1/automation/runs", headers=self._h(), json={
            "content": PLAYBOOK, "targets": {"asset_ids": [self.asset_id]}})
        # run row + job created, job immediately failed (no executor)
        job = db.session.get(ScanJob, r.get_json()["job"]["id"])
        self.assertEqual(job.status, "failed")

    def test_inventory_uses_immutable_ids(self):
        ex = FakeExecutor()
        set_executor(ex)
        self.client.post("/api/v1/automation/runs", headers=self._h(), json={
            "content": PLAYBOOK, "targets": {"asset_ids": [self.asset_id]}})
        self.assertIn(f"artemis_{self.asset_id}", ex.last_inventory)
        self.assertIn("ansible_host=10.0.0.1", ex.last_inventory)


if __name__ == "__main__":
    unittest.main()
