"""P5-D signed agent-local Ansible execution: HMAC-signed manifest, digest +
signature verification, rejection of tampered content, and result mapping."""

import base64
import hashlib
import json
import unittest
from datetime import datetime, timedelta, timezone

from agent import artemis_agent
from artemis import create_app
from artemis.extensions import db
from artemis.models.agent import Agent
from artemis.models.agent_work import AgentWork
from artemis.models.scan_job import ScanJob
from artemis.services import job_service
from artemis.services.automation import agent_local
from artemis.services.auth_service import create_user

PLAYBOOK = "- hosts: targets\n  tasks:\n    - ansible.builtin.command: /bin/true\n"


class AgentLocalTests(unittest.TestCase):
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
        self.agent = Agent(agent_key="secret-key", hostname="edge", ip="10.9.9.9",
                           status="active", enabled=1,
                           capabilities_json=json.dumps(["ansible_local"]))
        db.session.add(self.agent)
        db.session.commit()
        self.client = self.app.test_client()

    def tearDown(self):
        self._org.__exit__(None, None, None)
        db.drop_all()
        self.ctx.pop()

    def _job(self):
        j = job_service.create_job("ansible_run", target="1 host")
        db.session.commit()
        return j

    def test_manifest_is_signed_and_verifies(self):
        job = self._job()
        digest = hashlib.sha256(PLAYBOOK.encode()).hexdigest()
        work = agent_local.create_work(self.agent, job_id=job.id, kind="ansible_local",
                                       content_body=PLAYBOOK, content_digest=digest,
                                       variables={"pkg": "nginx"})
        self.assertTrue(work.verify(self.agent))
        manifest = work.manifest()
        ok, reason = artemis_agent._verify_work(manifest, "secret-key")
        self.assertTrue(ok, reason)

    def test_wrong_key_fails_verification(self):
        job = self._job()
        work = agent_local.create_work(self.agent, job_id=job.id, kind="ansible_local",
                                       content_body=PLAYBOOK,
                                       content_digest=hashlib.sha256(PLAYBOOK.encode()).hexdigest())
        ok, _ = artemis_agent._verify_work(work.manifest(), "wrong-key")
        self.assertFalse(ok)

    def test_secret_variables_are_encrypted_in_manifest(self):
        job = self._job()
        work = agent_local.create_work(
            self.agent, job_id=job.id, kind="ansible_local", content_body=PLAYBOOK,
            content_digest=hashlib.sha256(PLAYBOOK.encode()).hexdigest(),
            variables={"ordinary": "value"},
            secret_variables={"ansible_password": "do-not-persist"},
        )
        self.assertNotIn("do-not-persist", work.payload_json)
        self.assertIn("secret_box", work.manifest()["payload"])
        self.assertEqual(
            artemis_agent._decrypt_work_secrets(work.manifest(), "secret-key"),
            {"ansible_password": "do-not-persist"},
        )
        self.assertEqual(
            artemis_agent._redact_lines("password=do-not-persist", {"p": "do-not-persist"}),
            ["password=***"],
        )

    def test_tampered_content_is_rejected_by_digest(self):
        job = self._job()
        work = agent_local.create_work(self.agent, job_id=job.id, kind="ansible_local",
                                       content_body=PLAYBOOK,
                                       content_digest=hashlib.sha256(PLAYBOOK.encode()).hexdigest())
        manifest = work.manifest()
        manifest["payload"]["content_b64"] = base64.b64encode(b"- hosts: all\n  tasks: []\n").decode()
        # signature still matches the *old* payload, so verify catches the swap
        ok, reason = artemis_agent._verify_work(manifest, "secret-key")
        self.assertFalse(ok)

    def test_poll_delivers_then_records_result(self):
        job = self._job()
        agent_local.create_work(self.agent, job_id=job.id, kind="ansible_local",
                                content_body=PLAYBOOK,
                                content_digest=hashlib.sha256(PLAYBOOK.encode()).hexdigest())
        h = {"X-Agent-Key": "secret-key"}
        polled = self.client.get("/api/v1/agents/work/poll", headers=h).get_json()["work"]
        self.assertEqual(polled["kind"], "ansible_local")
        self.assertEqual(AgentWork.query.one().status, "delivered")

        self.client.post("/api/v1/agents/work/result", headers=h, json={
            "work_id": polled["id"], "status": "succeeded", "rc": 0,
            "events": ["PLAY [targets]", "ok: [localhost]"],
        })
        self.assertEqual(AgentWork.query.one().status, "succeeded")
        self.assertEqual(db.session.get(ScanJob, job.id).status, "success")

    def test_expired_delivery_is_requeued(self):
        job = self._job()
        work = agent_local.create_work(self.agent, job_id=job.id, kind="ansible_local",
                                       content_body=PLAYBOOK)
        work.status = "delivered"
        work.delivered_at = (datetime.now(timezone.utc) - timedelta(
            seconds=agent_local.WORK_LEASE_SECONDS + 1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        db.session.commit()
        polled = agent_local.poll_work(self.agent)
        self.assertEqual(polled["id"], work.id)
        self.assertEqual(db.session.get(AgentWork, work.id).status, "delivered")

    def test_cancelling_parent_cancels_queued_work(self):
        job = self._job()
        agent_local.create_work(self.agent, job_id=job.id, kind="ansible_local",
                                content_body=PLAYBOOK)
        job_service.cancel_job(job)
        self.assertEqual(AgentWork.query.one().status, "cancelled")

    def test_rejected_result_fails_the_job(self):
        job = self._job()
        w = agent_local.create_work(self.agent, job_id=job.id, kind="ansible_local",
                                    content_body=PLAYBOOK)
        h = {"X-Agent-Key": "secret-key"}
        self.client.get("/api/v1/agents/work/poll", headers=h)
        self.client.post("/api/v1/agents/work/result", headers=h, json={
            "work_id": w.id, "status": "rejected", "reason": "signature mismatch"})
        self.assertEqual(db.session.get(ScanJob, job.id).status, "failed")

    def test_agent_without_capability_gets_no_local_executor(self):
        from artemis.services.automation.agent_local import agent_supports_local
        self.agent.capabilities_json = json.dumps(["remote_shell"])
        db.session.commit()
        self.assertFalse(agent_supports_local(self.agent))


if __name__ == "__main__":
    unittest.main()
