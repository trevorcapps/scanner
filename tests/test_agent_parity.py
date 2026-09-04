"""P3.4 agent parity: v3 report schema (patch state, service health, platform),
capability health, rollout rings, and upgrade status."""

import json
import unittest
from contextlib import contextmanager

from agent import artemis_agent
from artemis import create_app
from artemis.extensions import db
from artemis.models.agent import Agent
from artemis.services.agent_service import process_report
from artemis.services.auth_service import create_access_token, create_user


class AgentParityTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app("testing", start_background_services=False)
        self.ctx_obj = self.app.app_context()
        self.ctx_obj.push()
        db.drop_all()
        db.create_all()
        self.admin = create_user("admin", "password-123", role="admin")
        self.tok = create_access_token(self.admin)
        self.agent = Agent(agent_key="k", hostname="h", ip="10.0.0.9",
                           status="active", enabled=1, agent_version="1.2.0")
        db.session.add(self.agent)
        db.session.commit()
        self.client = self.app.test_client()

    def tearDown(self):
        db.drop_all()
        self.ctx_obj.pop()

    def _report(self, **over):
        base = {
            "hostname": "h", "ip": "10.0.0.9", "agent_version": "1.4.0",
            "telemetry_schema_version": 3, "host_platform": "linux",
            "os_info": {"pretty_name": "Debian 12"},
            "system_info": {"uptime_seconds": 4242},
            "packages": [], "ports": [],
            "capabilities": ["remote_shell", "patch_status"],
            "patch_status": {"reboot_required": True, "pending_updates": 7,
                             "security_updates": 2, "package_manager": "apt"},
            "service_health": {"manager": "systemd", "state": "running", "failed_units": []},
            "telemetry": {"collectors": {"packages": {"status": "ok"},
                                         "patch_status": {"status": "ok"},
                                         "ports": {"status": "error"}}},
        }
        base.update(over)
        return base

    def test_agent_reports_v3_schema(self):
        report = artemis_agent.collect_report()
        self.assertEqual(report["telemetry_schema_version"], 3)
        self.assertIn("patch_status", report)
        self.assertIn("service_health", report)
        self.assertIn(report["host_platform"], ("linux", "macos", "other"))
        self.assertIn("patch_status", artemis_agent.AGENT_CAPABILITIES)

    def test_unsupported_fields_are_explicit_not_zero(self):
        status = artemis_agent.get_patch_status()
        # On the CI/dev box there is no apt/dnf reboot marker guaranteed; the
        # contract is that unknown answers are the string "unsupported".
        for key in ("reboot_required", "pending_updates", "security_updates"):
            self.assertIn(status[key], (True, False, "unsupported", 0) if key == "reboot_required"
                          else (int, "unsupported"))
            if isinstance(status[key], str):
                self.assertEqual(status[key], "unsupported")

    def test_process_report_stores_patch_and_health(self):
        process_report(self.agent, self._report())
        a = db.session.get(Agent, self.agent.id)
        self.assertEqual(a.reboot_required, "true")
        self.assertEqual(a.pending_updates, 7)
        self.assertEqual(a.security_updates, 2)
        self.assertEqual(a.host_platform, "linux")
        self.assertEqual(a.uptime_seconds, 4242)
        self.assertEqual(json.loads(a.capability_health_json)["ports"], "error")
        self.assertEqual(a.upgrade_status, "up_to_date")   # 1.4.0 == current

    def test_upgrade_status_reflects_target_version(self):
        from artemis.services.auth_scan_service import set_setting
        set_setting("agent_target_version", "1.5.0")
        process_report(self.agent, self._report(agent_version="1.4.0"))
        self.assertEqual(db.session.get(Agent, self.agent.id).upgrade_status, "pending")

    def test_fleet_view_and_rollout_ring(self):
        process_report(self.agent, self._report())
        h = {"Authorization": f"Bearer {self.tok}"}
        fleet = self.client.get("/api/v1/agents/fleet", headers=h).get_json()
        self.assertEqual(fleet["summary"]["total"], 1)
        self.assertEqual(fleet["summary"]["reboot_required"], 1)

        r = self.client.put(f"/api/v1/agents/{self.agent.id}/rollout-ring", headers=h,
                            json={"ring": "canary"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(db.session.get(Agent, self.agent.id).rollout_ring, "canary")


if __name__ == "__main__":
    unittest.main()
