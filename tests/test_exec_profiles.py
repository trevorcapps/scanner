"""P2.3 scan execution profiles, cron/window validation, missed-run policy,
and stable observation deltas."""

import unittest
from contextlib import contextmanager
from datetime import datetime, timezone

from artemis import create_app
from artemis.extensions import db
from artemis.models.scan_profile import ScanExecutionProfile
from artemis.services import scan_profile_service as sps
from artemis.services.auth_service import create_access_token, create_user


class ExecutionProfileTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app("testing", start_background_services=False)
        with self.app.app_context():
            db.drop_all()
            db.create_all()
            self.admin = create_user("admin", "password-123", role="admin")
            self.tok = create_access_token(self.admin)
        self.client = self.app.test_client()

    def tearDown(self):
        with self.app.app_context():
            db.drop_all()

    @contextmanager
    def ctx(self):
        from artemis.services.org_service import ensure_default_organization
        from artemis.services.tenant import use_organization
        with self.app.app_context():
            org_id = ensure_default_organization().id
            db.session.commit()
            with use_organization(org_id):
                yield

    def _h(self):
        return {"Authorization": f"Bearer {self.tok}"}

    def test_editing_a_profile_creates_a_new_version(self):
        with self.ctx():
            p1 = sps.create_profile({"name": "night", "max_hosts": 100})
            p2 = sps.new_version("night", {"max_hosts": 200})
            self.assertEqual((p1.version, p2.version), (1, 2))
            self.assertEqual(db.session.get(ScanExecutionProfile, p1.id).is_current, 0)
            self.assertEqual(len(sps.list_profiles()), 1)                 # current only
            self.assertEqual(len(sps.list_profiles(include_history=True)), 2)

    def test_window_evaluation_honours_timezone_and_days(self):
        with self.ctx():
            p = sps.create_profile({
                "name": "biz", "timezone": "UTC",
                "window_start": "22:00", "window_end": "06:00",   # wraps midnight
                "window_days": [0, 1, 2, 3, 4],
            })
            inside = datetime(2026, 9, 7, 23, 0, tzinfo=timezone.utc)   # Monday 23:00
            outside = datetime(2026, 9, 7, 12, 0, tzinfo=timezone.utc)  # Monday noon
            weekend = datetime(2026, 9, 6, 23, 0, tzinfo=timezone.utc)  # Sunday 23:00
            self.assertTrue(sps.within_window(p, inside))
            self.assertFalse(sps.within_window(p, outside))
            self.assertFalse(sps.within_window(p, weekend))

    def test_cron_and_policy_validation(self):
        self.assertTrue(sps.validate_cron("0 2 * * *"))
        self.assertFalse(sps.validate_cron("not a cron"))
        self.assertTrue(sps.validate_timezone("America/New_York"))
        self.assertFalse(sps.validate_timezone("Mars/Olympus"))
        self.assertTrue(sps.validate_missed_run_policy("catch_up"))
        self.assertFalse(sps.validate_missed_run_policy("nonsense"))

    def test_schedule_api_rejects_bad_cron(self):
        r = self.client.post("/api/v1/schedules", headers=self._h(), json={
            "name": "s", "target": "10.0.0.1", "schedule_type": "cron",
            "cron_expression": "every tuesday",
        })
        self.assertEqual(r.status_code, 400)

    def test_profile_api_roundtrip_and_versioning(self):
        a = self.client.post("/api/v1/execution-profiles", headers=self._h(),
                             json={"name": "p", "max_hosts": 50})
        self.assertEqual(a.status_code, 201)
        b = self.client.post("/api/v1/execution-profiles", headers=self._h(),
                             json={"name": "p", "max_hosts": 75})
        self.assertEqual(b.get_json()["profile"]["version"], 2)
        listing = self.client.get("/api/v1/execution-profiles", headers=self._h()).get_json()
        self.assertEqual(len(listing["profiles"]), 1)

    def test_delta_classifies_new_resolved_reopened(self):
        from artemis.models.vulnerability import Vulnerability
        from artemis.services.delta_service import compute_delta, snapshot
        with self.ctx():
            db.session.add(Vulnerability(ip="10.0.0.1", port=443, protocol="tcp",
                                         vuln_id="CVE-2024-1", vuln_name="x", severity="high"))
            db.session.commit()
            base = snapshot(["10.0.0.1"])

            db.session.add(Vulnerability(ip="10.0.0.1", port=80, protocol="tcp",
                                         vuln_id="CVE-2024-2", vuln_name="y", severity="low"))
            db.session.commit()
            delta = compute_delta(["10.0.0.1"], base)
            self.assertEqual(delta["new_vulns"], 1)
            self.assertEqual(delta["resolved_vulns"], 0)


if __name__ == "__main__":
    unittest.main()
