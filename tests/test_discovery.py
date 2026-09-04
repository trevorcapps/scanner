"""P3.2 monitored-subnet discovery: scope authorization, approval gating,
bounded sweeps, and scan allow/deny enforcement."""

import unittest
from contextlib import contextmanager
from unittest.mock import patch

from artemis import create_app
from artemis.extensions import db
from artemis.models.asset import Asset
from artemis.services import discovery_service as svc
from artemis.services.auth_service import create_access_token, create_user


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app("testing", start_background_services=False)
        with self.app.app_context():
            db.drop_all()
            db.create_all()
            self.admin = create_user("admin", "password-123", role="admin")
            self.analyst = create_user("analyst", "password-123", role="analyst")
            self.admin_tok = create_access_token(self.admin)
            self.analyst_tok = create_access_token(self.analyst)
        self.client = self.app.test_client()

    def tearDown(self):
        with self.app.app_context():
            db.drop_all()

    @contextmanager
    def ctx(self):
        from artemis.services.org_service import ensure_default_organization
        from artemis.services.tenant import use_organization
        with self.app.app_context():
            oid = ensure_default_organization().id
            db.session.commit()
            with use_organization(oid):
                yield

    def _h(self, tok):
        return {"Authorization": f"Bearer {tok}"}

    def test_private_small_scope_is_auto_approved(self):
        with self.ctx():
            scope = svc.create_scope({"name": "lab", "cidrs": ["10.0.0.0/28"]})
            self.assertEqual(scope.approval_state, "approved")

    def test_public_or_broad_scope_needs_approval(self):
        with self.ctx():
            public = svc.create_scope({"name": "wan", "cidrs": ["9.9.9.0/28"]})
            self.assertEqual(public.approval_state, "pending")
            broad = svc.create_scope({"name": "big", "cidrs": ["10.0.0.0/18"]})
            self.assertEqual(broad.approval_state, "pending")

    def test_absolute_limit_rejected(self):
        with self.ctx():
            with self.assertRaises(ValueError):
                svc.create_scope({"name": "huge", "cidrs": ["10.0.0.0/8"]})

    def test_dispatch_blocked_until_approved(self):
        with self.ctx():
            scope = svc.create_scope({"name": "wan", "cidrs": ["45.33.0.0/25"]})
            sid = scope.id
            with self.assertRaises(PermissionError):
                svc.dispatch_discovery(sid)
            svc.approve_scope(sid, self.admin.id, approve=True)
            with patch("artemis.tasks.scan_tasks.run_discovery_job.apply_async") as sent:
                job = svc.dispatch_discovery(sid)
            sent.assert_called_once()
            self.assertEqual(job.job_type, "discovery")

    def test_scan_allow_deny_rules(self):
        with self.ctx():
            from artemis.services.auth_scan_service import set_setting
            set_setting("scan_deny", '["10.9.0.0/16"]')
            self.assertFalse(svc.check_scan_allowed("10.9.0.5"))
            self.assertTrue(svc.check_scan_allowed("10.8.0.5"))
            set_setting("scan_allow", '["10.8.0.0/24"]')
            self.assertFalse(svc.check_scan_allowed("10.7.0.5"))

    def test_run_scope_upserts_discovered_assets(self):
        with self.ctx():
            scope = svc.create_scope({"name": "lab", "cidrs": ["192.168.50.0/29"], "max_hosts": 8})

            def fake_scan(targets, options=None, cancel_check=None):
                return {"192.168.50.2": {}, "192.168.50.3": {}}

            with patch("artemis.scanners.nmap_scanner.scan", side_effect=fake_scan), \
                 patch("artemis.scanners.nmap_scanner.parse_scan",
                       side_effect=lambda r: [{"ip": ip} for ip in r]):
                summary = svc.run_scope(scope)
            self.assertEqual(summary["hosts_seen"], 2)
            self.assertEqual(Asset.query.filter(Asset.lifecycle == "active").count(), 2)

    def test_scope_creation_is_analyst_gated(self):
        r = self.client.post("/api/v1/discovery-scopes", headers=self._h(self.analyst_tok),
                             json={"name": "x", "cidrs": ["10.0.0.0/28"]})
        self.assertEqual(r.status_code, 201)
        # approval is admin-only
        sid = r.get_json()["scope"]["id"]
        r2 = self.client.post(f"/api/v1/discovery-scopes/{sid}/approve",
                              headers=self._h(self.analyst_tok), json={"approve": True})
        self.assertEqual(r2.status_code, 403)


if __name__ == "__main__":
    unittest.main()
