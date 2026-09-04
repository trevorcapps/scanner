"""P3.3 historical inventory: package observation intervals and asset timeline."""

import unittest
from contextlib import contextmanager

from artemis import create_app
from artemis.extensions import db
from artemis.models.asset import Asset
from artemis.models.inventory_history import AssetTimelineEvent, SoftwareObservation
from artemis.services import inventory_service as inv
from artemis.services.auth_service import create_user


class InventoryHistoryTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app("testing", start_background_services=False)
        self.ctx_obj = self.app.app_context()
        self.ctx_obj.push()
        db.drop_all()
        db.create_all()
        create_user("admin", "password-123", role="admin")
        from artemis.services.org_service import ensure_default_organization
        from artemis.services.tenant import use_organization
        self.org_id = ensure_default_organization().id
        db.session.commit()
        self._org = use_organization(self.org_id)
        self._org.__enter__()
        self.asset = Asset(ip="10.0.0.1", hostname="box", lifecycle="active", first_seen="2026-01-01")
        db.session.add(self.asset)
        db.session.commit()

    def tearDown(self):
        self._org.__exit__(None, None, None)
        db.drop_all()
        self.ctx_obj.pop()

    def _pkgs(self, *pairs):
        return [{"name": n, "version": v} for n, v in pairs]

    def test_install_update_remove_intervals(self):
        r1 = inv.record_inventory("10.0.0.1", self._pkgs(("openssl", "3.0.11"), ("curl", "8.5.0")))
        self.assertEqual(r1, {"installed": 2, "updated": 0, "removed": 0})

        r2 = inv.record_inventory("10.0.0.1", self._pkgs(("openssl", "3.0.13"), ("curl", "8.5.0")))
        self.assertEqual((r2["updated"], r2["removed"]), (1, 0))

        r3 = inv.record_inventory("10.0.0.1", self._pkgs(("openssl", "3.0.13")))
        self.assertEqual(r3["removed"], 1)   # curl gone

        obs = SoftwareObservation.query.filter_by(package_name="openssl").order_by(
            SoftwareObservation.first_seen).all()
        self.assertEqual([o.package_version for o in obs], ["3.0.11", "3.0.13"])
        self.assertIsNotNone(obs[0].removed_at)      # the 3.0.11 interval is closed
        self.assertIsNone(obs[1].removed_at)         # 3.0.13 still active

        curl = SoftwareObservation.query.filter_by(package_name="curl").one()
        self.assertIsNotNone(curl.removed_at)

    def test_timeline_events_are_emitted(self):
        inv.record_inventory("10.0.0.1", self._pkgs(("nginx", "1.24.0")))
        inv.record_inventory("10.0.0.1", self._pkgs(("nginx", "1.25.0")))
        inv.record_inventory("10.0.0.1", [])

        kinds = [e.kind for e in AssetTimelineEvent.query.order_by(AssetTimelineEvent.id).all()]
        self.assertEqual(kinds, ["package_installed", "package_updated", "package_removed"])

    def test_identity_and_port_change_events(self):
        inv.record_identity_change("10.0.0.1", hostname="renamed-box", os_name="Debian 13")
        self.assertTrue(AssetTimelineEvent.query.filter_by(kind="hostname_changed").count())

        inv.record_port_changes("10.0.0.1", [(443, "tcp", "https")])
        self.assertTrue(AssetTimelineEvent.query.filter_by(kind="port_opened").count())

    def test_history_api_endpoints(self):
        inv.record_inventory("10.0.0.1", self._pkgs(("vim", "9.1")))
        client = self.app.test_client()
        from artemis.services.auth_service import create_access_token
        tok = create_access_token(db.session.get(
            __import__("artemis.models.user", fromlist=["User"]).User, 1))
        h = {"Authorization": f"Bearer {tok}"}
        tl = client.get(f"/api/v1/assets/{self.asset.id}/timeline", headers=h).get_json()
        self.assertTrue(tl["events"])
        sh = client.get(f"/api/v1/assets/{self.asset.id}/software-history", headers=h).get_json()
        self.assertEqual(sh["observations"][0]["package_name"], "vim")


if __name__ == "__main__":
    unittest.main()
