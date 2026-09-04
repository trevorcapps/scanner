"""P3.1 asset business context, lifecycle, tags, dynamic groups, and the
discovery guarantees (no manual-field clobber, no silent reactivation)."""

import unittest
from contextlib import contextmanager

from artemis import create_app
from artemis.extensions import db
from artemis.models.asset import Asset
from artemis.models.asset_group import AssetReviewEvent
from artemis.services import asset_lifecycle_service as svc
from artemis.services.asset_service import store_asset_info
from artemis.services.auth_service import create_access_token, create_user


class AssetLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app("testing", start_background_services=False)
        with self.app.app_context():
            db.drop_all()
            db.create_all()
            self.admin = create_user("admin", "password-123", role="admin")
            self.reader = create_user("reader", "password-123", role="readonly")
            self.tok = create_access_token(self.admin)
            self.reader_tok = create_access_token(self.reader)
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

    def _h(self, tok=None):
        return {"Authorization": f"Bearer {tok or self.tok}"}

    def _asset(self, ip="10.0.0.1"):
        a = Asset(ip=ip, hostname="auto-name", lifecycle="active", first_seen="2026-01-01")
        db.session.add(a)
        db.session.commit()
        return a.id

    def test_manual_context_is_recorded_and_not_clobbered_by_discovery(self):
        with self.ctx():
            aid = self._asset()
            svc.update_business_context(aid, {"criticality": "critical", "hostname": "prod-db-1",
                                             "business_owner": "platform"})
            store_asset_info("10.0.0.1", dns_info={"hostname": "discovered-name"})
            a = db.session.get(Asset, aid)
            self.assertEqual(a.hostname, "prod-db-1")          # manual value kept
            self.assertEqual(a.criticality, "critical")
            self.assertIn("hostname", a.manual_fields)

    def test_decommission_then_rediscovery_creates_review_event(self):
        with self.ctx():
            aid = self._asset("10.0.0.2")
            svc.decommission(aid, "returned to vendor")
            self.assertEqual(store_asset_info("10.0.0.2", dns_info={"hostname": "x"}), False)
            a = db.session.get(Asset, aid)
            self.assertEqual(a.lifecycle, "decommissioned")   # NOT reactivated
            self.assertEqual(
                AssetReviewEvent.query.filter_by(asset_id=aid,
                                                 kind="decommissioned_reappeared").count(), 1)

    def test_stale_transition(self):
        with self.ctx():
            aid = self._asset("10.0.0.3")
            db.session.get(Asset, aid).last_seen = "2000-01-01T00:00:00Z"
            db.session.commit()
            self.assertEqual(svc.mark_stale_assets(), 1)
            self.assertEqual(db.session.get(Asset, aid).lifecycle, "stale")

    def test_dynamic_group_membership_follows_the_filter(self):
        with self.ctx():
            a1 = self._asset("10.0.0.10")
            a2 = self._asset("10.0.0.11")
            svc.update_business_context(a1, {"environment": "prod", "criticality": "high"})
            svc.update_business_context(a2, {"environment": "dev"})
            g = svc.create_group("prod-critical", kind="dynamic",
                                 filter_spec={"environment": "prod", "criticality": ["high", "critical"]})
            members = {a.id for a in svc.group_members(g.id)}
            self.assertEqual(members, {a1})

    def test_bulk_tag_and_decommission_via_api(self):
        with self.ctx():
            ids = [self._asset(f"10.1.0.{i}") for i in range(3)]
        r = self.client.post("/api/v1/assets/bulk", headers=self._h(),
                             json={"op": "tag", "asset_ids": ids, "tag": "batch"})
        self.assertEqual(r.get_json()["updated"], 3)
        r = self.client.post("/api/v1/assets/bulk", headers=self._h(),
                             json={"op": "decommission", "asset_ids": ids, "reason": "sunset"})
        self.assertEqual(r.status_code, 200)
        with self.ctx():
            self.assertTrue(all(db.session.get(Asset, i).lifecycle == "decommissioned" for i in ids))

    def test_readonly_cannot_mutate_context(self):
        with self.ctx():
            aid = self._asset("10.2.0.1")
        r = self.client.put(f"/api/v1/assets/{aid}/context", headers=self._h(self.reader_tok),
                            json={"criticality": "low"})
        self.assertEqual(r.status_code, 403)


if __name__ == "__main__":
    unittest.main()
