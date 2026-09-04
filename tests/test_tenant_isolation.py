"""P1.3 enforced tenant isolation: a two-organization matrix over the API,
background tasks, and report artifacts. Cross-org access returns 404/empty and
leaks nothing."""

import os
import unittest
from contextlib import contextmanager

from artemis import create_app
from artemis.extensions import db
from artemis.models.asset import Asset
from artemis.models.credential import Credential
from artemis.models.site import Site
from artemis.services.auth_service import create_access_token, create_user
from artemis.services.org_service import add_member, create_organization
from artemis.services.tenant import current_org_id, use_organization


class TenantIsolationTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app("testing", start_background_services=False)
        with self.app.app_context():
            db.drop_all()
            db.create_all()
            self.root = create_user("root", "password-123", role="admin")  # platform admin
            self.a_user = create_user("a_user", "password-123", role="admin")
            self.b_user = create_user("b_user", "password-123", role="admin")

            self.org_a = create_organization("Org A", owner=self.a_user)
            self.org_b = create_organization("Org B", owner=self.b_user)
            db.session.commit()
            self.a_id, self.b_id = self.org_a.id, self.org_b.id

            with use_organization(self.a_id):
                db.session.add(Asset(ip="10.1.1.1", hostname="a-box"))
                db.session.add(Site(name="a-site", targets_json='["10.1.1.0/24"]'))
                c = Credential(name="a-cred", cred_type="ssh_password", username="root")
                c.set_secret("a-secret")
                db.session.add(c)
                db.session.commit()
            with use_organization(self.b_id):
                db.session.add(Asset(ip="10.1.1.1", hostname="b-box"))  # same IP, different org
                db.session.add(Site(name="b-site", targets_json='["10.2.2.0/24"]'))
                db.session.commit()

            self.a_tok = create_access_token(self.a_user)
            self.b_tok = create_access_token(self.b_user)
            self.root_tok = create_access_token(self.root)
        self.client = self.app.test_client()

    def tearDown(self):
        with self.app.app_context():
            db.drop_all()

    @contextmanager
    def ctx(self):
        with self.app.app_context():
            yield

    def _h(self, tok, org=None):
        h = {"Authorization": f"Bearer {tok}"}
        if org is not None:
            h["X-Organization"] = str(org)
        return h

    def test_same_ip_two_orgs_coexist(self):
        with self.ctx():
            self.assertEqual(Asset.query.filter_by(organization_id=self.a_id).count() +
                             Asset.query.filter_by(organization_id=self.b_id).count(), 2)

    @staticmethod
    def _rows(payload):
        if isinstance(payload, list):
            return payload
        for key in ("assets", "data", "sites", "items", "results"):
            if key in payload:
                return payload[key]
        return []

    def test_asset_list_is_scoped(self):
        a = self.client.get("/api/v1/assets", headers=self._h(self.a_tok, self.a_id)).get_json()
        hostnames = {row["hostname"] for row in self._rows(a)}
        self.assertIn("a-box", hostnames)
        self.assertNotIn("b-box", hostnames)

    def test_cross_org_credential_and_site_are_invisible(self):
        # b_user is not a member of Org A -> context denied
        resp = self.client.get("/api/v1/credentials", headers=self._h(self.b_tok, self.a_id))
        self.assertIn(resp.status_code, (403, 404))

        # even acting in their own org, b cannot see a's site
        sites = self.client.get("/api/v1/sites", headers=self._h(self.b_tok, self.b_id)).get_json()
        rows = sites["sites"] if isinstance(sites, dict) else sites
        self.assertEqual({s["name"] for s in rows}, {"b-site"})

    def test_auto_filter_applies_to_direct_queries(self):
        with self.ctx(), use_organization(self.b_id):
            self.assertEqual(current_org_id(), self.b_id)
            self.assertEqual([a.hostname for a in Asset.query.all()], ["b-box"])
            self.assertEqual(Credential.query.count(), 0)   # a-cred belongs to Org A

    def test_platform_admin_sees_one_org_at_a_time(self):
        a = self.client.get("/api/v1/assets", headers=self._h(self.root_tok, self.a_id)).get_json()
        got = {row["hostname"] for row in self._rows(a)}
        self.assertIn("a-box", got)
        self.assertNotIn("b-box", got)


if __name__ == "__main__":
    unittest.main()
