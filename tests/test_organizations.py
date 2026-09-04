"""P1.1 organization identity: memberships, per-org roles, the platform admin,
API-key org binding, and the active-organization switch."""

import unittest
from contextlib import contextmanager

from artemis import create_app
from artemis.extensions import db
from artemis.models.api_key import ApiKey
from artemis.models.organization import Organization, OrganizationMembership
from artemis.services.auth_service import create_access_token, create_user, generate_api_key


class OrganizationTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app("testing", start_background_services=False)
        with self.app.app_context():
            db.drop_all()
            db.create_all()
            self.owner = create_user("owner", "password-123", role="admin")     # first => platform admin
            self.analyst = create_user("analyst", "password-123", role="analyst")
            self.owner_tok = create_access_token(self.owner)
            self.analyst_tok = create_access_token(self.analyst)
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
        if org:
            h["X-Organization"] = str(org)
        return h

    def test_every_user_joins_default_org(self):
        with self.ctx():
            default = Organization.query.filter_by(is_default=1).one()
            self.assertEqual(
                OrganizationMembership.query.filter_by(organization_id=default.id).count(), 2
            )
            self.assertTrue(self.owner.platform_admin)
            self.assertFalse(self.analyst.platform_admin)

    def test_list_shows_only_my_orgs(self):
        with self.ctx():
            from artemis.services.org_service import create_organization
            create_organization("Acme", owner=self.owner)
            db.session.commit()

        # analyst is not a member of Acme
        resp = self.client.get("/api/v1/organizations", headers=self._h(self.analyst_tok))
        self.assertEqual({o["slug"] for o in resp.get_json()["organizations"]}, {"default"})

        # owner is a platform admin -> sees all
        resp = self.client.get("/api/v1/organizations", headers=self._h(self.owner_tok))
        self.assertIn("acme", {o["slug"] for o in resp.get_json()["organizations"]})

    def test_create_org_makes_caller_admin_and_isolates_role(self):
        resp = self.client.post("/api/v1/organizations", headers=self._h(self.analyst_tok),
                                json={"name": "Beta Corp"})
        self.assertEqual(resp.status_code, 201)
        beta_id = resp.get_json()["organization"]["id"]

        # analyst is admin in Beta ...
        r = self.client.post("/api/v1/credentials", headers=self._h(self.analyst_tok, org=beta_id),
                             json={"name": "k", "cred_type": "ssh_password",
                                   "username": "root", "password": "p"})
        self.assertEqual(r.status_code, 200)

        # ... but still only analyst in Default
        r = self.client.post("/api/v1/credentials", headers=self._h(self.analyst_tok),
                             json={"name": "k2", "cred_type": "ssh_password",
                                   "username": "root", "password": "p"})
        self.assertEqual(r.status_code, 403)

    def test_cross_org_access_is_denied_as_not_found(self):
        with self.ctx():
            from artemis.services.org_service import create_organization
            secret_org = create_organization("Secret", owner=self.owner)
            db.session.commit()
            secret_id = secret_org.id
        resp = self.client.get(f"/api/v1/organizations/{secret_id}/members",
                               headers=self._h(self.analyst_tok, org=secret_id))
        self.assertIn(resp.status_code, (403, 404))

    def test_member_management_and_last_admin_guard(self):
        with self.ctx():
            from artemis.services.org_service import create_organization
            org = create_organization("Team", owner=self.owner)
            db.session.commit()
            org_id = org.id

        # add analyst as a member
        resp = self.client.post(f"/api/v1/organizations/{org_id}/members",
                                headers=self._h(self.owner_tok, org=org_id),
                                json={"user_id": self.analyst.id, "role": "analyst"})
        self.assertEqual(resp.status_code, 201)

        # cannot demote the only admin
        resp = self.client.put(f"/api/v1/organizations/{org_id}/members/{self.owner.id}",
                               headers=self._h(self.owner_tok, org=org_id),
                               json={"role": "analyst"})
        self.assertEqual(resp.status_code, 409)

    def test_api_key_is_pinned_to_its_org(self):
        with self.ctx():
            from artemis.services.org_service import create_organization
            org = create_organization("KeyOrg", owner=self.owner)
            db.session.commit()
            raw = generate_api_key(self.owner.id, name="k", organization_id=org.id)
            db.session.commit()
            key_org = ApiKey.query.filter_by(key_prefix=raw[:12]).one().organization_id
            self.assertEqual(key_org, org.id)

        # the key ignores an X-Organization header pointing elsewhere
        resp = self.client.get("/api/v1/organizations",
                               headers={"X-API-Key": raw, "X-Organization": "default"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["active_organization_id"], key_org)

    def test_switch_sets_session_active_org(self):
        with self.ctx():
            from artemis.services.org_service import create_organization
            org = create_organization("Switchy", owner=self.owner)
            db.session.commit()
            org_id = org.id
        resp = self.client.post("/api/v1/organizations/switch", headers=self._h(self.owner_tok),
                                json={"organization_id": org_id})
        self.assertEqual(resp.status_code, 200)
        follow = self.client.get("/api/v1/organizations", headers=self._h(self.owner_tok))
        self.assertEqual(follow.get_json()["active_organization_id"], org_id)


if __name__ == "__main__":
    unittest.main()
