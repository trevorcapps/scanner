"""P0.4 security baseline: envelope encryption, audit trail, rate limiting,
transport hardening, and the production config guard."""

import base64
import os
import unittest
from contextlib import contextmanager
from unittest.mock import patch

from artemis import create_app
from artemis.extensions import db
from artemis.models.audit_event import AuditEvent
from artemis.models.credential import Credential
from artemis.services import audit_service, crypto_service
from artemis.services.auth_service import create_access_token, create_user

_TEST_KEY = base64.b64encode(b"artemis-test-key-000000000000000").decode()


class CryptoServiceTests(unittest.TestCase):
    def setUp(self):
        self._env = dict(os.environ)
        os.environ["ARTEMIS_ENCRYPTION_KEY"] = _TEST_KEY
        crypto_service.reset_cache()

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)
        crypto_service.reset_cache()

    def test_roundtrip(self):
        sealed = crypto_service.seal("s3cr3t")
        self.assertTrue(sealed.startswith("enc:v1:"))
        self.assertNotIn("s3cr3t", sealed)
        self.assertEqual(crypto_service.open_envelope(sealed), "s3cr3t")

    def test_tamper_is_detected(self):
        sealed = crypto_service.seal("value")
        broken = sealed[:-4] + ("AAAA" if not sealed.endswith("AAAA") else "BBBB")
        with self.assertRaises(crypto_service.CryptoError):
            crypto_service.open_envelope(broken)

    def test_rotation_marks_stale_envelopes(self):
        old = crypto_service.seal("value")
        self.assertFalse(crypto_service.needs_reseal(old))
        os.environ["ARTEMIS_ENCRYPTION_KEYS"] = f"new:{_TEST_KEY},default:{_TEST_KEY}"
        crypto_service.reset_cache()
        self.assertTrue(crypto_service.needs_reseal(old))          # wrapped by "default"
        self.assertEqual(crypto_service.open_envelope(old), "value")  # still readable

    def test_unconfigured_seal_raises(self):
        os.environ.pop("ARTEMIS_ENCRYPTION_KEY", None)
        crypto_service.reset_cache()
        self.assertFalse(crypto_service.is_configured())
        with self.assertRaises(crypto_service.CryptoNotConfigured):
            crypto_service.seal("x")


class ProductionGuardTests(unittest.TestCase):
    def test_production_refuses_without_secret_and_key(self):
        from artemis.security import InsecureConfigError, validate_production_config

        app = create_app("testing", start_background_services=False)
        app.config["TESTING"] = False
        with patch.dict(os.environ, {"ARTEMIS_SERVING": "1"}, clear=True):
            crypto_service.reset_cache()
            with self.assertRaises(InsecureConfigError):
                validate_production_config(app)

    def test_dev_override_allows_insecure(self):
        from artemis.security import validate_production_config

        app = create_app("testing", start_background_services=False)
        app.config["TESTING"] = False
        with patch.dict(os.environ, {"ARTEMIS_ALLOW_INSECURE": "1", "ARTEMIS_SERVING": "1"}, clear=True):
            crypto_service.reset_cache()
            validate_production_config(app)  # must not raise


class SecurityBaselineApiTests(unittest.TestCase):
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
        with self.app.app_context():
            yield

    def _h(self, tok):
        return {"Authorization": f"Bearer {tok}"}

    # ---- credentials -------------------------------------------------------
    def test_credential_secret_is_encrypted_at_rest(self):
        resp = self.client.post("/api/v1/credentials", headers=self._h(self.admin_tok), json={
            "name": "svc", "cred_type": "ssh_password", "username": "root", "password": "hunter2",
        })
        self.assertEqual(resp.status_code, 200)
        with self.ctx():
            row = Credential.query.filter_by(name="svc").one()
            self.assertTrue(row.secret_enc.startswith("enc:v1:"))
            self.assertEqual(row.reveal_secret(), "hunter2")
            self.assertNotIn("hunter2", row.to_dict().values())

    def test_credential_mutation_is_admin_only(self):
        resp = self.client.post("/api/v1/credentials", headers=self._h(self.analyst_tok), json={
            "name": "x", "cred_type": "ssh_password", "username": "root", "password": "p",
        })
        self.assertEqual(resp.status_code, 403)

    def test_resolving_a_credential_secret_writes_an_audit_event(self):
        with self.ctx():
            c = Credential(name="c", cred_type="ssh_password", username="root")
            c.set_secret("pw")
            db.session.add(c)
            db.session.commit()
            cid = c.id
            from artemis.services.auth_scan_service import resolve_credential_secrets

            secrets = resolve_credential_secrets(cid)
            db.session.commit()
            self.assertEqual(secrets["password"], "pw")
            self.assertEqual(
                AuditEvent.query.filter_by(action="secret.read", target_id=str(cid)).count(), 1
            )

    # ---- audit trail ------------------------------------------------------
    def test_login_success_and_failure_are_audited(self):
        self.client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"})
        self.client.post("/api/v1/auth/login", json={"username": "admin", "password": "password-123"})
        with self.ctx():
            self.assertEqual(AuditEvent.query.filter_by(action="auth.failed").count(), 1)
            self.assertEqual(AuditEvent.query.filter_by(action="auth.login").count(), 1)

    def test_role_change_is_audited(self):
        self.client.put(f"/api/v1/users/{self.analyst.id}", headers=self._h(self.admin_tok),
                        json={"role": "admin"})
        with self.ctx():
            ev = AuditEvent.query.filter_by(action="role.change").one()
            self.assertEqual(ev.detail_json and "analyst" in ev.detail_json, True)

    def test_audit_api_is_admin_only(self):
        self.assertEqual(
            self.client.get("/api/v1/audit-events", headers=self._h(self.analyst_tok)).status_code, 403
        )
        self.assertEqual(
            self.client.get("/api/v1/audit-events", headers=self._h(self.admin_tok)).status_code, 200
        )

    # ---- rate limiting --------------------------------------------------
    def test_login_rate_limit_is_deterministic(self):
        codes = [
            self.client.post("/api/v1/auth/login", json={"username": "x", "password": "y"}).status_code
            for _ in range(13)
        ]
        self.assertEqual(codes.count(429), 3)          # policy: 10 per window
        last = self.client.post("/api/v1/auth/login", json={"username": "x", "password": "y"})
        self.assertEqual(last.status_code, 429)
        self.assertIn("Retry-After", last.headers)

    # ---- transport hardening ------------------------------------------
    def test_responses_carry_correlation_and_hardening_headers(self):
        resp = self.client.get("/api/v1/health")
        self.assertTrue(resp.headers.get("X-Request-ID"))
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertIn("Content-Security-Policy", resp.headers)


if __name__ == "__main__":
    unittest.main()
