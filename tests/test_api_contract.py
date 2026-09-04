"""P2.4 API contract: uniform error envelope, legacy-surface deprecation
headers, expanded webhook events, and job lifecycle webhooks with event IDs."""

import json
import unittest
from contextlib import contextmanager

from artemis import create_app
from artemis.extensions import db
from artemis.models.webhook import WEBHOOK_EVENTS, Webhook, WebhookDelivery
from artemis.services import job_service
from artemis.services.auth_service import create_access_token, create_user


class ApiContractTests(unittest.TestCase):
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
        with self.app.app_context():
            yield

    def _h(self):
        return {"Authorization": f"Bearer {self.tok}"}

    def test_error_responses_use_the_uniform_envelope(self):
        r = self.client.get("/api/v1/no-such-route", headers=self._h())
        self.assertEqual(r.status_code, 404)
        body = r.get_json()
        self.assertEqual(set(body) >= {"error", "code", "request_id"}, True)
        self.assertEqual(body["code"], "not_found")
        self.assertEqual(body["request_id"], r.headers["X-Request-ID"])

    def test_unauthenticated_api_error_is_json_envelope(self):
        r = self.client.get("/api/v1/assets")
        self.assertEqual(r.status_code, 401)
        self.assertIn("code", r.get_json())

    def test_legacy_surface_carries_deprecation_headers(self):
        r = self.client.get("/api/assets", headers=self._h())
        self.assertEqual(r.headers.get("Deprecation"), "true")
        self.assertIn("Sunset", r.headers)
        v1 = self.client.get("/api/v1/assets", headers=self._h())
        self.assertNotIn("Deprecation", v1.headers)

    def test_webhook_event_catalogue_expanded(self):
        for event in ("job.completed", "job.failed", "finding.resolved",
                      "asset.decommissioned", "integration.failed"):
            self.assertIn(event, WEBHOOK_EVENTS)

    def test_job_completion_emits_a_webhook_with_event_id(self):
        with self.ctx():
            db.session.add(Webhook(url="https://example.test/hook",
                                   events_json=json.dumps(["job.completed"]), enabled=True))
            db.session.commit()
            job = job_service.create_job("port", target="10.0.0.1")
            job_service.mark_result(job, {"ports_found": 1})

            delivery = WebhookDelivery.query.filter_by(event="job.completed").one()
            payload = json.loads(delivery.payload_json)
            self.assertTrue(payload["id"].startswith("evt_"))
            self.assertEqual(payload["data"]["job_id"], job.id)

    def test_openapi_document_still_validates_with_new_routes(self):
        spec = self.client.get("/api/v1/openapi.json").get_json()
        paths = spec["paths"]
        self.assertIn("/api/v1/jobs", paths)
        self.assertIn("/api/v1/organizations", paths)
        self.assertIn("/api/v1/execution-profiles", paths)


if __name__ == "__main__":
    unittest.main()
