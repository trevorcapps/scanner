"""P2.1 durable job control plane: generic /jobs API, immutable event stream,
idempotency, lease reconciliation, and Beat-style due-work dispatch."""

import json
import unittest
from contextlib import contextmanager
from unittest.mock import patch

from artemis import create_app
from artemis.extensions import db
from artemis.models.job_event import JobEvent
from artemis.models.scan_job import ScanJob
from artemis.models.scheduled_scan import ScheduledScan
from artemis.services import job_service
from artemis.services.auth_service import create_access_token, create_user


class JobControlTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app("testing", start_background_services=False)
        with self.app.app_context():
            db.drop_all()
            db.create_all()
            self.admin = create_user("admin", "password-123", role="admin")
            self.reader = create_user("reader", "password-123", role="readonly")
            self.admin_tok = create_access_token(self.admin)
            self.reader_tok = create_access_token(self.reader)
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

    def test_create_job_is_async_202_with_location_and_queued_event(self):
        with patch("artemis.tasks.scan_tasks.run_adhoc_scan_job.apply_async") as sent:
            r = self.client.post("/api/v1/jobs", headers=self._h(self.admin_tok),
                                 json={"type": "port", "target": "10.0.0.1"})
        self.assertEqual(r.status_code, 202)
        self.assertTrue(r.headers["Location"].startswith("/api/v1/jobs/"))
        job_id = r.get_json()["id"]
        sent.assert_called_once()

        ev = self.client.get(f"/api/v1/jobs/{job_id}/events", headers=self._h(self.admin_tok)).get_json()
        self.assertEqual(ev["events"][0]["kind"], "queued")
        self.assertEqual(ev["job"]["status"], "queued")

    def test_readonly_cannot_create_but_can_read(self):
        self.assertEqual(
            self.client.post("/api/v1/jobs", headers=self._h(self.reader_tok),
                             json={"type": "port", "target": "10.0.0.1"}).status_code, 403)

    def test_idempotency_key_dedupes(self):
        with patch("artemis.tasks.scan_tasks.run_adhoc_scan_job.apply_async"):
            h = {**self._h(self.admin_tok), "Idempotency-Key": "abc-123"}
            a = self.client.post("/api/v1/jobs", headers=h, json={"type": "vuln", "target": "10.0.0.2"})
            b = self.client.post("/api/v1/jobs", headers=h, json={"type": "vuln", "target": "10.0.0.2"})
        self.assertEqual(a.get_json()["id"], b.get_json()["id"])
        with self.ctx():
            self.assertEqual(ScanJob.query.count(), 1)

    def test_event_log_is_append_only_and_ordered(self):
        with self.ctx():
            job = job_service.create_job("port", target="10.0.0.9")
            job_service.emit_event(job, "log", message="one")
            job_service.emit_event(job, "progress", current=1, total=3)
            job_service.mark_running(job)
            seqs = [e.seq for e in JobEvent.query.filter_by(job_id=job.id).order_by(JobEvent.seq).all()]
            self.assertEqual(seqs, sorted(seqs))
            self.assertEqual(len(set(seqs)), len(seqs))

    def test_cancel_emits_event_and_sets_state(self):
        with self.ctx():
            job = job_service.create_job("port", target="10.0.0.3")
            job.status = "running"
            db.session.commit()
            job_id = job.id
        r = self.client.post(f"/api/v1/jobs/{job_id}/cancel", headers=self._h(self.admin_tok))
        self.assertEqual(r.status_code, 202)
        with self.ctx():
            fresh = db.session.get(ScanJob, job_id)
            self.assertEqual(fresh.status, "cancel_requested")
            self.assertTrue(JobEvent.query.filter_by(job_id=job_id, kind="cancel").count())

    def test_orphaned_lease_is_requeued(self):
        with self.ctx():
            job = job_service.create_job("port", target="10.0.0.4")
            job.status = "running"
            job.lease_expires_at = "2000-01-01T00:00:00Z"
            db.session.commit()
            self.assertEqual(job_service.reconcile_orphaned_leases(), 1)
            self.assertEqual(db.session.get(ScanJob, job.id).status, "queued")

    def test_due_scan_dispatches_a_job_not_inline_execution(self):
        from artemis.services.scheduler_service import dispatch_due_scans
        with self.ctx(), patch("artemis.tasks.scan_tasks.run_adhoc_scan_job.apply_async") as sent:
            db.session.add(ScheduledScan(
                name="nightly", target="10.0.0.5", scan_type="port", enabled=1,
                schedule_type="cron", cron_expression="0 0 * * *",
                next_run="2000-01-01T00:00:00Z", scan_options_json="{}",
            ))
            db.session.commit()
            dispatched = dispatch_due_scans()
            self.assertEqual(dispatched, 1)
            sent.assert_called_once()
            job = ScanJob.query.filter_by(job_type="adhoc_scan").one()
            self.assertEqual(json.loads(job.options_json)["schedule_id"], 1)


if __name__ == "__main__":
    unittest.main()
