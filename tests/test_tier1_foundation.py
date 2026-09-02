import unittest
from types import SimpleNamespace
from unittest.mock import patch

from artemis import create_app
from artemis.extensions import db, socketio
from artemis.models.scan_job import ScanJob
from artemis.models.site import Site
from artemis.services.auth_service import create_access_token, create_user, generate_api_key
from artemis.services.job_service import dispatch_site_scan


class TierOneFoundationTests(unittest.TestCase):
    def test_production_rejects_in_memory_task_queue(self):
        with self.assertRaisesRegex(RuntimeError, 'Redis-backed Celery'):
            create_app('production', start_background_services=False)

    def setUp(self):
        self.app = create_app('testing', start_background_services=False)
        self.ctx = self.app.app_context()
        self.ctx.push()
        db.drop_all()
        db.create_all()

        self.admin = create_user('admin', 'password-123', role='admin')
        self.analyst = create_user('analyst', 'password-123', role='analyst')
        self.readonly = create_user('reader', 'password-123', role='readonly')
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def _headers(self, user):
        return {'Authorization': f'Bearer {create_access_token(user)}'}

    def test_readonly_user_can_read_but_cannot_create_site(self):
        response = self.client.get('/api/v1/sites', headers=self._headers(self.readonly))
        self.assertEqual(response.status_code, 200)

        response = self.client.post(
            '/api/v1/sites',
            json={'name': 'restricted', 'targets': ['127.0.0.1']},
            headers=self._headers(self.readonly),
        )
        self.assertEqual(response.status_code, 403)
        self.assertIn('Read-only', response.get_json()['error'])

    def test_api_key_cannot_exceed_owning_user_role(self):
        raw_key = generate_api_key(self.readonly.id, name='over-scoped', role='admin')
        response = self.client.post(
            '/api/v1/sites',
            json={'name': 'restricted-key', 'targets': ['127.0.0.1']},
            headers={'X-API-Key': raw_key},
        )
        self.assertEqual(response.status_code, 403)

    def test_unauthenticated_socket_connection_is_rejected(self):
        client = socketio.test_client(self.app)
        self.assertFalse(client.is_connected())

    def test_site_job_is_persisted_before_dispatch(self):
        site = Site(name='queue-test', targets_json='["127.0.0.1"]', scan_type='port')
        db.session.add(site)
        db.session.commit()

        with patch('artemis.tasks.scan_tasks.run_site_scan_job.apply_async') as apply_async:
            job = dispatch_site_scan(site, requested_by=self.analyst.id)

        persisted = db.session.get(ScanJob, job.id)
        self.assertEqual(persisted.status, 'queued')
        self.assertEqual(persisted.site_id, site.id)
        self.assertEqual(persisted.requested_by, self.analyst.id)
        apply_async.assert_called_once_with(args=[job.id], task_id=job.task_id)

    def test_eager_site_job_reaches_terminal_state(self):
        site = Site(name='eager-test', targets_json='["127.0.0.1"]', scan_type='port')
        db.session.add(site)
        db.session.commit()
        completed_scan = SimpleNamespace(
            id=31,
            status='success',
            targets_scanned=1,
            targets_failed=0,
            ports_found=2,
            vulns_found=0,
        )

        with patch('artemis.services.site_service.execute_site_scan', return_value=completed_scan):
            job = dispatch_site_scan(site, requested_by=self.analyst.id)

        db.session.expire_all()
        persisted = db.session.get(ScanJob, job.id)
        self.assertEqual(persisted.status, 'success')
        self.assertEqual(persisted.to_dict()['result']['ports_found'], 2)

    def test_job_status_and_cancellation_api(self):
        job = ScanJob(
            id='queued-job',
            job_type='site_scan',
            status='queued',
            created_at='2026-09-02T12:00:00Z',
        )
        db.session.add(job)
        db.session.commit()

        response = self.client.get('/api/v1/scan-jobs/queued-job', headers=self._headers(self.analyst))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['status'], 'queued')

        response = self.client.post(
            '/api/v1/scan-jobs/queued-job/cancel',
            headers=self._headers(self.analyst),
        )
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.get_json()['status'], 'cancelled')


if __name__ == '__main__':
    unittest.main()
