import os
import shutil
import tempfile
import unittest
from contextlib import contextmanager

from artemis import create_app
from artemis.extensions import db
from artemis.services.auth_service import create_access_token, create_user


class ReportingTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing', start_background_services=False)
        self.tmp = tempfile.mkdtemp(prefix='artemis-reports-')
        self.app.config['REPORTS_DIR'] = self.tmp
        with self.app.app_context():
            db.drop_all()
            db.create_all()
            self.tok = create_access_token(create_user('admin', 'password-123', role='admin'))
            self._seed()

    def tearDown(self):
        with self.app.app_context():
            db.drop_all()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _seed(self):
        from artemis.models.asset import Asset
        from artemis.models.vulnerability import Vulnerability
        db.session.add(Asset(ip='10.0.0.5', hostname='web01', os_name='Ubuntu 22.04',
                             device_type='server', first_seen='2026-01-01', scan_count=1))
        db.session.add(Vulnerability(
            ip='10.0.0.5', port=443, protocol='tcp', vuln_id='CVE-2024-0001',
            vuln_name='Test critical', severity='critical', cvss_score=9.8,
            description='bad', scan_date='2026-09-01'))
        db.session.add(Vulnerability(
            ip='10.0.0.5', port=80, protocol='tcp', vuln_id='CVE-2024-0002',
            vuln_name='Test high', severity='high', cvss_score=7.5,
            description='also bad', scan_date='2026-09-01'))
        db.session.commit()

    @contextmanager
    def ctx(self):
        with self.app.app_context():
            yield

    def _h(self):
        return {'Authorization': f'Bearer {self.tok}'}

    @property
    def client(self):
        return self.app.test_client()

    # --- service layer -------------------------------------------------------

    def test_scope_label_and_ips(self):
        from artemis.services.executive_report_service import _scope_label, _scope_ips
        with self.ctx():
            self.assertEqual(_scope_label({'type': 'environment'}), 'Entire environment')
            self.assertIsNone(_scope_ips({'type': 'environment'}))
            ips = _scope_ips({'type': 'filter', 'device_type': 'server'})
            self.assertEqual(ips, {'10.0.0.5'})

    def test_build_html_report(self):
        from artemis.services.executive_report_service import build_report
        with self.ctx():
            rec = build_report({'type': 'environment'}, kind='full', fmt='html')
            self.assertEqual(rec.status, 'ready', rec.error)
            self.assertTrue(os.path.isfile(rec.file_path))
            html = open(rec.file_path, encoding='utf-8').read()
            self.assertIn('Vulnerability Report', html)
            self.assertIn('CVE-2024-0001', html)
            self.assertEqual(rec.to_dict()['summary']['by_severity']['critical'], 1)

    def test_risk_snapshot(self):
        from artemis.services.risk_snapshot_service import capture_snapshot, get_snapshots
        with self.ctx():
            row = capture_snapshot(force=True)
            self.assertEqual(row.critical, 1)
            self.assertEqual(row.high, 1)
            self.assertGreaterEqual(row.risk_score, 15)
            self.assertEqual(len(get_snapshots(30)), 1)
            capture_snapshot(force=True)  # idempotent per day
            self.assertEqual(len(get_snapshots(30)), 1)

    # --- REST --------------------------------------------------------------

    def test_generate_validation(self):
        r = self.client.post('/api/v1/reports', json={'kind': 'bogus'}, headers=self._h())
        self.assertEqual(r.status_code, 400)
        r = self.client.post('/api/v1/reports',
                             json={'kind': 'executive', 'scope': {'type': 'nope'}}, headers=self._h())
        self.assertEqual(r.status_code, 400)

    def test_generate_and_download_html(self):
        r = self.client.post('/api/v1/reports',
                             json={'kind': 'executive', 'format': 'html',
                                   'scope': {'type': 'environment'}}, headers=self._h())
        self.assertEqual(r.status_code, 201, r.get_json())
        rid = r.get_json()['report']['id']

        lst = self.client.get('/api/v1/reports', headers=self._h()).get_json()
        self.assertTrue(any(x['id'] == rid for x in lst['reports']))

        dl = self.client.get(f'/api/v1/reports/{rid}/download', headers=self._h())
        self.assertEqual(dl.status_code, 200)
        self.assertIn(b'Vulnerability Report', dl.data)

        d = self.client.delete(f'/api/v1/reports/{rid}', headers=self._h())
        self.assertEqual(d.status_code, 200)

    def test_report_schedule_crud(self):
        bad = self.client.post('/api/v1/report-schedules',
                               json={'name': 'x', 'cron_expression': 'not-a-cron'}, headers=self._h())
        self.assertEqual(bad.status_code, 400)

        ok = self.client.post('/api/v1/report-schedules', json={
            'name': 'Weekly', 'kind': 'executive', 'format': 'html',
            'cron_expression': '0 8 * * 1', 'recipients': ['ciso@example.com'],
            'scope': {'type': 'environment'},
        }, headers=self._h())
        self.assertEqual(ok.status_code, 201, ok.get_json())
        sid = ok.get_json()['schedule']['id']
        self.assertTrue(ok.get_json()['schedule']['next_run'])

        # run now — no SMTP configured, so it generates then fails to send
        run = self.client.post(f'/api/v1/report-schedules/{sid}/run', headers=self._h())
        self.assertEqual(run.status_code, 200)
        self.assertEqual(run.get_json()['schedule']['last_status'], 'failed')

        self.assertEqual(
            self.client.delete(f'/api/v1/report-schedules/{sid}', headers=self._h()).status_code, 200)

    def test_branding_roundtrip(self):
        self.client.put('/api/v1/reports/branding',
                        json={'report_org_name': 'Acme Sec'}, headers=self._h())
        got = self.client.get('/api/v1/reports/branding', headers=self._h()).get_json()
        self.assertEqual(got['report_org_name'], 'Acme Sec')

    def test_test_email_requires_smtp(self):
        r = self.client.post('/api/v1/reports/test-email',
                             json={'recipient': 'a@b.com'}, headers=self._h())
        self.assertEqual(r.status_code, 400)
        self.assertIn('SMTP', r.get_json()['error'])


if __name__ == '__main__':
    unittest.main()
