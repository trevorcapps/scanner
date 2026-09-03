import unittest
from contextlib import contextmanager

from artemis import create_app
from artemis.extensions import db
from artemis.models.asset import Asset
from artemis.models.scan import Scan
from artemis.services.auth_service import create_access_token, create_user


class ApiCoverageTests(unittest.TestCase):
    """The Flask app context is bound per-request (via helpers below) rather than
    held open for the whole test, so ``g`` does not leak between identities."""

    def setUp(self):
        self.app = create_app('testing', start_background_services=False)
        with self.app.app_context():
            db.drop_all()
            db.create_all()
            admin = create_user('admin', 'password-123', role='admin')
            readonly = create_user('reader', 'password-123', role='readonly')
            self.admin_tok = create_access_token(admin)
            self.readonly_tok = create_access_token(readonly)

            db.session.add(Asset(ip='10.0.0.5', hostname='box', device_type='computer',
                                 first_seen='2026-01-01T00:00:00', last_seen='2026-01-02T00:00:00',
                                 scan_count=2))
            db.session.add(Scan(ip='10.0.0.5', protocol='tcp', port=22, state='open',
                                service='ssh', product='OpenSSH', version='9.2',
                                scan_date='2026-01-02T00:00:00'))
            db.session.commit()
        self.client = self.app.test_client()

    def tearDown(self):
        with self.app.app_context():
            db.drop_all()

    @contextmanager
    def ctx(self):
        with self.app.app_context():
            yield

    @staticmethod
    def _h(tok):
        return {'Authorization': f'Bearer {tok}'}

    def test_openapi_spec_is_served_and_well_formed(self):
        r = self.client.get('/api/v1/openapi.json')
        self.assertEqual(r.status_code, 200)
        spec = r.get_json()
        self.assertEqual(spec['openapi'], '3.0.3')
        self.assertIn('/api/v1/assets', spec['paths'])
        self.assertIn('bearerAuth', spec['components']['securitySchemes'])
        for path, ops in spec['paths'].items():
            for method, op in ops.items():
                self.assertIn('summary', op, f'{method.upper()} {path} missing summary')

    def test_docs_and_health_are_public(self):
        self.assertEqual(self.client.get('/api/v1/docs').status_code, 200)
        health = self.client.get('/api/v1/health')
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.get_json()['checks']['database'], 'ok')

    def test_assets_list_and_detail(self):
        r = self.client.get('/api/v1/assets', headers=self._h(self.readonly_tok))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.get_json()['assets']), 1)

        r = self.client.get('/api/v1/assets/10.0.0.5', headers=self._h(self.readonly_tok))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()['asset']['ip'], '10.0.0.5')

    def test_asset_patch_denied_for_readonly(self):
        r = self.client.patch('/api/v1/assets/10.0.0.5', json={'hostname': 'renamed'},
                              headers=self._h(self.readonly_tok))
        self.assertEqual(r.status_code, 403)

    def test_asset_patch_allowed_for_admin(self):
        r = self.client.patch('/api/v1/assets/10.0.0.5', json={'hostname': 'renamed'},
                              headers=self._h(self.admin_tok))
        self.assertEqual(r.status_code, 200)
        with self.ctx():
            self.assertEqual(Asset.query.filter_by(ip='10.0.0.5').first().hostname, 'renamed')

    def test_asset_delete_purges_related_rows(self):
        r = self.client.delete('/api/v1/assets/10.0.0.5', headers=self._h(self.admin_tok))
        self.assertEqual(r.status_code, 200)
        with self.ctx():
            self.assertIsNone(Asset.query.filter_by(ip='10.0.0.5').first())
            self.assertEqual(Scan.query.filter_by(ip='10.0.0.5').count(), 0)

    def test_scans_list_is_paginated(self):
        r = self.client.get('/api/v1/scans?per_page=1', headers=self._h(self.readonly_tok))
        body = r.get_json()
        self.assertEqual(body['pagination']['per_page'], 1)
        self.assertEqual(body['pagination']['total'], 1)

    def test_post_scans_rejects_bad_target(self):
        r = self.client.post('/api/v1/scans', json={'target': 'not a host!!'},
                             headers=self._h(self.admin_tok))
        self.assertEqual(r.status_code, 400)

    def test_post_scans_rejects_bad_type(self):
        r = self.client.post('/api/v1/scans', json={'target': '10.0.0.5', 'scan_type': 'bogus'},
                             headers=self._h(self.admin_tok))
        self.assertEqual(r.status_code, 400)

    def test_authenticated_inventory_is_one_scan_method_not_a_vuln_profile(self):
        r = self.client.get('/api/v1/scan-profiles', headers=self._h(self.readonly_tok))
        self.assertEqual(r.status_code, 200)
        profiles = r.get_json()['profiles']
        self.assertFalse(any(profile.get('auth_required') for profile in profiles))
        self.assertNotIn('authenticated', {profile['id'] for profile in profiles})

    def test_settings_redacts_secrets(self):
        with self.ctx():
            from artemis.services.auth_scan_service import set_setting
            set_setting('nvd_api_key', 'super-secret-value')
            set_setting('theme', 'dark')
        r = self.client.get('/api/v1/settings', headers=self._h(self.admin_tok))
        s = r.get_json()['settings']
        self.assertEqual(s['theme'], 'dark')
        self.assertEqual(s['nvd_api_key'], '••••')
        self.assertNotIn('_pg_migrated', s)


if __name__ == '__main__':
    unittest.main()
