import sqlite3
import unittest
from contextlib import contextmanager

from artemis import create_app
from artemis.extensions import db
from artemis.models.credential import Credential
from artemis.services.auth_service import create_access_token, create_user

import nvd_feeds


class VersionNormalizationTests(unittest.TestCase):
    def test_strips_epoch_revision_and_suffixes(self):
        cases = {
            '1:2.4.1-3+deb11u1': '2.4.1',
            '9.2p1-2': '9.2',
            '3.0.11-1~deb12u2': '3.0.11',
            '7.88.1-10+deb12u5': '7.88.1',
            '2:8.2.3995-1ubuntu2.16': '8.2.3995',
            '1.21.22': '1.21.22',
            '': '*',
            'notaversion': '*',
        }
        for raw, want in cases.items():
            self.assertEqual(nvd_feeds._normalize_version(raw), want, raw)


class CpeResolverTests(unittest.TestCase):
    def setUp(self):
        self.path = ':memory:'
        # a shared in-memory db won't persist across connections, so use a temp file
        import tempfile
        import os
        fd, self.dbfile = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        conn = sqlite3.connect(self.dbfile)
        conn.executescript(
            """
            CREATE TABLE nvd_cves (cve_id TEXT PRIMARY KEY, description TEXT,
                cvss_v3_score REAL, cvss_v3_severity TEXT, cvss_v2_score REAL, cvss_v2_severity TEXT);
            CREATE TABLE nvd_cpe_matches (id INTEGER PRIMARY KEY, cve_id TEXT, cpe23uri TEXT,
                vulnerable INTEGER, version_start TEXT, version_start_type TEXT,
                version_end TEXT, version_end_type TEXT);
            """
        )
        conn.executemany(
            "INSERT INTO nvd_cpe_matches (cve_id, cpe23uri, vulnerable) VALUES (?, ?, 1)",
            [
                ('CVE-1', 'cpe:2.3:a:nginx:nginx:1.0:*:*:*:*:*:*:*', ),
                ('CVE-2', 'cpe:2.3:a:f5:nginx:1.1:*:*:*:*:*:*:*', ),
                ('CVE-3', 'cpe:2.3:a:f5:nginx:1.2:*:*:*:*:*:*:*', ),
                ('CVE-4', 'cpe:2.3:a:someone:coolthing:2.0:*:*:*:*:*:*:*', ),
            ],
        )
        conn.commit()
        conn.close()

    def tearDown(self):
        import os
        os.remove(self.dbfile)

    def test_build_index_and_lookup(self):
        n = nvd_feeds.build_cpe_product_index(self.dbfile)
        self.assertGreaterEqual(n, 2)
        # f5 has 2 hits for 'nginx', nginx has 1 -> f5 wins
        self.assertEqual(
            nvd_feeds.resolve_cpe('nginx', '1.24.0-1', db_path=self.dbfile),
            'cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*',
        )
        # override map beats the index
        self.assertEqual(
            nvd_feeds.resolve_cpe('openssh-server', '1:9.2p1-2', db_path=self.dbfile),
            'cpe:2.3:a:openbsd:openssh:9.2:*:*:*:*:*:*:*',
        )
        # index-only product
        self.assertEqual(
            nvd_feeds.resolve_cpe('coolthing', '2.1', db_path=self.dbfile),
            'cpe:2.3:a:someone:coolthing:2.1:*:*:*:*:*:*:*',
        )
        # unknown -> generated fallback
        self.assertEqual(
            nvd_feeds.resolve_cpe('nonexistent-pkg', '1.0', db_path=self.dbfile),
            'cpe:2.3:a:nonexistent-pkg:nonexistent-pkg:1.0:*:*:*:*:*:*:*',
        )

    def test_kernel_gets_os_cpe(self):
        self.assertEqual(
            nvd_feeds.resolve_cpe('linux-image-6.1.0-18-amd64', '6.1.76-1', db_path=self.dbfile),
            'cpe:2.3:o:linux:linux_kernel:6.1.76:*:*:*:*:*:*:*',
        )


class AuthScanApiTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing', start_background_services=False)
        with self.app.app_context():
            db.drop_all()
            db.create_all()
            self.tok = create_access_token(create_user('admin', 'password-123', role='admin'))

    def tearDown(self):
        with self.app.app_context():
            db.drop_all()

    @contextmanager
    def ctx(self):
        with self.app.app_context():
            yield

    def _h(self):
        return {'Authorization': f'Bearer {self.tok}'}

    def test_auth_scan_requires_credentials(self):
        r = self.client_post({'target': '127.0.0.1', 'scan_type': 'auth'})
        self.assertEqual(r.status_code, 400)
        self.assertIn('credential', r.get_json()['error'])

    def test_auth_scan_accepts_use_all(self):
        r = self.client_post({'target': '127.0.0.1', 'scan_type': 'auth',
                              'options': {'use_all_credentials': True}})
        # 202 (queued) — eager celery will then try to SSH and fail, which is fine
        self.assertIn(r.status_code, (202, 503))

    def test_auth_scan_accepts_explicit_ids(self):
        with self.ctx():
            c = Credential(name='k', cred_type='ssh_password', username='root',
                           password='x', created_at='2026-01-01', updated_at='2026-01-01')
            db.session.add(c)
            db.session.commit()
            cid = c.id
        r = self.client_post({'target': '127.0.0.1', 'scan_type': 'auth',
                              'options': {'credential_ids': [cid]}})
        self.assertIn(r.status_code, (202, 503))

    @property
    def client(self):
        return self.app.test_client()

    def client_post(self, body):
        return self.client.post('/api/v1/scans', json=body, headers=self._h())


if __name__ == '__main__':
    unittest.main()
