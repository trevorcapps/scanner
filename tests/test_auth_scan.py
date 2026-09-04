import sqlite3
import unittest
from contextlib import contextmanager

from artemis import create_app
from artemis.extensions import db
from artemis.models.credential import Credential
from artemis.services.auth_service import create_access_token, create_user

import auth_scan
import nvd_feeds


class FakeSSHClient:
    """Answers _exec() from a {substring: output} table."""

    def __init__(self, responses):
        self.responses = responses

    def exec_command(self, cmd, timeout=30):
        out = ''
        for needle, value in self.responses.items():
            if needle in cmd:
                out = value
                break

        class _Stream:
            def __init__(self, data):
                self._data = data.encode()

            def read(self):
                return self._data

        return None, _Stream(out), _Stream('')


class HostFactsTests(unittest.TestCase):
    def test_parse_listening_ports(self):
        ss = (
            'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=712,fd=3))\n'
            'LISTEN 0 4096 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=901,fd=5))\n'
            'LISTEN 0 511 [::]:80 [::]:* users:(("nginx",pid=1002,fd=6))\n'
        )
        ports = auth_scan._parse_listening_ports(ss)
        by_port = {p['port']: p for p in ports}
        self.assertEqual(by_port[22]['process'], 'sshd')
        self.assertEqual(by_port[5432]['address'], '127.0.0.1')
        self.assertEqual(by_port[80]['process'], 'nginx')

    def test_collect_host_facts(self):
        client = FakeSSHClient({
            'hostname -f': 'web01.example.com',
            'uname -r': '6.1.0-18-amd64',
            'systemd-detect-virt': 'kvm',
            'model name': ': Intel(R) Xeon(R) E5-2680',
            'nproc': '4',
            'MemTotal': '8039248',
            '/proc/uptime': '128340.12 500000.00',
            'timedatectl show -p Timezone': 'Etc/UTC',
            'ip route show default': 'default via 10.0.0.1 dev eth0 proto dhcp',
            '/sys/class/net': (
                '/sys/class/net/eth0/address:52:54:00:ab:cd:ef\n'
                '/sys/class/net/lo/address:00:00:00:00:00:00'
            ),
            'ip -o -4 addr': '2: eth0    inet 10.0.0.23/24 brd 10.0.0.255 scope global eth0',
            'ss -H -tlnp': 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))',
            'who': 'root pts/0 2026-09-03 01:00',
        })
        os_info = {'os_family': 'debian', 'kernel': 'Linux web01 6.1.0-18-amd64'}
        facts = auth_scan.collect_host_facts(client, os_info)
        self.assertEqual(facts['hostname'], 'web01.example.com')
        self.assertEqual(os_info['hostname'], 'web01.example.com')
        self.assertEqual(facts['kernel_release'], '6.1.0-18-amd64')
        self.assertEqual(facts['virtualization'], 'kvm')
        self.assertEqual(facts['cpu_count'], 4)
        self.assertEqual(facts['memory_mb'], 7851)
        self.assertEqual(facts['uptime_seconds'], 128340)
        self.assertEqual(facts['timezone'], 'Etc/UTC')
        self.assertEqual(facts['default_gateway'], '10.0.0.1')
        self.assertEqual(facts['primary_mac'], '52:54:00:ab:cd:ef')
        self.assertEqual(facts['ipv4_addresses'], ['10.0.0.23'])
        self.assertEqual(facts['listening_ports'][0]['port'], 22)


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
                           created_at='2026-01-01', updated_at='2026-01-01')
            c.set_secret('x')
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
