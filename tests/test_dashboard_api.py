import unittest
from contextlib import contextmanager

from artemis import create_app
from artemis.extensions import db
from artemis.models.asset import Asset
from artemis.models.scan import Scan
from artemis.models.vulnerability import Vulnerability
from artemis.models.scan_history import ScanHistory
from artemis.services.auth_service import create_access_token, create_user


class DashboardApiTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing', start_background_services=False)
        with self.app.app_context():
            db.drop_all()
            db.create_all()
            self.tok = create_access_token(create_user('admin', 'password-123', role='admin'))

            db.session.add_all([
                Asset(ip='10.0.0.1', hostname='a', device_type='computer',
                      first_seen='2026-01-01', last_seen='2026-01-02', scan_count=1),
                Asset(ip='10.0.0.2', hostname='b', device_type='router',
                      first_seen='2026-01-01', last_seen='2026-01-02', scan_count=1),
                Asset(ip='192.168.1.5', hostname='c', device_type='computer',
                      first_seen='2026-01-01', last_seen='2026-01-02', scan_count=1),
            ])
            db.session.add_all([
                Scan(ip='10.0.0.1', protocol='tcp', port=22, state='open', service='ssh',
                     scan_date='2026-01-02T00:00:00'),
                Scan(ip='10.0.0.1', protocol='tcp', port=80, state='open', service='http',
                     scan_date='2026-01-02T00:00:00'),
                Scan(ip='10.0.0.2', protocol='tcp', port=443, state='open', service='https',
                     scan_date='2026-01-02T00:00:00'),
            ])
            db.session.add_all([
                Vulnerability(ip='10.0.0.1', port=80, protocol='tcp', vuln_id='CVE-2021-1',
                              vuln_name='Bad', severity='critical', cvss_score=9.8,
                              scan_date='2026-01-02'),
                Vulnerability(ip='10.0.0.1', port=22, protocol='tcp', vuln_id='CVE-2021-2',
                              vuln_name='Meh', severity='medium', cvss_score=5.0,
                              scan_date='2026-01-02'),
                Vulnerability(ip='10.0.0.2', port=443, protocol='tcp', vuln_id='ssl-weak',
                              vuln_name='Weak TLS', severity='low', cvss_score=3.1,
                              scan_date='2026-01-02'),
            ])
            db.session.add(ScanHistory(target='10.0.0.0/24', scan_type='port', status='success',
                                       started_at='2026-01-02T10:00:00', hosts_scanned=3,
                                       ports_found=3, vulns_found=3, new_vulns=2))
            db.session.commit()
        self.client = self.app.test_client()

    def tearDown(self):
        with self.app.app_context():
            db.drop_all()

    @contextmanager
    def ctx(self):
        with self.app.app_context():
            yield

    def _h(self):
        return {'Authorization': f'Bearer {self.tok}'}

    def get(self, path):
        r = self.client.get(path, headers=self._h())
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        return r.get_json()

    def test_summary(self):
        d = self.get('/api/v1/dashboard/summary')
        self.assertEqual(d['assets'], 3)
        self.assertEqual(d['open_ports'], 3)
        self.assertEqual(d['vulnerabilities']['by_severity']['critical'], 1)
        self.assertIn('scan_jobs', d)

    def test_cvss_distribution_buckets_sum_to_total(self):
        d = self.get('/api/v1/dashboard/cvss-distribution')
        self.assertEqual(len(d['buckets']), 10)
        self.assertEqual(sum(b['count'] for b in d['buckets']) + d['unscored'], d['total'])
        self.assertEqual(d['buckets'][9]['count'], 1)  # the 9.8

    def test_top_vulnerabilities_limit(self):
        d = self.get('/api/v1/dashboard/top-vulnerabilities?limit=2')
        self.assertEqual(len(d['vulnerabilities']), 2)
        self.assertEqual(d['vulnerabilities'][0]['severity'], 'critical')

    def test_risk_heatmap(self):
        d = self.get('/api/v1/dashboard/risk-heatmap')
        self.assertEqual(set(d['severities']), {'critical', 'high', 'medium', 'low'})
        self.assertTrue(any(r['device_type'] == 'computer' for r in d['rows']))
        self.assertEqual(d['assets'][0]['ip'], '10.0.0.1')  # highest risk

    def test_trends_day_count(self):
        d = self.get('/api/v1/dashboard/trends?days=7')
        self.assertEqual(len(d['series']), 7)
        self.assertTrue(all('date' in s for s in d['series']))

    def test_topology_link_integrity(self):
        d = self.get('/api/v1/dashboard/topology')
        node_ids = {n['id'] for n in d['nodes']}
        for link in d['links']:
            self.assertIn(link['source'], node_ids)
            self.assertIn(link['target'], node_ids)
        self.assertIn('10.0.0.0/24', node_ids)
        self.assertIn('192.168.1.0/24', node_ids)

    def test_scan_queue(self):
        d = self.get('/api/v1/dashboard/scan-queue')
        self.assertIn('counts', d)
        self.assertIn('recent', d)

    def test_assets_sort_and_pagination(self):
        d = self.get('/api/v1/assets?sort=risk&order=desc&page=1&per_page=2')
        self.assertEqual(d['pagination']['total'], 3)
        self.assertEqual(len(d['assets']), 2)
        self.assertEqual(d['assets'][0]['ip'], '10.0.0.1')

    def test_assets_severity_filter(self):
        d = self.get('/api/v1/assets?severity=critical')
        self.assertEqual([a['ip'] for a in d['assets']], ['10.0.0.1'])

    def test_vulns_sort_severity_and_pagination(self):
        d = self.get('/api/v1/vulnerabilities?sort=cvss&order=desc&page=1&per_page=2')
        self.assertEqual(len(d['vulnerabilities']), 2)
        self.assertEqual(d['vulnerabilities'][0]['cve_id'], 'CVE-2021-1')
        self.assertEqual(d['filtered_total'], 3)

    def test_vulns_severity_filter(self):
        d = self.get('/api/v1/vulnerabilities?severity=low')
        self.assertEqual(len(d['vulnerabilities']), 1)
        self.assertEqual(d['vulnerabilities'][0]['cve_id'], 'ssl-weak')


if __name__ == '__main__':
    unittest.main()
