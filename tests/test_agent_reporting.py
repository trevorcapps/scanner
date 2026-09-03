import unittest
from unittest.mock import patch

from artemis import create_app
from artemis.extensions import db
from artemis.models.agent import Agent
from artemis.models.cve_match import CveMatch
from artemis.models.software import InstalledSoftware
from artemis.services.agent_service import process_report
from artemis.services.vuln_service import get_unified_vulnerabilities


class AgentVulnerabilityReportingTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing', start_background_services=False)
        self.ctx = self.app.app_context()
        self.ctx.push()
        db.drop_all()
        db.create_all()
        self.agent = Agent(
            agent_key='agent-key', hostname='web-01', ip='10.0.0.8',
            status='active', enabled=1,
        )
        db.session.add(self.agent)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    @staticmethod
    def _report():
        return {
            'hostname': 'web-01',
            'ip': '10.0.0.8',
            'os_info': {'os_family': 'debian', 'pretty_name': 'Debian 12'},
            'system_info': {'uptime_seconds': 100},
            'packages': [{'name': 'openssl', 'version': '3.0.11-1~deb12u2'}],
            'package_count': 1,
            'ports': [],
        }

    @patch('exploit_ref.enrich_cves_with_exploits', side_effect=lambda rows: rows)
    @patch('nvd_feeds.match_cpes_local')
    def test_report_matches_packages_and_publishes_agent_findings(self, match_cpes, _enrich):
        match_cpes.return_value = [{
            'cve_id': 'CVE-2026-1000',
            'severity': 'high',
            'cvss_score': 8.1,
            'description': 'Test package vulnerability',
            'affected_cpe': 'cpe:2.3:a:openssl:openssl:3.0.11:*:*:*:*:*:*:*',
        }]

        report = process_report(self.agent, self._report())

        self.assertEqual(report.vulns_matched, 1)
        self.assertEqual(InstalledSoftware.query.filter_by(ip='10.0.0.8').count(), 1)
        match = CveMatch.query.filter_by(ip='10.0.0.8').one()
        self.assertEqual(match.detection_source, 'agent')
        findings = get_unified_vulnerabilities(ip='10.0.0.8')
        self.assertEqual(findings[0]['cve_id'], 'CVE-2026-1000')
        self.assertIn('agent', findings[0]['detection_sources'])

    @patch('nvd_feeds.match_cpes_local', return_value=None)
    def test_report_stores_inventory_when_local_nvd_cache_is_empty(self, _match_cpes):
        report = process_report(self.agent, self._report())

        self.assertEqual(report.vulns_matched, 0)
        software = InstalledSoftware.query.filter_by(ip='10.0.0.8').one()
        self.assertEqual(software.package_name, 'openssl')
        self.assertTrue(software.cpe.startswith('cpe:2.3:a:openssl:openssl:3.0.11'))


if __name__ == '__main__':
    unittest.main()
