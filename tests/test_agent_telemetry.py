import json
import unittest

from agent.artemis_agent import TELEMETRY_SCHEMA_VERSION, collect_report
from artemis.models.agent import Agent
from artemis.models.agent_report import AgentReport


class AgentTelemetryTests(unittest.TestCase):
    def test_collection_includes_resource_and_coverage_telemetry(self):
        report = collect_report()

        self.assertEqual(report['telemetry_schema_version'], TELEMETRY_SCHEMA_VERSION)
        self.assertIn('cpu', report['performance'])
        self.assertIn('memory', report['performance'])
        self.assertIn('top', report['processes'])
        self.assertIn('interfaces', report['network'])
        self.assertIn('filesystems', report['storage'])
        self.assertEqual(report['package_count'], len(report['packages']))
        self.assertTrue(report['telemetry']['collectors'])
        self.assertGreaterEqual(report['telemetry']['duration_ms'], 0)

    def test_agent_serializer_does_not_expose_secret_key(self):
        agent = Agent(
            id=7,
            agent_key='secret-agent-key',
            hostname='endpoint-7',
            os_info_json=json.dumps({'pretty_name': 'Test Linux'}),
            system_info_json=json.dumps({'uptime_seconds': 42}),
        )

        serialized = agent.to_dict()

        self.assertNotIn('agent_key', serialized)
        self.assertEqual(serialized['os'], 'Test Linux')
        self.assertEqual(serialized['system_info']['uptime_seconds'], 42)

    def test_report_serializer_returns_structured_payload_and_aliases(self):
        report = AgentReport(
            id=4,
            agent_id=7,
            report_json=json.dumps({'telemetry_schema_version': 2}),
            packages_count=12,
            ports_count=3,
            received_at='2026-09-02T12:00:00Z',
        )

        serialized = report.to_dict()

        self.assertEqual(serialized['report']['telemetry_schema_version'], 2)
        self.assertEqual(serialized['package_count'], 12)
        self.assertEqual(serialized['port_count'], 3)
        self.assertEqual(serialized['created_at'], serialized['received_at'])


if __name__ == '__main__':
    unittest.main()
