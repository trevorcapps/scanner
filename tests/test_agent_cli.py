"""Agent command-line entry points. The agent is stdlib-only and ships
separately, so these guard its argument handling and server contract without a
running server."""

import io
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

from agent import artemis_agent


class AgentCliTests(unittest.TestCase):
    def test_version_flag_exits_zero(self):
        proc = subprocess.run(
            [sys.executable, "agent/artemis_agent.py", "--version"],
            capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn(artemis_agent.__version__, proc.stdout + proc.stderr)

    def test_capabilities_advertised(self):
        self.assertIn("remote_shell", artemis_agent.AGENT_CAPABILITIES)
        report = artemis_agent.collect_report()
        self.assertEqual(report["capabilities"], artemis_agent.AGENT_CAPABILITIES)
        self.assertEqual(report["agent_version"], artemis_agent.__version__)

    def test_register_posts_expected_payload(self):
        captured = {}

        def fake_api_call(server, endpoint, data=None, key=None):
            captured["endpoint"] = endpoint
            captured["data"] = data
            return {"agent_key": "issued-key", "agent_id": 5}

        with patch.object(artemis_agent, "api_call", side_effect=fake_api_call), \
             patch.object(artemis_agent, "save_config") as save_config:
            artemis_agent.do_register("https://artemis.example", name="edge-1")

        self.assertEqual(captured["endpoint"], "/agents/register")
        self.assertEqual(captured["data"]["name"], "edge-1")
        self.assertIn("remote_shell", captured["data"]["capabilities"])
        save_config.assert_called_once()

    def test_api_request_is_quiet_on_http_error(self):
        stderr = io.StringIO()
        with patch("urllib.request.urlopen", side_effect=OSError("boom")), \
             patch.object(sys, "stderr", stderr):
            result = artemis_agent.api_request(
                "https://artemis.example", "/agents/shell/poll", method="GET", quiet=True,
            )
        self.assertIsNone(result)
        self.assertEqual(stderr.getvalue(), "")

    def test_api_request_reports_when_not_quiet(self):
        stderr = io.StringIO()
        with patch("urllib.request.urlopen", side_effect=OSError("boom")), \
             patch.object(sys, "stderr", stderr):
            artemis_agent.api_request("https://artemis.example", "/agents/report", data={})
        self.assertIn("boom", stderr.getvalue())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
