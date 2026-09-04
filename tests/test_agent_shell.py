import base64
import json
import time
import unittest

from agent.artemis_agent import RemotePty
from artemis import create_app
from artemis.extensions import db
from artemis.models.agent import Agent
from artemis.services.auth_service import create_access_token, create_user


class AgentShellApiTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing', start_background_services=False)
        self.ctx = self.app.app_context()
        self.ctx.push()
        db.drop_all()
        db.create_all()
        self.admin = create_user('shell-admin', 'password-123', role='admin')
        self.analyst = create_user('shell-analyst', 'password-123', role='analyst')
        self.agent = Agent(
            agent_key='remote-agent-key', hostname='managed-01', ip='10.20.30.40',
            status='active', enabled=1, last_checkin='2026-09-03T12:00:00Z',
            capabilities_json=json.dumps(['remote_shell']),
        )
        db.session.add(self.agent)
        db.session.commit()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    @staticmethod
    def _auth(user):
        return {'Authorization': f'Bearer {create_access_token(user)}'}

    @staticmethod
    def _agent_auth():
        return {'X-Agent-Key': 'remote-agent-key'}

    def _create_session(self):
        response = self.client.post(
            f'/api/v1/agents/{self.agent.id}/shell-sessions',
            json={'cols': 100, 'rows': 28},
            headers=self._auth(self.admin),
        )
        self.assertEqual(response.status_code, 201, response.get_data(as_text=True))
        return response.get_json()['session']

    def test_agent_detail_exposes_capability_without_secret(self):
        response = self.client.get(f'/api/v1/agents/{self.agent.id}', headers=self._auth(self.admin))

        agent = response.get_json()
        self.assertIn('remote_shell', agent['capabilities'])
        self.assertNotIn('agent_key', agent)

    def test_remote_shell_requires_admin(self):
        response = self.client.post(
            f'/api/v1/agents/{self.agent.id}/shell-sessions',
            json={},
            headers=self._auth(self.analyst),
        )

        self.assertEqual(response.status_code, 403)

    def test_session_round_trip_and_cooperative_close(self):
        session = self._create_session()

        poll = self.client.get('/api/v1/agents/shell/poll', headers=self._agent_auth())
        self.assertEqual(poll.status_code, 200)
        self.assertEqual(poll.get_json()['session']['id'], session['id'])
        self.assertEqual(poll.get_json()['session']['status'], 'requested')

        started = self.client.post(
            '/api/v1/agents/shell/output',
            json={'session_id': session['id'], 'event': 'started'},
            headers=self._agent_auth(),
        )
        self.assertEqual(started.status_code, 200)
        self.assertEqual(started.get_json()['session']['status'], 'running')

        encoded_input = base64.b64encode(b'whoami\r').decode()
        queued = self.client.post(
            f'/api/v1/agent-shell-sessions/{session["id"]}/input',
            json={'data': encoded_input},
            headers=self._auth(self.admin),
        )
        self.assertEqual(queued.status_code, 202)

        poll = self.client.get('/api/v1/agents/shell/poll', headers=self._agent_auth()).get_json()['session']
        self.assertEqual(poll['inputs'][0]['data'], encoded_input)
        self.assertEqual(
            self.client.get('/api/v1/agents/shell/poll', headers=self._agent_auth()).get_json()['session']['inputs'],
            [],
        )

        encoded_output = base64.b64encode(b'root\r\n').decode()
        self.client.post(
            '/api/v1/agents/shell/output',
            json={'session_id': session['id'], 'event': 'output', 'data': encoded_output},
            headers=self._agent_auth(),
        )
        output = self.client.get(
            f'/api/v1/agent-shell-sessions/{session["id"]}/output?after=0',
            headers=self._auth(self.admin),
        ).get_json()
        self.assertEqual(output['output'][0]['data'], encoded_output)

        closed = self.client.delete(
            f'/api/v1/agent-shell-sessions/{session["id"]}',
            headers=self._auth(self.admin),
        )
        self.assertEqual(closed.status_code, 202)
        self.assertEqual(
            self.client.get('/api/v1/agents/shell/poll', headers=self._agent_auth()).get_json()['session']['status'],
            'closing',
        )
        final = self.client.post(
            '/api/v1/agents/shell/output',
            json={'session_id': session['id'], 'event': 'closed', 'exit_code': 0},
            headers=self._agent_auth(),
        )
        self.assertEqual(final.get_json()['session']['status'], 'closed')

    def test_rejects_parallel_sessions_and_invalid_agent_key(self):
        self._create_session()
        duplicate = self.client.post(
            f'/api/v1/agents/{self.agent.id}/shell-sessions',
            json={},
            headers=self._auth(self.admin),
        )
        self.assertEqual(duplicate.status_code, 409)
        self.assertEqual(self.client.get('/api/v1/agents/shell/poll').status_code, 401)


class RemotePtyTests(unittest.TestCase):
    def test_pty_runs_an_interactive_shell_and_returns_output(self):
        shell = RemotePty('local-test', cols=80, rows=24)
        output = bytearray()
        try:
            shell.write(b"printf '__ARTEMIS_PTY_OK__\\n'; exit\n")
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                output.extend(shell.read())
                if shell.poll() is not None:
                    output.extend(shell.read())
                    break
                time.sleep(0.05)
        finally:
            shell.close()

        self.assertIn(b'__ARTEMIS_PTY_OK__', output)


if __name__ == '__main__':
    unittest.main()
