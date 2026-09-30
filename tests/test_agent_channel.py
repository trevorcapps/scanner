"""Protocol, tenant, replay, streaming and volatile-storage acceptance checks."""
import base64
import time
from unittest.mock import patch

import jwt

from artemis.extensions import db, socketio
from artemis.models.agent import Agent
from artemis.models.agent_shell import AgentShellSession
from artemis.services.agent_channel_service import issue_token
from artemis.services.agent_transport_store import MemoryStore, TransportFull, store, stream_key
from artemis.services.auth_service import create_access_token
from tests import test_agent_shell


class AgentChannelTests(test_agent_shell.AgentShellApiTests):
    def tearDown(self):
        self.doCleanups()
        super().tearDown()

    def connect_channel(self, agent=None):
        agent = agent or self.agent
        token = issue_token(agent)
        client = socketio.test_client(self.app, namespace='/agent', auth={'token': token})
        self.addCleanup(lambda: client.disconnect(namespace='/agent') if client.is_connected('/agent') else None)
        self.seq = 0
        self.jti = jwt.decode(token, options={'verify_signature': False})['jti']
        self.channel = client
        return client

    def envelope(self, kind, payload=None, **extra):
        self.seq += 1
        return {'v': 1, 'agent_id': self.agent.id, 'seq': self.seq,
                'expires': time.time() + 30, 'idempotency_key': f'{self.jti}:{self.seq}',
                'kind': kind, 'payload': payload or {}, **extra}

    def send(self, frame):
        return self.channel.emit('frame', frame, namespace='/agent', callback=True)

    def test_token_endpoint_is_agent_authenticated_and_uncacheable(self):
        self.assertEqual(self.client.post('/api/v1/agents/channel-token').status_code, 401)
        response = self.client.post('/api/v1/agents/channel-token', headers=self._agent_auth())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertNotIn(self.agent.agent_key, response.get_data(as_text=True))

    def test_rejects_expired_and_revoked_credentials(self):
        token = issue_token(self.agent)
        claims = jwt.decode(token, options={'verify_signature': False})
        claims['exp'] = time.time() - 1
        expired = jwt.encode(claims, self.app.config['SECRET_KEY'], algorithm='HS256')
        bad = socketio.test_client(self.app, namespace='/agent', auth={'token': expired})
        self.assertFalse(bad.is_connected('/agent'))
        channel = self.connect_channel()
        self.agent.agent_key = 'rotated'
        db.session.commit()
        result = self.send(self.envelope('presence'))
        self.assertIn('error', result)
        channel.disconnect(namespace='/agent')

    def test_streams_only_to_owner_and_retains_metadata_only(self):
        session = self._create_session()
        self.connect_channel()
        browser = socketio.test_client(self.app, headers={'Authorization': f'Bearer {create_access_token(self.admin)}'})
        outsider = socketio.test_client(self.app, headers={'Authorization': f'Bearer {create_access_token(self.analyst)}'})
        self.addCleanup(browser.disconnect)
        self.addCleanup(outsider.disconnect)
        self.assertNotIn('error', browser.emit('subscribe_shell', {'session_id': session['id']}, callback=True))
        self.assertIn('error', outsider.emit('subscribe_shell', {'session_id': session['id']}, callback=True))
        payload = {'event': 'output', 'event_id': 'chunk-1', 'data': base64.b64encode(b'private').decode()}
        frame = self.envelope('shell', payload, session_id=session['id'])
        first = self.send(frame)
        self.assertEqual(self.send(frame), first)  # lost acknowledgement
        conflict = {**frame, 'payload': {**payload, 'data': 'eA=='}}
        self.assertIn('error', self.send(conflict))
        self.assertEqual(len([e for e in browser.get_received() if e['name'] == 'shell_output']), 1)
        self.assertFalse(any(e['name'] == 'shell_output' for e in outsider.get_received()))
        self.assertNotIn('agent_shell_outputs', db.metadata.tables)
        self.assertNotIn('agent_shell_inputs', db.metadata.tables)
        # Retry after credential rotation uses an event ID, not a connection sequence.
        again = self.envelope('shell', payload, session_id=session['id'])
        self.send(again)
        self.send(self.envelope('presence'))  # heartbeat persists the metadata rollup
        saved = db.session.get(AgentShellSession, session['id'])
        self.assertEqual(saved.output_bytes, 7)

    def test_socket_input_and_resize_require_session_owner(self):
        session = self._create_session()
        owner = socketio.test_client(self.app, headers={'Authorization': f'Bearer {create_access_token(self.admin)}'})
        reader = socketio.test_client(self.app, headers={'Authorization': f'Bearer {create_access_token(self.analyst)}'})
        self.addCleanup(owner.disconnect)
        self.addCleanup(reader.disconnect)
        payload = {'session_id': session['id'], 'data': 'eA=='}
        self.assertIn('error', reader.emit('shell_input', payload, callback=True))
        self.assertTrue(owner.emit('shell_input', payload, callback=True)['accepted'])
        self.assertTrue(owner.emit('shell_resize', {'session_id': session['id'], 'cols': 80, 'rows': 24}, callback=True)['accepted'])
        saved = db.session.get(AgentShellSession, session['id'])
        self.assertEqual((saved.cols, saved.rows), (80, 24))

    def test_presence_exposes_bounded_metrics_and_rejects_bad_envelopes(self):
        self.connect_channel()
        frame = self.envelope('presence', {'latency_ms': 12, 'reconnect_count': 2})
        self.assertEqual(self.send(frame)['ack'], 1)
        connection = self.agent.to_dict()['connection']
        self.assertEqual(connection['transport'], 'websocket')
        self.assertEqual(connection['latency_ms'], 12)
        invalid = self.envelope('presence')
        invalid['agent_id'] += 1
        self.assertIn('error', self.send(invalid))
        invalid['agent_id'] = self.agent.id
        invalid['expires'] = time.time() - 1
        self.assertIn('error', self.send(invalid))
        invalid['expires'] = time.time() + 30
        invalid['kind'] = 'unknown'
        self.assertIn('error', self.send(invalid))

    def test_acknowledged_input_resumes_without_duplicate_bytes(self):
        session = self._create_session()
        self.connect_channel()
        self.client.post(f"/api/v1/agent-shell-sessions/{session['id']}/input",
                         json={'data': base64.b64encode(b'x').decode()}, headers=self._auth(self.admin))
        first = self.send(self.envelope('presence', {'input_session': session['id'], 'input_ack': 0}))
        self.assertEqual(len(first['session']['inputs']), 1)
        replay = self.send(self.envelope('presence', {'input_session': session['id'], 'input_ack': 1}))
        self.assertEqual(replay['session']['inputs'], [])

    def test_another_agent_cannot_publish_session_output(self):
        session = self._create_session()
        other = Agent(agent_key='other-key', hostname='other', enabled=1, status='active')
        db.session.add(other)
        db.session.commit()
        self.connect_channel(other)
        frame = self.envelope('shell', {'event': 'output', 'data': 'eA=='}, session_id=session['id'])
        frame['agent_id'] = other.id
        self.assertIn('error', self.send(frame))

    def test_full_queue_applies_backpressure_without_overwriting(self):
        backend = store()
        for _ in range(256):
            backend.append('test-queue', 'eA==')
        with self.assertRaises(TransportFull):
            backend.append('test-queue', 'eQ==')
        rows = backend.read('test-queue', after=1)
        self.assertEqual(rows[0]['id'], 2)
        self.assertEqual(backend.append('test-queue', 'eQ==')['id'], 257)

    def test_transport_reset_ends_lease_instead_of_reusing_output_sequences(self):
        session = self._create_session()
        saved = db.session.get(AgentShellSession, session['id'])
        store().delete(stream_key(saved, 'lease'))
        polled = self.client.get('/api/v1/agents/shell/poll', headers=self._agent_auth())
        self.assertIsNone(polled.get_json()['session'])
        self.assertEqual(saved.status, 'failed')
        self.assertEqual(saved.close_reason, 'transport_reset')

    def test_transient_data_expires(self):
        backend = MemoryStore()
        backend.append('test', 'terminal')
        with patch('artemis.services.agent_transport_store.time.time', return_value=time.time() + 1201):
            self.assertEqual(backend.read('test'), [])

    def test_hundred_agent_connections_are_independent(self):
        for n in range(100):
            agent = Agent(agent_key=f'fleet-{n}', hostname=f'fleet-{n}', enabled=1)
            db.session.add(agent)
        db.session.commit()
        clients = []
        try:
            for agent in Agent.query.filter(Agent.agent_key.like('fleet-%')).all():
                client = socketio.test_client(self.app, namespace='/agent', auth={'token': issue_token(agent)})
                self.assertTrue(client.is_connected('/agent'))
                clients.append(client)
            self.assertEqual(len(clients), 100)
        finally:
            for client in clients:
                client.disconnect(namespace='/agent')
