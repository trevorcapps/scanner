import hmac
import hashlib
import unittest
from contextlib import contextmanager
from unittest.mock import patch

from artemis import create_app
from artemis.extensions import db
from artemis.models.webhook import Webhook, WebhookDelivery
from artemis.services.auth_service import create_access_token, create_user


class _FakeResp:
    def __init__(self, status=200, body=b'ok'):
        self.status = status
        self._body = body
    def read(self, *a):
        return self._body
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False


class WebhookTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing', start_background_services=False)
        with self.app.app_context():
            db.drop_all()
            db.create_all()
            admin = create_user('admin', 'password-123', role='admin')
            analyst = create_user('analyst', 'password-123', role='analyst')
            self.admin_tok = create_access_token(admin)
            self.analyst_tok = create_access_token(analyst)
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

    def _make_hook(self, events=('ping',), url='https://example.test/hook'):
        with self.ctx():
            hook = Webhook(url=url, secret='test-secret', created_at='2026-01-01T00:00:00')
            hook.events = list(events)
            db.session.add(hook)
            db.session.commit()
            return hook.id

    def test_create_denied_for_non_admin(self):
        r = self.client.post('/api/v1/webhooks',
                             json={'url': 'https://x.test/h', 'events': ['ping']},
                             headers=self._h(self.analyst_tok))
        self.assertEqual(r.status_code, 403)

    def test_create_returns_secret_once_then_hidden(self):
        r = self.client.post('/api/v1/webhooks',
                             json={'url': 'https://x.test/h', 'events': ['scan.completed']},
                             headers=self._h(self.admin_tok))
        self.assertEqual(r.status_code, 201)
        self.assertIn('secret', r.get_json())

        r = self.client.get('/api/v1/webhooks', headers=self._h(self.admin_tok))
        self.assertNotIn('secret', r.get_json()['webhooks'][0])

    def test_create_rejects_unknown_event(self):
        r = self.client.post('/api/v1/webhooks',
                             json={'url': 'https://x.test/h', 'events': ['not.an.event']},
                             headers=self._h(self.admin_tok))
        self.assertEqual(r.status_code, 400)

    def test_delivery_signs_body_with_hmac_sha256(self):
        hook_id = self._make_hook()
        captured = {}

        def fake_urlopen(req, timeout=None):
            captured['headers'] = {k.lower(): v for k, v in req.header_items()}
            captured['body'] = req.data
            return _FakeResp(200)

        from artemis.tasks import webhook_tasks
        with self.ctx():
            d = WebhookDelivery(webhook_id=hook_id, event='ping',
                                payload_json='{"event":"ping"}', status='pending',
                                created_at='2026-01-01T00:00:00')
            db.session.add(d)
            db.session.commit()
            did = d.id
            with patch.object(webhook_tasks.urllib.request, 'urlopen', fake_urlopen):
                webhook_tasks.deliver_webhook.run(did)

            expected = 'sha256=' + hmac.new(b'test-secret', captured['body'],
                                            hashlib.sha256).hexdigest()
            self.assertEqual(captured['headers']['x-artemis-signature'], expected)
            self.assertEqual(captured['headers']['x-artemis-event'], 'ping')
            row = db.session.get(WebhookDelivery, did)
            self.assertEqual(row.status, 'success')
            self.assertEqual(row.response_code, 200)

    def test_failed_delivery_schedules_retry(self):
        hook_id = self._make_hook()
        from artemis.tasks import webhook_tasks

        class _Retry(Exception):
            pass

        def boom(req, timeout=None):
            raise OSError('connection refused')

        with self.ctx():
            d = WebhookDelivery(webhook_id=hook_id, event='ping', payload_json='{}',
                                status='pending', created_at='2026-01-01T00:00:00')
            db.session.add(d)
            db.session.commit()
            did = d.id
            with patch.object(webhook_tasks.urllib.request, 'urlopen', boom), \
                 patch.object(webhook_tasks.deliver_webhook, 'retry', side_effect=_Retry()):
                with self.assertRaises(_Retry):
                    webhook_tasks.deliver_webhook.run(did)

            row = db.session.get(WebhookDelivery, did)
            self.assertEqual(row.attempts, 1)
            self.assertEqual(row.status, 'pending')
            self.assertIsNotNone(row.next_retry_at)

    def test_emit_fans_out_to_subscribed_hooks_only(self):
        self._make_hook(events=['scan.completed'])
        self._make_hook(events=['agent.registered'])
        self._make_hook(events=[])  # empty == all events

        sent = []
        from artemis.services import webhook_service
        with self.ctx():
            with patch('artemis.tasks.webhook_tasks.deliver_webhook.delay',
                       side_effect=lambda did: sent.append(did)):
                webhook_service.emit('scan.completed', {'target': '10.0.0.1'})
            self.assertEqual(len(sent), 2)
            self.assertEqual(WebhookDelivery.query.count(), 2)


if __name__ == '__main__':
    unittest.main()
