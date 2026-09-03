import logging
import unittest

from artemis import create_app
from artemis.extensions import db
from artemis.services.auth_service import create_access_token, create_user
from artemis.services.log_service import clear_recent_logs, get_recent_logs


class ActivityLogTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing', start_background_services=False)
        with self.app.app_context():
            db.drop_all()
            db.create_all()
            self.token = create_access_token(create_user('admin', 'password-123', role='admin'))
        self.client = self.app.test_client()
        clear_recent_logs()

    def tearDown(self):
        with self.app.app_context():
            db.drop_all()
        clear_recent_logs()

    def test_history_captures_real_application_records(self):
        logging.getLogger('artemis.test').info('agent report accepted with 2 findings')

        records = get_recent_logs()

        self.assertEqual(records[-1]['message'], 'agent report accepted with 2 findings')
        self.assertEqual(records[-1]['level'], 'info')
        self.assertEqual(records[-1]['logger'], 'artemis.test')

    def test_authenticated_logs_endpoint_returns_history(self):
        logging.getLogger('artemis.test').warning('scan worker retrying')

        response = self.client.get(
            '/api/v1/logs?limit=10',
            headers={'Authorization': f'Bearer {self.token}'},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['logs'][-1]['message'], 'scan worker retrying')

    def test_logs_endpoint_requires_operator_authentication(self):
        response = self.client.get('/api/v1/logs')

        self.assertEqual(response.status_code, 401)


if __name__ == '__main__':
    unittest.main()
