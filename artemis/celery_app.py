"""Celery worker entry point.

Run with: celery -A artemis.celery_app:celery_app worker --loglevel=INFO
"""

from artemis import create_app


flask_app = create_app(start_background_services=False)
celery_app = flask_app.extensions['celery']

# Import tasks after Celery becomes the default application.
import artemis.tasks.scan_tasks  # noqa: E402,F401
