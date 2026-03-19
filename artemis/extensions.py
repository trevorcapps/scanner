"""Flask extensions for Artemis."""

from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO

db = SQLAlchemy()
socketio = SocketIO()


def init_celery(app):
    """Initialize Celery if broker is configured. Returns Celery app or None."""
    broker = app.config.get('CELERY_BROKER_URL')
    if not broker:
        return None

    try:
        from celery import Celery

        celery = Celery(
            app.import_name,
            broker=broker,
            backend=app.config.get('CELERY_RESULT_BACKEND', ''),
        )
        celery.conf.update(app.config)

        class ContextTask(celery.Task):
            def __call__(self, *args, **kwargs):
                with app.app_context():
                    return self.run(*args, **kwargs)

        celery.Task = ContextTask
        return celery
    except ImportError:
        return None
