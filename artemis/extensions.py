"""Flask extensions for Artemis."""

from celery import Celery, Task
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO

db = SQLAlchemy()
socketio = SocketIO()
migrate = Migrate()


def init_celery(app):
    """Create a Celery app whose tasks execute inside the Flask context."""
    class FlaskTask(Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                try:
                    return self.run(*args, **kwargs)
                finally:
                    # Never let one task's tenant context bleed into the next.
                    from artemis.services.tenant import set_task_organization
                    set_task_organization(None)

    celery = Celery(app.import_name, task_cls=FlaskTask)
    celery.conf.update(
        broker_url=app.config['CELERY_BROKER_URL'],
        result_backend=app.config['CELERY_RESULT_BACKEND'],
        task_always_eager=app.config['CELERY_TASK_ALWAYS_EAGER'],
        task_eager_propagates=app.config['CELERY_TASK_EAGER_PROPAGATES'],
        task_track_started=app.config['CELERY_TASK_TRACK_STARTED'],
        task_acks_late=app.config['CELERY_TASK_ACKS_LATE'],
        worker_prefetch_multiplier=app.config['CELERY_WORKER_PREFETCH_MULTIPLIER'],
        task_time_limit=app.config['CELERY_TASK_TIME_LIMIT'],
        task_serializer='json',
        result_serializer='json',
        accept_content=['json'],
        timezone='UTC',
        beat_schedule={
            'dispatch-due-work': {
                'task': 'artemis.dispatch_due_work',
                'schedule': float(app.config.get('DISPATCH_INTERVAL_SECONDS', 60)),
                'options': {'expires': 55},
            },
        },
    )
    celery.set_default()
    app.extensions['celery'] = celery
    return celery
