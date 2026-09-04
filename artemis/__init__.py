"""Artemis vulnerability scanner — app factory."""

import os
import sys
import logging

from flask import Flask, render_template, send_from_directory, abort

from artemis.config import config_map
from artemis.extensions import db, migrate, socketio, init_celery
from artemis.api import register_blueprints

logger = logging.getLogger(__name__)

# Ensure scanner root is on sys.path for legacy imports (device_type, nvd_feeds, etc.)
_scanner_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _scanner_dir not in sys.path:
    sys.path.insert(0, _scanner_dir)


def create_app(config_name=None, start_background_services=True):
    """Application factory."""
    if config_name is None:
        config_name = os.environ.get('FLASK_CONFIG', 'default')

    app = Flask(
        __name__,
        template_folder=os.path.join(_scanner_dir, 'templates'),
        static_folder=os.path.join(_scanner_dir, 'static'),
    )
    app.config.from_object(config_map[config_name])

    # Install this before initialization work so the UI has useful history as
    # soon as the application is ready.
    from artemis.services.log_service import install_recent_log_handler
    install_recent_log_handler()

    if config_name == 'production':
        if app.config['CELERY_BROKER_URL'] == 'memory://' or app.config['CELERY_TASK_ALWAYS_EAGER']:
            raise RuntimeError(
                'Production requires Redis-backed Celery; configure CELERY_BROKER_URL and disable eager mode'
            )

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    message_queue = None
    if not app.config['CELERY_TASK_ALWAYS_EAGER'] and app.config['CELERY_BROKER_URL'].startswith('redis'):
        message_queue = app.config['CELERY_BROKER_URL']
    socketio.init_app(app, message_queue=message_queue)

    celery = init_celery(app)
    app.celery = celery

    # Register blueprints
    register_blueprints(app)

    # Auth middleware — protect API routes
    _setup_auth_middleware(app)

    # Register SocketIO event handlers
    from artemis import socketio_handlers
    socketio_handlers.register_socketio_handlers()

    # ---- Frontend serving ----
    _ui_dir = os.path.join(_scanner_dir, 'static', 'ui')
    _ui_index = os.path.join(_ui_dir, 'index.html')
    # Path prefixes owned by the backend / classic app — never SPA-fallback these.
    # ('scan' is POST-only for the legacy report form and matches its exact rule
    #  first, so GET /scan still reaches the SPA.)
    _spa_reserved = ('api/', 'agent/', 'static/', 'socket.io/', 'report/',
                     'classic', 'favicon')

    def _serve_spa():
        if os.path.isfile(_ui_index):
            return send_from_directory(_ui_dir, 'index.html')
        # No build present (local dev without `npm run build`) — fall back to classic.
        return render_template('index.html')

    @app.route('/')
    def index():
        return _serve_spa()

    @app.route('/classic')
    def classic():
        return render_template('index.html')

    @app.route('/<path:sub_path>')
    def spa_fallback(sub_path):
        if sub_path.startswith(_spa_reserved) or '.' in sub_path.rsplit('/', 1)[-1]:
            abort(404)
        return _serve_spa()

    @app.route('/report/<ip>')
    def report(ip):
        from artemis.services.auth_service import _get_current_user
        from artemis.models.user import User
        # Require auth for reports (unless setup mode)
        if User.query.count() > 0 and not _get_current_user():
            return render_template('index.html')  # redirect to login
        from artemis.services.report_service import generate_report_view
        return generate_report_view(ip)

    @app.route('/scan', methods=['POST'])
    def scan_post():
        from flask import request
        from artemis.services.report_service import handle_scan_post
        return handle_scan_post(request)

    # Initialize database tables
    with app.app_context():
        _init_database(app)

    if start_background_services and app.config.get('START_BACKGROUND_SERVICES', True):
        from artemis.services.scheduler_service import start_scheduler
        start_scheduler(app)

    logger.info("Artemis app created successfully")
    return app


def _setup_auth_middleware(app):
    """Add before_request auth check for API routes."""
    from flask import g, jsonify
    from artemis.services.auth_service import _get_current_user, get_effective_role
    from artemis.models.user import User

    # Routes that don't require auth
    PUBLIC_PREFIXES = (
        '/api/v1/auth/',
        '/api/auth/',
        '/static/',
    )
    PUBLIC_PATHS = {
        '/api/v1/agents/register',
        '/api/v1/agents/report',
        '/api/v1/agents/deregister',
        '/api/v1/agents/shell/poll',
        '/api/v1/agents/shell/output',
        '/api/agents/register',
        '/api/agents/report',
        '/api/agents/deregister',
        '/api/agents/shell/poll',
        '/api/agents/shell/output',
        '/agent/install.sh',
        '/agent/artemis_agent.py',
        '/agent/uninstall.sh',
        '/api/v1/openapi.json',
        '/api/v1/docs',
        '/api/v1/health',
    }
    READONLY_SELF_SERVICE_PATHS = {
        '/api/v1/auth/change-password',
        '/api/auth/change-password',
    }
    READONLY_SELF_SERVICE_PREFIXES = ('/api/v1/api-keys', '/api/api-keys')

    @app.before_request
    def check_auth():
        from flask import request
        path = request.path

        # Protect the API and the administrative routes exposed by the agent shortcut.
        if not path.startswith(('/api/', '/agent/')):
            return None

        if path in PUBLIC_PATHS:
            return None

        # Skip auth for public endpoints
        for prefix in PUBLIC_PREFIXES:
            if path.startswith(prefix):
                return None

        # Skip auth if no users exist (setup mode)
        with app.app_context():
            if User.query.count() == 0:
                g.current_user = None
                g.auth_method = 'setup'
                return None

        user = _get_current_user()
        if not user:
            # Debug: log why auth failed
            token = request.cookies.get('artemis_token')
            auth_header = request.headers.get('Authorization', '')
            logger.debug(
                "Auth failed for %s: cookie=%s, header=%s",
                path, 'yes' if token else 'no', 'yes' if auth_header else 'no',
            )
            return jsonify({'error': 'Authentication required'}), 401

        if request.method not in ('GET', 'HEAD', 'OPTIONS'):
            is_self_service = path in READONLY_SELF_SERVICE_PATHS or path.startswith(READONLY_SELF_SERVICE_PREFIXES)
            if get_effective_role(user) == 'readonly' and not is_self_service:
                return jsonify({'error': 'Read-only credentials cannot modify resources'}), 403


def _init_database(app):
    """Prepare the databases.

    Postgres (SQLALCHEMY_DATABASE_URI) is the system of record; its schema is
    owned by Alembic (`flask db upgrade` in the container entrypoint), with
    ``db.create_all()`` as a dev-only convenience. The NVD/CPE/ExploitDB feed
    cache is a separate local SQLite file (``NVD_CACHE_PATH``).
    """
    if app.config.get('AUTO_CREATE_SCHEMA', True):
        db.create_all()

    # One-time copy of pre-Postgres application rows into Postgres.
    try:
        from artemis.services.legacy_migration import migrate_legacy_sqlite
        migrate_legacy_sqlite(app)
    except Exception as e:
        logger.warning(f"Legacy SQLite migration skipped: {e}")

    if not app.config.get('INITIALIZE_LEGACY_SCHEMA', True):
        return

    # Ensure the SQLite feed-cache schema exists (idempotent).
    cache_path = app.config.get('NVD_CACHE_PATH')
    if cache_path and cache_path != ':memory:':
        for label, fn_path in (('NVD', 'nvd_feeds.init_nvd_tables'),
                               ('CPE', 'cpe_dict.init_cpe_tables')):
            try:
                module_name, fn_name = fn_path.rsplit('.', 1)
                fn = getattr(__import__(module_name, fromlist=[fn_name]), fn_name)
                fn(cache_path)
            except Exception as e:
                logger.warning(f"Could not initialize {label} cache tables: {e}")
        logger.info(f"NVD feed cache ready: {cache_path}")

        # Product->vendor index for the auth-scan CPE resolver (no-op if the NVD
        # cache is empty or the index is already current).
        try:
            from nvd_feeds import build_cpe_product_index
            import sqlite3 as _sq
            _c = _sq.connect(cache_path)
            has_index = _c.execute(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='cpe_products'"
            ).fetchone()[0]
            rows = _c.execute("SELECT count(*) FROM cpe_products").fetchone()[0] if has_index else 0
            _c.close()
            if rows == 0:
                build_cpe_product_index(cache_path)
        except Exception as e:
            logger.warning(f"CPE product index unavailable: {e}")
