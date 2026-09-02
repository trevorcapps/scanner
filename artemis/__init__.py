"""Artemis vulnerability scanner — app factory."""

import os
import sys
import json
import logging

from flask import Flask, render_template

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

    if config_name == 'production':
        if app.config['CELERY_BROKER_URL'] == 'memory://' or app.config['CELERY_TASK_ALWAYS_EAGER']:
            raise RuntimeError('Production requires Redis-backed Celery; configure CELERY_BROKER_URL and disable eager mode')

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

    # Register SQL query blueprint
    from artemis.api.sql import sql_bp
    app.register_blueprint(sql_bp, url_prefix='/api/v1')
    app.register_blueprint(sql_bp, url_prefix='/api', name='sql_legacy')

    # Register SocketIO event handlers
    from artemis import socketio_handlers
    socketio_handlers.register_socketio_handlers()

    # Legacy routes (index + report)
    @app.route('/')
    def index():
        return render_template('index.html')

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
        '/api/agents/register',
        '/api/agents/report',
        '/agent/install.sh',
        '/agent/artemis_agent.py',
        '/agent/uninstall.sh',
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
            logger.debug(f"Auth failed for {path}: cookie={'yes' if token else 'no'}, header={'yes' if auth_header else 'no'}")
            return jsonify({'error': 'Authentication required'}), 401

        if request.method not in ('GET', 'HEAD', 'OPTIONS'):
            is_self_service = path in READONLY_SELF_SERVICE_PATHS or path.startswith(READONLY_SELF_SERVICE_PREFIXES)
            if get_effective_role(user) == 'readonly' and not is_self_service:
                return jsonify({'error': 'Read-only credentials cannot modify resources'}), 403


def _auto_migrate(db_path):
    """Add missing columns to existing tables. Safe to run repeatedly."""
    import sqlite3
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Define expected columns: (table, column, type, default)
    migrations = [
        ('agents', 'mac_address', 'TEXT', None),
    ]

    for table, column, col_type, default in migrations:
        cursor.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,))
        if not cursor.fetchone():
            continue
        cursor.execute(f"PRAGMA table_info({table})")
        existing = {row[1] for row in cursor.fetchall()}
        if column not in existing:
            default_clause = f" DEFAULT {default!r}" if default is not None else ""
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}{default_clause}")
            logger.info(f"Migration: added {table}.{column} ({col_type})")

    conn.commit()
    conn.close()


def _init_database(app):
    """Initialize all database tables — mirrors the old vuln_scan.init_db()."""
    db_path = app.config['DB_PATH']

    if app.config.get('AUTO_CREATE_SCHEMA', True):
        db.create_all()

    if not app.config.get('INITIALIZE_LEGACY_SCHEMA', True):
        return

    # Auto-migrate: add missing columns to existing tables
    _auto_migrate(db_path)

    # Also run legacy init for tables managed by external modules
    try:
        from nvd_feeds import init_nvd_tables
        init_nvd_tables(db_path)
    except Exception as e:
        logger.warning(f"Could not initialize NVD tables: {e}")

    try:
        from cpe_dict import init_cpe_tables
        init_cpe_tables(db_path)
    except Exception as e:
        logger.warning(f"Could not initialize CPE tables: {e}")

    logger.info(f"Database initialized: {db_path}")
