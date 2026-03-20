"""Artemis vulnerability scanner — app factory."""

import os
import sys
import json
import logging

from flask import Flask, render_template

from artemis.config import config_map
from artemis.extensions import db, socketio, init_celery
from artemis.api import register_blueprints

logger = logging.getLogger(__name__)

# Ensure scanner root is on sys.path for legacy imports (device_type, nvd_feeds, etc.)
_scanner_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _scanner_dir not in sys.path:
    sys.path.insert(0, _scanner_dir)


def create_app(config_name=None):
    """Application factory."""
    if config_name is None:
        config_name = os.environ.get('FLASK_CONFIG', 'default')

    app = Flask(
        __name__,
        template_folder=os.path.join(_scanner_dir, 'templates'),
        static_folder=os.path.join(_scanner_dir, 'static'),
    )
    app.config.from_object(config_map[config_name])

    # Initialize extensions
    db.init_app(app)
    socketio.init_app(app)

    # Optional Celery
    celery = init_celery(app)
    if celery:
        app.celery = celery

    # Register blueprints
    register_blueprints(app)

    # Register SQL query blueprint
    from artemis.api.sql import sql_bp
    app.register_blueprint(sql_bp, url_prefix='/api/v1')
    app.register_blueprint(sql_bp, url_prefix='/api', name='sql_legacy')

    # Register SocketIO event handlers
    from artemis import socketio_handlers  # noqa: F401

    # Legacy routes (index + report)
    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/report/<ip>')
    def report(ip):
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

    # Start background scheduler
    from artemis.services.scheduler_service import start_scheduler
    start_scheduler(app)

    logger.info("Artemis app created successfully")
    return app


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

    # Create SQLAlchemy tables (for any new models)
    db.create_all()

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
