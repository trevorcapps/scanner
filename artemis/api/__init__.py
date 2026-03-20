"""Register all API blueprints."""

from artemis.api.assets import assets_bp
from artemis.api.scans import scans_bp
from artemis.api.vulnerabilities import vulnerabilities_bp
from artemis.api.fingerprints import fingerprints_bp
from artemis.api.credentials import credentials_bp
from artemis.api.settings import settings_bp
from artemis.api.reports import reports_bp
from artemis.api.schedules import schedules_bp
from artemis.api.agents import agents_bp
from artemis.api.sites import sites_bp


def register_blueprints(app):
    """Register all API blueprints with versioned and legacy prefixes."""
    # Versioned API
    app.register_blueprint(assets_bp, url_prefix='/api/v1')
    app.register_blueprint(scans_bp, url_prefix='/api/v1')
    app.register_blueprint(vulnerabilities_bp, url_prefix='/api/v1')
    app.register_blueprint(fingerprints_bp, url_prefix='/api/v1')
    app.register_blueprint(credentials_bp, url_prefix='/api/v1')
    app.register_blueprint(settings_bp, url_prefix='/api/v1')
    app.register_blueprint(reports_bp, url_prefix='/api/v1')
    app.register_blueprint(schedules_bp, url_prefix='/api/v1')
    app.register_blueprint(agents_bp, url_prefix='/api/v1')
    app.register_blueprint(sites_bp, url_prefix='/api/v1')

    # Legacy (backward compat) — same blueprints, no version prefix
    app.register_blueprint(assets_bp, url_prefix='/api', name='assets_legacy')
    app.register_blueprint(vulnerabilities_bp, url_prefix='/api', name='vulns_legacy')
    app.register_blueprint(fingerprints_bp, url_prefix='/api', name='fp_legacy')
    app.register_blueprint(credentials_bp, url_prefix='/api', name='creds_legacy')
    app.register_blueprint(settings_bp, url_prefix='/api', name='settings_legacy')
    app.register_blueprint(reports_bp, url_prefix='/api', name='reports_legacy')
    app.register_blueprint(schedules_bp, url_prefix='/api', name='schedules_legacy')
    app.register_blueprint(agents_bp, url_prefix='/api', name='agents_legacy')
    app.register_blueprint(sites_bp, url_prefix='/api', name='sites_legacy')
