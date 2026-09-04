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
from artemis.api.auth import auth_bp
from artemis.api.webhooks import webhooks_bp
from artemis.api.openapi import docs_bp
from artemis.api.dashboard import dashboard_bp
from artemis.api.audit import audit_bp
from artemis.api.organizations import organizations_bp
from artemis.api.asset_mgmt import asset_mgmt_bp
from artemis.api.discovery import discovery_bp
from artemis.api.findings import findings_bp
from artemis.api.dispositions import dispositions_bp


def register_blueprints(app):
    """Register all API blueprints with versioned and legacy prefixes."""
    # Auth (no prefix — /api/v1/auth/login, etc.)
    app.register_blueprint(auth_bp, url_prefix='/api/v1')
    app.register_blueprint(auth_bp, url_prefix='/api', name='auth_legacy')

    # Agent install script at /agent/install.sh (convenience shortcut)
    app.register_blueprint(agents_bp, url_prefix='/agent', name='agents_shortcut')

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
    app.register_blueprint(webhooks_bp, url_prefix='/api/v1')
    app.register_blueprint(docs_bp, url_prefix='/api/v1')
    app.register_blueprint(dashboard_bp, url_prefix='/api/v1')
    app.register_blueprint(audit_bp, url_prefix='/api/v1')
    app.register_blueprint(organizations_bp, url_prefix='/api/v1')
    app.register_blueprint(asset_mgmt_bp, url_prefix='/api/v1')
    app.register_blueprint(discovery_bp, url_prefix='/api/v1')
    app.register_blueprint(findings_bp, url_prefix='/api/v1')
    app.register_blueprint(dispositions_bp, url_prefix='/api/v1')

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
    app.register_blueprint(webhooks_bp, url_prefix='/api', name='webhooks_legacy')
