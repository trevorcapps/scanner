"""Configuration for Artemis vulnerability scanner."""

import os

basedir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.lower() in ('1', 'true', 'yes', 'on')


class Config:
    """Base configuration."""
    # SECRET_KEY must be stable across restarts for JWT tokens to remain valid.
    # Set SECRET_KEY env var in production. Fallback generates a persistent key file.
    SECRET_KEY = os.environ.get('SECRET_KEY', None)
    if not SECRET_KEY:
        _key_path = os.path.join(basedir, '.secret_key')
        if os.path.exists(_key_path):
            with open(_key_path, 'r') as f:
                SECRET_KEY = f.read().strip()
        else:
            import secrets as _secrets
            SECRET_KEY = _secrets.token_hex(32)
            with open(_key_path, 'w') as f:
                f.write(SECRET_KEY)
            os.chmod(_key_path, 0o600)
    DATABASE_URL = os.environ.get('DATABASE_URL',
                                  f'sqlite:///{os.path.join(basedir, "vuln_scan.db")}')
    # SQLAlchemy
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Redis / Celery. Local development uses eager execution unless a broker is set.
    REDIS_URL = os.environ.get('REDIS_URL', '')
    CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL') or REDIS_URL or 'memory://'
    CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND') or REDIS_URL or 'cache+memory://'
    CELERY_TASK_ALWAYS_EAGER = _env_bool('CELERY_TASK_ALWAYS_EAGER', CELERY_BROKER_URL == 'memory://')
    CELERY_TASK_EAGER_PROPAGATES = _env_bool('CELERY_TASK_EAGER_PROPAGATES', False)
    CELERY_TASK_TRACK_STARTED = True
    CELERY_TASK_ACKS_LATE = True
    CELERY_WORKER_PREFETCH_MULTIPLIER = 1
    CELERY_TASK_TIME_LIMIT = int(os.environ.get('CELERY_TASK_TIME_LIMIT', '7200'))

    # Keep create_all for local compatibility. Production is migration-only.
    AUTO_CREATE_SCHEMA = _env_bool('AUTO_CREATE_SCHEMA', True)
    INITIALIZE_LEGACY_SCHEMA = _env_bool('INITIALIZE_LEGACY_SCHEMA', True)
    START_BACKGROUND_SERVICES = _env_bool('START_BACKGROUND_SERVICES', True)

    # NVD
    NVD_API_KEY = os.environ.get('NVD_API_KEY', '')

    # Scan profiles path
    SCAN_PROFILES_PATH = os.environ.get(
        'SCAN_PROFILES_PATH',
        os.path.join(basedir, 'scan_profiles.json'))

    # Database file path (legacy). Retained as an alias: a few top-level modules
    # (vuln_scan, nvd_feeds, cpe_dict) still import it. Application state now
    # lives in Postgres (SQLALCHEMY_DATABASE_URI); this only backs the NVD cache
    # and the one-time legacy-data migrator.
    DB_PATH = os.environ.get('DB_PATH', os.path.join(basedir, 'vuln_scan.db'))

    # Local SQLite read-cache for NVD CVE feeds, the CPE dictionary and the
    # ExploitDB mapping — ~3M+ rows of public data, rebuilt by `sync`. This is a
    # derived cache, never the system of record. Defaults to the legacy DB file
    # so the cache tables already present there are reused as-is.
    NVD_CACHE_PATH = os.environ.get('NVD_CACHE_PATH') or DB_PATH

    # Path to the pre-Postgres SQLite database. On first boot the migrator copies
    # any application rows (assets, scans, vulnerabilities, ...) from here into
    # Postgres, then records a sentinel and never runs again. Set to '' to skip.
    LEGACY_SQLITE_PATH = os.environ.get('LEGACY_SQLITE_PATH')
    if LEGACY_SQLITE_PATH is None:
        LEGACY_SQLITE_PATH = DB_PATH

    # Generated report artifacts (PDF/HTML). Lives on the data volume alongside
    # the NVD cache so history survives container recreation.
    REPORTS_DIR = os.environ.get(
        'REPORTS_DIR',
        os.path.join(os.path.dirname(NVD_CACHE_PATH) if NVD_CACHE_PATH not in ('', ':memory:')
                     else basedir, 'reports'))

    # API / docs
    API_VERSION = os.environ.get('API_VERSION', '2.0.0')

    # Debug
    DEBUG = os.environ.get('DEBUG', 'false').lower() == 'true'


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False
    AUTO_CREATE_SCHEMA = False


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    DB_PATH = ':memory:'
    NVD_CACHE_PATH = ':memory:'
    LEGACY_SQLITE_PATH = ''
    CELERY_BROKER_URL = 'memory://'
    CELERY_RESULT_BACKEND = 'cache+memory://'
    CELERY_TASK_ALWAYS_EAGER = True
    CELERY_TASK_EAGER_PROPAGATES = True
    INITIALIZE_LEGACY_SCHEMA = False
    START_BACKGROUND_SERVICES = False


config_map = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': Config,
}
