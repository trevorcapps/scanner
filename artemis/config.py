"""Configuration for Artemis vulnerability scanner."""

import os

basedir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(24))
    DATABASE_URL = os.environ.get('DATABASE_URL',
                                  f'sqlite:///{os.path.join(basedir, "vuln_scan.db")}')
    # SQLAlchemy
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Redis / Celery (optional)
    REDIS_URL = os.environ.get('REDIS_URL', '')
    CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', '')
    CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND', '')

    # NVD
    NVD_API_KEY = os.environ.get('NVD_API_KEY', '')

    # Scan profiles path
    SCAN_PROFILES_PATH = os.environ.get(
        'SCAN_PROFILES_PATH',
        os.path.join(basedir, 'scan_profiles.json'))

    # Database file path (for raw sqlite3 access where needed)
    DB_PATH = os.environ.get('DB_PATH', os.path.join(basedir, 'vuln_scan.db'))

    # Debug
    DEBUG = os.environ.get('DEBUG', 'false').lower() == 'true'


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    DB_PATH = ':memory:'


config_map = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': Config,
}
