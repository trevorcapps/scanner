"""Authentication service — JWT tokens, user management, API key auth."""

import hashlib
import logging
import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import request, jsonify, current_app, g

from artemis.extensions import db
from artemis.models.user import User
from artemis.models.api_key import ApiKey

logger = logging.getLogger(__name__)

# Roles hierarchy: admin > analyst > readonly
ROLE_HIERARCHY = {'admin': 3, 'analyst': 2, 'readonly': 1}


def _now_iso():
    return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')


# ==================== JWT Token Management ====================

import jwt
if not hasattr(jwt, 'encode'):
    raise ImportError(
        "The 'jwt' package is installed but PyJWT is required. "
        "Fix: pip uninstall jwt && pip install PyJWT"
    )


def create_access_token(user, expires_hours=24):
    """Create a JWT access token for a user."""
    payload = {
        'sub': user.id,
        'username': user.username,
        'role': user.role,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=expires_hours),
        'type': 'access',
    }
    return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')


def create_refresh_token(user, expires_days=30):
    """Create a JWT refresh token."""
    payload = {
        'sub': user.id,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(days=expires_days),
        'type': 'refresh',
    }
    return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')


def decode_token(token):
    """Decode and validate a JWT token. Returns payload or None."""
    try:
        return jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
    except Exception:
        return None


# ==================== User Management ====================

def create_user(username, password, email=None, role='analyst', display_name=None):
    """Create a new user. Returns the user or raises ValueError."""
    if User.query.filter_by(username=username).first():
        raise ValueError(f'Username "{username}" already exists')
    if email and User.query.filter_by(email=email).first():
        raise ValueError(f'Email "{email}" already in use')

    user = User(
        username=username,
        email=email,
        role=role,
        display_name=display_name or username,
        created_at=_now_iso(),
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    logger.info(f"Created user: {username} (role={role})")
    return user


def authenticate_user(username, password):
    """Authenticate by username/password. Returns user or None."""
    user = User.query.filter_by(username=username, enabled=1).first()
    if user and user.check_password(password):
        user.last_login = _now_iso()
        db.session.commit()
        return user
    return None


def create_default_admin():
    """Create default admin user if no users exist. Returns password if created."""
    if User.query.count() > 0:
        return None
    password = secrets.token_urlsafe(16)
    create_user('admin', password, role='admin', display_name='Administrator')
    logger.info(f"Default admin created — password: {password}")
    return password


# ==================== API Key Management ====================

def generate_api_key(user_id, name='default', role=None):
    """Generate a new API key for a user. Returns the raw key (only shown once)."""
    user = User.query.get(user_id)
    if not user:
        raise ValueError('User not found')

    raw_key = 'art_' + secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    api_key = ApiKey(
        user_id=user_id,
        key_hash=key_hash,
        key_prefix=raw_key[:12],
        name=name,
        role=role or user.role,
        created_at=_now_iso(),
        enabled=1,
    )
    db.session.add(api_key)
    db.session.commit()
    return raw_key


def authenticate_api_key(raw_key):
    """Authenticate by API key. Returns (api_key_record, user) or (None, None)."""
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    api_key = ApiKey.query.filter_by(key_hash=key_hash, enabled=1).first()
    if not api_key:
        return None, None

    # Check expiry
    if api_key.expires_at:
        try:
            exp = datetime.strptime(api_key.expires_at, '%Y-%m-%dT%H:%M:%SZ')
            if datetime.utcnow() > exp:
                return None, None
        except ValueError:
            pass

    user = User.query.filter_by(id=api_key.user_id, enabled=1).first()
    if not user:
        return None, None

    api_key.last_used = _now_iso()
    db.session.commit()
    return api_key, user


# ==================== Auth Middleware ====================

def _get_current_user():
    """Extract user from JWT token or API key in the request. Sets g.current_user."""
    # Check Authorization header
    auth_header = request.headers.get('Authorization', '')

    # Bearer token (JWT)
    if auth_header.startswith('Bearer '):
        token = auth_header[7:]
        payload = decode_token(token)
        if payload and payload.get('type') == 'access':
            user = User.query.filter_by(id=payload['sub'], enabled=1).first()
            if user:
                g.current_user = user
                g.auth_method = 'jwt'
                return user

    # API key (X-API-Key header or Authorization: ApiKey ...)
    api_key_raw = request.headers.get('X-API-Key', '')
    if not api_key_raw and auth_header.startswith('ApiKey '):
        api_key_raw = auth_header[7:]
    if api_key_raw:
        api_key, user = authenticate_api_key(api_key_raw)
        if user:
            g.current_user = user
            g.auth_method = 'api_key'
            g.api_key_role = api_key.role
            return user

    # Session cookie (for browser UI)
    token = request.cookies.get('artemis_token')
    if token:
        payload = decode_token(token)
        if payload and payload.get('type') == 'access':
            user = User.query.filter_by(id=payload['sub'], enabled=1).first()
            if user:
                g.current_user = user
                g.auth_method = 'cookie'
                return user

    return None


def login_required(f):
    """Decorator: require authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Skip auth if no users exist (first-run / setup mode)
        if User.query.count() == 0:
            g.current_user = None
            g.auth_method = 'setup'
            return f(*args, **kwargs)

        user = _get_current_user()
        if not user:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated


def role_required(min_role):
    """Decorator: require minimum role level."""
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated(*args, **kwargs):
            user = getattr(g, 'current_user', None)
            if user is None:
                # Setup mode — allow
                return f(*args, **kwargs)
            effective_role = getattr(g, 'api_key_role', user.role)
            if ROLE_HIERARCHY.get(effective_role, 0) < ROLE_HIERARCHY.get(min_role, 0):
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


def admin_required(f):
    """Shortcut for role_required('admin')."""
    return role_required('admin')(f)
