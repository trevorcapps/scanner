"""Auth API blueprint — login, register, token refresh, user management, API keys."""

import logging
from flask import Blueprint, request, jsonify, make_response, g

from artemis.services.auth_service import (
    authenticate_user, create_access_token, create_refresh_token,
    decode_token, create_user, generate_api_key,
    login_required, admin_required,
)
from artemis.extensions import db
from artemis.models.user import User
from artemis.models.api_key import ApiKey

logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/auth/login', methods=['POST'])
def login():
    """Authenticate and return JWT tokens."""
    data = request.get_json(force=True)
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    user = authenticate_user(username, password)
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401

    access_token = create_access_token(user)
    refresh_token = create_refresh_token(user)

    resp = make_response(jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': user.to_dict(),
    }))
    # Set cookie for browser UI
    resp.set_cookie('artemis_token', access_token,
                     httponly=True, samesite='Lax', max_age=86400)
    return resp


@auth_bp.route('/auth/logout', methods=['POST'])
def logout():
    """Clear auth cookie."""
    resp = make_response(jsonify({'status': 'logged_out'}))
    resp.delete_cookie('artemis_token')
    return resp


@auth_bp.route('/auth/refresh', methods=['POST'])
def refresh():
    """Refresh access token using refresh token."""
    data = request.get_json(force=True)
    refresh_token = data.get('refresh_token', '')

    payload = decode_token(refresh_token)
    if not payload or payload.get('type') != 'refresh':
        return jsonify({'error': 'Invalid or expired refresh token'}), 401

    user = User.query.filter_by(id=payload['sub'], enabled=1).first()
    if not user:
        return jsonify({'error': 'User not found or disabled'}), 401

    access_token = create_access_token(user)

    resp = make_response(jsonify({
        'access_token': access_token,
        'user': user.to_dict(),
    }))
    resp.set_cookie('artemis_token', access_token,
                     httponly=True, samesite='Lax', max_age=86400)
    return resp


@auth_bp.route('/auth/me', methods=['GET'])
@login_required
def me():
    """Get current user info."""
    user = getattr(g, 'current_user', None)
    if user:
        return jsonify({'user': user.to_dict()})
    return jsonify({'user': None, 'setup_mode': True})


@auth_bp.route('/auth/setup', methods=['POST'])
def setup():
    """First-time setup: create the initial admin user. Only works if no users exist."""
    if User.query.count() > 0:
        return jsonify({'error': 'Setup already completed'}), 403

    data = request.get_json(force=True)
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or len(password) < 8:
        return jsonify({'error': 'Username required, password must be 8+ characters'}), 400

    user = create_user(username, password, role='admin',
                       email=data.get('email'), display_name=data.get('display_name'))

    access_token = create_access_token(user)
    refresh_token = create_refresh_token(user)

    resp = make_response(jsonify({
        'status': 'setup_complete',
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': user.to_dict(),
    }))
    resp.set_cookie('artemis_token', access_token,
                     httponly=True, samesite='Lax', max_age=86400)
    return resp


# ==================== User Management (Admin only) ====================

@auth_bp.route('/users', methods=['GET'])
@admin_required
def list_users():
    """List all users."""
    users = User.query.order_by(User.id).all()
    return jsonify([u.to_dict() for u in users])


@auth_bp.route('/users', methods=['POST'])
@admin_required
def create_user_endpoint():
    """Create a new user."""
    data = request.get_json(force=True)
    username = data.get('username', '').strip()
    password = data.get('password', '')
    role = data.get('role', 'analyst')

    if not username or len(password) < 8:
        return jsonify({'error': 'Username required, password must be 8+ characters'}), 400
    if role not in ('admin', 'analyst', 'readonly'):
        return jsonify({'error': 'Role must be admin, analyst, or readonly'}), 400

    try:
        user = create_user(username, password, role=role,
                           email=data.get('email'), display_name=data.get('display_name'))
        return jsonify(user.to_dict()), 201
    except ValueError as e:
        return jsonify({'error': str(e)}), 409


@auth_bp.route('/users/<int:uid>', methods=['PUT'])
@admin_required
def update_user(uid):
    """Update a user."""
    user = User.query.get_or_404(uid)
    data = request.get_json(force=True)

    if 'role' in data and data['role'] in ('admin', 'analyst', 'readonly'):
        user.role = data['role']
    if 'display_name' in data:
        user.display_name = data['display_name']
    if 'email' in data:
        user.email = data['email']
    if 'enabled' in data:
        user.enabled = 1 if data['enabled'] else 0
    if 'password' in data and len(data['password']) >= 8:
        user.set_password(data['password'])

    db.session.commit()
    return jsonify(user.to_dict())


@auth_bp.route('/users/<int:uid>', methods=['DELETE'])
@admin_required
def delete_user(uid):
    """Delete a user."""
    user = User.query.get_or_404(uid)
    current = getattr(g, 'current_user', None)
    if current and current.id == uid:
        return jsonify({'error': 'Cannot delete yourself'}), 400
    ApiKey.query.filter_by(user_id=uid).delete()
    db.session.delete(user)
    db.session.commit()
    return jsonify({'status': 'deleted', 'id': uid})


# ==================== API Key Management ====================

@auth_bp.route('/api-keys', methods=['GET'])
@login_required
def list_api_keys():
    """List API keys for the current user (admins see all)."""
    user = g.current_user
    if user and user.role == 'admin':
        keys = ApiKey.query.order_by(ApiKey.id.desc()).all()
    elif user:
        keys = ApiKey.query.filter_by(user_id=user.id).order_by(ApiKey.id.desc()).all()
    else:
        keys = []
    return jsonify([k.to_dict() for k in keys])


@auth_bp.route('/api-keys', methods=['POST'])
@login_required
def create_api_key():
    """Generate a new API key."""
    user = g.current_user
    if not user:
        return jsonify({'error': 'Auth required'}), 401

    data = request.get_json(force=True) if request.is_json else {}
    name = data.get('name', 'default')

    raw_key = generate_api_key(user.id, name=name)
    return jsonify({'key': raw_key, 'name': name, 'warning': 'Save this key — it cannot be retrieved again.'}), 201


@auth_bp.route('/api-keys/<int:kid>', methods=['DELETE'])
@login_required
def delete_api_key(kid):
    """Delete an API key."""
    user = g.current_user
    key = ApiKey.query.get_or_404(kid)
    if user and user.role != 'admin' and key.user_id != user.id:
        return jsonify({'error': 'Forbidden'}), 403
    db.session.delete(key)
    db.session.commit()
    return jsonify({'status': 'deleted', 'id': kid})


@auth_bp.route('/auth/change-password', methods=['POST'])
@login_required
def change_password():
    """Change own password."""
    user = g.current_user
    if not user:
        return jsonify({'error': 'Auth required'}), 401

    data = request.get_json(force=True)
    current = data.get('current_password', '')
    new_pass = data.get('new_password', '')

    if not user.check_password(current):
        return jsonify({'error': 'Current password is incorrect'}), 401
    if len(new_pass) < 8:
        return jsonify({'error': 'New password must be 8+ characters'}), 400

    user.set_password(new_pass)
    db.session.commit()
    return jsonify({'status': 'password_changed'})
