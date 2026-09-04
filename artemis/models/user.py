"""User model — authentication and role-based access."""

import bcrypt
from artemis.extensions import db


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Text, unique=True, nullable=False)
    email = db.Column(db.Text, unique=True)
    password_hash = db.Column(db.Text, nullable=False)
    # Legacy default role. Ordinary authorization is per-organization via
    # OrganizationMembership; this is retained as the seed role for a user's
    # membership in the Default organization and as a fallback.
    role = db.Column(db.Text, default='analyst')  # admin, analyst, readonly
    # Cross-organization platform administrator (decision D1). Audited.
    platform_admin = db.Column(db.Integer, nullable=False, default=0)
    display_name = db.Column(db.Text)
    enabled = db.Column(db.Integer, default=1)
    created_at = db.Column(db.Text)
    last_login = db.Column(db.Text)

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(
            password.encode('utf-8'), bcrypt.gensalt()
        ).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(
            password.encode('utf-8'),
            self.password_hash.encode('utf-8')
        )

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'platform_admin': bool(self.platform_admin),
            'display_name': self.display_name,
            'enabled': self.enabled,
            'created_at': self.created_at,
            'last_login': self.last_login,
        }
