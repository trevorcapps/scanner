"""API Key model — for automation and integration auth."""

from artemis.extensions import db


class ApiKey(db.Model):
    __tablename__ = 'api_keys'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    key_hash = db.Column(db.Text, nullable=False)
    key_prefix = db.Column(db.Text)  # First 8 chars for identification
    name = db.Column(db.Text)
    role = db.Column(db.Text, default='analyst')
    enabled = db.Column(db.Integer, default=1)
    created_at = db.Column(db.Text)
    last_used = db.Column(db.Text)
    expires_at = db.Column(db.Text)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'key_prefix': self.key_prefix,
            'name': self.name,
            'role': self.role,
            'enabled': self.enabled,
            'created_at': self.created_at,
            'last_used': self.last_used,
            'expires_at': self.expires_at,
        }
