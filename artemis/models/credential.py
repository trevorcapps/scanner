"""Credential model."""

from artemis.extensions import db


class Credential(db.Model):
    __tablename__ = 'credentials'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, unique=True, nullable=False)
    cred_type = db.Column(db.Text, nullable=False)
    username = db.Column(db.Text, nullable=False)
    key_path = db.Column(db.Text)
    password = db.Column(db.Text)
    created_at = db.Column(db.Text)
    updated_at = db.Column(db.Text)

    def to_dict(self, mask_password=False):
        return {
            'id': self.id,
            'name': self.name,
            'cred_type': self.cred_type,
            'username': self.username,
            'key_path': self.key_path or '',
            'password': '' if mask_password else (self.password or ''),
            'password_set': bool(self.password) if mask_password else None,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
        }
