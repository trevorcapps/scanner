"""Credential model.

Secret material (SSH password / key passphrase, and the private key itself) is
stored only as a sealed envelope produced by :mod:`artemis.services.crypto_service`.
The plaintext columns and the filesystem ``key_path`` were removed in the P0.4
security baseline; ``key_path`` is retained only as an optional informational
label of where the key originally came from.
"""

from artemis.extensions import db
from artemis.services import crypto_service


class Credential(db.Model):
    __tablename__ = 'credentials'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, unique=True, nullable=False)
    cred_type = db.Column(db.Text, nullable=False)          # ssh_password | ssh_key
    username = db.Column(db.Text, nullable=False)
    # Optional human note of the key's origin (not used for auth).
    key_path = db.Column(db.Text)
    # Sealed envelopes ("enc:v1:..."). Never plaintext.
    secret_enc = db.Column(db.Text)                         # password or key passphrase
    private_key_enc = db.Column(db.Text)                    # PEM private key body
    key_kind = db.Column(db.Text)                           # rsa | ed25519 | ecdsa | auto
    created_at = db.Column(db.Text)
    updated_at = db.Column(db.Text)

    # ---- secret accessors -------------------------------------------------
    def set_secret(self, value):
        self.secret_enc = crypto_service.seal(value) if value else None

    def set_private_key(self, value):
        self.private_key_enc = crypto_service.seal(value) if value else None

    def reveal_secret(self):
        return crypto_service.open_envelope(self.secret_enc) if self.secret_enc else None

    def reveal_private_key(self):
        return crypto_service.open_envelope(self.private_key_enc) if self.private_key_enc else None

    @property
    def secret_set(self):
        return bool(self.secret_enc)

    @property
    def private_key_set(self):
        return bool(self.private_key_enc)

    def needs_reseal(self):
        return any(
            enc is not None and crypto_service.needs_reseal(enc)
            for enc in (self.secret_enc, self.private_key_enc)
        )

    def to_dict(self, **_ignored):
        """Serialize without any secret material."""
        return {
            'id': self.id,
            'name': self.name,
            'cred_type': self.cred_type,
            'username': self.username,
            'key_path': self.key_path or '',
            'key_kind': self.key_kind or '',
            'secret_set': self.secret_set,
            'private_key_set': self.private_key_set,
            'password_set': self.secret_set,   # backward-compatible alias
            'created_at': self.created_at,
            'updated_at': self.updated_at,
        }
