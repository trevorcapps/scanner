"""Settings key-value model."""

from artemis.extensions import db


class Setting(db.Model):
    __tablename__ = 'settings'

    key = db.Column(db.Text, primary_key=True)
    value = db.Column(db.Text)
