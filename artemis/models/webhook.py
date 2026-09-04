"""Webhook + WebhookDelivery models."""

import json
import secrets

from artemis.extensions import db
from artemis.models._tenant import TenantMixin

# Events a webhook may subscribe to.
WEBHOOK_EVENTS = (
    'scan.completed',
    'vulnerability.discovered',
    'asset.discovered',
    'agent.registered',
    'agent.report.received',
    'site.scan.completed',
    'ping',
)


def generate_webhook_secret():
    return secrets.token_urlsafe(32)


class Webhook(TenantMixin, db.Model):
    __tablename__ = 'webhooks'

    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.Text, nullable=False)
    secret = db.Column(db.Text, nullable=False, default=generate_webhook_secret)
    events_json = db.Column(db.Text, nullable=False, default='[]')
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    description = db.Column(db.Text)
    created_at = db.Column(db.Text)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'))
    last_delivery_at = db.Column(db.Text)
    last_status = db.Column(db.Text)

    @property
    def events(self):
        try:
            return json.loads(self.events_json or '[]')
        except (TypeError, ValueError):
            return []

    @events.setter
    def events(self, value):
        self.events_json = json.dumps(list(value or []))

    def subscribed_to(self, event):
        ev = self.events
        return not ev or event in ev

    def to_dict(self, include_secret=False):
        d = {
            'id': self.id,
            'organization_id': self.organization_id,
            'url': self.url,
            'events': self.events,
            'enabled': bool(self.enabled),
            'description': self.description,
            'created_at': self.created_at,
            'created_by': self.created_by,
            'last_delivery_at': self.last_delivery_at,
            'last_status': self.last_status,
        }
        if include_secret:
            d['secret'] = self.secret
        return d


class WebhookDelivery(TenantMixin, db.Model):
    __tablename__ = 'webhook_deliveries'

    id = db.Column(db.Integer, primary_key=True)
    webhook_id = db.Column(db.Integer, db.ForeignKey('webhooks.id', ondelete='CASCADE'),
                           nullable=False, index=True)
    event = db.Column(db.Text, nullable=False)
    payload_json = db.Column(db.Text, nullable=False)
    status = db.Column(db.Text, nullable=False, default='pending')  # pending|success|failed
    response_code = db.Column(db.Integer)
    response_body = db.Column(db.Text)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.Text)
    delivered_at = db.Column(db.Text)
    next_retry_at = db.Column(db.Text)

    def to_dict(self):
        return {
            'id': self.id,
            'webhook_id': self.webhook_id,
            'event': self.event,
            'status': self.status,
            'response_code': self.response_code,
            'response_body': self.response_body,
            'attempts': self.attempts,
            'created_at': self.created_at,
            'delivered_at': self.delivered_at,
            'next_retry_at': self.next_retry_at,
        }
