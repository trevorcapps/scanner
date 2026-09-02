"""Webhooks API blueprint."""

import logging
from datetime import datetime, timezone

from flask import Blueprint, request, jsonify, g

from artemis.extensions import db
from artemis.models.webhook import (
    Webhook, WebhookDelivery, WEBHOOK_EVENTS, generate_webhook_secret,
)
from artemis.services.auth_service import role_required
from artemis.services.webhook_service import send_test
from artemis.api._pagination import paginate

logger = logging.getLogger(__name__)

webhooks_bp = Blueprint('webhooks', __name__)


def _now_iso():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _validate_events(events):
    if not isinstance(events, list):
        return None, 'events must be a list'
    bad = [e for e in events if e not in WEBHOOK_EVENTS]
    if bad:
        return None, f'unknown events: {", ".join(bad)}'
    return events, None


@webhooks_bp.route('/webhooks', methods=['GET'])
def list_webhooks():
    """
    ---
    get:
      summary: List webhooks
      tags: [Webhooks]
      responses:
        200: {description: Webhooks (secrets omitted)}
      security: [{bearerAuth: []}]
    """
    hooks = Webhook.query.order_by(Webhook.id.desc()).all()
    return {'webhooks': [h.to_dict() for h in hooks], 'available_events': list(WEBHOOK_EVENTS)}


@webhooks_bp.route('/webhooks', methods=['POST'])
@role_required('admin')
def create_webhook():
    """
    ---
    post:
      summary: Create a webhook
      tags: [Webhooks]
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [url]
              properties:
                url: {type: string}
                events: {type: array, items: {type: string}}
                description: {type: string}
                enabled: {type: boolean}
      responses:
        201: {description: Created (secret returned once)}
        400: {description: Invalid payload}
      security: [{bearerAuth: []}]
    """
    data = request.get_json(silent=True) or {}
    url = (data.get('url') or '').strip()
    if not url.startswith(('http://', 'https://')):
        return {'error': 'url must be an http(s) URL'}, 400

    events, err = _validate_events(data.get('events', []))
    if err:
        return {'error': err}, 400

    user = getattr(g, 'current_user', None)
    hook = Webhook(
        url=url,
        secret=generate_webhook_secret(),
        enabled=bool(data.get('enabled', True)),
        description=(data.get('description') or '').strip() or None,
        created_at=_now_iso(),
        created_by=user.id if user else None,
    )
    hook.events = events
    db.session.add(hook)
    db.session.commit()
    return jsonify(hook.to_dict(include_secret=True)), 201


@webhooks_bp.route('/webhooks/<int:wid>', methods=['GET'])
def get_webhook(wid):
    """
    ---
    get:
      summary: Get one webhook
      tags: [Webhooks]
      parameters: [{in: path, name: wid, required: true, schema: {type: integer}}]
      responses:
        200: {description: The webhook}
        404: {description: Not found}
      security: [{bearerAuth: []}]
    """
    hook = db.session.get(Webhook, wid)
    if not hook:
        return {'error': 'Webhook not found'}, 404
    return {'webhook': hook.to_dict()}


@webhooks_bp.route('/webhooks/<int:wid>', methods=['PATCH'])
@role_required('admin')
def update_webhook(wid):
    """
    ---
    patch:
      summary: Update a webhook
      tags: [Webhooks]
      parameters: [{in: path, name: wid, required: true, schema: {type: integer}}]
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                url: {type: string}
                events: {type: array, items: {type: string}}
                description: {type: string}
                enabled: {type: boolean}
                rotate_secret: {type: boolean}
      responses:
        200: {description: Updated}
        404: {description: Not found}
      security: [{bearerAuth: []}]
    """
    hook = db.session.get(Webhook, wid)
    if not hook:
        return {'error': 'Webhook not found'}, 404

    data = request.get_json(silent=True) or {}
    if 'url' in data:
        if not str(data['url']).startswith(('http://', 'https://')):
            return {'error': 'url must be an http(s) URL'}, 400
        hook.url = data['url'].strip()
    if 'events' in data:
        events, err = _validate_events(data['events'])
        if err:
            return {'error': err}, 400
        hook.events = events
    if 'description' in data:
        hook.description = (data['description'] or '').strip() or None
    if 'enabled' in data:
        hook.enabled = bool(data['enabled'])
    rotated = None
    if data.get('rotate_secret'):
        hook.secret = generate_webhook_secret()
        rotated = hook.secret
    db.session.commit()
    out = hook.to_dict()
    if rotated:
        out['secret'] = rotated
    return {'webhook': out}


@webhooks_bp.route('/webhooks/<int:wid>', methods=['DELETE'])
@role_required('admin')
def delete_webhook(wid):
    """
    ---
    delete:
      summary: Delete a webhook and its delivery log
      tags: [Webhooks]
      parameters: [{in: path, name: wid, required: true, schema: {type: integer}}]
      responses:
        200: {description: Deleted}
        404: {description: Not found}
      security: [{bearerAuth: []}]
    """
    hook = db.session.get(Webhook, wid)
    if not hook:
        return {'error': 'Webhook not found'}, 404
    WebhookDelivery.query.filter_by(webhook_id=wid).delete()
    db.session.delete(hook)
    db.session.commit()
    return {'deleted': wid}


@webhooks_bp.route('/webhooks/<int:wid>/test', methods=['POST'])
@role_required('admin')
def test_webhook(wid):
    """
    ---
    post:
      summary: Send a synthetic `ping` event to this webhook
      tags: [Webhooks]
      parameters: [{in: path, name: wid, required: true, schema: {type: integer}}]
      responses:
        202: {description: Test delivery queued}
        404: {description: Not found}
      security: [{bearerAuth: []}]
    """
    hook = db.session.get(Webhook, wid)
    if not hook:
        return {'error': 'Webhook not found'}, 404
    return jsonify({'delivery_id': send_test(hook)}), 202


@webhooks_bp.route('/webhooks/<int:wid>/deliveries', methods=['GET'])
def webhook_deliveries(wid):
    """
    ---
    get:
      summary: Delivery log for a webhook (paginated, newest first)
      tags: [Webhooks]
      parameters:
        - {in: path, name: wid, required: true, schema: {type: integer}}
        - {in: query, name: page, schema: {type: integer}}
        - {in: query, name: per_page, schema: {type: integer}}
      responses:
        200: {description: Paginated WebhookDelivery rows}
        404: {description: Not found}
      security: [{bearerAuth: []}]
    """
    if not db.session.get(Webhook, wid):
        return {'error': 'Webhook not found'}, 404
    q = WebhookDelivery.query.filter_by(webhook_id=wid).order_by(WebhookDelivery.id.desc())
    return paginate(q, key='deliveries')
