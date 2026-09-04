"""Celery task that delivers a single WebhookDelivery with HMAC signing + retry."""

import hmac
import json
import logging
import hashlib
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta

from celery import shared_task

from artemis.extensions import db
from artemis.models.webhook import Webhook, WebhookDelivery

logger = logging.getLogger(__name__)

_TIMEOUT = 10
_MAX_ATTEMPTS = 5
_RESP_CAP = 2048


def _now():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')


def _sign(secret, body):
    return 'sha256=' + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


@shared_task(bind=True, name='artemis.deliver_webhook', max_retries=_MAX_ATTEMPTS,
             acks_late=True)
def deliver_webhook(self, delivery_id):
    delivery = db.session.get(WebhookDelivery, delivery_id)
    if not delivery or delivery.status == 'success':
        return
    hook = db.session.get(Webhook, delivery.webhook_id)
    if not hook:
        delivery.status = 'failed'
        delivery.response_body = 'webhook deleted'
        db.session.commit()
        return

    body = delivery.payload_json.encode()
    try:
        event_id = json.loads(delivery.payload_json).get('id', '')
    except (TypeError, ValueError):
        event_id = ''
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'Artemis-Webhook/1.0',
        'X-Artemis-Event': delivery.event,
        'X-Artemis-Event-Id': event_id,
        'X-Artemis-Delivery': str(delivery.id),
        'X-Artemis-Signature': _sign(hook.secret, body),
    }

    delivery.attempts = (delivery.attempts or 0) + 1
    delivery.next_retry_at = None
    code = None
    resp_text = ''
    try:
        req = urllib.request.Request(hook.url, data=body, headers=headers, method='POST')
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            code = resp.status
            resp_text = resp.read(_RESP_CAP).decode('utf-8', 'replace')
        success = 200 <= code < 300
    except urllib.error.HTTPError as e:
        code = e.code
        resp_text = (e.read(_RESP_CAP).decode('utf-8', 'replace') if e.fp else '')
        success = False
    except Exception as e:
        resp_text = f'{type(e).__name__}: {e}'
        success = False

    delivery.response_code = code
    delivery.response_body = resp_text[:_RESP_CAP]
    hook.last_delivery_at = _iso(_now())

    if success:
        delivery.status = 'success'
        delivery.delivered_at = _iso(_now())
        hook.last_status = f'{code}'
        db.session.commit()
        return

    if delivery.attempts < _MAX_ATTEMPTS:
        countdown = 30 * (2 ** (delivery.attempts - 1))
        delivery.status = 'pending'
        delivery.next_retry_at = _iso(_now() + timedelta(seconds=countdown))
        hook.last_status = f'retry ({code or "err"})'
        db.session.commit()
        raise self.retry(countdown=countdown)

    delivery.status = 'failed'
    delivery.delivered_at = _iso(_now())
    hook.last_status = f'failed ({code or "err"})'
    db.session.commit()
    logger.warning(f"webhook {hook.id} delivery {delivery.id} failed after {delivery.attempts} attempts")
