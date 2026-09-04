"""Outbound webhook dispatch.

``emit(event, payload)`` is fire-and-forget: it records a WebhookDelivery per
subscribed webhook and hands each off to the ``deliver_webhook`` Celery task
(delivering inline when Celery runs eager). It never raises into the caller.
"""

import json
import logging
import uuid
from datetime import datetime, timezone

from artemis.extensions import db
from artemis.models.webhook import Webhook, WebhookDelivery

logger = logging.getLogger(__name__)


def _now_iso():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def emit(event, payload):
    """Queue ``event`` for every enabled webhook subscribed to it.

    Each delivery carries a stable ``event_id`` so receivers can deduplicate and
    request replay.
    """
    try:
        hooks = Webhook.query.filter_by(enabled=True).all()
    except Exception as e:
        logger.warning(f"webhook emit({event}) skipped — no webhook table? {e}")
        return

    targets = [h for h in hooks if h.subscribed_to(event)]
    if not targets:
        return

    delivery_ids = []
    try:
        for hook in targets:
            event_id = f'evt_{uuid.uuid4().hex}'
            body = json.dumps({
                'id': event_id, 'event': event, 'delivered_at': _now_iso(),
                'data': payload,
            }, default=str)
            d = WebhookDelivery(webhook_id=hook.id, event=event,
                                payload_json=body, status='pending',
                                created_at=_now_iso())
            db.session.add(d)
            db.session.flush()
            delivery_ids.append(d.id)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.warning(f"webhook emit({event}) could not persist deliveries: {e}")
        return

    from artemis.tasks.webhook_tasks import deliver_webhook
    for did in delivery_ids:
        try:
            deliver_webhook.delay(did)
        except Exception as e:
            logger.warning(f"webhook delivery {did} not queued ({e}); delivering inline")
            try:
                deliver_webhook.run(did)
            except Exception:
                logger.exception(f"inline webhook delivery {did} failed")


def send_test(webhook):
    """Emit a synthetic ``ping`` to a single webhook. Returns the delivery id."""
    body = json.dumps({'event': 'ping', 'delivered_at': _now_iso(),
                       'data': {'webhook_id': webhook.id, 'message': 'Artemis test event'}})
    d = WebhookDelivery(webhook_id=webhook.id, event='ping', payload_json=body,
                        status='pending', created_at=_now_iso())
    db.session.add(d)
    db.session.commit()

    from artemis.tasks.webhook_tasks import deliver_webhook
    try:
        deliver_webhook.delay(d.id)
    except Exception:
        deliver_webhook.run(d.id)
    return d.id
