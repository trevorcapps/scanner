"""Write and query the durable :class:`AuditEvent` trail."""

import json
import logging

from flask import g, has_request_context, request

from artemis.extensions import db
from artemis.models.audit_event import AuditEvent

logger = logging.getLogger("artemis.audit")

# Canonical action names. Keep this list in sync with the acceptance criteria in
# docs/ROADMAP_IMPLEMENTATION_PLAN.md P0.4.
AUTH_LOGIN = "auth.login"
AUTH_LOGOUT = "auth.logout"
AUTH_FAILED = "auth.failed"
SECRET_READ = "secret.read"
SECRET_WRITE = "secret.write"
ROLE_CHANGE = "role.change"
USER_CREATE = "user.create"
SCAN_START = "scan.start"
SCAN_CANCEL = "scan.cancel"
SHELL_OPEN = "shell.open"
SHELL_CLOSE = "shell.close"
EXPORT = "data.export"
AGENT_KEY_ISSUE = "agent.key.issue"
SETTINGS_CHANGE = "settings.change"


def _actor():
    user = getattr(g, "current_user", None) if has_request_context() else None
    if user is not None:
        kind = getattr(g, "auth_method", "user")
        label = getattr(user, "username", None)
        if kind == "api_key":
            label = getattr(g, "api_key_name", None) or label
        return user.id, label, ("api_key" if kind == "api_key" else "user")
    if has_request_context():
        agent = getattr(g, "current_agent", None)
        if agent is not None:
            return None, getattr(agent, "name", None) or getattr(agent, "hostname", None), "agent"
    return None, "system", "system"


def record(action, *, outcome="success", target_type=None, target_id=None,
           detail=None, actor_user_id=None, actor_label=None, actor_kind=None,
           organization_id=None, commit=False):
    """Append one audit row. Best-effort: never raises into the caller."""
    try:
        if actor_user_id is None and actor_label is None:
            actor_user_id, actor_label, actor_kind = _actor()

        source_ip = None
        request_id = None
        if has_request_context():
            source_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
            if source_ip and "," in source_ip:
                source_ip = source_ip.split(",")[0].strip()
            request_id = getattr(g, "request_id", None)
            if organization_id is None:
                organization_id = getattr(g, "organization_id", None)

        event = AuditEvent(
            created_at=AuditEvent.utcnow_iso(),
            action=action,
            outcome=outcome,
            actor_user_id=actor_user_id,
            actor_label=actor_label,
            actor_kind=actor_kind,
            source_ip=source_ip,
            target_type=target_type,
            target_id=None if target_id is None else str(target_id),
            request_id=request_id,
            organization_id=organization_id,
            detail_json=json.dumps(detail, separators=(",", ":")) if detail else None,
        )
        db.session.add(event)
        db.session.flush()
        if commit:
            db.session.commit()

        logger.info(
            "audit %s outcome=%s target=%s/%s actor=%s",
            action, outcome, target_type, target_id, actor_label,
            extra={"audit": True, "audit_action": action, "audit_outcome": outcome},
        )
        return event
    except Exception:  # noqa: BLE001 - auditing must not break the request
        logger.exception("failed to write audit event %s", action)
        db.session.rollback()
        return None


def query(limit=100, action=None, actor_user_id=None, target_type=None,
          target_id=None, before=None):
    q = AuditEvent.query
    if action:
        q = q.filter(AuditEvent.action == action)
    if actor_user_id is not None:
        q = q.filter(AuditEvent.actor_user_id == actor_user_id)
    if target_type:
        q = q.filter(AuditEvent.target_type == target_type)
    if target_id is not None:
        q = q.filter(AuditEvent.target_id == str(target_id))
    if before:
        q = q.filter(AuditEvent.created_at < before)
    return q.order_by(AuditEvent.created_at.desc()).limit(min(limit, 1000)).all()


def prune(older_than_iso):
    """Delete rows older than an ISO timestamp. Returns the count removed."""
    removed = AuditEvent.query.filter(AuditEvent.created_at < older_than_iso).delete(
        synchronize_session=False
    )
    db.session.commit()
    return removed
