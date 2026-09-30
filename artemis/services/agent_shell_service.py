"""Volatile transport for browser-to-agent PTY sessions."""

import base64
import binascii
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone

from flask import has_request_context, request
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError

from artemis.extensions import db
from artemis.models.agent_shell import AgentShellSession
from artemis.services.agent_transport_store import TransportFull, store, stream_key

logger = logging.getLogger(__name__)

ACTIVE_STATES = ('requested', 'running', 'closing')
MAX_INPUT_BYTES = 16 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_SESSION_SECONDS = 15 * 60
IDLE_SECONDS = 5 * 60


class ShellSessionError(ValueError):
    pass


def _now():
    return datetime.now(timezone.utc)


def _iso(value=None):
    return (value or _now()).strftime('%Y-%m-%dT%H:%M:%SZ')


def _decode_chunk(data_b64, maximum):
    try:
        raw = base64.b64decode(data_b64, validate=True)
    except (binascii.Error, TypeError, ValueError) as exc:
        raise ShellSessionError('data must be valid base64') from exc
    if len(raw) > maximum:
        raise ShellSessionError(f'data exceeds {maximum} byte limit')
    return raw


def expire_sessions(now=None):
    """Move expired or idle sessions toward cooperative agent shutdown."""
    now = now or _now()
    now_iso = _iso(now)
    idle_cutoff = _iso(now - timedelta(seconds=IDLE_SECONDS))
    sessions = AgentShellSession.query.filter(
        AgentShellSession.status.in_(ACTIVE_STATES),
    ).filter(
        or_(
            AgentShellSession.expires_at <= now_iso,
            AgentShellSession.last_activity_at <= idle_cutoff,
        )
    ).all()
    for session in sessions:
        if session.expires_at <= now_iso:
            session.status = 'expired'
            session.closed_at = now_iso
            store().delete(stream_key(session, 'input'))
        else:
            session.status = 'closing'
        session.close_reason = 'timeout'
        session.error_message = session.error_message or 'Session expired'

    if sessions:
        db.session.commit()
        for session in sessions:
            _wake(session)
    return len(sessions)


def create_session(agent, user_id=None, cols=120, rows=32):
    expire_sessions()
    active = AgentShellSession.query.filter(
        AgentShellSession.agent_id == agent.id,
        AgentShellSession.status.in_(ACTIVE_STATES),
    ).first()
    if active:
        raise ShellSessionError('This agent already has an active shell session')
    if not agent.enabled or agent.status != 'active':
        raise ShellSessionError('The agent is not active')
    if 'remote_shell' not in agent.to_dict().get('capabilities', []):
        raise ShellSessionError('The agent does not advertise remote shell support')

    now = _now()
    session = AgentShellSession(
        agent_id=agent.id,
        user_id=user_id,
        status='requested',
        cols=max(20, min(int(cols), 300)),
        rows=max(5, min(int(rows), 100)),
        created_at=_iso(now),
        last_activity_at=_iso(now),
        expires_at=_iso(now + timedelta(seconds=MAX_SESSION_SECONDS)),
        source=request.remote_addr if has_request_context() else None,
    )
    db.session.add(session)
    try:
        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        raise ShellSessionError('This agent already has an active shell session') from exc
    store().set(stream_key(session, 'lease'), session.id)
    _cache_session(session)
    _wake(session)
    logger.warning('Remote shell %s requested for agent %s by user %s', session.id, agent.id, user_id)
    return session


def get_session(session_id, user_id=None):
    session = db.session.get(AgentShellSession, session_id)
    from artemis.services.tenant import current_org_id
    org_id = current_org_id(required=False)
    if (not session or (org_id is not None and session.organization_id != org_id)
            or (user_id is not None and session.user_id != user_id)):
        return None
    _check_transport(session)
    return session


def queue_input(session, data_b64):
    _check_transport(session)
    if session.status not in ('requested', 'running'):
        raise ShellSessionError(f'Session is {session.status}')
    raw = _decode_chunk(data_b64, MAX_INPUT_BYTES)
    if not raw:
        return None
    try:
        item = store().append(stream_key(session, 'input'), data_b64, ttl=_queue_ttl(session))
    except TransportFull as exc:
        raise ShellSessionError(str(exc)) from exc
    session.last_activity_at = _iso()
    db.session.commit()
    _wake(session)
    return item


def resize_session(session, cols, rows):
    if session.status not in ACTIVE_STATES:
        raise ShellSessionError(f'Session is {session.status}')
    session.cols = max(20, min(int(cols), 300))
    session.rows = max(5, min(int(rows), 100))
    session.last_activity_at = _iso()
    db.session.commit()
    _wake(session)
    return session


def request_close(session):
    if session.status in ('closed', 'failed', 'expired'):
        return session
    session.status = 'closing'
    session.close_reason = 'operator'
    session.last_activity_at = _iso()
    db.session.commit()
    _wake(session)
    logger.warning('Remote shell %s close requested', session.id)
    return session


def poll_agent(agent, after=None, input_session=None, input_limit=100):
    expire_sessions()
    session = AgentShellSession.query.filter(
        AgentShellSession.agent_id == agent.id,
        AgentShellSession.status.in_(ACTIVE_STATES),
    ).order_by(AgentShellSession.created_at.desc()).first()

    agent.last_checkin = _iso()
    agent.status = 'active'
    if not session:
        db.session.commit()
        return None

    if not _check_transport(session):
        return None
    if after is not None and input_session != session.id:
        after = 0
    inputs = store().read(stream_key(session, 'input'), after=max(0, int(after or 0)),
                          limit=input_limit, consume=after is None)
    payload = {
        'id': session.id,
        'status': session.status,
        'cols': session.cols,
        'rows': session.rows,
        'expires_at': session.expires_at,
        'inputs': inputs,
    }
    session.last_agent_poll_at = _iso()
    session.output_bytes = max(session.output_bytes, int(store().get(stream_key(session, 'bytes')) or 0))
    db.session.commit()
    _cache_session(session)
    return payload


def record_agent_event(agent, session_id, event, data_b64=None, exit_code=None, error=None, event_id=None, input_ack=None):
    if event == 'output':
        fast = _stream_output(agent, session_id, data_b64, event_id, input_ack)
        if fast is not None:
            return fast
    session = db.session.get(AgentShellSession, session_id)
    if not session or session.agent_id != agent.id or session.organization_id != agent.organization_id:
        raise ShellSessionError('Unknown shell session')

    if not _check_transport(session):
        raise ShellSessionError('Transient transport was reset; start a new session')
    event_key = f'shell-event:{session.organization_id}:{session.id}:{event_id}' if event_id else None
    if event_key and store().get(event_key):
        return session
    session.output_bytes = max(session.output_bytes, int(store().get(stream_key(session, 'bytes')) or 0))
    now = _iso()
    if event == 'started':
        if session.status == 'requested':
            session.status = 'running'
            session.started_at = now
    elif event == 'output':
        if session.status not in ('requested', 'running', 'closing'):
            raise ShellSessionError('Session is closed')
        raw = _decode_chunk(data_b64, 64 * 1024)
        if session.status == 'requested':
            session.status = 'running'
            session.started_at = now
        if session.output_bytes + len(raw) > MAX_OUTPUT_BYTES:
            session.status = 'closing'
            _wake(session)
            session.error_message = 'Output limit reached'
            session.close_reason = 'output_limit'
        elif raw:
            try:
                chunk = store().append(stream_key(session, 'output'), data_b64, ttl=_queue_ttl(session))
            except TransportFull as exc:
                raise ShellSessionError(str(exc)) from exc
            from artemis.extensions import socketio
            socketio.emit('shell_output', {'session_id': session.id, **chunk},
                          room=f'shell:{session.organization_id}:{session.id}')
            session.output_bytes += len(raw)
    elif event in ('exited', 'closed'):
        if session.status in ('closed', 'failed', 'expired'):
            return session
        session.status = 'closed'
        session.exit_code = int(exit_code) if exit_code is not None else None
        session.closed_at = now
        session.close_reason = session.close_reason or 'agent_exit'
        store().delete(stream_key(session, 'input'))
        store().expire(stream_key(session, 'output'), 300)
        logger.warning('Remote shell %s closed with exit code %s', session.id, session.exit_code)
    elif event == 'error':
        session.status = 'failed'
        # Agent errors may contain command content; retain only a fixed reason.
        session.error_message = 'Agent shell error'
        session.close_reason = 'agent_error'
        session.closed_at = now
        store().delete(stream_key(session, 'input'))
        store().expire(stream_key(session, 'output'), 300)
        logger.error('Remote shell %s failed: %s', session.id, session.error_message)
    else:
        raise ShellSessionError('Unknown shell event')

    pending_input = []
    if input_ack is not None and event == 'output':
        pending_input = store().read(stream_key(session, 'input'), after=max(0, int(input_ack)), limit=4)
    session.last_agent_poll_at = now
    if event in ('closed', 'exited', 'error'):
        from artemis.services import audit_service
        audit_service.record(
            audit_service.SHELL_CLOSE, target_type='shell_session', target_id=session.id,
            actor_user_id=session.user_id, actor_label='shell operator', actor_kind='user',
            organization_id=session.organization_id,
            detail={'agent_id': agent.id, 'reason': session.close_reason, 'exit_code': session.exit_code},
        )
    db.session.commit()
    _cache_session(session)
    if event_key:
        store().set(event_key, True)
    if pending_input:
        _wake(session)
    return session


def get_output(session, after=0, limit=200):
    if not _check_transport(session):
        return []
    return store().read(stream_key(session, 'output'), after=max(0, int(after)),
                        limit=max(1, min(int(limit), 500)))


def _wake(session, cache=True):
    if cache:
        _cache_session(session)
    from artemis.extensions import socketio
    socketio.emit('shell_command', {
        'v': 1, 'agent_id': session.agent_id, 'session_id': session.id,
        'seq': store().next_sequence(stream_key(session, 'control')),
        'expires': time.time() + 30, 'idempotency_key': str(uuid.uuid4()),
        'session': {'id': session.id, 'status': session.status, 'cols': session.cols,
                    'rows': session.rows, 'expires_at': session.expires_at,
                    'inputs': store().read(stream_key(session, 'input'), limit=4)},
    }, namespace='/agent', room=f'agent:{session.organization_id}:{session.agent_id}')


def _queue_ttl(session):
    expiry = datetime.fromisoformat(session.expires_at.replace('Z', '+00:00'))
    return max(1, min(1200, int((expiry - _now()).total_seconds()) + 300))


def _check_transport(session):
    if session.status in ACTIVE_STATES and session.expires_at <= _iso():
        session.status = 'expired'
        session.close_reason = 'timeout'
        session.closed_at = _iso()
        session.output_bytes = max(session.output_bytes, int(store().get(stream_key(session, 'bytes')) or 0))
        db.session.commit()
        _wake(session)
        return False
    if session.status in ACTIVE_STATES and store().get(stream_key(session, 'lease')) != session.id:
        session.status = 'failed'
        session.close_reason = 'transport_reset'
        session.error_message = 'Transient transport was reset; start a new session'
        session.closed_at = _iso()
        db.session.commit()
        return False
    return True


def _cache_session(session):
    values = {column.name: getattr(session, column.name) for column in AgentShellSession.__table__.columns}
    store().set(stream_key(session, 'metadata'), values, ttl=_queue_ttl(session))


def _stream_output(agent, session_id, data_b64, event_id, input_ack):
    """PTY output never needs an ORM write. Heartbeats/final events roll up counts."""
    key = f'org:{agent.organization_id}:shell:{session_id}'
    with store().serial(key):
        values = store().get(key + ':metadata')
        if not values:
            return None
        session = AgentShellSession(**values)
        if session.agent_id != agent.id or session.organization_id != agent.organization_id:
            raise ShellSessionError('Unknown shell session')
        if session.status == 'requested':
            return None  # persist the initial lifecycle transition
        if session.status not in ('running', 'closing'):
            raise ShellSessionError('Session is closed')
        if store().get(key + ':lease') != session.id:
            return None  # ordinary path marks transport reset in PostgreSQL
        event_key = f'shell-event:{session.organization_id}:{session.id}:{event_id}' if event_id else None
        if event_key and store().get(event_key):
            session.output_bytes = max(session.output_bytes, int(store().get(key + ':bytes') or 0))
            return session
        raw = _decode_chunk(data_b64, 64 * 1024)
        count = max(session.output_bytes, int(store().get(key + ':bytes') or 0))
        if count + len(raw) > MAX_OUTPUT_BYTES or session.expires_at <= _iso():
            return None  # persist close/expiry rather than silently dropping output
        if raw:
            try:
                chunk = store().append(key + ':output', data_b64, ttl=_queue_ttl(session))
            except TransportFull as exc:
                raise ShellSessionError(str(exc)) from exc
            count += len(raw)
            store().set(key + ':bytes', count, ttl=_queue_ttl(session))
            from artemis.extensions import socketio
            socketio.emit('shell_output', {'session_id': session.id, **chunk},
                          room=f'shell:{session.organization_id}:{session.id}')
        session.output_bytes = count
        if event_key:
            store().set(event_key, True)
        if input_ack is not None:
            pending = store().read(key + ':input', after=max(0, int(input_ack)), limit=4)
            if pending:
                latest = store().get(key + ':metadata') or values
                if latest['status'] in ACTIVE_STATES:
                    _wake(AgentShellSession(**latest), cache=False)
        return session
