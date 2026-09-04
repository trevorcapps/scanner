"""Database-backed transport for browser-to-agent PTY sessions."""

import base64
import binascii
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import or_

from artemis.extensions import db
from artemis.models.agent_shell import AgentShellInput, AgentShellOutput, AgentShellSession


logger = logging.getLogger(__name__)

ACTIVE_STATES = ('requested', 'running', 'closing')
MAX_INPUT_BYTES = 16 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_SESSION_SECONDS = 15 * 60
IDLE_SECONDS = 5 * 60
OUTPUT_RETENTION_SECONDS = 24 * 60 * 60


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
        AgentShellSession.status.in_(('requested', 'running')),
    ).filter(
        or_(
            AgentShellSession.expires_at <= now_iso,
            AgentShellSession.last_activity_at <= idle_cutoff,
        )
    ).all()
    for session in sessions:
        session.status = 'closing'
        session.error_message = session.error_message or 'Session expired'

    retention_cutoff = _iso(now - timedelta(seconds=OUTPUT_RETENTION_SECONDS))
    retained_ids = [row[0] for row in db.session.query(AgentShellSession.id).filter(
        AgentShellSession.closed_at.is_not(None),
        AgentShellSession.closed_at <= retention_cutoff,
    ).all()]
    if retained_ids:
        AgentShellOutput.query.filter(AgentShellOutput.session_id.in_(retained_ids)).delete(
            synchronize_session=False,
        )
    if sessions:
        db.session.commit()
    elif retained_ids:
        db.session.commit()
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
    )
    db.session.add(session)
    db.session.commit()
    logger.warning('Remote shell %s requested for agent %s by user %s', session.id, agent.id, user_id)
    return session


def get_session(session_id, user_id=None):
    session = db.session.get(AgentShellSession, session_id)
    if not session or (user_id is not None and session.user_id != user_id):
        return None
    return session


def queue_input(session, data_b64):
    if session.status not in ('requested', 'running'):
        raise ShellSessionError(f'Session is {session.status}')
    raw = _decode_chunk(data_b64, MAX_INPUT_BYTES)
    if not raw:
        return None
    item = AgentShellInput(session_id=session.id, data_b64=data_b64, created_at=_iso())
    session.last_activity_at = _iso()
    db.session.add(item)
    db.session.commit()
    return item


def resize_session(session, cols, rows):
    if session.status not in ACTIVE_STATES:
        raise ShellSessionError(f'Session is {session.status}')
    session.cols = max(20, min(int(cols), 300))
    session.rows = max(5, min(int(rows), 100))
    session.last_activity_at = _iso()
    db.session.commit()
    return session


def request_close(session):
    if session.status in ('closed', 'failed', 'expired'):
        return session
    session.status = 'closing'
    session.last_activity_at = _iso()
    db.session.commit()
    logger.warning('Remote shell %s close requested', session.id)
    return session


def poll_agent(agent):
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

    inputs = AgentShellInput.query.filter_by(session_id=session.id).order_by(AgentShellInput.id).limit(100).all()
    payload = {
        'id': session.id,
        'status': session.status,
        'cols': session.cols,
        'rows': session.rows,
        'inputs': [item.to_dict() for item in inputs],
    }
    for item in inputs:
        db.session.delete(item)
    session.last_agent_poll_at = _iso()
    db.session.commit()
    return payload


def record_agent_event(agent, session_id, event, data_b64=None, exit_code=None, error=None):
    session = db.session.get(AgentShellSession, session_id)
    if not session or session.agent_id != agent.id:
        raise ShellSessionError('Unknown shell session')

    now = _iso()
    if event == 'started':
        if session.status == 'requested':
            session.status = 'running'
            session.started_at = now
    elif event == 'output':
        raw = _decode_chunk(data_b64, 64 * 1024)
        if session.status == 'requested':
            session.status = 'running'
            session.started_at = now
        if session.output_bytes + len(raw) > MAX_OUTPUT_BYTES:
            session.status = 'closing'
            session.error_message = 'Output limit reached'
        elif raw:
            db.session.add(AgentShellOutput(session_id=session.id, data_b64=data_b64, created_at=now))
            session.output_bytes += len(raw)
    elif event in ('exited', 'closed'):
        session.status = 'closed'
        session.exit_code = int(exit_code) if exit_code is not None else None
        session.closed_at = now
        logger.warning('Remote shell %s closed with exit code %s', session.id, session.exit_code)
    elif event == 'error':
        session.status = 'failed'
        session.error_message = str(error or 'Agent shell error')[:500]
        session.closed_at = now
        logger.error('Remote shell %s failed: %s', session.id, session.error_message)
    else:
        raise ShellSessionError('Unknown shell event')

    session.last_agent_poll_at = now
    db.session.commit()
    return session


def get_output(session, after=0, limit=200):
    rows = AgentShellOutput.query.filter(
        AgentShellOutput.session_id == session.id,
        AgentShellOutput.id > max(0, int(after)),
    ).order_by(AgentShellOutput.id).limit(max(1, min(int(limit), 500))).all()
    return [row.to_dict() for row in rows]
