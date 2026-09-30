"""Versioned agent Socket.IO channel with short-lived enrollment credentials."""
import hashlib
import json
import time
import uuid
from types import SimpleNamespace

import jwt
from flask import current_app, g, request
from flask_socketio import join_room
from sqlalchemy import event, inspect

from artemis.extensions import db, socketio
from artemis.models.agent import Agent
from artemis.services.agent_transport_store import store

NAMESPACE = '/agent'
TOKEN_SECONDS = 300
MAX_FRAME_BYTES = 128 * 1024


def _fingerprint(agent):
    return hashlib.sha256(agent.agent_key.encode()).hexdigest()


def issue_token(agent):
    now = int(time.time())
    return jwt.encode({'sub': str(agent.id), 'org': agent.organization_id,
                       'key': _fingerprint(agent), 'aud': 'artemis-agent',
                       'iat': now, 'exp': now + TOKEN_SECONDS, 'jti': str(uuid.uuid4())},
                      current_app.config['SECRET_KEY'], algorithm='HS256')


def authenticate(token, allow_cached=False):
    payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'],
                         audience='artemis-agent', options={'require': ['sub', 'org', 'exp', 'jti', 'key']})
    cached = store().get(f"identity:{payload['org']}:{payload['sub']}") if allow_cached else None
    if cached and cached['key'] == payload['key']:
        g.organization_id = payload['org']
        from artemis.services.tenant import bind_rls_org
        bind_rls_org(payload['org'])
        return SimpleNamespace(id=int(payload['sub']), organization_id=payload['org']), payload
    agent = Agent.query.execution_options(skip_tenant_filter=True).filter_by(
        id=int(payload['sub']), organization_id=payload['org'], enabled=1).first()
    if not agent or _fingerprint(agent) != payload['key']:
        raise ValueError('Revoked agent identity')
    store().set(f'identity:{agent.organization_id}:{agent.id}', {'key': _fingerprint(agent)}, TOKEN_SECONDS)
    g.organization_id = agent.organization_id
    from artemis.services.tenant import bind_rls_org
    bind_rls_org(agent.organization_id)
    return agent, payload


def presence(agent):
    value = store().get(f'presence:{agent.organization_id}:{agent.id}') or {}
    return {'transport': value.get('transport', 'https'),
            'connected': value.get('transport') == 'websocket',
            'latency_ms': value.get('latency_ms'),
            'reconnect_count': value.get('reconnect_count', 0),
            'queue_depth': value.get('queue_depth', 0)}


def _session(allow_cached=False):
    saved = store().get('socket:' + request.sid)
    if not saved:
        raise ValueError('Expired connection')
    agent, claims = authenticate(saved['token'], allow_cached=allow_cached)
    current = store().get(f'connection:{agent.organization_id}:{agent.id}')
    if current != request.sid:
        raise ValueError('Connection superseded')
    return agent, claims


def register_agent_channel():
    @socketio.on('connect', namespace=NAMESPACE)
    def connect(auth=None):
        if not current_app.config.get('AGENT_CHANNEL_ENABLED', True):
            return False
        try:
            token = (auth or {}).get('token', '')
            agent, _claims = authenticate(token)
            store().set('socket:' + request.sid, {'token': token, 'agent_id': agent.id, 'org': agent.organization_id}, TOKEN_SECONDS)
            store().set(f'connection:{agent.organization_id}:{agent.id}', request.sid, TOKEN_SECONDS)
            join_room(f'agent:{agent.organization_id}:{agent.id}')
            return True
        except (jwt.PyJWTError, ValueError, TypeError):
            return False

    @socketio.on('frame', namespace=NAMESPACE)
    def frame(data):
        with store().serial('socket:' + request.sid):
            return process_frame(data)

    def process_frame(data):
        try:
            fast_output = (isinstance(data, dict) and data.get('kind') == 'shell'
                           and isinstance(data.get('payload'), dict)
                           and data['payload'].get('event') == 'output')
            agent, claims = _session(allow_cached=fast_output)
            if not isinstance(data, dict) or len(json.dumps(data).encode()) > MAX_FRAME_BYTES:
                raise ValueError('Frame too large')
            seq = data.get('seq')
            if (data.get('v') != 1 or data.get('agent_id') != agent.id
                    or not isinstance(seq, int) or isinstance(seq, bool) or seq < 1
                    or not isinstance(data.get('expires'), (int, float))
                    or not time.time() < data['expires'] <= time.time() + 60
                    or data.get('idempotency_key') != f"{claims['jti']}:{seq}"):
                raise ValueError('Invalid or expired envelope')
            key = f"ack:{claims['jti']}"
            previous = store().get(key) or {'seq': 0}
            digest = hashlib.sha256(json.dumps(data, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            if seq == previous['seq']:
                if digest != previous.get('digest'):
                    raise ValueError('Conflicting replay')
                return previous['response']
            if seq != previous['seq'] + 1:
                raise ValueError('Sequence gap or replay')
            from artemis.services.rate_limit_service import check
            if not check('agent_channel', identifier=f'agent:{agent.id}')[0]:
                return {'error': 'Backpressure: rate limit'}
            kind = data.get('kind')
            payload = data.get('payload') or {}
            if not isinstance(payload, dict):
                raise TypeError('Invalid payload')
            from artemis.services import agent_shell_service as shell
            from artemis.services.automation import agent_local
            if kind == 'presence':
                store().set(f'presence:{agent.organization_id}:{agent.id}', {
                    'transport': 'websocket',
                    'latency_ms': max(0, min(float(payload.get('latency_ms', 0)), 60000)),
                    'reconnect_count': max(0, min(int(payload.get('reconnect_count', 0)), 1000000)),
                    'queue_depth': max(0, min(int(payload.get('queue_depth', 0)), 256)),
                }, 45)
                response = {'session': shell.poll_agent(agent, after=payload.get('input_ack', 0),
                                                       input_session=payload.get('input_session'), input_limit=4)}
            elif kind == 'shell':
                session = shell.record_agent_event(
                    agent, data.get('session_id'), payload.get('event'),
                    data_b64=payload.get('data'), exit_code=payload.get('exit_code'),
                    event_id=payload.get('event_id'), input_ack=payload.get('input_ack'))
                response = {'session': session.to_dict()}
            elif kind == 'work_lease':
                response = {'work': agent_local.poll_work(agent)}
            elif kind == 'work_result':
                work = agent_local.record_result(agent, data.get('job_id'), payload)
                if not work:
                    raise ValueError('Unknown work')
                response = {'work': work.to_dict()}
            elif kind == 'work_state':
                work = agent_local.get_work(agent, data.get('job_id'))
                if not work:
                    raise ValueError('Unknown work')
                response = {'status': work.status}
            else:
                raise ValueError('Unknown channel')
            response.update({'ack': seq, 'v': 1})
            store().set(key, {'seq': seq, 'response': response, 'digest': digest}, TOKEN_SECONDS)
            return response
        except (jwt.PyJWTError, ValueError, TypeError, OverflowError):
            db.session.rollback()
            return {'error': 'Invalid agent frame'}

    @socketio.on('disconnect', namespace=NAMESPACE)
    def disconnect(reason=None):
        saved = store().get('socket:' + request.sid)
        if saved:
            key = f"connection:{saved['org']}:{saved['agent_id']}"
            if store().get(key) == request.sid:
                store().delete(f"presence:{saved['org']}:{saved['agent_id']}")
                store().delete(key)
        store().delete('socket:' + request.sid)

    def operator_command(data, kind):
        from artemis.services import agent_shell_service as shell
        from artemis.services.auth_service import _get_current_user
        from artemis.socketio_handlers import _require_socket_role
        _clear_operator_context()
        if not isinstance(data, dict) or not _require_socket_role('admin'):
            return {'error': 'Forbidden'}
        user = _get_current_user()
        session = shell.get_session(data.get('session_id'), user_id=user.id) if user else None
        if not session:
            return {'error': 'Unknown session'}
        from artemis.services.rate_limit_service import check
        if not check('agent_channel', identifier=f'operator:{user.id}')[0]:
            return {'error': 'Rate limit reached'}
        try:
            if kind == 'input':
                shell.queue_input(session, data.get('data'))
            else:
                shell.resize_session(session, data.get('cols'), data.get('rows'))
            return {'accepted': True}
        except (ValueError, TypeError):
            return {'error': 'Invalid shell command or transport queue full'}

    @socketio.on('shell_input')
    def shell_input(data):
        return operator_command(data, 'input')

    @socketio.on('shell_resize')
    def shell_resize(data):
        return operator_command(data, 'resize')

    @socketio.on('subscribe_shell')
    def subscribe_shell(data):
        from artemis.services.agent_shell_service import get_session
        from artemis.services.auth_service import _get_current_user
        from artemis.socketio_handlers import _require_socket_role
        # Interactive access always requires an authenticated operator, including setup mode.
        _clear_operator_context()
        if not _require_socket_role('admin'):
            return {'error': 'Forbidden'}
        user = _get_current_user()
        session = get_session((data or {}).get('session_id'), user_id=user.id) if user else None
        if not session:
            return {'error': 'Unknown session'}
        join_room(f'shell:{session.organization_id}:{session.id}')
        return {'session': session.to_dict()}

    @socketio.on('unsubscribe_shell')
    def unsubscribe_shell(data):
        from flask_socketio import leave_room

        from artemis.services.agent_shell_service import get_session
        from artemis.services.auth_service import _get_current_user
        from artemis.socketio_handlers import _require_socket_role
        _clear_operator_context()
        if not _require_socket_role('admin'):
            return
        user = _get_current_user()
        session = get_session((data or {}).get('session_id'), user_id=user.id) if user else None
        if session:
            leave_room(f'shell:{session.organization_id}:{session.id}')


def _clear_operator_context():
    # Re-resolve the actor and membership for each interactive socket action.
    # Never reuse an HTTP actor or an agent event's tenant from the app context.
    for name in ('current_user', 'organization_id', 'org_role', 'is_platform_admin',
                 'api_key_role', 'api_key_organization_id', 'auth_method'):
        g.pop(name, None)


@event.listens_for(db.session, 'before_flush')
def _track_agent_revocations(session, _context, _instances):
    changed = session.info.setdefault('agent_channel_revocations', set())
    for agent in list(session.dirty) + list(session.deleted):
        if not isinstance(agent, Agent):
            continue
        state = inspect(agent)
        if agent in session.deleted or any(state.attrs[name].history.has_changes()
                                          for name in ('agent_key', 'enabled', 'organization_id')):
            changed.add((agent.organization_id, agent.id))
            old_orgs = state.attrs.organization_id.history.deleted
            for org_id in old_orgs:
                changed.add((org_id, agent.id))


@event.listens_for(db.session, 'after_commit')
def _revoke_agent_cache(session):
    for org_id, agent_id in session.info.pop('agent_channel_revocations', set()):
        store().delete(f'identity:{org_id}:{agent_id}')
        store().delete(f'connection:{org_id}:{agent_id}')
        store().delete(f'presence:{org_id}:{agent_id}')


@event.listens_for(db.session, 'after_rollback')
def _discard_pending_revocations(session):
    session.info.pop('agent_channel_revocations', None)
