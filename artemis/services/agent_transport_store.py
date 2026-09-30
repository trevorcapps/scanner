"""Bounded, volatile transport storage. Redis failure fails closed.

Production uses a separate Redis instance with persistence disabled. The memory
implementation is restricted to development/testing and is owned by one app.
"""
import json
import threading
import time
from contextlib import contextmanager

from flask import current_app

TTL = 1200  # fifteen-minute shell lease plus five minutes
MAX_CHUNKS = 256


class TransportFull(ValueError):
    pass


class MemoryStore:
    def __init__(self):
        self.values = {}
        self.lock = threading.RLock()

    @contextmanager
    def serial(self, key):
        with self.lock:
            yield

    def get(self, key):
        with self.lock:
            value, expiry = self.values.get(key, (None, 0))
            return value if expiry > time.time() else None

    def set(self, key, value, ttl=TTL):
        with self.lock:
            now = time.time()
            if len(self.values) >= 4096:
                self.values = {k: v for k, v in self.values.items() if v[1] > now}
                if len(self.values) >= 4096 and key not in self.values:
                    raise TransportFull('Transport capacity reached')
            self.values[key] = (value, now + ttl)

    def delete(self, key):
        with self.lock:
            self.values.pop(key, None)

    def next_sequence(self, key):
        with self.lock:
            value = (self.get(key) or 0) + 1
            self.set(key, value)
            return value

    def expire(self, key, ttl):
        with self.lock:
            value = self.get(key)
            if value is not None:
                self.set(key, value, ttl)

    def append(self, key, data, ttl=TTL):
        with self.lock:
            stream = self.get(key) or {'sequence': 0, 'rows': []}
            if len(stream['rows']) >= MAX_CHUNKS:
                raise TransportFull('Transport queue full; wait for acknowledgement')
            stream['sequence'] += 1
            row = {'id': stream['sequence'], 'data': data}
            stream['rows'].append(row)
            self.set(key, stream, ttl)
            return row

    def read(self, key, after=0, limit=200, consume=False):
        with self.lock:
            stream = self.get(key)
            if not stream:
                return []
            rows = [r for r in stream['rows'] if r['id'] > after][:limit]
            if consume:
                stream['rows'] = stream['rows'][len(rows):]
            else:
                stream['rows'] = [r for r in stream['rows'] if r['id'] > after]
            return rows


class RedisStore:
    def __init__(self, url):
        import redis
        self.client = redis.Redis.from_url(url, decode_responses=True,
                                           socket_connect_timeout=2, socket_timeout=3)

    @contextmanager
    def serial(self, key):
        with self.client.lock('artemis:transport:lock:' + key, timeout=10, blocking_timeout=1):
            yield

    def get(self, key):
        value = self.client.get('artemis:transport:' + key)
        return json.loads(value) if value else None

    def set(self, key, value, ttl=TTL):
        self.client.set('artemis:transport:' + key, json.dumps(value), ex=ttl)

    def delete(self, key):
        self.client.delete('artemis:transport:' + key)

    def next_sequence(self, key):
        base = 'artemis:transport:' + key
        with self.client.pipeline() as pipe:
            pipe.incr(base)
            pipe.expire(base, TTL)
            return int(pipe.execute()[0])

    def expire(self, key, ttl):
        self.client.expire('artemis:transport:' + key, ttl)

    def append(self, key, data, ttl=TTL):
        # Atomic capacity check + monotonic sequence + bounded stream append.
        script = '''
        if redis.call('XLEN', KEYS[1]) >= tonumber(ARGV[3]) then return -1 end
        local seq = redis.call('INCR', KEYS[2])
        redis.call('XADD', KEYS[1], seq .. '-0', 'data', ARGV[1])
        redis.call('EXPIRE', KEYS[1], ARGV[2])
        redis.call('EXPIRE', KEYS[2], ARGV[2])
        return seq
        '''
        base = 'artemis:transport:' + key
        seq = self.client.eval(script, 2, base, base + ':seq', data, ttl, MAX_CHUNKS)
        if seq == -1:
            raise TransportFull('Transport queue full; wait for acknowledgement')
        return {'id': int(seq), 'data': data}

    def read(self, key, after=0, limit=200, consume=False):
        base = 'artemis:transport:' + key
        # Acknowledgement and read are one operation to preserve ordered delivery.
        script = '''
        if tonumber(ARGV[1]) > 0 then
            local old = redis.call('XRANGE', KEYS[1], '-', ARGV[1] .. '-0')
            for _, row in ipairs(old) do redis.call('XDEL', KEYS[1], row[1]) end
        end
        local rows = redis.call('XRANGE', KEYS[1], '(' .. ARGV[1] .. '-0', '+', 'COUNT', ARGV[2])
        if ARGV[3] == '1' then
            for _, row in ipairs(rows) do redis.call('XDEL', KEYS[1], row[1]) end
        end
        return rows
        '''
        rows = self.client.eval(script, 1, base, after, limit, '1' if consume else '0')
        return [{'id': int(seq.split('-')[0]), 'data': fields[1]} for seq, fields in rows]


def store():
    app = current_app._get_current_object()
    if 'agent_transport_store' not in app.extensions:
        url = app.config.get('AGENT_TRANSPORT_REDIS_URL')
        if url:
            backend = RedisStore(url)
        elif app.config.get('TESTING') or app.debug or app.config['CELERY_TASK_ALWAYS_EAGER']:
            backend = MemoryStore()
        else:
            raise RuntimeError('AGENT_TRANSPORT_REDIS_URL is required for volatile agent traffic')
        app.extensions['agent_transport_store'] = backend
    return app.extensions['agent_transport_store']


def stream_key(session, direction):
    return f'org:{session.organization_id}:shell:{session.id}:{direction}'
