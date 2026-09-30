# Persistent agent channel (P5-A)

Artemis agent 1.5 adds an outbound Socket.IO WebSocket connection. HTTPS
inventory reporting continues independently. The connection carries presence,
terminal controls and output, signed work leases/results, and cancellation
state. Agents without the optional client continue using HTTPS.

## Deployment and upgrade

1. Stop web and worker processes before running `flask db upgrade`. Revision
   `c6d7e8f9a0b1` ends existing shell sessions, removes stored terminal chunks,
   adds source/close metadata, and enforces one active operator lease per agent.
2. Configure `AGENT_TRANSPORT_REDIS_URL` to a dedicated Redis with both RDB and
   AOF persistence disabled. Compose supplies `transport-redis` with a 128 MB
   limit, no eviction, no data volume, and no published port. The durable Celery
   broker remains a separate instance. Production requires this configuration.
3. Restart the application and rebuild the frontend. Set
   `AGENT_CHANNEL_ENABLED=false` to disable new WebSocket connections while
   retaining HTTPS transport. Restart processes after changing this flag.
4. Upgrade endpoints using `agent/install.sh --upgrade --server URL` on Linux
   or `agent/install-macos.sh --upgrade --server URL` on macOS. Both installers
   create an isolated virtual environment and install the hashed transport lock
   served at `/agent/requirements.lock`. Python 3.10 or later is required.
   Updating only the Python source retains HTTP fallback until the client is
   installed. Enrollment keys and existing configuration are preserved.

The Caddy overlay already forwards WebSocket upgrades. Use HTTPS in production;
certificate validation stays enabled. Keep a single Gunicorn worker per web
instance as configured in Compose. Multiple instances need sticky routing for
browser Socket.IO polling and the shared Redis message queue for room fan-out.
The agent forces WebSocket transport.

## Protocol and authorization

`POST /api/v1/agents/channel-token` exchanges `X-Agent-Key` for a five-minute
JWT restricted to the `/agent` namespace. It is sent in connection auth, never
in a URL. Agents renew credentials after four minutes and reconnect with jitter.
Disabling/deleting an agent or rotating its enrollment key invalidates cached
identity and presence after the database transaction commits.

Client frames include protocol version 1, agent ID, sequence, expiry, and a
credential-specific idempotency key. `shell` frames include a session ID; work
frames identify the signed work item. The controller accepts one ordered frame
at a time, returns an acknowledgement, and caches that response for retries.
Conflicting replays, gaps, expired credentials/envelopes, unknown channels,
foreign work/sessions, and frames above 128 KiB are rejected. Terminal input
has its own acknowledged sequence and resumes after reconnect. Work results
continue using the existing durable, idempotent job completion contract.

Shell launch, subscription, input, resize, and close require an authenticated
administrator who owns the session in the active organization. Terminal traffic
uses the browser's authenticated Socket.IO room. The UI identifies the agent's
process privilege, including possible root access. Typed work never uses the
terminal stream.

## Storage, limits, and fallback

PostgreSQL retains session actor, source, agent, start/end, duration, close
reason, exit status, and aggregate byte count. It never receives terminal bytes.
Counts are rolled up during agent heartbeats and closure; abrupt transport loss
can leave the final byte count incomplete.

Input/output use bounded Redis streams, capped at 256 chunks per direction.
Chunks are acknowledged rather than overwritten. Individual input is limited
to 16 KiB, output frames to 64 KiB, and session output to 1 MiB. Sessions have
a fifteen-minute absolute lease and a five-minute idle timeout. Queue expiry
is bounded by the absolute lease plus five minutes; closed output expires
within five minutes. An unavailable Redis fails closed. Loss of the volatile
transport state ends affected sessions rather than reusing sequence numbers.
Development/testing without Redis uses a bounded per-application memory store.

The HTTPS fallback keeps the existing endpoints and response shapes. New agents
request up to twenty seconds of server-held waiting when idle and retain input
acknowledgements across a fallback. Active HTTP sessions batch output; older
agents remain supported. Browser streaming also replays acknowledged Redis
output every two seconds to recover missed socket messages, using chunk IDs to
avoid rendering duplicates.

The agent inspector shows transport, round-trip time, reconnect count and queue
depth. Heartbeats expire after 45 seconds. A stale presence record displays the
HTTPS fallback rather than claiming a live WebSocket.

## Validation and rollback

Protocol tests cover credentials, roles, session ownership, replay conflicts,
input acknowledgement, stream backpressure, transport reset, expiry, and a
100-agent connection fixture. Real loopback validation used PostgreSQL 16,
Redis 7 with persistence disabled, and the Compose Gunicorn WebSocket worker:
100 simultaneous agent connections and a full-fleet reconnect passed; terminal
echo p95 was 148 ms across 30 samples. This measurement does not establish WAN
latency or macOS endpoint performance. Existing PTY and HTTPS round-trip tests
remain covered.

Fresh PostgreSQL migrations, upgrade with stored legacy chunks, downgrade, and
re-upgrade passed. Rollback recreates empty legacy chunk tables; discarded
transcripts are not restored. Stop all new web/worker processes before
rolling back the schema and application together. Existing agents can resume
HTTPS transport against the previous server.

The client uses the maintained
[python-socketio client](https://python-socketio.readthedocs.io/en/stable/client.html).
Its direct dependencies are pinned in the `agent-client` extra in
`pyproject.toml`; `scripts/lock-deps.sh` generates `agent/requirements.lock`.
