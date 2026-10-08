# Backend Hardening — V11 Infrastructure Layer

> V11 establishes backend resilience and infrastructure boundaries.
> Authentication/RBAC, Redis-backed distributed messaging, production
> observability, and deployment hardening are intentionally deferred to
> later volumes.

```text
V02–V10 domain engines
        ↓
ApplicationRuntime (lifecycle) + ReadinessManager (traffic fitness)
        ↓
FastAPI (request IDs, error envelope, CORS, body limits)
        ↓
ManagedWorker supervision + WebSocketManager (lifecycle boundary)
```

## Application lifecycle

`backend/app/runtime/manager.py` (`ApplicationRuntime`):

```text
CREATED → INITIALIZING → READY → DRAINING → STOPPED
```

Invalid transitions raise `InvalidLifecycleTransition`. Startup runs the
15 ordered phases (configuration → … → workers → websocket → ready);
only the critical prefix (configuration/logging/database) can block READY —
everything else degrades honestly through health. Shutdown runs the 11
ordered phases (draining → stop work → stop streams/workers → flush →
close websockets → close database → stopped); it is idempotent and one
failing phase never blocks the rest.

Construction stays in `create_app` (the suite builds apps without a
lifespan context); the runtime wraps and records it, it never relocates it.

## Health and readiness

- `GET /live` — process alive (trivial, cheap).
- `GET /ready` — traffic fitness via `ReadinessManager`: application
  initialized, database reachable (session + `SELECT 1`), required workers
  running, not shutting down. `200 {ready:true}` or `503 {ready:false}`.
  Optional subsystems (`NOT_CONFIGURED`/`DISABLED`/`DEGRADED`) never fail it.
- `GET /health` and `GET /api/v1/health` — component diagnostics
  (`application`, `database`, `camera_manager`, `inference`, `tracking`,
  `safety`, `spatial`, `quality`, `autonomous`, `intelligence`, `incidents`,
  `websocket`, `workers`), each `READY/DEGRADED/NOT_READY/FAILED/DISABLED/
  UNKNOWN` with message, latency, timestamp, metadata. Lightweight only:
  no inference runs, no camera connections, no secrets, no credentials.

## Error envelope

```json
{
  "error": {
    "code": "invalid_transition",
    "message": "Incident cannot transition from CLOSED to ACKNOWLEDGED",
    "details": {},
    "request_id": "..."
  }
}
```

`details` is omitted when empty. The central registry
(`backend/app/core/exceptions.py:ERROR_CODES`) holds new UPPER_SNAKE codes
(`SERVICE_NOT_READY`, `DEPENDENCY_UNAVAILABLE`, …); V10 codes
(`invalid_transition`, `invalid_state`) are frozen byte-for-byte.
Business logic raises `DomainError` subclasses; the central handler maps
them (validation→422, not-found→404, conflict/invalid→409,
dependency/readiness→503, unexpected→500 without stack-trace leaks).

## Request IDs and logging

Inbound `X-Request-ID` is honored when sane (1–128 printable ASCII chars);
otherwise a fresh 12-hex ID is generated. Every response echoes it, error
bodies carry it, and it is available to logging via `RequestContext`
(request_id/timestamp/method/path — no identity; V16 owns that).
API errors log request_id/method/path/status/latency; worker errors log
worker/camera_id/component/error type. Secrets are never logged
(redacting formatter + no raw payloads).

## Worker supervision

`backend/app/workers/base.py`: `ManagedWorker`
(`CREATED→STARTING→RUNNING→STOPPING→STOPPED`, `RUNNING→FAILED`),
`WorkerSnapshot` (name/state/started_at/stopped_at/last_heartbeat/
restart_count/last_error), `WorkerSupervisor` registry with stale detection
(`WORKER_HEARTBEAT_TIMEOUT_SECONDS`, monotonic heartbeats, tz-aware
exposure), bounded retries only — no restart storms. A failed optional
worker marks its component DEGRADED; the platform stays operational.
Critical failures gate `/ready` through the required set.

## WebSocket architecture

`backend/app/websocket/manager.py` (`WebSocketManager`) surrounds the
existing `streams_ws` per-connection delta loop — it does not rewrite it.
The manager owns registration, metadata, heartbeat/idle tracking,
subscriptions (`camera_id`/`event_type`/`domain`; empty = today's full
compatible feed), bounded per-client queues (`WEBSOCKET_QUEUE_MAX_SIZE`),
priority classes (high: incident lifecycle/safety/risk_cluster — never
silently dropped; normal: tracking/detection; low: frame — droppable with
accounting), stale disconnects, malformed-message isolation, graceful
shutdown (bounded close with reason), and in-memory metrics
(`active_connections`, `connections_total`, `disconnects_total`,
`messages_sent/dropped/failed`, `queue_depth`, `slow_clients` — never PG).
All 22 V01–V10 wire types are unchanged.

## Configuration and CORS

`CORS_ALLOWED_ORIGINS` / `CORS_ALLOW_CREDENTIALS` are environment-driven.
Wildcard + credentials is rejected in **every** environment; production
rejects wildcard origins and requires ≥1 explicit origin; dev/test use
explicit localhost/test origins. Violations fail startup
(`ConfigurationError`), never degrade silently, and never surface via
`/ready`. Startup also fails fast on empty database URL, non-positive
timeouts, and out-of-range queue/body sizes. JSON bodies are capped at
`MAX_REQUEST_BODY_BYTES` (413 + envelope).

## Security baseline

No auth (deferred): bounded request IDs, bounded payload fields, validated
path/query params, no stack-trace leaks, safe CORS defaults, no debug mode
by default, no secret logging, no DB internals in responses.

## Pagination

V10 contract preserved byte-for-byte: `{incidents, total, page, page_size}`.
Other endpoints keep their established `{count, …}` / `{items}` shapes.
No `has_next` in V11; any future expansion is a versioned, compatible change.

## Testing

Hermetic as ever: `unit/test_runtime_lifecycle.py`,
`unit/test_health_models.py`, `unit/test_error_envelope.py`,
`unit/test_readiness.py`, `unit/test_worker_base.py`,
`unit/test_hardening_config.py`, `integration/test_request_id.py`,
`integration/test_ws_manager.py` — plus the Commit 02/03 suites for
endpoints, workers, sockets, and database lifecycle. V01–V10 suites are
never weakened to make V11 pass.

## Non-claims and limitations

- No Redis broker (abstractions ready for V12).
- No authentication/RBAC/OAuth/JWT (V16).
- No production rate limiting, K8s, Prometheus/Grafana deployment.
- No GPU deployment, notification providers, or new domain models.
