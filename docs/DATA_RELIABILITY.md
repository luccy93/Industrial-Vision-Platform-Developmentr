# Data Reliability — V12 PostgreSQL + Redis Integration

> V11 established backend resilience and infrastructure boundaries.
> Authentication/RBAC, production observability, and deployment hardening
> remain intentionally deferred to later volumes.

```text
V05–V08 domain engines → genuine events
V09 intelligence      → normalized unified events + clusters (memory)
V10 incidents         → lifecycle (PostgreSQL, authoritative)
        ↓                        ↓
operational_events (PG history)  event_outbox (PG intents, same txn)
        ↓                        ↓ publisher (drain → local fan-out / Redis)
EventBus ── local fan-out ──► subscribers (metrics, WS remote ingest)
         └─ Redis Pub/Sub ──► remote subscribers (distributed only)
```

## PostgreSQL architecture

One centrally managed sync engine per database URL (`backend/app/
infrastructure/db.py`, psycopg2 driver — the stack is synchronous by
design). Server databases use explicit pool settings (`DB_POOL_SIZE=5`,
`DB_MAX_OVERFLOW=10`, `DB_POOL_TIMEOUT_SECONDS=30`,
`DB_POOL_RECYCLE_SECONDS=1800`, `DB_CONNECT_TIMEOUT_SECONDS=10`,
`pool_pre_ping` health checks); the SQLite dev/test path is unchanged.
`get_db` yields request-scoped sessions (commit on success, rollback on
error, always close). Background workers and repositories own independent
short-lived sessions — request sessions are never shared. Engine dispose
runs in the `close_database` shutdown phase.

## What is persisted (and what is not)

Persisted — meaningful operational records only:

- Cameras, zones, quality/autonomous profiles, defect catalog (V01–V08).
- Incidents + timeline + evidence metadata + assignments + counters (V10).
- **V12**: `operational_events` — one row per canonical V09 unified event
  identity that gains operational significance (incident linkage):
  event/camera/domain/type/severity/risk/status, event + persistence
  timestamps, bounded JSON metadata. Idempotent upsert on both the
  primary key and the `(camera, domain, source event)` unique key.
- **V12**: `event_outbox` — delivery intents (uuid PK, UNIQUE event id,
  kind, envelope JSON, pending/sent/failed, attempts, next-retry).

Never persisted by default: video frames, detections, track updates,
telemetry samples, worker heartbeats, raw payloads.

## Transaction boundaries

- Every repository method owns one short-lived session; mutating methods
  commit explicitly, failures roll back, sessions always close.
- Multi-record changes are atomic where required: incident lifecycle
  moves (`transition_with_timeline`), incident creation + numbering,
  assignment insert + parent update, profile + regions + associations,
  event row + outbox intent (`record_event_with_outbox`).
- Incident `_create_from_cluster` / `_update_from_cluster` span sessions
  by design (create → timeline → links → refresh); each step commits
  independently and the whole flow is idempotent, so a crash resumes
  safely on the next sync instead of rolling back minutes of work.
- No nested transactions without demonstrated need. Retries are explicit
  and bounded (`next_incident_number` retries transient
  Integrity/Operational errors only); integrity violations and programming
  errors are never hidden behind broad retries.
- Blocking sync DB calls stay off latency-critical paths: no per-frame,
  per-detection, or per-WebSocket-message engines/sessions. (The WS loop
  performs indexed primary-key reads only — a documented, bounded
  exception, not a pattern to extend.)

## Migration workflow

Linear Alembic chain `001 → 006` (`006_create_operational_events` adds
both V12 tables with indexes). Never edit an applied migration. Verify
with the upgrade/downgrade cycle test (now covers 002–006) and, before
release, against a disposable database (`alembic upgrade head`,
`downgrade -1`, `upgrade head`).

## Redis lifecycle and configuration

`RedisLifecycleManager` owns exactly one client: `start()` connects with
bounded timeouts and verifies via ping (idempotent); `close()` is
idempotent and never raises. No client is created per request, frame, or
event. URLs may carry passwords — only `scheme://host:port/db` (no
credentials) ever reaches logs, errors, or health payloads.

Settings (`REDIS_*`): `REDIS_ENABLED=false` and `REDIS_REQUIRED=false`
default to local single-process delivery. `EVENT_BUS_MODE=local` default;
`distributed` requires `REDIS_ENABLED=true` plus a URL (validated at
startup — never a silent local fallback). Required + unreachable fails
startup (`create_app` raises) and reports `/ready` 503. Optional +
unreachable degrades honestly (`DEGRADED`, platform stays servable).

## Local versus distributed event-bus behavior

- **Local** (default): synchronous in-process fan-out. All existing
  direct-call flows are untouched; the bus is additive notification.
- **Distributed** (explicit): local fan-out PLUS Redis pub/sub for
  cross-process delivery. Publication failures are observed (raised),
  never silent. Subscribers never republish (origin tag + bounded
  seen-set prevent echo loops and duplicates).
- Envelope v1: `{v, event_id, event_type, domain, camera_id, timestamp,
  origin, payload}` — validated, size-bounded (`EVENT_MAX_PAYLOAD_BYTES`),
  malformed/oversize/unknown safely dropped. Payloads reuse existing
  `to_websocket()` contracts; no new event types invented; reserved V09
  domains stay reserved.

## Delivery guarantees and limitations

- PostgreSQL commits are the durability boundary. An event is never
  claimed durable before its transaction commits.
- Event row + outbox intent commit atomically; the publisher drains with
  bounded batches and exponential-backoff retries (`OUTBOX_MAX_ATTEMPTS`,
  `OUTBOX_RETRY_BASE_SECONDS`). Crash between commit and acknowledgement
  redelivers — **subscribers must be idempotent** (the incident feed
  dedupes redelivered envelope ids; plain counters must tolerate repeats).
- Redis Pub/Sub is notification transport with at-most-once semantics
  per subscriber: subscribers that disconnect miss messages. Anything
  requiring recovery reconciles against PostgreSQL history. Pub/Sub is
  never described as guaranteed delivery or storage.
- No outbox exists for appearance: it materially prevents lost
  cross-process lifecycle notifications after a post-commit crash.
- Outbox intents that exhaust attempts become observably `failed`
  (never retried without bound, never deleted silently).

## Bus scope (locked)

Carried: V05 safety, V06 zone/proximity, V07 quality decisions + genuine
defects, V08 collision-risk + lane events, V09 unified events + cluster
updates, V10 lifecycle (created/updated/status/assigned/resolved/closed/
evidence). Never: frames, frame metadata, detections, track updates, FPS
samples, heartbeats, health polls, reserved-domain synthesis.

Worker stages publish new-or-changed events only (bounded per-worker
published sets, failure-isolated, skipped entirely with no bus or with a
subscriber-less local bus). Incident lifecycle changes queue outbox
intents from `_record_change` (failure-isolated; unwired managers behave
exactly as V11).

## Health/readiness behavior

- `/live` stays trivial (no DB/Redis round trip).
- `/ready` stays fast: `application` + `database` (`SELECT 1`) + `workers`
  required; `redis` required **only** when `REDIS_REQUIRED=true`
  (real ping; unreachable → 503). Optional Redis never fails readiness.
- `/health` (+ versioned) gains `redis` (READY/DISABLED/DEGRADED/NOT_READY
  per required policy) and `eventbus` (mode, subscriptions, delivered,
  duplicates) components — additive, secret-free, cheap. Pool telemetry
  (`driver`, `pooled`, `checked_out`, `size`, `overflow`) rides in DB
  metadata without URLs or credentials.

## Retention and cleanup

`OPERATIONAL_EVENT_RETENTION_DAYS=90`: bounded deletes (500-row batches)
of stale history (`last_seen` cutoff) and sent outbox intents ride the
existing incident auto-resolve sweep. Failed intents are retained for
inspection under the same bound. No unbounded growth paths.

## Failure modes, observability, recovery

| Failure | Behavior |
|---|---|
| PG unreachable at request | 503 `service_not_ready` (never 500 for dependency faults) |
| PG write fails mid-sync | Logged + counted (`history_failures`, `outbox_failures`); sync continues; next pass resumes idempotently |
| Redis required + down | Startup fails; `/ready` 503 |
| Redis optional + down | `DEGRADED`, local delivery continues |
| Oversize/malformed envelope | Dropped + warned; bus and workers stay healthy |
| Subscriber raises | Isolated + counted; publisher continues |
| Outbox attempts exhausted | `failed`, observable via `count_by_status()` |
| Slow WS client | Bounded queue sheds LOW first; HIGH lifecycle never silently dropped; drops counted |
| Shutdown | Publisher/subscriber stop → WS drain → Redis close → DB dispose (idempotent, bounded) |

Recover cross-process state by reconciling against `operational_events`
and incident detail endpoints — never by replaying Pub/Sub.

## Caching decision

No Redis cache in V12. Reads are cheap indexed lookups; incident state is
mutable. Caching would add invalidation risk without measured need.
PostgreSQL is the source of truth. Revisit only with profiling evidence.

## Local development and Docker

Compose already runs `postgres:16` + `redis:7`. The api service pins
`REDIS_ENABLED=false` / `EVENT_BUS_MODE=local`, so `docker compose up`
works with zero Redis dependence. For distributed mode, set
`REDIS_ENABLED=true`, `EVENT_BUS_MODE=distributed` (and
`REDIS_REQUIRED=true` to enforce it) with a reachable `REDIS_URL`.

## Tests

- `unit/test_v12_config.py` — settings + deployment-mode validation.
- `unit/test_event_envelope.py`, `unit/test_event_bus.py` — contracts.
- `unit/test_redis_lifecycle.py` — offline via `tests/redis_helpers.py`
  deterministic fake (ping/publish/pubsub/close + scripted failures).
- `integration/test_operational_store.py` — upsert/idempotency/orphans/
  retention/outbox atomicity (+ migration cycle covers 006).
- `integration/test_outbox_publisher.py` — drain/retry/backoff/crash
  recovery/invalid/lifecycle.
- `integration/test_redis_subscriber.py` — roundtrip/malformed/echo/
  lifecycle.
- `integration/test_event_distribution.py` — producer hooks, remote
  ingest + dedup, worker publish, retention, redis health/readiness
  policy, required-mode startup failure.
- Optional real-Redis smoke runs only with an explicit service;
  otherwise it reports SKIPPED, never PASS-by-fake.
