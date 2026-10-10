# Alerting & Notifications — V15

Durable, observable notifications over genuine operational events.
PostgreSQL is the source of truth; Redis Pub/Sub is transport only.
No authentication exists on this platform (V16 owns it): **do not expose
the alerting APIs to untrusted networks.**

## Architecture and event sources

```text
operational_events (V12 durable history) ──┐
incident_transitions (V15, same-txn) ──────┴─→ AlertingEvaluator ─→ notifications
                                                        │                  ↓
                                              alert_evaluations    delivery_attempts
                                              (NOTIFIED/SUPPRESSED)   ↓
                                                              DeliveryWorker ─→ in-app | SMTP | webhook
```

Evaluated sources: V05 safety, V06 spatial, V07 quality decisions,
V08 collision/lane events (via durable operational history), V09
unified events, V10 incident lifecycle transitions. Never frames,
detections, tracks, telemetry, heartbeats, or reserved-domain
synthesis. Reserved TRACKING/PERCEPTION/SYSTEM domains never match.

## Rule model and supported filters

Rule: name, description, enabled, `domains`, `event_types`,
`min_severity`/`min_priority` (existing V09 rank semantics),
`camera_ids`, `incident_statuses` (entered states), `channels`
(in_app/email/webhook, ≥1 required), `cooldown_seconds` (0–86400),
`suppression_scope` (RULE | RULE_CAMERA). Unknown domains, event
types, statuses, or channels are rejected at creation (422) — never
treated as wildcards. **Empty filter lists deliberately match all.**
Disabled rules never match. Cooldown starts when the notification
commits, never on external delivery success.

## Notification and delivery data lifecycle

- `notifications`: UNIQUE(`rule_id`, `source_event_id`) — one incident
  legitimately yields many notifications (unique transition IDs), but
  the same pair never duplicates.
- `delivery_attempts`: UNIQUE(`notification_id`, `channel`,
  `destination`) — email one row (recipient count only), webhook one
  row per allowlisted URL, in-app one row auto-completing in the worker.
- Notification + evaluation + delivery rows commit atomically with rule
  counters. A crash before commit leaves nothing; after commit the
  evaluator/publisher recover via watermarks and pending queues.
- Payloads bounded (4096-char message, 512-char errors, 64KB webhook
  bodies). No credentials, source URLs with secrets, or raw provider
  output stored anywhere.

## Channels

- **In-app** (mandatory, always available): the notification row itself;
  per-channel row still tracked for uniform observability.
- **SMTP** (optional, stdlib): host/port/TLS (`starttls`|`ssl`|`none`),
  env credentials, sender + explicit recipient list (no discovery),
  timeouts, 8000-char bodies with incident links, sanitized error
  categories. Unconfigured → visible `unavailable`, never silent success.
- **Webhook** (optional, httpx): central exact-URL allowlist (≤5),
  no redirects, bounded timeouts/body, optional HMAC
  (`X-IVP-Signature`), 429/5xx retryable vs 4xx/auth terminal, secrets
  only in env, never in logs.

## Configuration and local setup

`ALERTING_ENABLED=false` default — nothing sends until an operator
enables a rule. Worker knobs (`ALERTING_EVAL_INTERVAL_SECONDS=10`,
batches, `ALERTING_MAX_ATTEMPTS=8`, `ALERTING_RETRY_BASE_SECONDS=30`,
timeouts), retention (`ALERTING_RETENTION_DAYS=90`), SMTP/* and
`ALERTING_WEBHOOK_URLS`/`SECRET` placeholders in `.env.example`
(no real secrets). Invalid combos fail startup fast. Local/offline
testing needs nothing beyond SQLite.

## Durable processing and restart recovery

Evaluator watermarks (`alerting_cursor`: `evaluator-events`,
`evaluator-transitions` on `(timestamp, id)`) advance only past fully
processed items in the same transaction as outcomes. Restarts rescan
safely; UNIQUE constraints collapse redelivery. The outbox-style
`pending → sent|failed` delivery queue recovers identically. Shutdown
stops evaluator/delivery before closing Redis/DB (existing phases).

## Idempotency and duplicate-delivery limitations

At-most-once processing per (rule, source) via uniqueness; at-least-once
external delivery (crash after provider acceptance redelivers — SMTP and
generic webhooks may receive duplicates; exactly-once is never claimed).
Local + Redis double delivery collapses on the same keys. Manual retry
requeues the same row (failed only; attempts preserved).

## Retry and terminal failure semantics

Exponential backoff with jitter (`base × 2^min(attempts,6)`), per-attempt
timeouts, max attempts → terminal `failed` with categorized error.
Unconfigured channels and invalid payloads go terminal immediately
(no blind retries). Manual retry is operator-explicit and idempotent.

## Alert storm/cooldown policy

Bounded evaluation batches + per-cycle notification ceiling; unprocessed
items stay behind the watermark (never dropped). Cooldown suppressions
persist as `SUPPRESSED_COOLDOWN` evaluation rows (never notifications),
counted on the rule, visible in diagnostics — never silent discards.
Scopes: `RULE` (rule-wide clock) and `RULE_CAMERA` (per-camera clock
from notification history; cameraless events use a stable empty key).

## Operational health signals and troubleshooting

`GET /api/v1/alerting/status`: engine enabled flag, evaluator/delivery
worker snapshots, per-channel availability (booleans + destination
count, never secrets), delivery counters, V16 warning. Health component
`alerting`: DISABLED when off, FAILED on worker failure, else READY.
Readiness unaffected (alerting never gates traffic). Check worker
snapshots → delivery counts → `last_error` categories → rule
trigger/suppressed counters, in that order.

## Secret handling

Secrets exist only as environment variables, injected at adapter
construction. They never enter rule rows, payloads, logs, API
responses, or health output (verified by tests asserting absence).

## Deployment security limitation before V16

No authentication or RBAC exists: rule management, manual retry, and
notification reads must be network-restricted to trusted operators
until V16. This limitation is returned in the status payload and must
be repeated in deployment runbooks.

## Test instructions

- Backend: `pytest backend/tests/integration/test_alerting*.py
  backend/tests/unit/test_alerting_*.py` (fakes only: `FakeChannelAdapter`,
  httpx `MockTransport`, monkeypatched smtplib — no network).
- Migration: spatial-integration Alembic cycle covers 008 up/down.
- Frontend: `npm run test:run` (notifications/rules suites, mocked fetch,
  no live services).

## What is not supported in V15

SMS, push, Slack/Teams providers, scheduled reports, per-user inboxes
or read state, rule deletion (disable instead; history is preserved),
exactly-once external delivery, loss-free Redis transport, and
cross-system transactions spanning PostgreSQL and providers.
