# V36 Governance Automation and Compliance Operations

V36 adds opt-in, bounded, idempotent governance automation above the V35
governance and retention layer. It schedules non-destructive retention
evaluation, deduplicated review reminders, local compliance snapshots, and
governance health checks. It does not delete evidence, release holds, decide
dispositions, generate forensic exports, or certify regulatory compliance.

The automation workspace is an additive section of the existing `/governance`
page. V36 introduces no second scheduler, policy engine, notification system,
audit system, or integrity service.

## Non-negotiable guarantees

- No physical evidence deletion, overwrite, path removal, database cascade
  deletion, storage cleanup, or evidence destruction is implemented.
- Scheduled retention evaluation is non-destructive. It records evaluation
  state only; it never treats `FAILED`, `UNAVAILABLE`, `INCOMPLETE`, `PARTIAL`,
  or `NOT_RUN` verification as a successful integrity result.
- Legal holds never expire, release, or get approved automatically. Reminders
  only prompt a human reviewer.
- Dispositions are never approved or rejected automatically. Reminders only
  prompt a human reviewer.
- Forensic exports are never requested, approved, generated, verified, or
  delivered automatically. Export reminders only prompt a human reviewer.
- No automation job or snapshot is deleted, pruned, overwritten, or archived by
  V36. There are no `DELETE` automation routes.
- Automation is disabled by default. It requires both
  `GOVERNANCE_AUTOMATION_ENABLED=true` and explicit per-schedule enablement.
- Every schedule, job, retry, cancellation, snapshot, and configuration change
  is bounded and audited through the existing V35 governance audit.
- Compliance snapshots are local aggregate records with a self-digest. They are
  not regulatory certification, legal attestation, immutable storage, or an
  external trust anchor.
- Reminder delivery is local queue state. A `PENDING` reminder is not a claim
  that an external channel delivered it.

## Architecture and reuse

V36 composes existing platform services:

- V33 scheduler/worker semantics: `GovernanceAutomationScheduler` is a
  `ManagedWorker` with a single managed thread, explicit start/stop, a bounded
  poll interval, and a bounded number of jobs per tick. V36 does not create a
  second generic scheduler.
- V33 leases and retries: jobs use conditional claim, owner identity, lease
  expiry, heartbeat, and stale-lease recovery. Retries are bounded child jobs
  with deterministic exponential backoff and deterministic jitter.
- V35 governance: the executor calls `GovernanceService` for retention,
  holds, dispositions, export approvals, compliance reports, and audit
  records. V35 evidence, case, custody, export, and audit semantics are
  unchanged.
- V15 notifications: reminders write existing `NotificationORM` and
  `DeliveryAttemptORM` rows through `GovernanceNotifier` under the
  `GOVERNANCE` domain. The existing delivery worker remains the only delivery
  mechanism. V36 adds a per-window dedup version and a `reminder_window`
  context field.
- V16 RBAC: all routes require authentication and an explicit capability. The
  frontend is usability only and never an authorization boundary.
- V18 observability: bounded-label counters and histograms, sanitized logs,
  request IDs, and the existing readiness endpoint.
- V29 redaction: reminder text, snapshot payloads, CSV output, and error
  messages pass through the existing redaction helpers.
- V30–V34 integrity/forensics: health checks read V33 audit status and V34
  custody status without repairing, rewriting, or re-verifying evidence.

## Data model

Alembic revision `013_create_governance_automation` follows
`012_create_governance`. It creates only V36-owned tables and indexes. All
foreign keys are non-cascading; `downgrade()` drops only the V36 tables.

### `governance_job_schedules`

One row per job type. Fields include `schedule_id`, `job_type`, `enabled`,
`interval_minutes`, `config`, `config_version`, `last_slot`,
`last_idempotency_key`, `updated_by`, `updated_role`, and timestamps. Seven
schedules are seeded disabled. `config_version` increments on every update and
optimistic concurrency rejects stale writes with `409`.

### `governance_jobs`

One row per job attempt. Fields include `job_id`, `job_type`, `status`,
`trigger`, `schedule_slot`, `dedup_key`, `retry_of_job_id`, `attempt`,
`max_attempts`, `config_version`, `config_snapshot`, requester identity,
`request_id`, `available_at`, lease fields, cancellation fields, result JSON,
and sanitized error fields. `dedup_key` is unique, and
`(retry_of_job_id, attempt)` is unique.

### `governance_job_events`

Append-only lifecycle events: `CREATED`, `CLAIMED`, `HEARTBEAT`,
`RETRY_SCHEDULED`, `CANCEL_REQUESTED`, `CANCELLED`, `SUCCEEDED`, `FAILED`,
`RECOVERED`, and `UNAVAILABLE`. Update and delete triggers protect the table.

### `governance_snapshots`

Append-only local compliance snapshots. Fields include `snapshot_id`,
`snapshot_type`, `as_of`, `generated_at`, `generated_by`, `job_id`, `trigger`,
`dedup_key`, `payload`, `payload_digest`, `row_count`, and
`schema_version`. The digest is recomputed on read; an invalid digest is
reported as `digest_valid=false` and never silently accepted.

## Schedule semantics

- Intervals are UTC epoch-aligned buckets. A slot ID is deterministic for
  `(job_type, slot_start)`.
- `(job_type, schedule_slot)` is unique, so one slot creates at most one job
  even under concurrent scheduler cycles.
- Schedules are seeded disabled with bounded default intervals and configs.
- Missed slots are not replayed. The scheduler never backfills a backlog.
- `interval_minutes` is constrained to 5–10080. Configuration values are
  validated per job type and clamped to bounded item counts.
- Updating a schedule requires a reason and the current `config_version`.

Default schedules:

| Job type | Default interval | Default config |
| --- | --- | --- |
| `RETENTION_EVALUATION` | 1440 min | `batch_limit=100` |
| `RETENTION_REVIEW_REMINDERS` | 1440 min | `upcoming_days=30`, `max_items=100` |
| `LEGAL_HOLD_REMINDERS` | 1440 min | `max_items=100`, `active_hold_age_days=30`, include pending/active |
| `DISPOSITION_REVIEW_REMINDERS` | 1440 min | `max_items=100`, `min_age_days=1` |
| `EXPORT_APPROVAL_REMINDERS` | 1440 min | `max_items=100`, `upcoming_days=14` |
| `COMPLIANCE_SNAPSHOT` | 1440 min | `{}` |
| `GOVERNANCE_HEALTH_CHECK` | 60 min | `{}` |

## Job lifecycle

1. `PENDING`: created with a deterministic dedup key and bounded config.
2. `RUNNING`: conditionally claimed by one owner with a lease expiry.
3. Terminal: `SUCCEEDED`, `FAILED`, `CANCELLED`, or `UNAVAILABLE`.
4. Retry: a terminal retryable job creates one child with
   `retry_of_job_id` and `attempt + 1`, capped by `max_attempts`.
5. Recovery: an expired lease moves the job to `UNAVAILABLE` and records a
   `RECOVERED` event. Side effects must remain idempotent after recovery.

Finishing a job requires the same lease owner. A mismatched owner cannot
overwrite terminal state.

## Retry and cancellation

- Retry delays use deterministic exponential backoff with deterministic
  jitter. The base and maximum delays are configurable and bounded.
- Retry is allowed only for `FAILED`, `UNAVAILABLE`, and `CANCELLED` jobs and
  only while attempts remain.
- Cancelling a `PENDING` job moves it directly to `CANCELLED`.
- Cancelling a `RUNNING` job records `cancel_requested_at` and
  `cancel_requested_by`; the executor observes cancellation cooperatively.
- Terminal jobs return `409` for cancellation.
- The API reports `cancel_requested` separately from `cancelled`.

## Reminders

Four reminder job types emit five event types through the V15 pipeline:

| Job type | Event types |
| --- | --- |
| `RETENTION_REVIEW_REMINDERS` | `GOVERNANCE_RETENTION_REVIEW_DUE` |
| `LEGAL_HOLD_REMINDERS` | `GOVERNANCE_LEGAL_HOLD_PENDING_APPROVAL`, `GOVERNANCE_LEGAL_HOLD_REVIEW_DUE` |
| `DISPOSITION_REVIEW_REMINDERS` | `GOVERNANCE_DISPOSITION_REVIEW_DUE` |
| `EXPORT_APPROVAL_REMINDERS` | `GOVERNANCE_EXPORT_APPROVAL_REVIEW_DUE` |

Reminder properties:

- Severity is `HIGH`; V15 rules must explicitly target `GOVERNANCE` and the
  reminder event type. No rule means `NO_RULE`, not a silent success.
- Dedup key includes rule, event type, target, target version, and the job
  slot/run window. Repeating the same window does not duplicate a reminder.
- V15 cooldown remains rule + target + event type and can suppress a new
  window. The outcome is reported as `COOLDOWN`.
- Disabled notifier, muted notifications, missing rules, and delivery failures
  are reported honestly as `DISABLED`, `MUTED`, `NO_RULE`, or `ERROR`.
- Reminder context explicitly records `automatic_hold_release=false`,
  `automatic_disposition_approval=false`, and
  `automatic_export_generation=false`.
- Reminder activity reports `PENDING`, `DELIVERED`, `FAILED`, or `PARTIAL`
  from local delivery rows with `delivery_claimed=false`.

## Compliance snapshots

- Snapshot type is `COMPLIANCE_SUMMARY`, generated from the V35 `SUMMARY`
  compliance report.
- Payload is canonicalized and SHA-256 digested. The digest is revalidated on
  every read and CSV generation.
- `row_count` is the report's `sections.retention.evaluated_cases`.
- Snapshot generation is idempotent by dedup key. Replaying the same key
  returns the stored snapshot with `replayed=true`.
- Stored snapshots are never updated or deleted.
- CSV export includes report-level non-claims, including
  `regulatory_certification_claimed=false` and
  `external_immutable_storage_claimed=false`.

## Health

`GET /api/v1/governance/automation/health` reports:

- Scheduler state, queue depth, and stale leases.
- V35 governance audit outcome.
- V33 integrity status and latest audit status.
- Overall `OK`, `DEGRADED`, or `FAILED`.

Integrity maps to `OK` only when the latest V33 audit status is `PASS`.
`FAIL`, `PARTIAL`, `UNAVAILABLE`, `NOT_RUN`, and `RUNNING` are never treated
as a pass. A failed or unavailable check produces `DEGRADED`/`FAILED`, not a
silent success.

## RBAC

| Capability | ADMIN | OPERATOR | VIEWER |
| --- | --- | --- | --- |
| `governance_automation_read` | yes | yes | yes |
| `governance_automation_configure` | yes | no | no |
| `governance_automation_retry` | yes | yes | no |
| `governance_automation_cancel` | yes | yes | no |
| `governance_snapshot_read` | yes | yes | yes |
| `governance_snapshot_generate` | yes | yes | no |

Manual run uses `governance_automation_retry`. Schedule configuration is
ADMIN-only. All reads are available to every authenticated role. The frontend
hides unavailable controls but the backend remains the authorization boundary.

## API

All routes are under `/api/v1/governance/automation` and require
authentication. There are no `DELETE` routes.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/status` | Automation status, queue, schedules, last jobs |
| `GET` | `/health` | Scheduler, audit, and integrity health |
| `GET` | `/schedules` | List all seven schedules |
| `PUT` | `/schedules/{job_type}` | Update schedule (ADMIN, versioned, reason required) |
| `GET` | `/jobs` | Paginated job history with filters |
| `GET` | `/jobs/{job_id}` | Job detail and append-only events |
| `POST` | `/jobs/run` | Manual synchronous run (idempotent) |
| `POST` | `/jobs/{job_id}/retry` | Bounded retry child (reason required) |
| `POST` | `/jobs/{job_id}/cancel` | Cancel pending or request cooperative cancel |
| `GET` | `/snapshots` | Paginated snapshot history |
| `POST` | `/snapshots` | Generate a local SUMMARY snapshot |
| `GET` | `/snapshots/{snapshot_id}` | Snapshot detail with digest validation |
| `GET` | `/snapshots/{snapshot_id}/csv` | Stored snapshot CSV |
| `GET` | `/reminders` | Reminder queue and local delivery state |

Error mapping: `404` for unknown schedule/job/snapshot, `409` for version
conflicts and invalid job state, `422` for validation failures, `503` when
automation is not initialized.

## Frontend

The existing `/governance` page renders an additive `AutomationWorkspace`
section with:

1. Overview metrics, scheduler state, queue counts, assurance, and non-claims.
2. Schedule table and an ADMIN-only versioned editor with reason and bounded
   JSON configuration.
3. Job history with filters, pagination, manual run, retry, and cancel
   confirmation dialogs requiring a reason.
4. Reminder activity with explicit pending-versus-delivered local state and a
   visible warning that pending is not external delivery.
5. Snapshot history, digest validity, and CSV download.
6. Automation health with audit and integrity states.

Each section fails independently; one unavailable endpoint does not hide fresh
data from other sections. Viewers see read-only tables and an explanation of
the missing capability.

## Configuration

```powershell
$env:GOVERNANCE_AUTOMATION_ENABLED="false"          # opt-in, default false
$env:GOVERNANCE_AUTOMATION_POLL_SECONDS="30"       # 1-3600
$env:GOVERNANCE_AUTOMATION_LEASE_SECONDS="120"     # 5-3600
$env:GOVERNANCE_AUTOMATION_MAX_ATTEMPTS="3"        # 1-5
$env:GOVERNANCE_AUTOMATION_RETRY_BASE_SECONDS="30" # 1-3600
$env:GOVERNANCE_AUTOMATION_RETRY_MAX_SECONDS="900" # 1-86400
$env:GOVERNANCE_AUTOMATION_JOB_TIMEOUT_SECONDS="300" # 5-3600
$env:GOVERNANCE_AUTOMATION_MAX_PENDING_JOBS="100"  # 1-1000
$env:GOVERNANCE_AUTOMATION_MAX_JOBS_PER_TICK="5"   # 1-50
```

Reminder delivery additionally requires the existing V15 settings:

```powershell
$env:GOVERNANCE_ALERTING_ENABLED="true"
$env:GOVERNANCE_ALERT_COOLDOWN_SECONDS="300"
```

An enabled V15 alert rule must target the `GOVERNANCE` domain and the desired
reminder event type. V36 does not create alert rules automatically.

## Operations and recovery

1. Run `python -m alembic -c backend/alembic.ini upgrade head` before enabling
   automation. The revision is additive and reversible.
2. Keep `GOVERNANCE_AUTOMATION_ENABLED=false` until schedules and alert rules
   have been reviewed.
3. Enable one schedule at a time with a recorded reason. Verify the next slot
   and the first job result.
4. Inspect `/health` and `/status` after enabling. `DEGRADED` or `FAILED`
   requires investigation; it is not a pass.
5. Stale leases recover to `UNAVAILABLE`. Retry with a reason only after
   checking the job events and the underlying governance state.
6. Cancellation is cooperative for running jobs. Verify the terminal state in
   job history.
7. Snapshots are append-only. Generate a new snapshot instead of mutating an
   existing one.
8. There is no automated job or snapshot pruning. Capacity planning must
   account for retained automation history.

## Metrics and logging

Bounded-label metrics:

- `ivp_governance_automation_jobs_total{job_type,trigger,status}`
- `ivp_governance_automation_job_duration_seconds{job_type}`
- `ivp_governance_automation_reminders_total{category,outcome}`
- `ivp_governance_automation_snapshots_total{trigger,status}`
- `ivp_governance_automation_queue_depth{status}`
- `ivp_governance_automation_stale_jobs`

Unknown label values collapse to `UNKNOWN`. Logs include job ID, job type,
status, and request ID, and never include evidence bytes, secrets, or raw
export paths.

## Testing

Deterministic local tests cover:

- Scheduler integration, epoch-aligned slots, and slot idempotency.
- Job lifecycle, conditional claim, lease heartbeat, and stale recovery.
- Bounded retry/backoff and retry-child uniqueness.
- Pending cancellation and cooperative running cancellation.
- Concurrent scheduler cycles and concurrent manual runs.
- Reminder dedup, cooldown, disabled notifier, missing rule, and every
  reminder category.
- Snapshot digest, idempotent replay, CSV, and read-time digest validation.
- RBAC for every capability, pagination, and absence of delete routes.
- Bounded metric cardinality, redaction, snapshot digest tamper detection, and
  bounded failure records.
- V10/V15/V16/V29–V35 regressions.
- Migration upgrade/downgrade/re-upgrade when PostgreSQL or SQLite migration
  tests run.

These tests use synthetic fixtures and injected clocks. They do not prove live
scheduler timing, live SMTP/webhook delivery, or production PostgreSQL
behavior; those require separate deployment validation.

## Known limitations

- Automation is disabled by default and is not a compliance certification.
- Reminder delivery depends on V15 rules, channels, and the existing delivery
  worker. V15 has no per-user notification preference table.
- Scheduled retention evaluation is bounded by `batch_limit`; cases beyond the
  batch are not evaluated in that slot and are not replayed automatically.
- Missed slots are not backfilled. A paused scheduler does not catch up.
- Health checks observe local audit and integrity state; they do not repair it.
- Snapshot digests are local self-digests, not external anchors.
- No automatic job or snapshot pruning exists; operators must plan retention
  capacity.
- PostgreSQL trigger behavior is covered by offline SQL generation and SQLite
  integration tests in CI; a live PostgreSQL migration is a deployment step.
