# V33 Continuous Integrity Monitoring

V33 adds a dedicated, offline continuous-audit subsystem that re-runs the
existing V30 evidence, V31 signed-checkpoint/trust, and V32 transparency
verifiers on a bounded schedule, records sanitized findings, and exposes an
authenticated operational dashboard. It is monitoring and reporting — not a new
cryptographic layer.

## Non-negotiable guarantees

- **Read-only protected inputs.** The auditor never writes, repairs, rewrites,
  quarantines, deletes, or re-signs evidence, integrity sidecars, audit chains,
  checkpoints, transparency logs, tree heads, inclusion/consistency proofs,
  receipts, trust stores, or trust states. Only the isolated V33 monitoring
  store is written.
- **No cryptography is duplicated.** Scopes delegate to
  `tools/release/evidence_verification.py` (V30), `tools/release/trust.py`
  (V31), and `tools/release/transparency.py` / `tools/release/merkle.py` (V32).
  A verifier failure is never converted into a pass.
- **Confirmed failure wins.** An overall `PASS` requires every requested scope
  to pass. A confirmed signature, binding, Merkle, or trust failure always
  produces `FAIL`. Unavailable inputs produce `UNAVAILABLE` or `PARTIAL`.
- **No external anchoring is claimed.** V33 is local/offline. It contacts no
  transparency service, cloud KMS, GitHub, registry, staging, or production
  endpoint. `external_anchor_configured` is always `false`, and a `SIMULATED`
  local test receipt is reported as simulated, never external.
- **No secrets.** Findings, scope details, API payloads, metrics, and
  notifications pass through V29 redaction. Audit records never contain
  evidence bytes, private keys, credentials, or raw authorization material.

## Architecture

| Component | Responsibility |
| --- | --- |
| `backend/app/integrity/scheduler.py` | Opt-in `ManagedWorker`; durable schedule slots, bounded interval, stale-run recovery, daily retention pruning. |
| `backend/app/integrity/runner.py` | Expands scopes, acquires a durable execution lease, enforces timeout/cancellation/retries/batch bounds, captures before/after input snapshots, aggregates status, persists findings, records metrics, and queues alerts. |
| `backend/app/integrity/verification/` | One adapter per scope. Reuses V30–V32 verifiers and normalizes their results into `ScopeExecution`. |
| `backend/app/integrity/store.py` | Isolated SQLite monitoring store: run summaries, scope results, findings, leases, alert dedup/cooldown state. No Alembic migration and no writes to the application schema. |
| `backend/app/integrity/service.py` | Read-oriented API service plus synchronous manual-run orchestration. |
| `backend/app/integrity/alerting.py` | Sanitized notifications, severity threshold, per-finding dedup, correlated cooldown, pending delivery rows. |
| `backend/app/api/v1/integrity.py` | Authenticated read APIs and authorized audit start/cancel. |

The scheduler starts only when both `INTEGRITY_MONITORING_ENABLED` and
`INTEGRITY_SCHEDULER_ENABLED` are true. Tests and default deployments never
start a background audit thread implicitly.

## Scopes

| Scope | Verifies | Reused implementation |
| --- | --- | --- |
| `EVIDENCE` | Report/manifest bindings, sidecar hashes, audit-chain continuity, replacement detection. | V30 |
| `SIGNED_CHECKPOINTS` | Ed25519 signature, payload bindings, sequence, replay, trust purpose and lifecycle. | V31 |
| `TRANSPARENCY_LOG` | JSONL schema, hash chain, entry references, Merkle root of entries. | V32 |
| `TREE_HEADS` | Tree-head signature, trust store/fingerprint, timestamp, split-view comparison, optional receipt. | V32 |
| `INCLUSION_PROOFS` | RFC 6962/9162 inclusion paths bound to tree size, leaf index, digest, log ID, and root. | V32 |
| `CONSISTENCY_PROOFS` | Append-only consistency between old/new sizes and roots. | V32 |
| `TRUST_STATE` | Trust stores and prior trust states are readable and valid; no state is advanced. | V31/V32 |
| `FULL` | Every concrete scope. `FULL` must stand alone. | All |

A configured-but-missing input is `UNAVAILABLE` with a `*_NOT_CONFIGURED`,
`*_MISSING`, or `*_UNAVAILABLE` reason. An unconfigured scope is never silently
skipped as a pass.

## Outcomes and reason codes

Overall statuses: `PASS`, `FAIL`, `PARTIAL`, `UNAVAILABLE`, `NOT_RUN`.
Scope statuses additionally use `NOT_RUN` for cancelled/deadline-exceeded work.

Required reason codes include:

`EVIDENCE_MISSING`, `EVIDENCE_MODIFIED`, `EVIDENCE_REPLACED`,
`CHECKPOINT_MISSING`, `CHECKPOINT_SIGNATURE_INVALID`, `CHECKPOINT_REPLAY`,
`TRUST_KEY_UNKNOWN`, `TRUST_KEY_REVOKED`, `TRUST_KEY_EXPIRED`,
`TREE_HEAD_INVALID`, `TREE_HEAD_REPLAY`, `TREE_HEAD_TIMESTAMP_REGRESSION`,
`INCLUSION_PROOF_INVALID`, `CONSISTENCY_PROOF_INVALID`, `TRUST_STATE_INVALID`,
`VERIFICATION_UNAVAILABLE`, `AUDIT_CANCELLED`, `AUDIT_TIMEOUT`,
`AUDIT_EXECUTION_ERROR`, `AUDIT_ALREADY_RUNNING`, `AUDIT_RETRY_EXHAUSTED`,
`BATCH_LIMIT_REACHED`, `FINDINGS_TRUNCATED`, `CONCURRENT_EVIDENCE_CHANGE`,
`AUDIT_INTERRUPTED`, and the configuration codes listed above. Raw V30–V32
verifier codes are mapped to this stable vocabulary; unknown codes become
`VERIFICATION_FAILED`, never a pass.

Aggregation rules:

1. Any scope `FAIL` → overall `FAIL`.
2. Any `UNAVAILABLE` or `PARTIAL` with at least one other result → `PARTIAL`.
3. All scopes `UNAVAILABLE` → `UNAVAILABLE`.
4. All scopes `PASS` → `PASS`.
5. Cancellation/timeout before any completed scope → `NOT_RUN`; after work →
   `PARTIAL` unless a confirmed failure exists.
6. A before/after input change downgrades a passing scope to `PARTIAL` with
   `CONCURRENT_EVIDENCE_CHANGE`.

## Findings

Every finding contains: `finding_id`, `audit_run_id`, `scope`, `severity`
(`INFO`/`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`), `reason_code`, safe `artifact_id`
(relative identifier or basename, never an absolute path), `detected_at`
(UTC), sanitized `explanation`, `verification_source`, and
`recommended_action`. Finding IDs are deterministic for
`(run, scope, reason, artifact, source)`, so retries cannot duplicate them.

## Persistence and resource bounds

The monitoring store is an isolated SQLite database:

- `INTEGRITY_MONITORING_DB_URL` must be a `sqlite:` URL. Empty derives
  `integrity-monitoring.db` beside a SQLite `DATABASE_URL`, otherwise
  `./var/integrity-monitoring.db`.
- Cross-process duplicate prevention requires every worker/API process to share
  the same store file; SQLite write locking plus a durable execution lease
  serializes runs. This is not a distributed lock for multiple hosts.
- Audit runs, scope results, findings, and alert state are retained for
  `INTEGRITY_RETENTION_DAYS`; the scheduler prunes terminal runs once per day.
- Run summaries and findings are paginated newest-first.

Bounds (all validated at startup):

| Setting | Default | Bound |
| --- | --- | --- |
| `INTEGRITY_MAX_SCOPES` | 8 | 1–16 |
| `INTEGRITY_BATCH_ARTIFACTS` | 500 | 1–10,000 |
| `INTEGRITY_MAX_CONCURRENT_RUNS` | 1 | 1–4 |
| `INTEGRITY_AUDIT_TIMEOUT_SECONDS` | 300 | 1–3,600 |
| `INTEGRITY_MAX_RETRIES` | 1 | 0–5 |
| `INTEGRITY_MAX_FINDINGS` | 1,000 | 1–10,000 |
| `INTEGRITY_API_PAGE_SIZE` | 20 | 1–100 (default; maximum is 100) |
| `INTEGRITY_RETENTION_DAYS` | 30 | 1–3,650 |
| `INTEGRITY_STALE_RUN_SECONDS` | 900 | 60–86,400 |
| `INTEGRITY_SCHEDULER_INTERVAL_SECONDS` | 300 | 30–86,400 |

No hot-loop scans: the scheduler waits a bounded interval between cycles,
reuses durable schedule slots, and processes each configured directory once per
run with a hard artifact bound. Truncation is reported, never hidden.

## API and RBAC

All routes require an authenticated session (`read`). Starting or cancelling an
audit requires the `integrity_audit_run` capability, granted to `ADMIN` and
`OPERATOR`; `VIEWER` has read-only access.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/integrity/status` | Latest run, last success/failure, counts, trust overview, scheduler, assurance. |
| `GET` | `/api/v1/integrity/summary` | Aggregate operational counts, retention, page-size defaults, assurance. |
| `GET` | `/api/v1/integrity/audits` | Paginated audit history with status/scope/trigger/time filters. |
| `GET` | `/api/v1/integrity/audits/{audit_id}` | Run summary plus scope results and findings. |
| `GET` | `/api/v1/integrity/findings` | Paginated findings with severity/scope/reason/artifact/time filters. |
| `GET` | `/api/v1/integrity/history` | Paginated terminal history (newest first). |
| `POST` | `/api/v1/integrity/audits` | Bounded synchronous audit; returns the terminal run summary plus scope results/findings. |
| `POST` | `/api/v1/integrity/audits/{audit_id}/cancel` | Cancels an in-process run; terminal runs return `409`. |

Manual runs accept at most 16 scopes, reject unknown/duplicate scopes and
`FULL` combined with explicit scopes, and support an optional
`idempotency_key` (replaying the same key returns the original run). Page size
is clamped to 100; values above 100 fail validation. `POST /audits` executes
within the configured audit timeout and never mutates protected inputs.

Cross-process cancellation is not claimed: cancellation signals an in-process
run. A stale run is recovered by the scheduler as `UNAVAILABLE` with
`AUDIT_INTERRUPTED`, never as a pass.

## Dashboard

`/integrity` provides:

- Overview metrics: latest audit, last success, total audits, open findings,
  artifacts checked, verified evidence/checkpoints/tree heads.
- Trust overview: key lifecycle counts, evidence/transparency trust-state
  availability, latest tree head, assurance, limitations.
- An explicit assurance banner stating that no external anchor is configured.
- Findings with severity/scope/reason filters and pagination.
- Audit history with status filter, pagination, and per-run scope detail.
- Run-audit controls for ADMIN/OPERATOR with explicit scope selection.
- Loading, empty, unavailable, and error states. Empty means genuinely no
  records; an API failure is never rendered as a pass or stale data.

## Alerting and metrics

When `INTEGRITY_ALERTING_ENABLED=true`, findings at or above
`INTEGRITY_ALERT_MIN_SEVERITY` are matched against enabled alert rules whose
domain is `INTEGRITY` and event type is `INTEGRITY_FINDING` (plus the generic
`INTEGRITY_AUDIT_FAILED` / `INTEGRITY_AUDIT_UNAVAILABLE` vocabulary). Rules are
evaluated through the existing V15 matcher and repository.

- Per-finding dedup is keyed by `finding_id` and rule.
- A correlation key (scope + reason code + safe artifact id) enforces
  `INTEGRITY_ALERT_COOLDOWN_SECONDS`; correlated repeats are suppressed.
- Notifications and delivery rows are sanitized and created as `pending` for
  the existing delivery worker. V33 never claims a channel delivered
  successfully.
- No high-cardinality labels: metrics use bounded `service`, `trigger`,
  `status`, `severity`, `scope`, and scheduler `outcome` values only.

Metrics:

`ivp_integrity_audit_runs_total`, `ivp_integrity_audit_duration_seconds`,
`ivp_integrity_findings_total`, `ivp_integrity_artifacts_checked_total`,
`ivp_integrity_scope_failures_total`, `ivp_integrity_scheduler_runs_total`,
`ivp_integrity_last_success_timestamp_seconds`, `ivp_integrity_running_audits`,
`ivp_integrity_external_anchor_configured` (always `0` offline).

## Configuration

Protected inputs are configured explicitly; empty means unconfigured:

```
INTEGRITY_MONITORING_ENABLED=true
INTEGRITY_MONITORING_DB_URL=sqlite:///./var/integrity-monitoring.db
INTEGRITY_SCHEDULER_ENABLED=false
INTEGRITY_SCHEDULER_INTERVAL_SECONDS=300

INTEGRITY_EVIDENCE_ROOT=
INTEGRITY_EVIDENCE_MANIFEST=
INTEGRITY_EVIDENCE_REPORT=
INTEGRITY_EVIDENCE_INTEGRITY=
INTEGRITY_EVIDENCE_AUDIT=
INTEGRITY_EVIDENCE_CHECKPOINT=
INTEGRITY_EVIDENCE_TRUST_STORE=
INTEGRITY_EVIDENCE_TRUST_STATE=
INTEGRITY_EVIDENCE_TRUSTED_FINGERPRINT=

INTEGRITY_TRANSPARENCY_LOG=
INTEGRITY_TREE_HEADS_DIR=
INTEGRITY_INCLUSION_PROOFS_DIR=
INTEGRITY_CONSISTENCY_PROOFS_DIR=
INTEGRITY_TRANSPARENCY_TRUST_STORE=
INTEGRITY_TRANSPARENCY_TRUST_STATE=
INTEGRITY_TREE_HEAD_TRUSTED_FINGERPRINT=
INTEGRITY_RECEIPT=
```

Point these at the same read-only mounts used by the V30–V32 CLIs. Never point
them at a writable producer directory unless the deployment accepts that the
auditor can read whatever the producer writes; the auditor still never writes.

## Operations

- Manual run: `POST /api/v1/integrity/audits` with explicit scopes, or use the
  `/integrity` dashboard.
- Scheduled run: enable the scheduler and set a bounded interval; verify
  `/api/v1/integrity/status` reports `scheduler.state=RUNNING` and inspect
  `last_cycle_at` / `last_success_at`.
- Incident triage: open `/integrity`, filter findings by severity/reason, and
  use `verification_source` plus `recommended_action`. A `PARTIAL` or
  `UNAVAILABLE` result means assurance is incomplete; it is not a clean bill.
- Recovery: fix the underlying artifact or configuration, then re-run the
  scope. Do not edit the monitoring store or protected artifacts to force a
  pass. The scheduler recovers interrupted runs as `UNAVAILABLE`.

## Limitations

- V33 is local/offline and does not provide external transparency anchoring,
  independent freshness, remote attestation, or a distributed lock.
- The monitoring store is SQLite; cross-host deployments must not assume
  shared leases unless all processes use the same file on shared storage.
- Cross-process cancellation is not claimed; cancellation is in-process.
- A local trust state is tamper-evident, not independently monotonic.
- A clean audit proves that the configured verifiers found no failure in the
  inputs they could read; it does not prove that an attacker with simultaneous
  write access to both evidence and trust material could not rewrite history.
- Windows hosts skip POSIX private-key permission and some symlink tests; those
  checks are reported as skipped, not passed.

## Validation

```powershell
python -m pytest backend/tests/unit/test_v33_integrity_audit.py `
  backend/tests/unit/test_v33_integrity_alerting.py `
  backend/tests/integration/test_v33_integrity_api.py -q
python -m ruff check backend
python -m ruff format --check backend
python -m compileall -q backend
```

The V33 tests cover scope execution, failure precedence, read-only input
integrity, idempotency, duplicate-run prevention, pagination, retention,
scheduler slot dedup, stale-run recovery, API/RBAC, page bounds, sanitized
findings, alert dedup/cooldown, and bounded metrics.

## V34 incident response and forensics

V34 consumes V33 findings and audit runs as read-only inputs. Confirmed
failures can be correlated into durable forensic cases; `UNAVAILABLE`,
`NOT_RUN`, `SIMULATED`, and operational findings are never promoted to a
confirmed security incident. Repeated findings are deduplicated by finding ID
and stable correlation dimensions, so later audit runs update the existing case
instead of creating duplicates. V34 never writes to the V33 monitoring store,
never edits or deletes findings, and never treats a later PASS as resolving an
older unresolved critical finding. See
[V34_INTEGRITY_INCIDENT_RESPONSE_AND_FORENSICS.md](V34_INTEGRITY_INCIDENT_RESPONSE_AND_FORENSICS.md).
