# V35 Forensic Governance, Retention and Compliance Readiness

V35 adds a governance and compliance-readiness layer above the V34 forensic case
system. It records versioned retention policies, deterministic retention
evaluations, legal holds, disposition reviews, export approvals, and an
append-only local governance access audit. It does not delete evidence, release
holds automatically, approve dispositions automatically, or certify regulatory
compliance.

## Non-negotiable guarantees

- No physical evidence deletion, overwrite, path removal, database cascade
  deletion, storage cleanup, or evidence destruction is implemented.
- A disposition approval authorizes only a future, separately scoped process.
  It does not delete, move, or schedule deletion of any record.
- Legal holds never expire or release automatically. Release requires an
  explicit ADMIN action with a reason.
- Overlapping holds are supported. Releasing one hold never releases another.
- Policy versions are append-only. A policy update creates a new version and
  never rewrites historical decisions or evaluations.
- Retention evaluation is deterministic, repeatable, and non-destructive. It
  accepts an injected clock and reports missing metadata as explicit
  `INCOMPLETE`/`UNAVAILABLE` states instead of guessing.
- Export approval, generation, verification, and delivery are distinct states.
  Approval never proves that an external recipient received or validated a
  package.
- Governance audit records are local, append-only, and self-digested. They are
  not an external hash chain, immutable storage, or trust anchor.
- No regulatory certification, legal-compliance attestation, external
  immutable-storage claim, or external trust-anchor claim is made.

## Architecture and reuse

V35 reuses the existing platform rather than creating parallel systems:

- V10 incidents: forensic cases can retain their existing incident links.
- V15 alerting: `GovernanceNotifier` writes the existing notification and
  delivery rows under a new bounded `GOVERNANCE` alert domain. Alerting is
  disabled by default.
- V16 authentication/RBAC: every route requires an authenticated principal and
  an explicit capability. The frontend is not an authorization boundary.
- V18 observability: governance failures use the existing sanitized logging and
  request-ID conventions.
- V29 redaction/retention security: policy, hold, disposition, export, audit,
  report, and CSV output pass through the existing redaction helpers.
- V30 integrity: governance never repairs or rewrites evidence. Integrity
  failures block disposition approval; they never authorize discarding evidence.
- V31/V32 trust and transparency: governance reports preserve the existing
  local-only assurance and `external_anchor_claimed=false` semantics.
- V33 continuous auditing: findings remain the source of integrity context.
- V34 forensics: governance wraps existing case, custody, verification, and
  export behavior. V34 export IDs, paths, hashes, statuses, and semantics are
  preserved.

The governance service is constructed only when V34 forensics is available. If
initialization fails, the API returns `503` for governance routes rather than
starting an unsafe partial workflow.

## Governance data model

Alembic revision `012_create_governance` adds only V35-owned tables after
`011_create_forensics`:

| Table | Purpose |
| --- | --- |
| `governance_policy_versions` | Append-only policy versions keyed by stable `policy_id` + `version`. |
| `governance_retention_evaluations` | Immutable evaluation snapshots with policy version, as-of date, state, and reasons. |
| `governance_legal_holds` | One case + optional evidence reference per hold, with explicit lifecycle fields. |
| `governance_legal_hold_events` | Append-only hold history (`CREATED`, approved, rejected, released, withdrawn). |
| `governance_disposition_requests` | Disposition review requests with one open request per case. |
| `governance_disposition_decisions` | Append-only review decisions and reasons. |
| `governance_export_approvals` | Export request, approval, generation, and verification state. |
| `governance_access_audit` | Append-only local governance access events with self-digests. |

All timestamps are UTC-aware. Unique keys cover policy `(policy_id, version)`,
evaluation idempotency, one open disposition per case (`open_key`), and audit
event idempotency. Foreign keys reference existing forensic cases by identifier;
there is no cascading deletion of forensic or governance history.

PostgreSQL append-only triggers reject updates and deletes on policy versions,
hold events, disposition decisions, and access audit rows. The SQLite migration
tests use equivalent triggers for local verification. Trigger behavior for
PostgreSQL is validated through offline SQL generation; no shared database is
migrated by this repository's test suite.

## Policy versioning

A policy has a stable `policy_id` and one row per version. Creation and updates
record the actor, role, timestamp, reason, and optional idempotency key. Updates
must specify the expected version when the caller needs optimistic concurrency.
Policy states are `DRAFT`, `ENABLED`, `DISABLED`, and `ARCHIVED`.

The seeded `POL-DEFAULT` policy is the safe fallback:

- enabled and applicable to all case/evidence categories;
- retention and review durations unset (organization-defined);
- export approval required;
- evidence bytes disallowed;
- legal-hold eligible;
- disposition review required;
- cannot be disabled or archived.

Policy selection is deterministic. A specific case-type or evidence-category
policy takes precedence over the default. Existing evaluations retain the policy
snapshot that was applied; a later policy update does not silently alter prior
evaluations.

## Retention evaluation

The evaluator is pure with respect to protected records. It receives the case
metadata, the selected policy, the as-of timestamp, holds, the latest
disposition, and the latest V34 verification. It returns:

- policy ID/version and retention start/deadline;
- next review date;
- governance state;
- data status (`OK`, `INCOMPLETE`, `UNAVAILABLE`);
- integrity status and legal-hold IDs;
- disposition eligibility;
- reason codes explaining due, blocked, stale, or unavailable conditions;
- `deletion_authorized=false` and a non-deletion note.

Governance states are `ACTIVE`, `REVIEW_DUE`, `LEGAL_HOLD`,
`DISPOSITION_REVIEW_REQUIRED`, `DISPOSITION_APPROVED`, and
`DISPOSITION_BLOCKED`. They are review states, not deletion instructions.
Evaluation is manual and bounded; there is no background scheduler. Repeating
the same evaluation returns the stored evaluation with `replayed=true`.

Missing retention start, unconfigured durations, missing policy, and unavailable
verification are reported explicitly. An integrity failure sets a blocking
reason; it never makes evidence eligible for disposal.

## Legal-hold lifecycle

A hold has a stable ID, mandatory reason, requester, case, optional evidence
reference, scope, and complete event history. New holds start in
`PENDING_APPROVAL` when approval is configured. `PENDING_APPROVAL` and `ACTIVE`
both block disposition and export, closing the race where approval could
complete while a hold request is still pending.

Transitions are explicit:

`PENDING_APPROVAL -> ACTIVE | REJECTED | WITHDRAWN`

`ACTIVE -> RELEASED`

Approval/rejection/release require the ADMIN-only `legal_hold_approve`
capability and a reason. The requester cannot approve their own hold. Rejected,
released, and withdrawn holds remain queryable with their event history. There
is no expiry, automatic release, or silent removal.

## Disposition review

Disposition review is a review workflow, not a deletion engine. A request
requires an existing applicable policy, a passing V34 verification, a terminal
case status (`RESOLVED`/`CLOSED`), no blocking hold, and a fresh retention
evaluation with `disposition_eligible=true`.

Lifecycle:

`REVIEW_REQUIRED -> APPROVAL_PENDING -> APPROVED | BLOCKED`

`WITHDRAWN` is preserved. One open request per case is enforced by a unique
`open_key`. The requester cannot approve their own request. `DUAL_REVIEWER`
policies require two distinct reviewers. Approval is blocked when:

- any pending/active legal hold applies;
- integrity verification is not `PASS`;
- the case is not terminal;
- the policy or evaluation is stale;
- hold or verification state changed after the request;
- the policy does not require disposition review.

All decisions and reasons are appended. Approval sets
`physical_deletion_performed=false` and
`authorizes_future_process=true`. No physical deletion is performed or
scheduled.

## Export approvals

Governance export requests are separate from generation:

`PENDING_APPROVAL` or `POLICY_AUTO_APPROVED` → `APPROVED` → `GENERATED` →
`VERIFIED`.

The requester cannot approve their own request. Active or pending holds block
approval and generation. Generation wraps the existing V34 deterministic export
service, preserves path-traversal protections and redaction, and records the
V34 `export_id`, SHA-256, manifest/root digests, size, and file count. Generated
exports cannot be withdrawn or deleted.

Direct V34 ADMIN exports remain available for backward compatibility. When
governance is initialized, they are policy/hold-guarded and audited with
`approval_id=null`. The V34 evidence-byte configuration check still runs before
governance policy checks, preserving the existing
`"evidence-byte export is disabled"` error contract.

`delivery_claimed=false` and `external_recipient_validated=false` are always
reported. A download link or generation record is not evidence of delivery.

## Governance access audit

Governance-relevant events are stored in `governance_access_audit` with event
ID, actor, role, event type, target, case ID, UTC timestamp, outcome, reason,
request ID, sanitized metadata, and a per-event self-digest. The API verifies
the digest when reading a single event.

Recorded events include policy changes, retention evaluations/reviews, hold
lifecycle actions, disposition actions, export request/approval/generation/
verification/download, case/evidence/custody/export reads initiated through the
V34 API, and report generation. Credentials, tokens, private keys, evidence
contents, and secret-bearing payloads are never recorded.

The assurance is `LOCAL_SELF_DIGEST_ONLY`. This is not a hash chain, an external
anchor, or proof of immutable storage. PostgreSQL triggers prevent updates and
deletes on audit rows, but an operator with database-owner access can still
alter storage outside the application.

## API and RBAC

All routes are under `/api/v1/governance` and require authentication.

| Capability | ADMIN | OPERATOR | VIEWER | Routes |
| --- | --- | --- | --- | --- |
| `governance_read` | yes | yes | yes | status, policies, retention queue, holds, dispositions, export approvals, SUMMARY reports |
| `governance_policy_write` | yes | no | no | policy create/update/state |
| `retention_evaluate` | yes | yes | no | retention evaluate/review |
| `legal_hold_write` | yes | yes | no | hold request/withdraw |
| `legal_hold_approve` | yes | no | no | hold approve/reject/release |
| `disposition_request` | yes | yes | no | disposition request/withdraw |
| `disposition_review` | yes | no | no | disposition approve/reject |
| `forensic_export_request` | yes | yes | no | export request/withdraw |
| `forensic_export_approve` | yes | no | no | export approve/reject |
| `forensic_export` | yes | no | no | export generate/verify/download (V34 capability) |
| `governance_audit_read` | yes | no | no | access audit |
| `governance_report_generate` | yes | no | no | DETAIL reports / case-scoped CSV |

Read routes use bounded pagination (`page`, `page_size`, maximum 100). Mutation
schemas validate lengths and numeric ranges. Optional idempotency keys make
retried creates/transitions return the stored result. Server-side authorization
is authoritative; frontend visibility is only a usability aid.

Error behavior is consistent with the existing API envelope: `401`
unauthenticated, `403` insufficient capability, `404` not found, `409`
state/version/separation/blocking conflicts, `422` validation, `503` governance
disabled/not initialized.

## Persistence and migration

Run the additive migration during the normal release window:

```powershell
python -m alembic -c backend/alembic.ini upgrade head
```

`downgrade()` removes only the eight V35 tables and their indexes/triggers.
V01–V34 records are untouched. The isolated migration test verifies
upgrade → downgrade → re-upgrade and confirms that the default policy is seeded
after upgrade.

## Configuration

```powershell
$env:GOVERNANCE_ENABLED="true"
$env:GOVERNANCE_RETENTION_BATCH_LIMIT="100"
$env:GOVERNANCE_PAGE_SIZE="20"
$env:GOVERNANCE_AUDIT_PAGE_SIZE="50"
$env:GOVERNANCE_LEGAL_HOLD_REQUIRES_APPROVAL="true"
$env:GOVERNANCE_REPORT_UPCOMING_DAYS="30"
$env:GOVERNANCE_REPORT_MAX_ROWS="500"
$env:GOVERNANCE_ALERTING_ENABLED="false"
$env:GOVERNANCE_ALERT_COOLDOWN_SECONDS="300"
```

Durations are organization-defined and are not seeded with invented regulatory
values. Legal-hold approval is enabled by default.

## Dashboard

`/governance` provides:

1. Governance overview and explicit non-claims.
2. Retention policy list, version display, creation, version append, and
   state changes.
3. Retention review queue with evaluate/review actions and blocked reasons.
4. Legal holds with request, approve, reject, release, and withdraw actions.
5. Disposition review queue with separation-of-duties actions and the
   no-deletion note.
6. Export approvals with request, approve, reject, generate, verify, download,
   and withdraw actions.
7. Access audit history for administrators, including digest assurance.
8. Compliance-readiness summary/detail reports and CSV download.

Sensitive actions require an explicit reason and a confirmation step. Loading,
empty, partial, unavailable, and error states are rendered explicitly. The page
does not hide server errors behind success states.

## Metrics and observability

Governance integrates with existing sanitized logging and alerting. V15 gains a
bounded `GOVERNANCE` domain with event types for hold creation/approval/release,
disposition approval, export approval, export generation failure, and export
verification failure. Metrics/log labels must not include actor IDs, case IDs,
evidence IDs, or arbitrary user input. Governance alerting is disabled by
default and reuses existing notification/delivery rows with deterministic dedup.

## Security boundaries

- V29 redaction applies to logs, exceptions, reports, CSV, and audit metadata.
- V30 verification is read-only. A failure blocks disposition and is never a
  reason to delete evidence.
- V31/V32 verification remains governed by their existing configuration and
  assurance semantics.
- V33 findings remain review context; only confirmed failures retain their
  existing incident-promotion rules.
- V34 cases, custody records, evidence references, export IDs, paths, hashes,
  and statuses are preserved.
- No governance action bypasses authentication or RBAC.
- No per-case ACL is added; V35 preserves V34 authenticated global-read
  semantics. DETAIL reports and access audit are ADMIN-only.

## Operational procedures

1. Run the migration and confirm the default policy exists.
2. Configure organization-defined retention/review durations with a documented
   reason. Do not invent legal durations.
3. Evaluate retention manually or in bounded batches. Review due items.
4. Request legal holds when needed; an independent ADMIN approves them.
5. Request disposition review only for terminal cases with passing
   verification. An independent ADMIN reviews it.
6. Request export approval; an independent ADMIN approves it; a separate
   ADMIN-only generation/verification step creates and verifies the package.
7. Generate readiness reports and CSV for internal review. Treat them as
   readiness evidence, not certification.
8. Never edit governance, custody, or audit rows to force a state. Never delete
   evidence or generated exports.

## Known limitations

- Retention evaluation is manual; V35 adds no background scheduler.
- Durations are unset by default and must be configured by the organization.
- There is no per-case ACL; all authenticated roles can read governance records,
  while sensitive reports/audit/actions are capability-gated.
- Local self-digest audit does not prove immutable storage or external
  anchoring. PostgreSQL triggers are a defense-in-depth control, not a
  tamper-proof guarantee against database owners.
- V29 redaction is pattern/name-based and is not universal DLP.
- PostgreSQL trigger behavior is verified by offline SQL generation; the local
  migration cycle uses SQLite. No shared PostgreSQL database is migrated by the
  test suite.
- Windows hosts skip POSIX permission/symlink tests.
- No external transparency provider is configured or independently verified;
  all assurance remains local.
- V35 does not implement actual destruction, deletion, or disposition
  execution. A future volume must separately authorize any such process.

## Validation

```powershell
python -m pytest backend/tests/unit/test_v35_governance.py `
  backend/tests/unit/test_v35_retention.py `
  backend/tests/integration/test_v35_governance_api.py -q
python -m pytest backend/tests/unit/test_v34_forensics.py `
  backend/tests/integration/test_v34_forensics_api.py -q
python -m ruff check backend
python -m ruff format --check backend
python -m compileall -q backend
cd frontend
npm run lint
npm run typecheck
npm run test:run
npm run build
```

The focused tests cover policy versioning, deterministic retention evaluation,
missing metadata, hold overlap and separation of duties, disposition blocking,
export approval/generation/verification separation, audit digest verification,
report aggregation, CSV output, RBAC, pagination, idempotency, and migration
upgrade/downgrade/re-upgrade.
