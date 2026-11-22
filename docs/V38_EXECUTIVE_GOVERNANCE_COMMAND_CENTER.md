# V38 Executive Governance Command Center

V38 adds an executive governance command center and strategic decision-support
layer above V35 governance, V36 automation, and V37 intelligence. It composes
deterministic executive KPIs, a versioned health model, compatible historical
comparisons, advisory strategic actions, and bounded local executive reports.

V38 is a read-mostly consumer of existing records. It never executes a
sensitive governance operation, never approves or releases a legal hold, never
decides a disposition, never generates an export on its own, never modifies
evidence, and never deletes a record. It is not a regulatory certification, an
audit opinion, a safety guarantee, a financial metric, or a statistical
forecast.

## Non-negotiable guarantees

- No evidence deletion, overwrite, path removal, cascade deletion, storage
  cleanup, or evidence destruction is implemented.
- No automatic legal decision, disposition approval or rejection, legal-hold
  approval or release, export approval, evidence modification, or policy change
  is implemented.
- Executive KPIs are derived from stored V10–V37 records. A missing or
  unreadable source is reported as `UNAVAILABLE` or `PARTIAL`; it is never
  converted to zero.
- Every KPI exposes its name, definition, source, calculation time, window,
  availability, completeness, and applicable model/policy version.
- Health is a deterministic, versioned (`EXEC_HEALTH_V1`), explainable
  aggregation of fixed signals. The overall status is a severity ranking plus an
  explicit coverage status — never an averaged compliance percentage.
- Historical comparisons read stored snapshots only. They use compatible
  periods and UTC boundaries, mark gaps and unavailable sources, never
  interpolate, and never fabricate a past risk score. Incompatible model or
  policy versions are explained, not hidden.
- Strategic actions link to V37 recommendations but never resolve, dismiss, or
  acknowledge them automatically. Every action has an owner, due date, lifecycle
  history, idempotent creation, and validated transitions.
- Executive reports are bounded local JSON/CSV documents with a self-digest and
  a source snapshot digest validated on read. There is no email, PDF, external
  distribution, publication, or third-party delivery path.
- No `DELETE` route exists in the executive API. Protected reporting history is
  append-only.
- V38 starts no scheduler. Executive views and reports are computed on demand;
  the V36 scheduler is untouched and remains disabled by default.
- V38 reuses V36 `governance_snapshots`. It does not duplicate the V37
  `INTELLIGENCE_SUMMARY` snapshot type or create a second analytics, risk,
  recommendation, dashboard, reporting, audit, scheduler, or auth engine.

## Architecture and reuse

V38 lives under `backend/app/governance/executive/` and is exposed at
`/api/v1/governance/executive` and the `/governance/executive` frontend route.
It is additive to the existing `/governance` workspace.

- V14 analytics conventions: bounded windows, UTC boundaries, explicit
  availability, and `null` rates when a denominator is zero.
- V18 observability: bounded-label metrics, sanitized logs, and request IDs.
- V29 redaction: action text, report payloads, configuration, error details, and
  stored snapshot content pass through existing redaction helpers.
- V33 integrity: latest audit findings by severity are read through an additive
  `latest_findings_by_severity` summary extension.
- V34 forensics: forensic case counts and an additive `integrity_findings` block
  are read through the existing forensic service summary.
- V35 governance: readiness metrics, audits, holds, dispositions, exports, and
  policies are read; action/report/config writes use the existing V35
  `record_access` audit. V38 adds read-only `next_review_known`,
  `retention_deadline_known`, and related coverage counts instead of calling the
  report generator from read paths.
- V36 automation: failed and stale job counts use an additive read-only
  `count_jobs_in_range()`. Snapshots and their canonical SHA-256 self-digest are
  reused unchanged.
- V37 intelligence: risk counts, SLA backlog, and recommendations are read. A
  strategic action may be created only from an `OPEN` or `ACKNOWLEDGED`
  recommendation.
- V16 RBAC: every route requires authentication and an explicit capability. The
  frontend is usability only, never the authorization boundary.

V09 `backend/app/intelligence/` remains the operational event-risk engine. V38
executive health is a governance decision-support aggregate, not an operational
risk score.

## Data model

Alembic revision `015_create_governance_executive` follows
`014_create_governance_intelligence`. It creates exactly three V38-owned tables.
All foreign keys are non-cascading; `downgrade()` drops only the V38 tables.

### `governance_executive_actions`

One row per strategic action. The primary key is a deterministic UUIDv5 derived
from the idempotency key. Rows store the linked V37 recommendation id, rule id,
severity, optional case id, title, description, owner, due date, priority,
lifecycle status, optimistic `version`, completion/block/cancel metadata, and
actor/reason audit fields. Rows are mutable for lifecycle updates and cannot be
deleted.

### `governance_executive_action_events`

Append-only history: `CREATED`, `ASSIGNED`, and `TRANSITIONED`. Rows record the
from/to status, actor, role, reason, bounded detail, and timestamp. Rows are
protected against update and delete.

### `governance_executive_reports`

Report metadata and integrity linkage for generated reports. Each row stores the
report type, format, status, UTC window, generator, V36 snapshot id and type,
schema version, source coverage, available/unavailable sections, payload digest,
report digest, row count, redaction flag, idempotency key, and reason. Rows are
append-only and protected against update and delete.

`governance_snapshots` is reused for the `EXECUTIVE_SUMMARY`, `EXECUTIVE_RISK`,
`EXECUTIVE_SLA`, `EXECUTIVE_OPERATIONS`, and operational `EXECUTIVE_CONFIG`
snapshot types. V38 does not create a fourth table or a second snapshot store.

## Executive KPI catalog

V38 defines 15 ordered KPIs. Each calculation returns the common envelope:
`kpi_id`, `name`, `definition`, `source`, `unit`, `window`, `calculated_at`,
`availability`, `completeness`, `applicable`, `value`, `numerator`,
`denominator`, `detail`, `model_version`, `policy_version`,
`unavailable_reason`, and `source_refs`.

| KPI | Source | Unit | Window |
|---|---|---|---|
| Open forensic cases | V34 forensic cases | count | current state |
| Critical forensic cases | V34 forensic cases | count | current state |
| Critical integrity findings | V33 integrity audit store | count | latest audit run |
| Overdue retention reviews | V35 retention evaluations | count | current state |
| Retention deadlines reached | V35 retention evaluations | count | current state |
| Blocking legal holds | V35 legal holds | count | current state |
| Oldest blocking legal-hold age | V35 legal holds | hours | current state |
| Open disposition reviews | V35 disposition requests | count | current state |
| Pending export approvals | V35 export approvals | count | current state |
| Failed automation jobs | V36 automation jobs | count | rolling window |
| Stale automation jobs | V36 automation jobs | count | current state |
| Open recommendations | V37 recommendations | count | current state |
| Open critical recommendations | V37 recommendations | count | current state |
| Breached or missed SLA items | V37 SLA backlog | count | current state |
| Operational SLA compliance ratio | V37 SLA backlog | ratio | current state |

`completeness` distinguishes `COMPLETE`, `PARTIAL`, and `UNAVAILABLE` and carries
known, unknown, and total counts. `unavailable_reason` is always populated for an
unavailable KPI. `source_coverage` aggregates applicable, available, partial,
and unavailable KPI ids into `COMPLETE`, `PARTIAL`, or `UNAVAILABLE`.

The SLA compliance ratio is a documented operational ratio of known items:
`(WITHIN_TARGET + AT_RISK) / (WITHIN_TARGET + AT_RISK + BREACHED + MISSED)`.
`UNKNOWN` and `NOT_APPLICABLE` items are excluded and reported as coverage gaps.
It is not a blended governance compliance percentage.

## Deterministic health model (`EXEC_HEALTH_V1`)

Health evaluates fixed signals over the KPI catalog. A signal is evaluated only
when its KPI is applicable, available, and numeric. An unavailable KPI is a
coverage gap, never a zero and never a passing signal.

| Signal | KPI | Rule | Status |
|---|---|---|---|
| `CRITICAL_INTEGRITY_FINDINGS` | Critical integrity findings | `>= 1` | `CRITICAL` |
| `SLA_BREACHED_ITEMS` | Breached or missed SLA items | `>= 1` | `DEGRADED` |
| `CRITICAL_FORENSIC_CASES` | Critical forensic cases | `>= 1` | `DEGRADED` |
| `BLOCKING_LEGAL_HOLD_AGE` | Oldest blocking legal-hold age | `>= 168h` | `DEGRADED` |
| `OVERDUE_GOVERNANCE_REVIEWS` | Overdue retention reviews | `>= 1` | `ATTENTION_REQUIRED` |
| `OPEN_CRITICAL_RECOMMENDATIONS` | Open critical recommendations | `>= 1` | `ATTENTION_REQUIRED` |
| `FAILED_AUTOMATION_JOBS` | Failed automation jobs | `>= 1` | `ATTENTION_REQUIRED` |
| `STALE_AUTOMATION_JOBS` | Stale automation jobs | `>= 1` | `ATTENTION_REQUIRED` |
| `PENDING_EXPORT_APPROVALS` | Pending export approvals | `>= 1` | `ATTENTION_REQUIRED` |

The overall status is the highest triggered severity:
`HEALTHY`, `ATTENTION_REQUIRED`, `DEGRADED`, `CRITICAL`, or `UNAVAILABLE`.
`UNAVAILABLE` is a coverage outcome, not a severity. If no signal triggers,
complete coverage yields `HEALTHY` and partial coverage yields
`ATTENTION_REQUIRED`. If no applicable KPI is available, the result is
`UNAVAILABLE`. Thresholds are fixed in `EXEC_HEALTH_V1`; they are not
configurable, and `averaged_score_used` is always `false`. The response includes
the evaluated and triggered signals, each signal's explanation and source
availability, the fixed threshold block, coverage detail, and non-claims.

## Strategic actions

Strategic actions are internal governance tracking records linked to a V37
recommendation.

- Creation requires a V37 recommendation in `OPEN` or `ACKNOWLEDGED` state.
  `DISMISSED` and `RESOLVED` recommendations return
  `409 RECOMMENDATION_NOT_ACTIONABLE`.
- Creation requires title, owner, due date, and a reason, plus an idempotency
  key. The deterministic action id and action event are not duplicated on replay.
- Lifecycle statuses are `OPEN`, `IN_PROGRESS`, `BLOCKED`, `COMPLETED`, and
  `CANCELLED`.
- Allowed transitions:
  - `OPEN -> IN_PROGRESS | BLOCKED | COMPLETED | CANCELLED`
  - `IN_PROGRESS -> BLOCKED | COMPLETED | CANCELLED`
  - `BLOCKED -> IN_PROGRESS | CANCELLED`
  - `COMPLETED` and `CANCELLED` are terminal.
- Every transition requires `expected_version` for optimistic concurrency and
  returns `409` on a stale version. Completion requires an outcome summary;
  blocking requires a block reason; cancellation requires a cancel reason.
- Assignment and reassignment require an owner and a reason, increment the
  version, and append an `ASSIGNED` event.
- The linked V37 recommendation is never resolved, dismissed, or acknowledged
  automatically. No action approves or releases a hold, decides a disposition,
  generates an export, or modifies evidence.

## Executive reports

V38 supports four report types: `EXECUTIVE_SUMMARY`, `EXECUTIVE_RISK`,
`EXECUTIVE_SLA`, and `EXECUTIVE_OPERATIONS`, in `json` or `csv`.

- Every payload uses a deterministic section order: `executive_health`, `kpis`,
  `risk`, `sla`, `operations`, `actions`, `source_coverage`, `assurance`.
- Every section carries an explicit availability. A source that cannot be read
  is marked `UNAVAILABLE` with a reason; no section is silently omitted.
- Payloads are bounded by row count, payload bytes, and CSV bytes. Oversized
  reports fail with a stable `503` rather than truncating silently.
- JSON keys are sorted and CSV is a deterministic flattened `path,value`
  export. Re-generating with the same type and idempotency key replays the
  existing report without duplication or re-audit.
- Each report stores a payload digest and a report digest. Reads validate both,
  plus the source V36 snapshot self-digest. Tampering raises a stable integrity
  error and the report is preserved for investigation.
- Report views audit `EXECUTIVE_REPORT_VIEWED`.
- Reports are never emailed, published, externally distributed, or rendered as
  PDF.

## Compatible historical comparisons

Comparisons read stored report snapshots only. They are available as:

- `GET /comparisons/{report_id}` — compare a stored report with the current
  period.
- `GET /comparisons/{report_id}/vs/{other_report_id}` — compare two stored
  reports.

A comparison is `COMPARABLE`, `INCOMPATIBLE`, or `UNAVAILABLE`. Period length,
UTC boundaries, health model version, risk model version, policy version, and
schema version are checked. Incompatible periods or model versions return
`INCOMPATIBLE` with explained `incompatibilities` and no delta. Unavailable
sources produce explicit `gaps` without a delta. Comparisons never interpolate
missing buckets, never fabricate a historical risk score, and always report
`interpolated=false` and `fabricated_history=false`.

## Configuration

Operational configuration is append-only. A config write appends an
`EXECUTIVE_CONFIG` snapshot through V36 storage and audits
`EXECUTIVE_CONFIG_UPDATED`. The supported keys are:

- `default_window_days` (1–90)
- `comparison_period_days` (1–90)
- `action_due_soon_hours` (1–720)
- `report_max_rows` (50–5000)
- `include_recommendations_in_summary`
- `health_thresholds_fixed` (must remain `true`)

Health thresholds remain fixed in `EXEC_HEALTH_V1` and cannot be changed through
configuration. Unknown keys and invalid ranges are rejected with a stable
validation error. Configuration writes are ADMIN-only and require a reason.

## API and RBAC

Base path: `/api/v1/governance/executive`.

| Method and path | Purpose | Capability |
|---|---|---|
| `GET /status` | Status and source availability | `governance_executive_read` |
| `GET /health` | Deterministic health | `governance_executive_read` |
| `GET /kpis` | Source-preserving KPIs | `governance_executive_read` |
| `GET /actions` | List actions (bounded, paginated) | `governance_executive_action_read` |
| `POST /actions` | Create an action | `governance_executive_action_write` |
| `GET /actions/{id}` | Action detail and event history | `governance_executive_action_read` |
| `POST /actions/{id}/transition` | Validated lifecycle transition | `governance_executive_action_write` |
| `POST /actions/{id}/assign` | Assign or reassign an owner | `governance_executive_action_assign` |
| `GET /reports` | Report metadata | `governance_executive_detail_read` |
| `POST /reports` | Generate a bounded local report | `governance_executive_report_generate` |
| `GET /reports/{id}` | Report metadata and payload | `governance_executive_detail_read` |
| `GET /reports/{id}/content` | Stored JSON/CSV content | `governance_executive_detail_read` |
| `GET /comparisons/{id}` | Compare with the current period | `governance_executive_detail_read` |
| `GET /comparisons/{id}/vs/{other}` | Compare two stored reports | `governance_executive_detail_read` |
| `GET /config` | Read operational configuration | `governance_executive_detail_read` |
| `PUT /config` | Append operational configuration | `governance_executive_configure` |

Role mapping:

- Summary reads: ADMIN, OPERATOR, VIEWER.
- Detail, action, and report reads: ADMIN, OPERATOR.
- Report generation, action assignment, and configuration writes: ADMIN only.
- Action create/transition: ADMIN, OPERATOR.

All list routes are bounded and paginated. All queries are parameterized. Error
envelopes are stable: `404`, `409`, `422`, `503`, and `403` codes are preserved.
No `DELETE` route exists for protected reporting history.

## Frontend

`/governance/executive` renders the V38 command center. The existing
`/governance` page adds a compact link card to it. The workspace uses the
existing design system, chart primitives, and role-aware controls:

- Executive status and health cards with explicit coverage.
- KPI table with definition, value, availability, completeness, source, and
  model/policy versions.
- Action list, detail, lifecycle history, validated transitions, and
  ADMIN-only assignment.
- Report list, detail, digest state, unavailable sections, and local download.
- Current-period and stored-report comparisons with incompatibility and gap
  explanations.
- ADMIN-only report generation and append-only configuration.
- Loading, empty, partial, unavailable, and error states. Missing data is shown
  as unavailable, never as zero, and stale data is not substituted.

## Observability and metrics

Bounded-label Prometheus metrics are added for executive health status, KPI
availability, action status counts, report generation outcome, comparison
status, and action transitions. Metric label values are a fixed vocabulary; no
case id, recommendation id, action id, report id, policy id, or free-text value
becomes a label. Logs and error details pass through the V29 redaction helpers.
Request IDs are preserved through the existing middleware.

## Configuration

```powershell
$env:GOVERNANCE_EXECUTIVE_ENABLED="true"
$env:GOVERNANCE_EXECUTIVE_PAGE_SIZE="20"
$env:GOVERNANCE_EXECUTIVE_DEFAULT_WINDOW_DAYS="30"
$env:GOVERNANCE_EXECUTIVE_MAX_ACTIONS="500"
$env:GOVERNANCE_EXECUTIVE_MAX_REPORT_ROWS="500"
$env:GOVERNANCE_EXECUTIVE_REPORT_MAX_BYTES="524288"
$env:GOVERNANCE_EXECUTIVE_COMPARISON_PERIOD_DAYS="30"
$env:GOVERNANCE_EXECUTIVE_ACTION_DUE_SOON_HOURS="72"
```

When `GOVERNANCE_EXECUTIVE_ENABLED=false`, the API returns `503`. V38 starts no
scheduler and does not modify V36 scheduling.

## Testing and validation

The V38 suite is synthetic, deterministic, and local-only. It covers:

- KPI envelopes, source availability, completeness, and never-zero behavior.
- Health determinism, severity ranking, coverage, and fixed thresholds.
- Compatible and incompatible comparisons, UTC boundaries, gaps, and absence of
  interpolation or fabricated history.
- Action creation idempotency, lifecycle validation, optimistic concurrency,
  RBAC, audit history, and no automatic recommendation resolution.
- Report JSON/CSV determinism, idempotency, size bounds, redaction, source
  coverage, unavailable sections, and digest/tamper validation.
- Configuration append-only writes, replay, and fixed health thresholds.
- Cross-case isolation, metrics cardinality, migration upgrade/downgrade, and
  concurrency.
- V10/V14/V15/V16/V29–V37 regression smoke checks.

Local validation executes the full backend suite, focused V38 tests, Ruff check
and format, `compileall`, frontend lint/typecheck/tests/build, the migration
cycle, workflow pinning audit, and all six Compose configuration checks. A live
PostgreSQL migration, live object storage, live SMTP/webhook delivery, browser
runtime, scheduler timing, and production deployment are deployment validation
steps and are not claimed by the local suite.

## Operations and recovery

1. Run the Alembic upgrade to `015_create_governance_executive` before enabling
   the V38 API. The revision is additive and reversible.
2. Keep `GOVERNANCE_EXECUTIVE_ENABLED=true` unless the workspace must be
   disabled; `503` is returned when disabled or unavailable.
3. Review `/status`, `/health`, and `/kpis` before trusting a summary. Treat
   `PARTIAL`, `UNAVAILABLE`, `truncated`, and `unknown` as explicit data-quality
   states.
4. Review configuration source digests and fixed health thresholds before
   changing operating cadence.
5. Plan capacity for retained action, event, and report metadata. V38 performs
   no pruning and exposes no `DELETE` route.
6. To roll back, stop executive writes, run the Alembic downgrade to
   `014_create_governance_intelligence`, and restore the pre-upgrade backup if
   V38 rows must be discarded. Downgrading drops only V38 tables and does not
   touch V01–V37 schema, evidence, custody, exports, holds, dispositions, audit,
   automation, or intelligence records.

## Limitations and non-claims

- V38 aggregates stored records; it does not independently verify evidence,
  re-run integrity checks, repair findings, or backfill missing history.
- Health is a deterministic local aggregate, not regulatory certification, an
  SLA warranty, a safety guarantee, or a statistical forecast.
- The SLA compliance ratio covers known operational items only and excludes
  unknown sources; it is not a blended governance compliance percentage.
- Reports are local JSON/CSV records with self-digests. They are not externally
  anchored, immutable, or distributed.
- Comparisons are limited to stored compatible snapshots; no historical value is
  reconstructed.
- Strategic actions are advisory internal tracking records and never execute a
  sensitive governance operation.
- PostgreSQL trigger behavior is covered by offline SQL generation and SQLite
  integration tests; a live PostgreSQL migration remains a deployment step.
