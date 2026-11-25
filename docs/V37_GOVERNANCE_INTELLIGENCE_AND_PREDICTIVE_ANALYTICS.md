# V37 Governance Intelligence and Predictive Analytics

V37 adds deterministic, explainable governance intelligence above V35
governance and V36 automation. It scores governance risk, tracks versioned
operational SLAs, reports bounded backlog and trend analytics, raises advisory
recommendations, and compares local governance snapshots. It does not use an
LLM, machine learning, statistical forecasting, or an external AI service, and
it never makes an automatic governance decision.

"Predictive" in V37 means deterministic forward-looking prioritization and
operational due dates. It is not a probability, forecast, legal opinion, or
regulatory certification.

## Non-negotiable guarantees

- No evidence deletion, overwrite, path removal, cascade deletion, storage
  cleanup, or evidence destruction is implemented.
- No automatic legal decision, disposition approval or rejection, legal-hold
  approval or release, export generation, evidence modification, or policy
  change is implemented.
- Confirmed integrity failures are scored only when a V34 forensic verification
  outcome is `FAIL`. `PARTIAL`, `UNAVAILABLE`, `NOT_RUN`, simulated, and
  incomplete checks are never described as confirmed failures or as `PASS`.
- Risk scores are deterministic rule-based prioritization aids in `0..100`.
  They are not calibrated probabilities, forecasts, or legal advice.
- Operational SLA targets are organization-configurable and versioned. They are
  distinct from legal or regulatory deadlines.
- Backlog and trend analytics use actual historical records, explicit bounded
  windows, and explicit coverage gaps. An unavailable source is never reported
  as zero.
- Recommendations are advisory and auditable. Dismissal requires a reason and is
  ADMIN-only. No recommendation executes an action.
- Intelligence snapshots are local aggregate records with a self-digest. They
  are not regulatory certification, external immutable storage, or an external
  trust anchor.
- No `DELETE` route exists in the intelligence API.
- V37 starts no scheduler. Intelligence is computed on demand; V36 scheduling
  is untouched and remains disabled by default.

## Architecture and reuse

V37 lives under `backend/app/governance/intelligence/` and is additive to the
existing `/governance` workspace. It does not create a second analytics engine,
scheduler, policy engine, notification system, audit system, or integrity
service.

- V35 governance: risk inputs come from retention evaluations, legal holds,
  dispositions, export approvals, and enabled policies. V37 records audit events
  through the existing V35 governance audit.
- V36 automation: intelligence snapshots reuse the existing
  `governance_snapshots` table, canonical JSON encoding, and SHA-256
  self-digest. V37 adds the `INTELLIGENCE_SUMMARY` snapshot type; the V36
  `COMPLIANCE_SUMMARY` type is unchanged.
- V34 forensics: latest verification outcomes and case severity/status are read
  without re-verifying, repairing, or rewriting evidence.
- V10 incidents: an originating incident contributes a bounded risk factor when
  it is non-terminal.
- V14 analytics conventions: bounded windows, UTC buckets, explicit
  availability, and `null` rates when the denominator is zero.
- V15 notifications: newly opened `CRITICAL` recommendations may notify through
  the existing `GovernanceNotifier` only when
  `GOVERNANCE_INTELLIGENCE_ALERTS_ENABLED=true`. The default is off, and no new
  delivery mechanism exists.
- V16 RBAC: every route requires authentication and an explicit capability. The
  frontend is usability only, never the authorization boundary.
- V18 observability: bounded-label metrics, sanitized logs, and request IDs.
- V29 redaction: rationales, dismissal reasons, source references, and error
  details pass through existing redaction helpers.

V09 `backend/app/intelligence/` remains the operational event-risk engine. V37
`backend/app/governance/intelligence/` is governance risk over forensic and
governance records; the two risk concepts are intentionally separate.

## Data model

Alembic revision `014_create_governance_intelligence` follows
`013_create_governance_automation`. It creates only four V37-owned tables. All
foreign keys are non-cascading; `downgrade()` drops only the V37 tables.

### `governance_risk_models`

Versioned deterministic model definitions. Each row stores `model_id`,
`version`, `name`, `state`, `thresholds`, `factor_points`, `effective_from`,
actor/reason metadata, and `created_at`. Rows are append-only and protected by
database triggers. The seeded platform default is `RISK-DEFAULT` v1.

### `governance_sla_targets`

Versioned operational targets per bounded target key. Each row stores
`target_key`, `version`, `target_hours`, `warning_hours`, `effective_from`, and
actor/reason metadata. Rows are append-only. v1 seeds four targets from the Unix
epoch so historical records resolve a version.

### `governance_recommendations`

One deduplicated row per `rule_id|scope_type|scope_id`. The primary key is a
deterministic UUIDv5 derived from that key. Rows carry severity, risk level,
title, rationale, source references, lifecycle status, optimistic `version`, and
acknowledgement/dismissal/resolution metadata. Rows are mutable for lifecycle
updates and cannot be deleted.

### `governance_recommendation_events`

Append-only lifecycle history: `CREATED`, `REFRESHED`, `ACKNOWLEDGED`,
`DISMISSED`, `RESOLVED`, `REOPENED`, and `AUTO_RESOLVED`. Rows are protected
against update and delete.

`governance_snapshots` is reused unchanged. `INTELLIGENCE_SUMMARY` payloads are
aggregate-only: no case IDs, evidence IDs, or evidence bytes.

## Deterministic risk model

### Thresholds (model v1)

| Level | Range |
|---|---|
| `LOW` | 0–24 |
| `MODERATE` | 25–49 |
| `HIGH` | 50–74 |
| `CRITICAL` | 75–100 |

Score = `min(100, sum(selected factor points))`. A new model version must
validate a contiguous, ordered partition of `0..100`; factor points are bounded
`0..50` and unknown factors are rejected. Historical scores retain the model
version used at calculation time.

### Factor catalog (model v1)

| Factor | Points | Condition |
|---|---:|---|
| `CONFIRMED_INTEGRITY_FAILURE` | 45 | Latest V34 verification outcome is `FAIL` |
| `INTEGRITY_VERIFICATION_PARTIAL` | 12 | Outcome is `PARTIAL`; explicitly not a confirmed failure |
| `INTEGRITY_VERIFICATION_UNAVAILABLE` | 0 | Outcome is `UNAVAILABLE` |
| `INTEGRITY_VERIFICATION_NOT_RUN` | 0 | `NOT_RUN` or no verification |
| `INTEGRITY_VERIFICATION_SIMULATED` | 0 | Simulated/local-test verification |
| `RETENTION_REVIEW_OVERDUE` | 20 / 10 | Review overdue >7 days / ≤7 days |
| `DISPOSITION_REVIEW_OVERDUE` | 15 | Pending disposition past its operational SLA |
| `DISPOSITION_BLOCKED` | 15 | Blocked for a non-integrity reason |
| `LEGAL_HOLD_REVIEW_OVERDUE` | 10 | Active or pending hold past its operational SLA |
| `EXPORT_APPROVAL_EXPIRED` | 15 | Approval expired |
| `EXPORT_APPROVAL_EXPIRING` | 8 | Expiry within 7 days |
| `POLICY_MISSING_OR_DISABLED` | 10 | No enabled applicable policy |
| `LINKED_OPEN_INCIDENT` | 10 | Originating V10 incident is non-terminal |
| `CASE_SEVERITY_HIGH` | 10 | Case severity `HIGH` |
| `CASE_SEVERITY_CRITICAL` | 15 | Case severity `CRITICAL` |

### Correlation and double-counting suppression

Factors declare fixed correlation groups. Only the highest-points factor in a
group contributes; suppressed factors remain visible with `suppressed=true`,
`suppressed_by`, and a reason.

- Integrity verification states are one group.
- Expired export approval supersedes expiring approval.
- `CRITICAL` case severity supersedes `HIGH`.
- A disposition blocked by `INTEGRITY_NOT_PASS` or `INTEGRITY_UNAVAILABLE` is
  suppressed when an integrity factor is already selected.

### Explanation contract

Every score returns:

- `score`, `risk_level`, `model_id`, `model_version`;
- ordered `factors[]` with factor ID, label, points, reason, source references,
  data status, correlation group, and suppression state;
- `policy_context` (policy ID/version/state, case type, evidence category);
- `calculated_at` in UTC;
- `data_completeness` (`COMPLETE`, `PARTIAL`, `UNAVAILABLE`);
- `missing_data[]` with source, status, and an honest explanation;
- `non_claims`.

A failed verification read is `UNAVAILABLE`; it is never converted into a
failure or a pass.

## Operational SLAs

Default v1 targets:

| Target key | Target | Warning window |
|---|---:|---:|
| `RETENTION_REVIEW` | 720h (30d) | 168h (7d) |
| `DISPOSITION_REVIEW` | 240h (10d) | 48h (2d) |
| `LEGAL_HOLD_REVIEW` | 168h (7d) | 24h (1d) |
| `EXPORT_APPROVAL` | 120h (5d) | 24h (1d) |

Each calculation resolves the target version effective at the item's start
time. Later versions never rewrite historical calculations. A missing start or
no effective version returns `UNKNOWN` with an explanation, not zero.

Unresolved states are `WITHIN_TARGET`, `AT_RISK`, and `BREACHED`. Resolved
states are `MET` and `MISSED`. Unresolved items expose only `open_age_hours`;
`duration_hours` remains `null` and `resolved=false`. Every result carries
`sla_kind=OPERATIONAL` and a non-claim that legal/regulatory deadlines are not
modeled.

## Backlog and trend analytics

The SLA backlog is computed on demand from current V35 records. Each section
reports its own availability: retention evaluations, open dispositions, blocking
legal holds, and open export approvals. A failed read makes that section
`UNAVAILABLE` and is never rendered as an empty or zero backlog. Items are
ordered by open age, and unresolved items expose only `open_age_hours`.

Trends reuse the V14 bounded-window convention. A request may span at most 90
days; the default window is 30 days and buckets are `hour`, `day`, or `week` in
UTC. Five sources are reported:

| Source | Definition |
|---|---|
| `governance_events` | V35 access-audit events grouped into bounded categories |
| `retention_evaluations` | Retention evaluation observations by governance state |
| `recommendations` | Recommendation lifecycle events |
| `sla_inflow` | Disposition, hold, export, and retention-review inflow by target key |
| `risk_scores` | Deliberately `UNAVAILABLE`: historical scores are not persisted |

Every source reports `availability`, `definition`, `coverage_start`,
`coverage_available`, `no_history`, `truncated`, `total`, `categories`,
`category_totals`, and `buckets[]`. Bucket rules are explicit:

- A bucket before the earliest stored record is `count=null` and
  `coverage=BEFORE_COVERAGE`; it is not a zero.
- A bucket that straddles the first stored record is marked
  `partial_coverage=true`.
- A bucket inside recorded coverage with no rows is a genuine `count=0`.
- When coverage itself cannot be read, `in_coverage` is `null` and
  `coverage=UNKNOWN` rather than being asserted.
- A source that cannot be read reports `count=null` in every bucket, even if
  some rows were available before the failure.
- A source with no recorded history reports `NO_HISTORY` and `count=null`.

Row caps produce explicit `truncated` flags and a `partial` response. Historical
gaps are never silently interpolated, and no forecast or statistical model is
used.

## Recommendations

Deterministic rules raise advisory recommendations with stable UUIDv5
identifiers and `rule_id|scope_type|scope_id` deduplication keys. Supported rules
cover critical/high risk cases, confirmed or unavailable integrity verification,
overdue retention and disposition reviews, overdue legal-hold review, expired
export approval, snapshot integrity attention, and automation health. Every
candidate carries a rationale and source references.

Lifecycle transitions are optimistic-concurrency guarded:

- `OPEN -> ACKNOWLEDGED`, `DISMISSED`, or `RESOLVED`;
- `ACKNOWLEDGED -> DISMISSED` or `RESOLVED`;
- `DISMISSED -> OPEN` only when a recurrence is observed;
- source-condition clearing auto-resolves to `RESOLVED` with actor `SYSTEM`;
- a later recurrence reopens the same deduplicated row.

Acknowledged and dismissed rows keep append-only lifecycle events. Dismissal
requires a reason of at least 3 characters, is ADMIN-only, and suppresses the
same candidate only while its condition persists. Refresh is bounded,
idempotent, and performs no governance mutation. Newly created `CRITICAL`
recommendations may notify through the existing V15 notifier only when
`GOVERNANCE_INTELLIGENCE_ALERTS_ENABLED=true`; the default is off.

Lifecycle writes use a compare-and-set update on the observed `version`, not a
read-modify-write in application code. Two concurrent transitions with the same
expected version therefore produce one success and one `409` conflict, and
exactly one lifecycle event. A concurrent refresh that loses a unique-key race
rolls back and retries once against the winner's row, so duplicate suppression
holds without surfacing a database error.

## Snapshot generation and comparison

Manual generation reuses the V36 snapshot repository and canonical SHA-256
self-digest. `INTELLIGENCE_SUMMARY` payloads contain aggregate model, risk, SLA,
recommendation, automation, and coverage data only — no case IDs, evidence IDs,
or evidence bytes.

- List responses omit the stored payload; detail responses include it with an
  explicit `integrity.state` of `VALID` or `INTEGRITY_FAILED`.
- Generation is idempotent per idempotency key; a replay returns the existing
  snapshot without creating another row.
- Comparison accepts only the same snapshot type and schema version. A different
  type or schema returns `INCOMPATIBLE`.
- Recomputing either digest yields `INTEGRITY_FAILED` with
  `tampered_snapshot_ids` and no diff.
- Successful comparison returns a bounded `COMPARED` diff with
  `added`/`removed`/`changed` counts and a `truncated` flag.
- Comparison never modifies, rewrites, or deletes either snapshot.

## Frontend

The existing `/governance` page renders `IntelligenceWorkspace` above the V36
automation workspace. It shows the active model version, factor explanations,
missing or unavailable data, operational SLA targets and backlog, bounded trend
buckets with explicit unavailable markers, the advisory recommendation lifecycle,
and snapshot generation/comparison. Controls are RBAC-aware; dismissal and
generation use confirmation dialogs with required reasons. No separate
governance application is introduced.

## API and RBAC

Prefix: `/api/v1/governance/intelligence`. No `DELETE` routes.

| Method / path | Capability |
|---|---|
| `GET /status` | `governance_intelligence_read` |
| `GET /risk/model` | `governance_risk_read` |
| `GET /risk/model/versions` | `governance_risk_read` |
| `PUT /risk/model` | `governance_intelligence_configure` |
| `GET /risk/cases` | `governance_risk_read` |
| `GET /risk/cases/{case_id}` | `governance_risk_read` |
| `GET /sla/targets` | `governance_sla_read` |
| `PUT /sla/targets/{target_key}` | `governance_intelligence_configure` |
| `GET /sla/backlog` | `governance_sla_read` |
| `GET /trends` | `governance_trends_read` |
| `POST /recommendations/refresh` | `governance_intelligence_refresh` |
| `GET /recommendations` | `governance_recommendations_read` |
| `GET /recommendations/{recommendation_id}` | `governance_recommendations_read` |
| `POST /recommendations/{recommendation_id}/acknowledge` | `governance_recommendation_acknowledge` |
| `POST /recommendations/{recommendation_id}/dismiss` | `governance_recommendation_dismiss` |
| `GET /snapshots` | `governance_snapshot_read` |
| `POST /snapshots` | `governance_snapshot_generate` |
| `GET /snapshots/{snapshot_id}` | `governance_snapshot_read` |
| `GET /snapshots/{snapshot_id}/compare/{other_snapshot_id}` | `governance_snapshot_read` |

Capability map:

- Intelligence, risk, SLA, trends, and recommendation reads: ADMIN, OPERATOR,
  VIEWER.
- Recommendation acknowledge and refresh: ADMIN, OPERATOR.
- Recommendation dismiss and intelligence configure: ADMIN only.
- Snapshot read/generate reuse existing V36 capabilities.

Pagination is bounded (`page >= 1`, `page_size <= 100`). Risk and trend windows
are bounded to 90 days. Stable error envelopes are used; `503` means intelligence
is disabled or unavailable, `403` means RBAC denial, `404` means unknown ID,
`409` means a version or integrity conflict, and `422` means invalid input.
Responses expose bounded identifiers, counts, states, reasons, and source
references only — never evidence bytes.

## Configuration

| Setting | Default | Meaning |
|---|---|---|
| `GOVERNANCE_INTELLIGENCE_ENABLED` | `true` | Enable the intelligence service |
| `GOVERNANCE_INTELLIGENCE_PAGE_SIZE` | `20` | Default bounded page size |
| `GOVERNANCE_INTELLIGENCE_MAX_CASES` | `500` | Maximum cases scored per request |
| `GOVERNANCE_INTELLIGENCE_MAX_RECOMMENDATIONS` | `500` | Maximum recommendations per refresh |
| `GOVERNANCE_INTELLIGENCE_DEFAULT_WINDOW_DAYS` | `30` | Default bounded trend window |
| `GOVERNANCE_INTELLIGENCE_ALERTS_ENABLED` | `false` | Optional V15 critical alerts |
| `GOVERNANCE_INTELLIGENCE_ALERT_MIN_SEVERITY` | `CRITICAL` | Minimum alert severity |

No intelligence scheduler setting exists.

## Observability and security

Metrics use bounded labels only: risk level, data completeness, SLA target key,
SLA state, recommendation status/severity, refresh outcome, and comparison
status. Actor IDs, case IDs, recommendation IDs, evidence IDs, and
user-controlled strings are never metric labels. Logs and error details pass
through V29 redaction.

## Testing and validation

The V37 suite is synthetic, deterministic, and local-only. It covers risk-score
determinism, factor completeness, correlation suppression, confirmed versus
unavailable/simulated integrity states, versioned SLA history, bounded trend
windows, historical coverage gaps, unavailable-not-zero sources, recommendation
deduplication and lifecycle, concurrent transitions and refreshes, cross-case
isolation, metric cardinality, malicious identifiers and ranges, snapshot
idempotency, tamper detection, incompatible comparison, RBAC, migration
upgrade/downgrade, and V10/V14/V15/V16/V29-V36 regression smoke checks. A
downgrade test seeds V35 audit history and a V36 snapshot, then proves both rows
survive `014 -> 013 -> 014`.

The focused V37 suite is 48 tests (14 hardening, 14 analytics, 17 foundation,
and 3 migration). The final local full backend run recorded 2266 passed, 4
skipped, and 11 deselected; the frontend suite recorded 132 passed across 26
files. Ruff check/format, `compileall`, the workflow SHA-pin audit, and all six
Compose configuration checks passed.

The suite does not validate a live PostgreSQL migration, live SMTP/webhook
delivery, real scheduler timing, Docker runtime containers, external trust
anchors, or a production deployment.

## Limitations and non-claims

- Risk scoring is computed on demand from existing V35/V36 records.
- Scores are deterministic prioritization aids, not probabilities or forecasts.
- Operational SLAs are not legal or regulatory deadlines.
- Recommendation dismissal suppresses re-raising only while the same condition
  persists.
- Snapshot comparison verifies a local self-digest only. It cannot prove
  external immutability or regulatory compliance.
- No live PostgreSQL migration, external notification delivery, scheduler
  timing, Docker runtime, external anchor, or production deployment was
  validated by the local V37 test suite.

## Relationship to V38 executive governance

V38 adds an advisory executive command center above V35/V36/V37 without changing
V37 risk models, SLA targets, recommendations, recommendation events,
`INTELLIGENCE_SUMMARY` snapshots, or scoring semantics. V38 reads current risk
counts, SLA backlog states, and recommendations, and it exposes executive health
as a separate versioned governance aggregate (`EXEC_HEALTH_V1`), distinct from
the V37 operational risk score. A strategic action may be created only from an
`OPEN` or `ACKNOWLEDGED` V37 recommendation; V38 never resolves, dismisses, or
acknowledges a recommendation automatically, and a `DISMISSED` or `RESOLVED`
recommendation returns `409 RECOMMENDATION_NOT_ACTIONABLE`. V38 adds no LLM,
machine learning, forecast, or external AI service, starts no scheduler, and
adds the additive revision `015_create_governance_executive`. See
[V38_EXECUTIVE_GOVERNANCE_COMMAND_CENTER.md](V38_EXECUTIVE_GOVERNANCE_COMMAND_CENTER.md).

## Relationship to V39 workflow orchestration

V39 reuses V37 `calculate_sla()` as the single SLA calculation engine. It maps
the V37 SLA states into workflow and task states; a missing due date is
`NOT_APPLICABLE`, a blocked item is `PAUSED`, and an unreadable source is
`UNAVAILABLE`. V39 references recommendations read-only and never resolves,
dismisses, or acknowledges one automatically. It starts no scheduler and adds the
additive revision `016_create_governance_workflows`; no V37 table is altered.
See
[V39_ENTERPRISE_GOVERNANCE_WORKFLOW_ORCHESTRATION.md](V39_ENTERPRISE_GOVERNANCE_WORKFLOW_ORCHESTRATION.md).
