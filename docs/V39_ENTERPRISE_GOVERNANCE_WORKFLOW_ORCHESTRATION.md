# V39 Enterprise Governance Workflow Orchestration

V39 adds an enterprise governance workflow orchestration and cross-domain
operations layer above V35 governance, V36 automation and snapshots, V37
intelligence and SLA, and V38 executive actions. It composes versioned workflow
templates, persistent workflow instances, dependency-aware tasks, ownership and
reassignment history, read-only cross-domain references, deterministic SLA
indicators, reasoned escalations, and append-only event history.

V39 coordinates review work. It never approves or releases a legal hold, never
approves or rejects a disposition, never deletes or modifies evidence, never
approves or generates an export, never alters custody, never resolves a V37
recommendation, and never completes a V38 strategic action. Human authorization
in the source domain remains authoritative.

## Non-negotiable guarantees

- No evidence deletion, overwrite, path removal, cascade deletion, storage
  cleanup, or evidence destruction is implemented.
- No automatic legal decision, disposition approval or rejection, legal-hold
  approval or release, export approval, custody change, recommendation
  resolution, or executive-action completion is implemented.
- Cross-domain references are read-only pointers. V39 validates that a source
  exists and is readable by the caller, stores a bounded snapshot label and
  version, and never mutates the source record.
- Missing due dates never mean zero time. A missing due date is reported as
  `NOT_APPLICABLE`; an unreadable source is `UNAVAILABLE`; a blocked item is
  `PAUSED`; a cancelled item is `NOT_APPLICABLE`.
- Task dependencies are immutable after instantiation. A graph change requires a
  new template version and a new workflow instance.
- Terminal workflows and tasks are final. V39 exposes no reopen route.
- Workflow completion requires all mandatory tasks to be complete and a bounded
  outcome summary. Optional incomplete tasks remain untouched but cannot be
  written after workflow termination.
- Blocking and cancellation require a reason. Task completion requires an
  outcome. Reassignment requires a reason.
- Every write is idempotent where a client key is accepted, uses optimistic
  concurrency where a version is accepted, and appends an event in the same
  transaction.
- No `DELETE` route exists in the workflow API. Protected history is append-only.
- V39 starts no scheduler and no second worker. SLA and escalation state are
  computed on demand or on explicit user action. The V36 scheduler is untouched
  and remains disabled by default.
- V39 reuses V15 notification delivery, V16 RBAC, V18 observability, V29
  redaction, V33 findings, V34 forensic cases, V35 governance records, V36 jobs
  and snapshots, V37 recommendations and SLA, and V38 actions. It does not
  duplicate those engines.

## Architecture and reuse

V39 lives under `backend/app/governance/workflows/` and is exposed at
`/api/v1/governance/workflows` and the `/governance/workflows` frontend route. It
is additive to the existing `/governance` workspace.

- V16 RBAC: dedicated capabilities for overview reads, detail reads, creation,
  transitions, assignment, task writes, escalation, template management, and
  audit reads. Template management is ADMIN-only.
- V18 observability: bounded-label metrics for workflow and task counts,
  creation outcomes, transition outcomes, dependency outcomes, escalation
  outcomes, overdue counts, and operation latency. Hostile labels normalize to
  `UNKNOWN`; metrics never use IDs, users, cases, or free text as labels.
- V29 redaction: titles, descriptions, reasons, outcomes, references, and event
  details pass through existing redaction helpers before persistence.
- V35 governance audit: workflow writes mirror a bounded audit event through the
  existing governance audit service.
- V37 SLA: `calculate_sla()` remains the single SLA calculation engine. V39
  derives a due-date-based operational target, calls the engine, and maps its
  states into the workflow vocabulary.
- V15 delivery: escalations queue notifications through `GovernanceNotifier`
  when delivery is configured. V39 never claims delivery.

## Lifecycle

Workflow states: `DRAFT`, `READY`, `IN_PROGRESS`, `BLOCKED`, `UNDER_REVIEW`,
`COMPLETED`, `CANCELLED`.

Task states: `PENDING`, `READY`, `IN_PROGRESS`, `BLOCKED`, `COMPLETED`,
`CANCELLED`.

Transitions are strict. An invalid transition returns a stable `409` envelope
with the domain code; a stale `expected_version` returns a version-conflict
`409`. Terminal states are final.

- `DRAFT -> READY -> IN_PROGRESS -> UNDER_REVIEW -> COMPLETED` is the normal
  path.
- `IN_PROGRESS <-> BLOCKED` requires a reason and pauses SLA time.
- `CANCELLED` is reachable from non-terminal states and requires a reason.
- Starting a workflow moves dependency-free tasks from `PENDING` to `READY`.
- Completing a task marks dependent tasks `READY` when all dependencies are
  complete, and appends `DEPENDENCY_SATISFIED`.

## Templates and versioning

Templates are keyed by `template_key` and versioned monotonically. Each version
stores a normalized definition, a deterministic SHA-256 definition digest, task
and dependency counts, and an idempotency key. Creating a new version marks the
previous version `SUPERSEDED` without changing its stored definition. Existing
workflow instances keep a pinned template snapshot and digest.

Template validation rejects duplicate task keys, empty task lists, unknown
dependencies, self-dependencies, cycles, over-limit task counts, over-limit
dependency counts, and out-of-bounds text. A disabled template cannot receive a
new version; disabling is terminal for the template but does not change existing
workflow instances.

## Cross-domain references

Supported domains: `FORENSIC_CASE`, `FORENSIC_FINDING`, `RETENTION_REVIEW`,
`LEGAL_HOLD`, `DISPOSITION`, `EXPORT_APPROVAL`, `AUTOMATION_JOB`,
`RECOMMENDATION`, and `EXECUTIVE_ACTION`.

Resolution distinguishes `AVAILABLE`, `MISSING`, `UNAVAILABLE`, `UNAUTHORIZED`,
and `DELETED`. Attachment rejects non-available sources with a stable
domain-specific error. Case-scoped references must match the workflow's case
boundary. Source authorization is preserved: the caller must hold the existing
source-domain read capability. V39 never fabricates source data and never mutates
a source record.

## Ownership

Workflows and tasks support `USER` and `ROLE` owners. User owners are validated
against the existing identity store and must be active; role owners are validated
against the existing role vocabulary. Assignment and reassignment require a
reason, bump the optimistic version, and append an assignment event. Detail
reads expose ownership history. Overview reports expose unassigned and overdue
counts.

## Escalations

Escalation types: `SLA_OVERDUE`, `SLA_AT_RISK`, `BLOCKED`, `UNASSIGNED`, and
`MANUAL`. Deterministic eligibility checks reject an escalation type that does
not match the current state. Creation requires a reason and an idempotency key.
Acknowledge and resolve require a version and a reason; resolve also requires a
resolution. Escalation transitions are strict and audited. Notifications are
queued through V15 only when configured; delivery is never claimed.

## Event history

Append-only workflow events include `WORKFLOW_CREATED`, `WORKFLOW_STARTED`,
`WORKFLOW_ASSIGNED`, `WORKFLOW_REASSIGNED`, `WORKFLOW_BLOCKED`,
`WORKFLOW_UNBLOCKED`, `WORKFLOW_COMPLETED`, `WORKFLOW_CANCELLED`, `TASK_CREATED`,
`TASK_ASSIGNED`, `TASK_STARTED`, `TASK_BLOCKED`, `TASK_COMPLETED`,
`TASK_CANCELLED`, `DEPENDENCY_SATISFIED`, `ESCALATION_CREATED`,
`ESCALATION_ACKNOWLEDGED`, `ESCALATION_RESOLVED`, `TEMPLATE_CREATED`,
`TEMPLATE_UPDATED`, and `TEMPLATE_DISABLED`. A per-workflow monotonic sequence
makes history order deterministic even when timestamps collide.

## API

All routes are under `/api/v1/governance/workflows`. Reads use bounded
pagination (`page`, `page_size`, maximum 100). Writes use explicit Pydantic
schemas, bounded text, and stable error envelopes. There are no `DELETE` routes.

- `GET /status`, `GET /ownership`
- `GET|POST /templates`, `POST /templates/{key}/versions`,
  `GET /templates/{id}`, `POST /templates/{id}/disable`
- `GET|POST /workflows`, `GET /workflows/{id}`,
  `POST /workflows/{id}/transitions`, `POST /workflows/{id}/assignments`,
  `GET /workflows/{id}/events`
- `GET /tasks`, `GET /workflows/{id}/tasks`,
  `POST /workflows/{id}/tasks/{task_id}/transitions`,
  `POST /workflows/{id}/tasks/{task_id}/assignments`
- `GET|POST /workflows/{id}/references`
- `GET /escalations`, `GET /workflows/{id}/escalations`,
  `POST /workflows/{id}/escalations`,
  `POST /escalations/{id}/acknowledge`, `POST /escalations/{id}/resolve`
- `GET /workflows/{id}/sla`

## Frontend

The `/governance/workflows` route renders `WorkflowWorkspace` beside the existing
governance workspace. It reads the overview status, ownership report, template
list, and paginated workflow list, and exposes detail only to ADMIN/OPERATOR.
VIEWER keeps aggregate reads and sees no write controls. Template creation and
disable controls are ADMIN-only. The workspace shows dependency state, SLA
indicators, read-only reference availability, escalation actions, and the
append-only event sequence. Every mutation uses an explicit reason where the API
requires one and refreshes the bounded detail view after success.

## RBAC

- `governance_workflow_read`: overview, ownership, and SLA reads - all roles.
- `governance_workflow_detail_read`: detail, templates, references, escalation
  lists - ADMIN and OPERATOR.
- `governance_workflow_create`: instantiate workflows - ADMIN and OPERATOR.
- `governance_workflow_transition`: workflow lifecycle - ADMIN and OPERATOR.
- `governance_workflow_assign`: workflow and task ownership - ADMIN and
  OPERATOR.
- `governance_workflow_task_write`: task lifecycle and reference attachment -
  ADMIN and OPERATOR.
- `governance_workflow_escalate`: create, acknowledge, and resolve escalations -
  ADMIN and OPERATOR.
- `governance_workflow_template_manage`: template versions and disable - ADMIN.
- `governance_workflow_audit_read`: append-only event history - ADMIN and
  OPERATOR.

Case boundaries are preserved. A viewer can read aggregate overview status but
cannot read workflow detail or write.

## Configuration

- `governance_workflow_enabled` (default `true`)
- `governance_workflow_page_size` (default `20`, 1-100)
- `governance_workflow_max_active_sample` (default `500`, 1-2000)
- `governance_workflow_default_warning_hours` (default `24`, 1-720)
- `governance_workflow_escalation_notifications_enabled` (default `false`)

## Migration

`016_create_governance_workflows` is a single additive revision after
`015_create_governance_executive`. It creates seven V39 tables with non-cascading
protected references, bounded text, UTC timestamps, unique and idempotency
constraints, version columns, and database triggers that block updates to
append-only tables and deletes on every V39 table. The downgrade drops only V39
objects.

## Validation scope

Local deterministic validation covers the focused V39 suites, the full backend
suite, Ruff, `compileall`, the migration upgrade/downgrade cycle, the frontend
lint/typecheck/tests/build, the workflow SHA audit, and the six Compose
configuration checks. No live PostgreSQL, Redis, Docker runtime, SMTP, webhook,
external service, or production deployment validation is claimed.
