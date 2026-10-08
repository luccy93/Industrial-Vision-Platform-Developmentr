# Incident Management — V10 Operational Layer

> V10 is an **operational incident-management layer**. It does not perform
> detection, tracking, safety analysis, quality inspection, autonomous
> perception, or risk scoring. Those responsibilities remain in V03–V09.
>
> Authentication and RBAC are intentionally deferred to V16: operators are
> opaque identifier strings, never validated identities.

```text
V05 Safety / V06 Spatial / V07 Quality / V08 Autonomous
      ↓
V09 Event & Risk Intelligence (clusters, unified events, risk)
      ↓
V10 Incident Management (incidents, lifecycle, timeline, evidence)
```

## Lifecycle

Explicit state machine (invalid moves return HTTP 409)::

```text
OPEN → ACKNOWLEDGED | INVESTIGATING | RESOLVED
ACKNOWLEDGED → INVESTIGATING | MITIGATED | RESOLVED
INVESTIGATING → MITIGATED | RESOLVED
MITIGATED → RESOLVED
RESOLVED → CLOSED
CLOSED → (terminal)
```

There is no REOPENED state: a new V09 cluster after closure creates a new
incident, and incidents are never silently reopened.

## Creation policy

Automatic creation consumes `RiskIntelligenceResult` / `RiskCluster` /
`UnifiedEvent` through the `IncidentManager` service boundary (never V09
private state). A cluster is incident-eligible when its priority is at least
as urgent as `INCIDENT_MIN_PRIORITY` (default P2 → P0/P1/P2 eligible).
Deduplication key is `(camera_id, source_cluster_id)` among non-closed
incidents, backstopped by a partial unique database index. Repeated updates
refresh risk/severity/priority/last-seen and link new events; timeline rows
appear only on meaningful change (risk-level change or the update-threshold
window). Resolved clusters never spawn duplicates.

Manual incidents (`source = MANUAL`) may exist without any cluster.

## Assignment, escalation, investigation

Assignment references stable operator identifier strings without validation.
Every assignment records previous/new assignee, actor, and timestamp in both
the audit table and the timeline. Escalation moves priority toward P0 (or to
an explicit target with mandatory reason); every change records old/new
priority, reason, timestamp, and actor — never silently. Investigation
entries record notes, findings, actions, and observations as timeline rows.

## Mitigation, resolution, closure

Mitigation records actor/timestamp/reason without claiming permanence.
Resolution requires a reason (`FALSE_ALARM`, `HAZARD_REMOVED`,
`OPERATOR_ACTION`, `AUTOMATIC_CLEAR`, `QUALITY_REWORKED`, `OTHER`) and is
never silent. Only `OPEN` incidents auto-resolve (configurable grace after
the underlying risk clears); acknowledgement and investigation states are
operator-owned. Closure requires a reason and is terminal: closed incidents
reject normal mutations. Incidents are never automatically closed.

## Evidence and timeline

Evidence rows store metadata only (type, URI, frame, description, checksum);
V10 uploads nothing and invents no files. Deletion is explicit and leaves a
timeline entry. The timeline is append-only across 14 event types; history is
never overwritten.

## Numbering

`INC-YYYY-XXXXXX` from the creation timestamp, allocated by an atomic
counter increment (never `count()+1`), backstopped by a UNIQUE constraint
with bounded retry.

## Persistence

Six PostgreSQL tables (`incidents`, `incident_events`, `incident_timeline`,
`incident_evidence`, `incident_assignments`, `incident_counters`) with the
recommended indexes; hot-path perception state stays in memory. No
frame-level writes: only creation, meaningful updates, links, lifecycle
changes, operator actions, and evidence metadata persist.

## Configuration

See `.env.example` (`INCIDENTS_*`): enable flag, minimum auto-create
priority, auto-resolve toggle and grace, timeline update threshold.

## API & WebSocket

```text
GET    /api/v1/incidents                        filterable, paginated list
POST   /api/v1/incidents                        manual create (201)
GET    /api/v1/incidents/{id}                   detail (summary, timeline,
                                                  linked events, evidence,
                                                  assignment, risk, actions)
PATCH  /api/v1/incidents/{id}                   title/description/metadata
                                                  (priority/category excluded)
POST   /api/v1/incidents/{id}/acknowledge
POST   /api/v1/incidents/{id}/investigate
POST   /api/v1/incidents/{id}/mitigate          reason required
POST   /api/v1/incidents/{id}/resolve           reason enum required
POST   /api/v1/incidents/{id}/close             closure reason required
POST   /api/v1/incidents/{id}/assign            assignee required
POST   /api/v1/incidents/{id}/unassign
POST   /api/v1/incidents/{id}/escalate          target priority + reason
                                                  required (up or down)
POST   /api/v1/incidents/{id}/notes             message + kind
GET    /api/v1/incidents/{id}/evidence
POST   /api/v1/incidents/{id}/evidence          uri required (201)
DELETE /api/v1/incidents/{id}/evidence/{eid}    metadata only; NOTE_ADDED row
```

List filters: `status`, `priority`, `severity`, `category`, `camera_id`,
`assigned_to`, `risk_level`, `created_from`, `created_to`, `page`,
`page_size` (comma-separated multi-values accepted). Unknown filter values
are HTTP 422, never silently ignored. Lifecycle violations return HTTP 409
with `{code: "invalid_transition", current_status, attempted_status}`
(operations on CLOSED incidents use `code: "invalid_state"`); unknown
incidents 404; validation failures 422. Structured 409 details travel inside
the platform error envelope under `error.details`.

WebSocket (`/ws/cameras/{id}`) carries seven incident message types with
bounded summary payloads (never timelines/evidence arrays), drained from the
manager's change feed per connection cursor: `incident_created`,
`incident_updated`, `incident_status_changed`, `incident_assigned`,
`incident_resolved`, `incident_closed`, `incident_evidence_added`. All
V01–V09 channels are preserved.

## Frontend

`/incidents` (filterable, paginated) and `/incidents/[id]` (summary, risk,
timeline, evidence, assignment, state-gated actions). Unavailable values
render as such, never as fake zeros.

## Testing

Deterministic and hermetic: fixed-epoch clock, real V09 engines driven with
synthetic tracks and scripted fixtures, in-process SQLite for repository and
migration tests. No GPU, camera, RTSP, internet, or weight downloads.

## Non-claims and limitations

- No detection, tracking, safety, quality, perception, or risk scoring.
- No authentication or RBAC (V16).
- No collaborative case management beyond notes/findings/actions.
- No cross-camera identity without explicit identity metadata.
- No historical analytics persistence (later volume).
