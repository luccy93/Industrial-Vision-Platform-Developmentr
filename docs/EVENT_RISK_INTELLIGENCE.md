# Event & Risk Intelligence — V09 Orchestration Layer

> V09 correlates the outputs of the V05 safety, V06 spatial, V07 quality, and
> V08 autonomous engines into unified events, correlated risk clusters, and
> explainable risk assessments. It is an **orchestration/intelligence layer**:
> it never re-runs inference, tracking, geometry, inspection, or perception,
> and it never invents source events.
>
> Risk scores are normalized operational heuristics in [0, 1] and are **not
> calibrated probabilities, statistical forecasts, or certified safety
> measurements**.
>
> V09 does **not** provide incident management, acknowledgement, suppression
> controls, assignment, investigation, or case management. Those capabilities
> belong to V10.

```text
Safety Engine ───────┐
Spatial Engine ──────┤  (spatial shares the V05 event lifecycle)
Quality Engine ──────┤
Autonomous Engine ───┤
                     ↓
          Event Intelligence (normalize → dedupe)
                     ↓
          Risk Intelligence (correlate → score → cluster)
                     ↓
          Unified Risk Intelligence (API + WebSocket + UI → V10)
```

## Source domains

V09 defines a seven-domain canonical taxonomy, but only four domains are
**active event sources** in V09:

```text
SAFETY     → SafetyEventAdapter      (V05 safety rules)
SPATIAL    → SpatialEventAdapter     (V06 zone/proximity rules)
QUALITY    → QualityEventAdapter     (V07 inspection events)
AUTONOMOUS → AutonomousEventAdapter  (V08 perception events)
```

The following are **reserved extension domains** with no registered adapter.
V09 never synthesizes events for them, and never converts raw tracks,
detections, frames, or generic system conditions into events:

```text
TRACKING     (reserved — no TRACK_CREATED / TRACK_LOST synthesis)
PERCEPTION   (reserved — perception output enters only via genuine V08 events)
SYSTEM       (reserved — no manufactured SYSTEM_ERROR from logs/reconnects)
```

Existing tracking/perception metadata may be consumed as **contextual
evidence** attached to genuine source events (e.g. a V08 collision risk
carries its track and object IDs into correlation) — that is evidence reuse,
not event synthesis.

## Event taxonomy

Canonical `UnifiedEventType` values with their sources:

```text
V05 safety:        FALL_RISK, CROWD_WARNING, CROWD_CRITICAL,
                   PERSON_VEHICLE_PROXIMITY, STATIONARY_OBJECT
V06 spatial:       RESTRICTED_ZONE_ENTRY, RESTRICTED_ZONE_EXIT,
                   RESTRICTED_ZONE_DWELL, PERSON_VEHICLE_PROXIMITY
V07 quality:       QUALITY_FAIL, QUALITY_REVIEW, QUALITY_ERROR,
                   DEFECT_DETECTED
V08 autonomous:    COLLISION_RISK, LANE_DEPARTURE_RISK, OBJECT_APPROACH,
                   OBJECT_CROSSING, SCENE_CHANGE
Reserved:          SYSTEM_ERROR (no producer in V09)
Fallback:          UNKNOWN (source type preserved in metadata)
```

SPATIAL vs SAFETY is decided by the source event's rule metadata (V06
precedent), because `PERSON_VEHICLE_PROXIMITY` is emitted by both engines.
The original source type is always preserved in
`metadata["source_event_type"]`.

## Severity normalization

Deterministic mapping with no upgrades:

```text
V05/V06 SafetySeverity → identical value (shared enum names)
V07 DefectSeverity    → identical value (shared enum names)
V08 RiskLevel         → NONE→INFO, LOW→LOW, MEDIUM→MEDIUM,
                        HIGH→HIGH, CRITICAL→CRITICAL, UNKNOWN→UNKNOWN
```

## Deduplication

Unified identity is `(camera_id, source_domain, source_event_id)`. Domain
engines already own per-frame continuity, so a repeated source event updates
the unified event in place (refresh, re-score) instead of duplicating it.
Distinct source IDs — e.g. two incidents on different objects — always stay
distinguishable.

## Correlation

Clusters link unified events on **one camera** (cross-camera identity is
unknown without explicit identity metadata, so clusters never span cameras)
when they share track/object identity, or share a location key with type
affinity inside the correlation window. Same camera alone never links.

## Lifecycle

Unified events mirror their source status (`ACTIVE`/`RESOLVED`, plus
`SUPPRESSED` only as a passive mirror of domain suppress APIs — V09 exposes
no suppression endpoints). Sources that vanish past
`EVENT_RESOLUTION_GRACE_SECONDS` resolve without flapping. Clusters stay
active while any member is active and resolve after the same grace once
empty, so risk de-escalates `HIGH → MEDIUM → LOW → RESOLVED` instead of
oscillating.

## Risk scoring

Deterministic formula with documented weights (defaults sum to a maximum of
exactly 1.0):

```text
score = clamp01(
    base
    + severity_weight    × severity_rank(severity)
    + persistence_weight × min(1, age_seconds / 60)
    + correlation_weight × min(1, (member_count − 1) / 4)
    + confidence_weight  × confidence
)
```

Every assessment carries its named factors
(`{name, value, weight, contribution, reason}`); scores are never emitted
without explanation. Escalation is therefore always explainable: a second
corroborating event raises the correlation contribution, persistent signals
accumulate persistence contribution.

Risk levels map from configurable thresholds (defaults 0.20 / 0.40 / 0.65 /
0.85, validated strictly ordered). Priority maps deterministically from risk
level with a severity floor: `NONE→P4, LOW→P3, MEDIUM→P2, HIGH→P1,
CRITICAL→P0, UNKNOWN→P3`, bumped one step toward P0 for HIGH/CRITICAL
severity so severe-but-uncertain signals are never buried.

## Persistence policy

All V09 state (unified events, clusters, assessments) lives in memory in the
engine, bounded per camera. V09 writes nothing frame-by-frame to PostgreSQL
and creates no tables. Historical analytics arrive in a later volume.

## Configuration

See `.env.example` (`INTELLIGENCE_*` / `RISK_*` / `EVENT_*` keys):
enable flag, four risk thresholds (validated ordered), correlation window,
resolution grace, base score plus four documented factor weights, per-camera
event/cluster caps.

## API & WebSocket

Read-only intelligence APIs (no mutation, no suppression endpoints):
`GET /api/v1/intelligence/status`, per-camera `.../intelligence/events`,
`.../intelligence/clusters`, `.../intelligence/risk` — all bounded.

WebSocket `/ws/cameras/{id}` keeps every V01–V08 message and adds
`intelligence_event` (delta on event+status), `risk_cluster` (delta on
cluster+status+risk level, so escalation re-publishes), and `risk_update`
(per-camera highest risk, sent on change). Never raw frames.

## Frontend

`/intelligence`: engine status with per-domain availability, highest
risk/priority cards, domain-filtered event table, cluster cards with factor
lists, lightweight timeline (recent list, no analytics infrastructure),
camera selector, live WebSocket feed with reconnect handling plus polling
fallback. Unavailable values render as such — never as fake zeros. Every
risk display carries the heuristic disclaimer.

## Testing

Deterministic and hermetic: fixed-epoch test clock, real domain engines
driven directly with synthetic tracks and scripted fixtures, exact-boundary
threshold tests, cross-domain scenario fixtures (A–E). No GPU, camera, RTSP,
internet, or weight downloads. See `docs/DEVELOPMENT.md` for the test layout.

## Non-claims

- No calibrated probabilities, forecasts, or certified safety measurements.
- No incident management, acknowledgement, suppression controls, assignment,
  investigation, or case management (V10).
- No cross-camera identity without explicit identity metadata.
- No historical analytics persistence (later volume).
