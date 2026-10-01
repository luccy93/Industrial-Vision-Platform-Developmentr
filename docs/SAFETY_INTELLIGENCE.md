# Safety Intelligence — V05 Deterministic Foundations

> V05 provides deterministic safety-intelligence foundations. It does not
> claim certified industrial safety compliance, physical-distance
> measurement, medical fall detection, or statistically calibrated risk
> probabilities.

```text
V04 TrackedObjects → Scene Safety Analysis → Safety Rules → Safety Events
  → Severity → Lifecycle → Real-Time Event Stream → Safety UI
```

## Architecture

`backend/app/safety/`: `SafetyRule.evaluate(scene)` ABC with four
independent rules (`FallRiskRule`, `CrowdDensityRule`,
`PersonVehicleProximityRule`, `StationaryObjectRule`), orchestrated by
`SafetyEngine.process(camera_id, tracked_objects, timestamp)`. Rules see only
V04 tracks — never YOLO internals or raw frames. Each rule is stateless across
frames (persistence derives from V04 track history), independently testable,
and configured from `Settings`.

## Rules

| Rule | Signal | Severity | Key config |
|---|---|---|---|
| Fall risk | person bbox width/height ≥ threshold for N consecutive history frames (`possible_fall` — not medical) | MEDIUM | `SAFETY_FALL_ASPECT_RATIO_THRESHOLD=1.2`, `SAFETY_FALL_PERSISTENCE_FRAMES=5` |
| Crowd density | camera-local confirmed-person count bands | MEDIUM / CRITICAL | `SAFETY_CROWD_WARNING_COUNT=5`, `SAFETY_CROWD_CRITICAL_COUNT=10` |
| Person/vehicle proximity | box IoU or center-distance/size ratio (**image-space**, never meters) | HIGH | `SAFETY_PROXIMITY_IOU_THRESHOLD=0.05`, `SAFETY_PROXIMITY_CENTER_DISTANCE_RATIO=0.3` |
| Stationary object | person/vehicle displacement within speed×duration over history span | LOW | `SAFETY_STATIONARY_SPEED_THRESHOLD=15.0` px/s, `SAFETY_STATIONARY_DURATION_SECONDS=10.0` |

## Event model & lifecycle

`SafetyEvent`: `event_id/camera_id/track_ids/event_type/severity/status/
confidence/timestamp/first_seen/last_seen/duration_ms/message/evidence/
metadata`. Stable IDs from rule+entity dedupe keys: one continuing condition
= one event (create → touch `last_seen` → `RESOLVED` after
`SAFETY_EVENT_RESOLUTION_GRACE_SECONDS=3.0` idle; `SUPPRESSED` via API).
Bounded to `SAFETY_MAX_EVENTS_PER_CAMERA=100` in memory — no PG writes in V05.

## Confidence semantics

Rule strength score in [0,1] from geometry strength, persistence, and track
confidence — documented, deterministic, and explicitly **not** a calibrated
probability.

## Per-camera isolation

Engine holds independent state per `camera_id`; concurrent cameras never
interfere. Stream restart resets that camera's safety state.

## Performance

Geometry-only (Python/NumPy over tracks): low-ms per scene, 50+ evaluations/s
minimum bar in perf tests. Runs inline in the inference worker thread after
tracking; failures isolated, streams continue.

## Image-space limitations

All distances/speeds are pixels (and px/s). Proximity is a risk *signal*;
stationary uses V04 speed; fall uses aspect ratio only — no pose, no depth,
no calibration. V06 owns zones/calibrated proximity.

## API & WebSocket

- `GET /api/v1/safety/status` — enabled, rules, camera/event counts, latency.
- `GET /api/v1/cameras/{id}/safety/events?status=active|resolved|all` — bounded.
- `POST …/safety/suppress/{event_id}` — ACTIVE → SUPPRESSED.
- `/ws/cameras/{id}` adds `safety_event` (new + resolution updates);
  `stream_status/frame/detection/tracking/stream_error` unchanged.

## Testing

Synthetic confirmed tracks only (offline, deterministic): rule geometry,
thresholds, disabled rules; engine creation/continuity/resolution/grace/
multi-event/isolation/stable IDs; model validation; API/WS compatibility;
perf latency/throughput/memory; full V01–V04 regression.

## Future extensions

New rules implement `SafetyRule` + registration (no engine changes). V06:
restricted zones & calibrated proximity. V10/V12: incident/DB persistence via
the existing event schema.
