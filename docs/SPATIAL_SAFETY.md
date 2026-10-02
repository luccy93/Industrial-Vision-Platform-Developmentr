# Spatial Safety — V06 Restricted Zones & Advanced Proximity

> V06 performs image-space spatial reasoning. Zone membership and proximity are
> camera-image approximations and do **not** represent physical-world distance,
> speed, or area unless camera calibration, depth, or another metric
> reconstruction capability is introduced in a future volume. No certified
> compliance, no medical claims, and no statistically calibrated risk scores.

```text
V04 Tracks → Spatial Scene Analysis → Zones → Entry/Exit/Dwell
           → Proximity Relationships → V05 SafetyEvent lifecycle → REST + WS
```

## Zone architecture

`backend/app/spatial/`:

| Module | Responsibility |
|---|---|
| `schemas.py` | `SafetyZone`, zone API contracts, `ZoneType`, `ZoneTransition`, `ProximityStrategy`, `ProximityRelationship`, membership view models |
| `geometry.py` | Pure functions: point-in-polygon, bbox IoU/overlap, center distance, polygon area, normalized↔pixel conversion |
| `rules.py` | V06 adapters that turn runtime detections into V05 `EventDraft`s (single event system) |
| `engine.py` | Per-camera zone registry, membership/dwell state, proximity pair evaluation, bounded cleanup, status |
| `repository.py` | PostgreSQL persistence (`zones` table, Alembic `002_create_zones`) |

**Persistence vs runtime.** Zone *configuration* is persisted per camera in
PostgreSQL and reloaded at startup, on camera attach, and after any zone
create/update/delete. Zone *runtime state* (who is inside, dwell timers, pair
observations) is intentionally **in memory only** — it is derived from live V04
track IDs, is meaningless after a restart, and is never written to PG.

## Polygon representation

Normalized `x, y ∈ [0, 1]` — resolution-independent and camera-scoped.
Minimum **3 finite points** spanning area in both axes (degenerate line/point
polygons are rejected). Polygon order is not enforced; point-in-polygon uses a
ray-cast that accepts any vertex order.

Membership uses the bbox **bottom-center** as a ground-contact approximation
(documented heuristic, not physical position):

```text
anchor_x = (x1 + x2) / 2 / frame_width
anchor_y = y2         / frame_height      ← lowest bbox edge
```

`SAFE` zones are stored and served but never generate events — they exist for
future masking/scoping work. Zone `metadata["classes"]` overrides the default
`person` + vehicle class filter per zone.

## Zone transitions

| Transition | Meaning |
|---|---|
| `RESTRICTED_ZONE_ENTRY` | anchor moved outside → inside |
| `RESTRICTED_ZONE_EXIT` | anchor moved inside → outside, or the track disappeared (`reason=track_disappeared`) |
| `ZONE_DWELL` | inside continuously for `dwell_threshold_seconds` (zone override, else `SPATIAL_DEFAULT_DWELL_SECONDS`) |

Dwell is re-emitted on every observed frame so the shared V05 lifecycle keeps
the event `ACTIVE` and its `duration_ms` growing. If a track vanishes while
inside, the runtime emits `EXIT` with `reason=track_disappeared` after
`SPATIAL_STATE_GRACE_SECONDS`, then purges the state — so events never remain
stuck `ACTIVE`.

```text
track visible:  [outside] ──ENTRY──▶ [inside ──dwell after N s──▶ inside] ──EXIT──▶ [outside]
track missing:  [inside] ──grace (SPATIAL_STATE_GRACE_SECONDS)──▶ EXIT(track_disappeared) + purge
```

## Proximity relationships

| Relationship | Default | Config |
|---|---|---|
| person ↔ vehicle | enabled | `SPATIAL_PERSON_VEHICLE_*` |
| person ↔ person | disabled | `SPATIAL_PERSON_PERSON_*` |
| vehicle ↔ vehicle | disabled | `SPATIAL_VEHICLE_VEHICLE_*` |

Strategies (`SPATIAL_PROXIMITY_STRATEGY`, or per-zone `metadata`):

- `CENTER_DISTANCE` — bbox center distance / mean bbox diagonal ≤ threshold
- `IOU` — bbox intersection-over-union ≥ `SPATIAL_PROXIMITY_IOU_THRESHOLD`
- `HYBRID` — either condition triggers (default; keeps V05 parity because V05
  person/vehicle proximity already uses IoU **or** ratio)

Pair identity is the canonical sorted `(min_track_id, max_track_id)`, so pair
order never duplicates an event. Pair enumeration is capped at
`MAX_PAIRS_PER_RELATIONSHIP = 2000` per relationship per frame to keep a busy
scene bounded; the overflow is dropped, not approximated.

All proximity thresholds are ratios of **image-space** distances. They are not
meters and are not comparable across cameras with different resolutions or
viewpoints without normalization.

## Configuration

```dotenv
SPATIAL_ENABLED=true
SPATIAL_DEFAULT_DWELL_SECONDS=5.0
SPATIAL_STATE_GRACE_SECONDS=5.0
SPATIAL_MAX_ZONES_PER_CAMERA=20
SPATIAL_PROXIMITY_STRATEGY=HYBRID          # CENTER_DISTANCE | IOU | HYBRID
SPATIAL_PROXIMITY_IOU_THRESHOLD=0.05
SPATIAL_PERSON_VEHICLE_ENABLED=true
SPATIAL_PERSON_VEHICLE_THRESHOLD=0.3
SPATIAL_PERSON_VEHICLE_SEVERITY=HIGH
SPATIAL_PERSON_PERSON_ENABLED=false
SPATIAL_PERSON_PERSON_THRESHOLD=0.25
SPATIAL_PERSON_PERSON_SEVERITY=MEDIUM
SPATIAL_VEHICLE_VEHICLE_ENABLED=false
SPATIAL_VEHICLE_VEHICLE_THRESHOLD=0.25
SPATIAL_VEHICLE_VEHICLE_SEVERITY=LOW
```

## API

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/v1/spatial/status` | engine status: enabled, strategy, thresholds, `zone_count`, `active_state_count`, `evaluations`, `latency_ms`, per-camera zones/states |
| `GET` | `/api/v1/cameras/{id}/zones` | all configured zones (`created_at`, `zone_id` order); `404` unknown camera |
| `POST` | `/api/v1/cameras/{id}/zones` | create; polygon auto-generated `zone_id` when omitted; `409` on duplicate `(camera_id, zone_id)`, `404` unknown camera, `422` invalid polygon, `409` over `SPATIAL_MAX_ZONES_PER_CAMERA` |
| `GET` | `/api/v1/cameras/{id}/zones/{zone_id}` | single zone |
| `PUT` | `/api/v1/cameras/{id}/zones/{zone_id}` | partial update; polygon re-validated |
| `DELETE` | `/api/v1/cameras/{id}/zones/{zone_id}` | delete + purge runtime state |
| `GET` | `/api/v1/cameras/{id}/zones/state` | live runtime: per-zone occupancy + dwell timers + pair counts (not persisted) |

Spatial events are also visible through the V05 REST contract
(`GET /api/v1/cameras/{id}/safety/events`) and V05 suppression
(`POST /api/v1/cameras/{id}/safety/suppress/{event_id}`) — there is one event
system, not two.

`zone_type` and `severity` inputs are case/whitespace-insensitive
(`"restricted"`, `" Danger "`); responses and stored values are always
uppercase (`RESTRICTED`, `DANGER`). Unknown values are still rejected with
`422`.

```bash
curl -X POST localhost:8000/api/v1/cameras/dev/zones \
  -H 'content-type: application/json' \
  -d '{"name":"Furnace hall","zone_type":"restricted","polygon":[{"x":0.2,"y":0.4},{"x":0.8,"y":0.4},{"x":0.8,"y":0.9},{"x":0.2,"y":0.9}]}'
```

## WebSocket

`/ws/cameras/{camera_id}` keeps every V02–V05 message and adds two typed
messages. Routing is driven by `event.metadata["rule"]`, **not** by event type,
because `PERSON_VEHICLE_PROXIMITY` exists in both V05 and V06:

| Rule | Message |
|---|---|
| `restricted_zone` | `type: "zone_event"` — zone id/type/name, track, transition, dwell seconds in `spatial` evidence |
| `proximity_relationships` | `type: "proximity_event"` — relationship, canonical track pair, strategy, ratio/IoU in `spatial` evidence |
| all V05 rules | `type: "safety_event"` (unchanged) |

```json
{
  "type": "zone_event",
  "camera_id": "dev",
  "event": {
    "event_id": "…", "event_type": "RESTRICTED_ZONE_ENTRY", "status": "ACTIVE",
    "track_ids": [17], "severity": "HIGH", "duration_ms": 0, "evidence": {"anchor_x": 0.51, "anchor_y": 0.63}
  },
  "spatial": {"anchor_x": 0.51, "anchor_y": 0.63, "zone_type": "restricted"}
}
```

The `event` object is the unchanged V05 `SafetyEvent` payload; `spatial`
carries the zone/proximity-specific evidence. Delivery semantics are inherited
from V05: the first pass publishes current state, afterwards only deltas (new
events and status changes, including resolutions).

## Frontend

`frontend/app/zones/page.tsx`: normalized SVG polygon editor (click to add
points, **Undo point** / **Clear** to revise, create/save/delete), zone list
with enable toggle and severity/type/dwell editing, engine status panel, live
runtime membership panel, and the spatial event feed. The Safety page gained a
scope filter (All / V05 rules / Spatial rules) and a `Spatial` badge so
operators can tell which engine produced an event.

## Testing

- `backend/tests/unit/test_geometry.py` — polygon/bbox math, degenerate rejection
- `backend/tests/unit/test_zone_runtime.py` — entry/exit/dwell/grace, class filters, isolation
- `backend/tests/unit/test_proximity.py` — strategies, canonical pairs, bounded enumeration
- `backend/tests/unit/test_zone_repository.py` — PG contract: CRUD, conflict, camera scoping, ORM/migration alignment
- `backend/tests/integration/test_spatial_api.py` — status, CRUD, membership state, error codes
- `backend/tests/integration/test_spatial_engine.py` — end-to-end spatial rules through `SafetyEngine`
- `backend/tests/integration/test_spatial_ws.py` — V05 compatibility + `zone_event`/`proximity_event`
- `backend/tests/integration/test_spatial_integration.py` — Alembic upgrade/downgrade cycle, startup warm-up, stream stop/restart state reset, V05 REST visibility
- `backend/tests/performance/test_spatial_perf.py` — bounded state, dwell/proximity latency budget, concurrency, event-history bound

```bash
pytest backend/tests -q
ruff check . && ruff format --check .
mypy .
cd frontend && npm run typecheck && npm run build
```

## Non-claims

- Image space only: no calibration, no depth, no metric distance/speed/area.
- Bbox bottom-center is a heuristic anchor, not a tracked foot position.
- `confidence` on spatial events is a heuristic strength value, not a
  calibrated probability.
- Zone dwell is measured in observed frames of camera-local track continuity —
  it is wall-clock time in a running stream, not time a subject spent in a
  physical zone.
- No certified regulatory compliance, no PPE detection, no incident escalation.
