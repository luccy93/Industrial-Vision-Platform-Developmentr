# Autonomous Perception — V08 Relative Scene Understanding

> V08 provides an autonomous-perception **foundation** for scene understanding
> and relative-motion analysis. It is **not a certified autonomous-driving or
> ADAS safety system**. Metric distance, physical coordinates, and production
> collision prediction require appropriate calibration, sensors, models, and
> validation.
>
> Confidence and risk scores are uncalibrated heuristic strengths in [0, 1].
> They are **not** probabilities. Unavailable values are explicit (`None` /
> `NOT_CONFIGURED` / `UNKNOWN`) — never zero, never fabricated.

```text
Camera / Frames
      ↓
Existing Detection (V03) → Existing Tracking (V04)
      ↓
Autonomous Perception
      ├── Scene Classification (heuristic baseline + adapter)
      ├── Lane Perception (geometry baseline + adapter)
      ├── Ego/Camera Geometry (UNKNOWN unless configured)
      ├── Relative Motion (V04 history + timestamps)
      ├── Trajectory Estimation (constant-velocity baseline)
      ├── Collision-Risk Foundation (relative-motion heuristic)
      └── Bird's-Eye Representation (RELATIVE_BEV only)
```

## Framework vs. certified driving capability

| Layer | V08 status |
|---|---|
| Scene/object/lane/trajectory/risk/BEV framework | **implemented** |
| Deterministic baselines (scene heuristic, OpenCV lanes, constant-velocity motion) | **implemented** — documented assumptions, honest confidence |
| Scripted fixture adapters (tests/dev) | **implemented** — explicit outputs, refused in production |
| Calibrated metric depth, certified TTC, production lane keeping | **not implemented** — clean adapter boundaries only |

## Domain model

`backend/app/autonomous/`: `schemas.py` (scene, objects, lanes, ego,
trajectories, risks, BEV, events, profiles), `motion.py` (pure timestamped
motion functions), `scene.py` / `lanes.py` / `depth.py` (model ABCs +
fixtures + registries), `trajectory.py`, `collision.py`, `bev.py`,
`engine.py`, `repository.py` (profile persistence), `ws.py`.

V08 owns scene representation, lanes, ego-relative motion, trajectories,
collision risk, BEV, and perception events. V05/V06 keep safety, zones, and
proximity; V07 keeps quality decisions and events. No engine depends on
another; all domains may consume shared primitives (V04 tracks, V06
geometry).

## Scene representation

`AutonomousScene`: `scene_id`, `camera_id`, `frame_id`, `timestamp`,
`scene_type` (ROAD/PARKING/WAREHOUSE/INDUSTRIAL_YARD/INDOOR_MOBILE_ROBOT/
UNKNOWN), `objects`, `lanes`, `ego_state`, `environment`, `metadata`.

## Perceived objects

`PerceivedObject`: `object_id` (`"track-{id}"` when a V04 track backs it),
`track_id` (no second tracking system — V04 IDs are reused),
image-space normalized velocity/acceleration (units/second, NOT m/s),
`relative_position`/`relative_depth` (nullable; depth only from a configured
estimator), `heading`, `object_state`
(MOVING/STATIONARY/APPROACHING/RECEDING/CROSSING/UNKNOWN, inferred from
history where evidence supports it).

## Motion estimation

Pure functions in `motion.py` over V04 `TrackHistoryEntry` centers +
timestamps: velocity, acceleration (EMA-smoothed in the engine),
movement direction, approach/recede classification from bbox-area growth and
reference-distance change. Zero/negative time deltas, missing timestamps,
and non-finite values yield `None`/safe fallbacks — never NaN, Inf, or
exceptions.

## Lane perception

`Lane`: canonical normalized polyline `points` + optional least-squares
`coefficients` (x as a function of y, highest-degree first), `confidence`,
`lane_type` (SOLID/DASHED/DOUBLE_SOLID/UNKNOWN), `side`. The deterministic
baseline uses OpenCV edge + line detection on the frame (suitable for
synthetic/test frames; honest confidence, `UNKNOWN` type when evidence is
weak). Lane departure is a *risk proxy* from the frame-center offset to lane
boundaries — `UNKNOWN` with fewer than two lanes — never a certified
measurement.

## Ego state

`EgoState` defaults to all-`None` with frame `UNKNOWN`: velocity
*unavailable* is representable and never fabricated. Relative/image-space
estimates may fill it when configured.

## Depth semantics

`DepthEstimator.estimate(frame, objects)` returns per-object `DepthReading`s
(`depth`, `unit`, `confidence`, `source`). Default: everything `None` with
`source=NOT_CONFIGURED`, and perception continues. The fixture returns
explicit unitless relative values for named objects (`unit="relative"`) and
`None` for the rest. No silent fake depth, no meters without calibration.

## Trajectory estimation

Constant-velocity baseline from EMA-smoothed image-space velocity over the
last history points: normalized points oldest → newest, configurable horizon
(`AUTONOMOUS_TRAJECTORY_HORIZON_SECONDS`), confidence decaying with horizon
distance. Assumptions documented on the model.

## Collision risk

`CollisionRiskEngine` over CONFIRMED track pairs with canonical
`(min, max)` identity: `risk_level`
(NONE/LOW/MEDIUM/HIGH/CRITICAL/UNKNOWN), uncalibrated `risk_score`,
`time_to_collision` **estimate** (present only with closing motion and depth;
`null` for receding/stationary/zero-velocity/missing-depth — division by
zero is impossible by construction), `reason`, and evidence. Missing
required inputs → `UNKNOWN`, never a fabricated probability. Pair state
uses ACTIVE/RESOLVED with `AUTONOMOUS_COLLISION_GRACE_SECONDS` — one ongoing
event per pair, not per-frame spam.

## Bird's-eye view

`BirdsEyeView` in frame `RELATIVE_BEV`: normalized `(x, y)` maps to
`(lateral=(x−0.5)×2, longitudinal=1−y)` — a unitless ordering proxy carrying
objects, lane polylines, trajectories, and risk flags. The UI labels it
"Relative BEV". No 3D reconstruction, no metric top-down claims.

## No-model behavior

```text
perception disabled              → no perception attempt, no result
no tracks                        → scene with zero objects, UNKNOWN-leaning type
scene/lane/depth model missing   → that subsystem reports NOT_CONFIGURED/UNKNOWN
lane detector failing            → zero lanes + error counter, pipeline continues
depth missing                    → relative_depth unavailable, risk uses UNKNOWN depth
```

## Quality events (V08: perception events)

`AutonomousPerceptionEvent`: `COLLISION_RISK`, `LANE_DEPARTURE_RISK`,
`OBJECT_APPROACH`, `OBJECT_CROSSING`, `SCENE_CHANGE`. Defect-style
suppression does not exist: lifecycle is ACTIVE → RESOLVED after grace.
Events are only generated when their required evidence is available.

## Persistence policy

Persisted (PostgreSQL, Alembic `004_create_autonomous_perception_profiles`):
`autonomous_perception_profiles` only. Never persisted: frames, tracks,
scenes, objects, trajectories, lanes, risk estimates, events. Historical
analytics arrive in a later volume.

## Configuration

See `.env.example` (`AUTONOMOUS_*` block). Key defaults:
`AUTONOMOUS_ENABLED=true`, all three model names empty (honest
NOT_CONFIGURED), lane/trajectory/collision/BEV on, depth off,
`AUTONOMOUS_PERCEPTION_INTERVAL_FRAMES=10`,
`AUTONOMOUS_TRAJECTORY_HORIZON_SECONDS=2.0`,
`AUTONOMOUS_COLLISION_GRACE_SECONDS=0.5`.

## API & WebSocket

REST: profile CRUD under `/api/v1/cameras/{id}/autonomous-profiles`,
`GET /api/v1/autonomous/status` (per-subsystem availability incl. explicit
depth `NOT_CONFIGURED`), bounded `.../autonomous/latest` and
`.../autonomous/events`.

WebSocket `/ws/cameras/{id}` keeps every V02–V07 message and adds
`autonomous_perception` (per new frame), `collision_risk` and `lane_event`
(delta-only). Never image/base64 payloads.

## Frontend

`/autonomous`: engine + per-subsystem availability badges
(AVAILABLE/NOT_CONFIGURED/ESTIMATED/UNKNOWN — unavailable metrics are never
shown as zero), scene type, perceived objects with track IDs and motion
state, lane overlay with IDs/confidence/type/departure state, Relative BEV
canvas (objects, trajectories, risk flags), collision-risk list, latency,
profile management.

## Testing

Deterministic and hermetic: synthetic frames (OpenCV-drawn lanes),
synthetic V04 tracks with exact histories, scripted fixtures, fixed-epoch
test clock. No GPU, CUDA, camera, RTSP, internet, weight downloads, depth
model, LiDAR, or stereo. See `docs/DEVELOPMENT.md` for the test layout.

## Non-claims

- No certified autonomous-driving or ADAS safety capability.
- No exact meters, object depth, physical-world coordinates, or lane-level
  localization accuracy.
- No certified collision time; TTC is an estimate or `null`.
- Confidence and risk scores are not calibrated probabilities.
- No persistent image storage or external uploads.
