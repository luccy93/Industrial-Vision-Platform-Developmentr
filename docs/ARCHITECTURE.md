# Architecture — Industrial AI Vision & Safety Intelligence Platform

## Target dataflow (conceptual)

```text
Camera
  ↓
Video Ingestion
  ↓
Frame Processing
  ↓
AI Inference
  ↓
Tracking
  ↓
Scene Understanding
  ↓
Safety / Quality / Perception
  ↓
Risk Engine
  ↓
Incident Engine
  ↓
API / WebSocket
  ↓
Dashboard
```

## V01 — Implemented (foundation only)

- Modular FastAPI monolith: `backend/app/{core,api/v1,domain}`.
- Versioned router skeleton: `/api/v1/{cameras,detections,incidents,alerts,analytics}` (stubs).
- Health probes: `GET /health`, `GET /ready`, `GET /api/v1/health`.
- Centralized `Settings`, structured logging, typed `AppError` → HTTP envelope.
- Pydantic v2 domain contracts: Camera, VideoStream, Frame, BoundingBox, Detection,
  TrackedObject, SafetyEvent, QualityEvent, PerceptionEvent, RiskAssessment, Incident, Alert.
- Next.js + TS + Tailwind shell: layout, sidebar, dashboard/system pages, API/WS clients,
  shared types, env config.
- Docker foundation: `backend/Dockerfile`, `frontend/Dockerfile`, `docker-compose.yml`
  (api, web, postgres, redis), GPU-ready but CPU-default.
- CI skeleton: `.github/workflows/ci.yml` (backend tests + frontend typecheck/build).
- Docs: constitution, architecture, development, README.

## V02 — Implemented (video ingestion)

- `backend/app/ingestion/`: `VideoSource` (USB/RTSP/file over OpenCV) →
  `StreamManager` worker threads → bounded `FrameBuffer` (drop-oldest) →
  `FrameSampler` → extensible `Preprocessor` → `IngestionFrame`.
- Camera configs in PostgreSQL (`cameras` table, Alembic `001_create_cameras`);
  stream state/buffers/metrics in memory.
- `/api/v1/cameras` CRUD + `start/stop/status`; WS `/ws/cameras/{id}`
  (`stream_status`/`frame` metadata/`stream_error`, no video bytes).
- Frontend Cameras page (status, FPS, counters, Start/Stop/Refresh).
- 68 pytest tests incl. perf bounds; see `docs/VIDEO_INGESTION.md`.

## V03 — Implemented (AI inference & detection)

- `backend/app/inference/`: `InferenceModel` ABC → `YOLOModel`/`MockModel`,
  `ModelManager` (load-once, thread-safe), per-camera `InferenceWorker`s with
  bounded queues + results rings, `GET /api/v1/inference/status`,
  `GET /api/v1/cameras/{id}/detections`, WS `detection` messages.
- CPU/GPU via `MODEL_DEVICE=auto`; weights external (`models/yolo11n.pt`,
  never committed). See `docs/INFERENCE.md`. **V03 = detection, V04 = tracking.**

## V04 — Implemented (multi-object tracking)

- `backend/app/tracking/`: `Tracker` ABC → native `ByteTrackTracker`
  (IoU + Hungarian, NumPy/SciPy CPU, zero new deps), `TrackingManager`
  (per-camera isolation), `TrackedObject` (TENTATIVE/CONFIRMED/LOST/REMOVED,
  bounded history, px/s velocity), `GET /api/v1/tracking/status`,
  `GET /api/v1/cameras/{id}/tracks`, WS `tracking` messages, UI track chips.
- See `docs/TRACKING.md`. **V03 = Detection, V04 = Tracking, V05 = Safety.**

## V05 — Implemented (safety intelligence foundations)

- `backend/app/safety/`: `SafetyRule` ABC → 4 geometry rules, `SafetyEngine`
  (per-camera state, dedup, grace resolution, suppress), `SafetyEvent`
  lifecycle, `GET /api/v1/safety/status`,
  `GET /api/v1/cameras/{id}/safety/events`, WS `safety_event`, Safety page.
- Deterministic foundations only: no compliance/meters/medical/calibrated claims.
- See `docs/SAFETY_INTELLIGENCE.md`.
  **V03 = Detection, V04 = Tracking, V05 = Industrial Safety Intelligence.**

## V06 — Implemented (restricted zones & advanced proximity)

- `backend/app/spatial/`: `geometry.py` (pure polygon/bbox math), `engine.py`
  (per-camera zone registry + membership/dwell state + proximity pair
  evaluation, bounded), `rules.py` (adapters into the V05 `SafetyRule` contract),
  `repository.py` (PG `zones` table), zone CRUD + `GET /api/v1/spatial/status`
  + `GET /api/v1/cameras/{id}/zones/state`, WS `zone_event`/`proximity_event`,
  Zones page with normalized SVG polygon editor.
- Zone configuration is persisted per camera (Alembic `002_create_zones`);
  membership/dwell/pair state is runtime-only and never written to PG.
- Spatial rules produce ordinary `SafetyEvent`s (dedup, grace resolution,
  suppression, REST visibility) — no parallel event system.
- Image space only: normalized `[0,1]` polygons, bbox bottom-center anchor,
  ratio/IoU thresholds. No calibration, depth, or metric distance.
- See `docs/SPATIAL_SAFETY.md`.

## V07 — Implemented (quality inspection framework)

- `backend/app/quality/`: `schemas.py` (profiles, regions, categories,
  observations, decisions, events, sessions), `policy.py` (pure decision
  functions), `regions.py` (ROI extraction + coordinate mapping, reuses V06
  geometry), `inspection.py` (model ABC + error codes), `fixture.py`
  (scripted test double), `registry.py` (honest model resolution),
  `engine.py` (inspection, decisions, events, sessions, metrics),
  `repository.py` (PG configuration), `ws.py` (message builders).
- Configuration is persisted per camera (Alembic
  `003_create_quality_inspection`); results, observations, events, and
  sessions are runtime-only and never written to PG.
- A missing model decides `ERROR` (`INSPECTION_MODEL_NOT_CONFIGURED`), never
  PASS; the fixture adapter resolves only outside production.
- Quality events (`QUALITY_FAIL`/`QUALITY_REVIEW`/`QUALITY_ERROR` +
  observation-level `DEFECT_DETECTED`) reuse the V05 lifecycle pattern in a
  separate domain — no safety-domain coupling.
- Worker integration: sampled (`QUALITY_INSPECTION_INTERVAL_FRAMES`),
  exception-isolated `_analyze_quality` stage; WS `quality_event` /
  `quality_result`; `/quality` page with profile management + region editor.
- Framework only — no claim that generic detectors find defects. See
  `docs/QUALITY_INSPECTION.md`.

## V08 — Implemented (autonomous perception foundation)

- `backend/app/autonomous/`: `schemas.py` (scene, objects, ego, lanes,
  trajectories, risks, BEV, events, profiles), `motion.py` (pure timestamped
  motion primitives), `scene.py`/`lanes.py`/`depth.py` (model ABCs + fixtures
  + registries), `scene_baseline.py` (heuristic classifier),
  `lane_baseline.py` (OpenCV edge+Hough lanes), `trajectory.py`
  (constant-velocity), `collision.py` (canonical-pair risk heuristic),
  `bev.py` (relative plane mapping), `engine.py` (perception, events,
  metrics), `repository.py` (PG profiles), `ws.py` (message builders).
- Perception profiles persisted per camera (Alembic
  `004_create_autonomous_perception_profiles`); scenes, objects,
  trajectories, risks, and events are runtime-only and never written to PG.
- Missing models degrade to `NOT_CONFIGURED`/`UNKNOWN` (never fake output);
  fixtures resolve only outside production; TTC is estimated-or-null.
- Perception events (`COLLISION_RISK`, `LANE_DEPARTURE_RISK`,
  `OBJECT_APPROACH`, `OBJECT_CROSSING`, `SCENE_CHANGE`) use deduped
  ACTIVE/RESOLVED lifecycle in a separate domain — no safety/quality coupling.
- Worker integration: sampled (`AUTONOMOUS_PERCEPTION_INTERVAL_FRAMES`),
  exception-isolated `_analyze_autonomous` stage; WS `autonomous_perception` /
  `collision_risk` / `lane_event`; `/autonomous` page with lane overlay +
  Relative BEV canvas.
- Foundation only — no certified driving/ADAS safety, no meters. See
  `docs/AUTONOMOUS_PERCEPTION.md`.

## V09 — Implemented (event & risk intelligence)

- `backend/app/intelligence/`: `schemas.py` (unified events, clusters,
  assessments, taxonomy), `normalize.py` (4 active domain adapters, 3
  reserved domains), `risk.py` (deterministic scoring, thresholds, priority),
  `correlate.py` (link predicates, affinity groups), `engine.py`
  (pull → normalize → dedupe → correlate → score), `ws.py` (message builders).
- Reads V05/V06/V07/V08 event outputs; owns no detectors, trackers, geometry,
  or models. No tables, no migration — all state in memory, bounded.
- Unified identity `(camera, domain, source event)`; per-camera clusters on
  shared identity/location/time; grace lifecycle with de-escalation.
- Worker integration: `_analyze_intelligence` stage; WS `intelligence_event` /
  `risk_cluster` / `risk_update`; `/intelligence` dashboard with live feed.
- Heuristic scores only — no probabilities, no incident management. See
  `docs/EVENT_RISK_INTELLIGENCE.md`.

## V10 — Implemented (incident management)

- `backend/app/incidents/`: `schemas.py` (incident/timeline/evidence/
  assignment contracts, state machine-adjacent enums), `statemachine.py`
  (explicit TRANSITIONS, allowed_actions, category precedence),
  `repository.py` (6-table PostgreSQL access, atomic numbering, dedupe),
  `manager.py` (single writer: V09 sync, lifecycle ops, change feed),
  `ws.py` (7 message builders).
- Six tables via Alembic `005_create_incident_management`
  (`incidents`, `incident_events`, `incident_timeline`, `incident_evidence`,
  `incident_assignments`, `incident_counters`); partial unique index
  `(camera_id, source_cluster_id)` over open states in both ORM and
  migration; incidents survive restarts (no reset/drop hooks).
- Worker integration: exception-isolated `_sync_incidents` stage after
  `_analyze_intelligence`; WS 7 incident messages on `/ws/cameras/{id}`;
  `/incidents` (filterable, paginated, manual create) + `/incidents/[id]`
  (summary, risk, timeline, linked events, evidence, assignment,
  state-gated actions).
- No auth/RBAC (V16); no auto-close; no reopen; no risk re-scoring. See
  `docs/INCIDENT_MANAGEMENT.md`.

## V11 — Implemented (backend hardening)

- `backend/app/runtime/`: `manager.py` (`ApplicationRuntime`, 15 startup +
  11 shutdown phases, idempotent), `health.py` (6 states, component model,
  worst-state aggregation), `readiness.py` (`ReadinessManager`, required-set
  policy, lightweight `SELECT 1` DB probe), `components.py` (12 cheap
  probes — no inference, no camera dials, no secrets).
- `backend/app/core/`: `APIError`/`ErrorDetail`/`ErrorEnvelope` models,
  `ERROR_CODES` registry (V10 codes frozen), `DomainError` + 6 subclasses,
  `RequestContext` + bounded request IDs, structured log helpers.
- `backend/app/workers/base.py`: `ManagedWorker`/`WorkerState`/
  `WorkerSnapshot`/`WorkerSupervisor` (heartbeats, staleness, bounded
  restarts); per-camera workers expose `health_snapshot()` adapters.
- `backend/app/websocket/manager.py`: lifecycle-boundary manager
  (registration, subscriptions, bounded prioritized queues, heartbeat,
  metrics, bounded shutdown) around the unchanged `streams_ws` delta loop.
- Endpoints: `GET /live` (new), `GET /ready` (real 200/503 verdict, legacy
  shape preserved), `GET /health` + `GET /api/v1/health` (component
  diagnostics, additive). V10 pagination frozen byte-for-byte.
- Settings-driven CORS (strict table, startup fail-fast),
  `MAX_REQUEST_BODY_BYTES` (413 + envelope), OpenAPI summaries.
  No Redis, no auth, no new domain features. See
  `docs/BACKEND_HARDENING.md`.

## Future volumes (explicitly NOT in V01–V11)

| Stage | Status | Notes |
|---|---|---|
| Live camera RTSP ingestion | done (V02) | OpenCV workers, reconnect w/ backoff |
| Frame processing pipeline | done (V02) | buffer → sample → resize/convert |
| YOLO production inference | done (V03) | Ultralytics, CPU/GPU, mock-tested |
| Multi-object tracking | done (V04) | native ByteTrack-compatible |
| Safety detection | partial (V05) | geometry foundations |
| Zones & advanced proximity | done (V06) | restricted-zone entry/exit/dwell, 3 relationships, image-space only |
| Quality inspection framework | done (V07) | profiles/regions/categories/policy/events — no trained defect model |
| Autonomous perception foundation | done (V08) | relative scene/motion/lanes/risk/BEV — no metric claims |
| Event & risk intelligence | done (V09) | unified events, correlated clusters, explainable scores — no incident mgmt |
| Incident management | done (V10) | lifecycle/assignment/evidence/timeline, auto-create + auto-resolve, WS feed |
| Trained defect models | planned (V10+) | specialized YOLO/segmentation/anomaly via `InspectionModel` |
| Trained perception models | planned (V10+) | learned scene/lane/depth via V08 adapter boundaries |
| PPE detection | planned (V10+) | helmet/vest |
| Incident intelligence | done (V10) | lifecycle/assignment/acknowledgement/timeline/evidence |
| Full dashboard analytics | planned | live grid, overlays, charts |
| AuthN/Z, multi-tenancy | planned | later hardening |
| Metrics/tracing | planned | Prometheus/OTel |

No future functionality is claimed as implemented. Stubs return `501`-style
“planned in later volume” payloads where appropriate (see API docs).

## Repository layout (V01)

```text
backend/
  app/
    main.py            # FastAPI factory + lifespan
    core/              # config, logging, exceptions
    api/v1/            # router + health + resource stubs
    domain/            # typed contracts (above)
  tests/               # unit + integration
  requirements*.txt
  Dockerfile
frontend/
  app/                 # Next.js App Router pages
  components/          # layout/ui/system
  lib/{api,websocket,config}
  types/ styles/
docs/ infra/ .github/
docker-compose.yml
.env.example
```

## Key decisions (V01)

- Monolith-first, not microservices: avoids ops overhead until throughput demands it.
- Pydantic v2 everywhere: single validation story from env → API → domain.
- Postgres/Redis-ready but optional: health reports `configured/reachable` honestly;
  `testing` never requires them.
- CPU-default, GPU-possible: `GPU_ENABLED/MODEL_DEVICE` config; compose includes
  commented GPU reservation example.
