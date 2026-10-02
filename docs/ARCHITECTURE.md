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

## Future volumes (explicitly NOT in V01–V06)

| Stage | Status | Notes |
|---|---|---|
| Live camera RTSP ingestion | done (V02) | OpenCV workers, reconnect w/ backoff |
| Frame processing pipeline | done (V02) | buffer → sample → resize/convert |
| YOLO production inference | done (V03) | Ultralytics, CPU/GPU, mock-tested |
| Multi-object tracking | done (V04) | native ByteTrack-compatible |
| Safety detection | partial (V05) | geometry foundations |
| Zones & advanced proximity | done (V06) | restricted-zone entry/exit/dwell, 3 relationships, image-space only |
| PPE detection | planned (V07+) | helmet/vest — no V06 equivalent |
| Quality inspection | planned | defect/anomaly |
| Autonomous perception | planned | scene graph |
| Risk engine | planned | scoring/thresholds |
| Incident intelligence | planned | lifecycle/notifications |
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
