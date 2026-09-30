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

## Future volumes (explicitly NOT in V01/V02/V03)

| Stage | Status | Notes |
|---|---|---|
| Live camera RTSP ingestion | done (V02) | OpenCV workers, reconnect w/ backoff |
| Frame processing pipeline | done (V02) | buffer → sample → resize/convert |
| YOLO production inference | done (V03) | Ultralytics, CPU/GPU, mock-tested |
| Multi-object tracking | planned | ByteTrack/OC-SORT eval |
| Safety detection | planned | PPE/zone/intrusion |
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
