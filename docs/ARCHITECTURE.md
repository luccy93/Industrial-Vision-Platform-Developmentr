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

## Future volumes (explicitly NOT in V01)

| Stage | Status | Notes |
|---|---|---|
| Live camera RTSP ingestion | planned (V02) | OpenCV/FFmpeg workers |
| Frame processing pipeline | planned | decode/resize/normalize |
| YOLO production inference | planned (V03+) | PyTorch/ONNX, GPU pool |
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
