# Industrial AI Vision & Safety Intelligence Platform

> Real-time computer vision for industrial safety, quality, and autonomous perception.

V02 adds the **real-time video ingestion pipeline** — USB/RTSP/file sources,
bounded frame buffering, sampling, preprocessing, stream lifecycle with
reconnect, PG-persisted camera configs, WS telemetry, and a Cameras page.
V03 adds the **AI inference engine** — Ultralytics YOLO behind an
`InferenceModel` abstraction, per-camera inference workers, detection API +
WebSocket `detection` messages, PG-free runtime results, and a detection panel.
V04 adds **multi-object tracking** — a native ByteTrack-compatible engine
(IoU + Hungarian via SciPy, CPU-only, zero new deps), per-camera isolated
trackers, TENTATIVE/CONFIRMED/LOST/REMOVED lifecycle, bounded history,
image-space velocity, tracking API + WebSocket `tracking` messages, and track
chips in the UI.
V05 adds the **safety intelligence engine** — four deterministic geometry
rules (fall-risk, crowd, person/vehicle proximity, stationary), event dedup +
lifecycle, safety API + WebSocket `safety_event`, and a Safety page. It does
**not** yet implement incidents, PPE/zone enforcement, or quality.
**V03 = Detection. V04 = Tracking. V05 = Industrial Safety Intelligence.**

## Features (V05)

- Four deterministic geometry rules (fall-risk, crowd, proximity, stationary) on V04 tracks — no NN, no new deps
- `SafetyEngine` per-camera state, dedup (stable IDs), grace-period resolution, suppress API
- `GET /api/v1/safety/status`, `GET /api/v1/cameras/{id}/safety/events` (bounded, in-memory)
- WS `safety_event` (new + resolution updates); Safety page with status/severity filters
- Documented non-claims: no certified compliance, no meters, no medical detection, uncalibrated scores

## Features (V04)

- Native ByteTrack-compatible tracker (IoU + Hungarian, NumPy/SciPy, CPU, no new deps)
- Per-camera isolated trackers; `(camera_id, track_id)` identity; IDs restart safely on stream restart
- Lifecycle TENTATIVE → CONFIRMED → LOST → REMOVED (`TRACK_MIN_HITS/MAX_AGE/IOU_THRESHOLD`)
- Bounded per-track history (`TRACK_HISTORY_SIZE`), image-space velocity (px/s)
- `GET /api/v1/tracking/status`, `GET /api/v1/cameras/{id}/tracks` (runtime state, no PG writes)
- WS `tracking` messages alongside V02/V03 messages; frontend track chips (`Person #17`, state, speed)

## Features (V03)

- `InferenceModel` ABC + `YOLOModel` (Ultralytics, lazy import, no silent downloads) + deterministic `MockModel`
- `MODEL_DEVICE=auto` (CUDA iff available, else CPU), conf/IoU/imgsz/max-det, class allowlist
- Per-camera inference workers, bounded queues (drop-oldest), results rings, isolated errors
- `GET /api/v1/inference/status`, `GET /api/v1/cameras/{id}/detections` (runtime state, no PG writes)
- WS `detection` messages alongside V02 `stream_status`/`frame`/`stream_error`
- Frontend detection panel (model, device, FPS, latency, classes + confidence)
- `python -m backend.app.inference.smoke_test` (READY or honest SKIPPED)

## Features (V02)
- Per-camera worker threads (FastAPI loop never blocked; one failure can't crash the backend)
- Bounded `FrameBuffer` (drop-oldest), `FrameSampler` (`TARGET_PROCESSING_FPS`/`FRAME_SKIP`), extensible `Preprocessor`
- Stream states: `DISCONNECTED→CONNECTING→CONNECTED→RUNNING→STOPPING→STOPPED` + `ERROR/RECONNECTING` with backoff
- Camera CRUD + `start/stop/status` under `/api/v1/cameras` (PostgreSQL; secrets write-only, redacted logs)
- WebSocket `/ws/cameras/{camera_id}`: `stream_status` / `frame` metadata / `stream_error` (no video bytes)
- Frontend Cameras page: status, FPS, counters, Start/Stop/Refresh, detection panel

## Features (V01)

- FastAPI + `/api/v1` router skeleton (`cameras, detections, incidents, alerts, analytics` stubs)
- Health probes: `GET /health`, `GET /ready`, `GET /api/v1/health`
- Centralized Pydantic-settings configuration (`development/testing/production`)
- Structured logging + typed error envelope (no stack-trace leaks)
- Pydantic v2 domain contracts for all 12 core entities
- Next.js + TypeScript + Tailwind shell (layout, system status, API/WS clients)
- Docker Compose for api/web/postgres/redis (CPU default, GPU-possible)
- pytest unit + integration suites; CI skeleton

## Architecture

```text
Camera → Ingestion → Frames → Inference → Tracking → Scene → Safety/Quality/Perception
  → Risk → Incident → API/WebSocket → Dashboard
```

See `docs/ARCHITECTURE.md` (implemented vs planned) and `docs/PROJECT_CONSTITUTION.md`.

## Technology Stack

| Layer | Choice |
|---|---|
| Backend | Python 3.11+, FastAPI, Pydantic v2, SQLAlchemy 2.x, Alembic, Uvicorn |
| Frontend | Next.js 14, React 18, TypeScript 5, Tailwind CSS 3 |
| Data | PostgreSQL 16 (ready), Redis 7 (ready) |
| Infra | Docker, Docker Compose, GitHub Actions (CI skeleton) |
| Tests | pytest, httpx TestClient, tsc, next build |

## Prerequisites

Python 3.11+, Node 20+, Docker + Compose, Git.

## Installation

```powershell
copy .env.example .env
pip install -r backend/requirements.txt
cd frontend; npm install
```

## Environment Setup

All keys documented in `.env.example`:
`APP_NAME, APP_ENV, LOG_LEVEL, API_HOST, API_PORT, DATABASE_URL, REDIS_URL,
GPU_ENABLED, MODEL_DEVICE, MODEL_CONFIDENCE_THRESHOLD, WEBSOCKET_ENABLED,
TARGET_PROCESSING_FPS, FRAME_SKIP, BUFFER_SIZE`.

## Video Ingestion Quickstart (V02)

```powershell
# 1. migrate + run
alembic -c backend/alembic.ini upgrade head
uvicorn backend.app.main:app --reload --port 8000
```

Register a file camera (no hardware needed):
`POST /api/v1/cameras {"name":"Dev","source_type":"file","source":"data/videos/sample.mp4"}`,
then `POST /api/v1/cameras/{id}/start` and `GET .../status`.
See `docs/VIDEO_INGESTION.md` for USB/RTSP setup, lifecycle, and troubleshooting.

## Local Development

```powershell
uvicorn backend.app.main:app --reload --port 8000
cd frontend; npm run dev
```

## Running Tests

```powershell
pytest backend/tests -v
cd frontend; npm run typecheck; npm run build
```

## Docker Usage

```powershell
docker compose config
docker compose up --build
```

## Project Roadmap

- **V01** — foundation
- **V02** — video ingestion pipeline
- **V03** — AI inference & detection (this release; V03 = detection, V04 = tracking)
- **V04** — multi-object tracking
- **V05** — safety intelligence foundations (this release)
- **V06+** — zones/proximity engine, quality/perception, risk, incidents, analytics
