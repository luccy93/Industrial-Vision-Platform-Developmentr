# Industrial AI Vision & Safety Intelligence Platform

> Real-time computer vision for industrial safety, quality, and autonomous perception.

V01 establishes the **production foundation** — modular architecture, typed contracts,
configuration, API skeleton, observability basics, Docker, and tests. It does **not**
yet implement live streaming, YOLO inference, tracking, or safety/quality analytics.

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
GPU_ENABLED, MODEL_DEVICE, MODEL_CONFIDENCE_THRESHOLD, WEBSOCKET_ENABLED`.

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

- **V01** — foundation (this release)
- **V02** — video ingestion + live camera stubs → frontend status
- **V03+** — inference, tracking, safety/quality/perception, risk, incidents, analytics
