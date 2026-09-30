# Development Guide (V02)

## Prerequisites

- Python 3.11+ (3.12 recommended), pip
- Node.js 20+, npm
- Docker + Docker Compose v2
- Git
- OpenCV (via `backend/requirements.txt`; local `opencv-contrib-python` is API-compatible)

## Backend — local (without Docker)

```powershell
copy .env.example .env
pip install -r backend/requirements.txt -r backend/requirements-dev.txt
alembic -c backend/alembic.ini upgrade head   # cameras table (needs DATABASE_URL)
uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000
# Health:
#   http://localhost:8000/health
#   http://localhost:8000/ready
#   http://localhost:8000/api/v1/health
# Cameras UI: http://localhost:3000/cameras (needs frontend dev server)
```

## Frontend — local

```powershell
cd frontend
copy .env.example .env.local
npm install
npm run dev
# http://localhost:3000
```

## Tests

```powershell
# Backend (from repo root; SQLite-backed, no USB/RTSP/GPU needed):
pytest backend/tests -v
# Frontend gates:
cd frontend; npm run typecheck; npm run build
# Lint / types:
ruff check backend; ruff format --check backend; python -m mypy backend
```

## Model weights (V03)

Weights are external: `MODEL_PATH=models/yolo11n.pt` (gitignored). Fetch
explicitly with `python -m backend.app.inference.smoke_test --download`, or
run the mock-backed suite which needs nothing. Validate a local model with
`python -m backend.app.inference.smoke_test` (READY or honest SKIPPED).

## Camera testing without hardware

Tests synthesize frames (NumPy) and video files (OpenCV writer) in tmp dirs.
For manual testing, point a `file` camera at `data/videos/sample.mp4` —
never commit large binaries. Full guide: `docs/VIDEO_INGESTION.md`.

## Tracking tuning (V04)

`TRACK_MIN_HITS` (confirmation), `TRACK_MAX_AGE` (LOST→REMOVED),
`TRACK_IOU_THRESHOLD` (association), `TRACK_HISTORY_SIZE` (memory bound),
`TRACK_HIGH_CONF` (stage-1/2 split). Full guide: `docs/TRACKING.md`.

## Docker

```powershell
docker compose config        # validate
docker compose up --build    # api + web + postgres + redis
docker compose down
```

GPU note: V01 runs CPU-only. For later CV volumes, uncomment the `deploy.reservations`
example in `docker-compose.yml` on a CUDA host with the NVIDIA container toolkit.

## Environments

`APP_ENV=development|testing|production`. `testing` must pass with no external
Postgres/Redis/GPU. Production requires real `DATABASE_URL`/`REDIS_URL` via env/secrets.

## Troubleshooting

- `pytest` import errors → run from repo root so `backend.*` imports resolve.
- Port clash on 8000/3000 → set `API_PORT` / `PORT` in `.env`.
- Docker `postgres` healthcheck slow → wait 10–20s, then retry `/ready`.
