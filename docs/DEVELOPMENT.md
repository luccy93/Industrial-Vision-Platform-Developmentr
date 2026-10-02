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
# Lint / types (repo-wide; the stray root main.py is excluded via pyproject.toml):
ruff check .; ruff format --check .; python -m mypy .
```

V06 tests are grouped by intent: `unit/test_geometry.py` (polygon math),
`unit/test_zone_runtime.py` (entry/exit/dwell/grace),
`unit/test_proximity.py` (strategies + bounded pairs),
`unit/test_zone_repository.py` (PG contract), `integration/test_spatial_api*.py`
(CRUD/status/state/ergonomics), `integration/test_spatial_engine.py` and
`test_spatial_ws.py` (lifecycle + V05 compatibility),
`integration/test_spatial_integration.py` (Alembic cycle, startup warm-up,
stream lifecycle), and `performance/test_spatial_perf.py` (state bounds,
latency budget, concurrency). Test timestamps come from
`backend/tests/safety_helpers.utc()` — a **fixed synthetic epoch**, so duration
assertions never depend on how fast the machine runs.

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

## Safety tuning (V05)

`SAFETY_*` in `.env.example`: fall aspect/persistence, crowd counts,
proximity IoU/distance, stationary speed/duration, resolution grace, per-camera
event cap. Rules are deterministic — tune against synthetic tracks in
`backend/tests/safety_helpers.py`. Full guide: `docs/SAFETY_INTELLIGENCE.md`.

## Spatial tuning (V06)

`SPATIAL_*` in `.env.example`: enable flag, default dwell, state grace,
per-camera zone cap, proximity strategy + IoU threshold, and per-relationship
enabled/threshold/severity triples. Zone geometry is normalized `[0,1]` image
space, so thresholds are resolution-independent but **not** comparable across
cameras with different viewpoints, and never meters. `zone_type`/`severity`
inputs are case-insensitive; stored/serialized values are always uppercase.
Full guide: `docs/SPATIAL_SAFETY.md`.

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
