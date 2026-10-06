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

V07 tests are grouped by intent: `unit/test_quality_schemas.py` (enums,
validation, config), `unit/test_quality_policy.py` (decision precedence,
boundaries, missing evidence), `unit/test_quality_regions.py` (ROI geometry),
`unit/test_quality_fixture_model.py` (scripted adapter + registry),
`unit/test_quality_repository.py` (PG contract),
`integration/test_quality_engine.py` (decisions, continuity, isolation,
honest errors), `integration/test_quality_api.py` (CRUD/status/latest,
404/409/422), `integration/test_quality_ws.py` (V02–V06 compatibility + new
messages), `integration/test_quality_integration.py` (startup warm-up, stream
lifecycle), and `performance/test_quality_perf.py` (latency, bounds,
concurrency). Test timestamps come from `backend/tests/quality_helpers.utc()`
— the same fixed-epoch pattern. The optional real-model check
(`python -m backend.app.quality.smoke_test`) reports READY only for a
loadable configured model, else honest SKIPPED; it is never in the suite.

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

## Quality tuning (V07)

`QUALITY_*` in `.env.example`: enable flag, inspection model name (empty =
honest ERROR), inspection sampling interval, per-camera profile cap,
per-profile region cap, observation/result/event caps, resolution grace,
default fail/review thresholds and severities, missing-evidence and error
behaviors. Region geometry is normalized `[0,1]` image space, reusing the V06
primitives. `inspection_type`/`severity` inputs are case-insensitive;
stored/serialized values are always uppercase. Tune the decision policy
against scripted fixture observations in `backend/tests/quality_helpers.py`.
Full guide: `docs/QUALITY_INSPECTION.md`.

## Intelligence tuning (V09)

`INTELLIGENCE_*` / `RISK_*` / `EVENT_*` in `.env.example`: enable flag, four
ordered risk thresholds, correlation window, resolution grace, base score plus
four documented factor weights (severity, persistence, correlation,
confidence), per-camera event/cluster caps. Scores are deterministic functions
of these values — tune against real domain engines driven with synthetic
tracks and scripted fixtures in `backend/tests/intelligence_helpers.py`
(fixed-epoch clock). Full guide: `docs/EVENT_RISK_INTELLIGENCE.md`.

## Autonomous tuning (V08)

`AUTONOMOUS_*` in `.env.example`: enable flag, model-adapter names (empty =
honest `NOT_CONFIGURED`), per-subsystem feature flags, perception sampling
interval, trajectory horizon/history, collision threshold/grace, object/event/
result/profile caps, motion speed and approach-area thresholds. Motion and
trajectory quantities are normalized image units per second — tune against
synthetic V04 tracks with exact histories in
`backend/tests/autonomous_helpers.py` (fixed-epoch clock, OpenCV-drawn lane
frames). Full guide: `docs/AUTONOMOUS_PERCEPTION.md`.

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
