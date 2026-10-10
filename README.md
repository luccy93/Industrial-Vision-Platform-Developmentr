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
lifecycle, safety API + WebSocket `safety_event`, and a Safety page.
V06 adds the **spatial safety engine** — PG-persisted camera zones with
normalized polygons, image-space entry/exit/dwell reasoning, advanced proximity
relationships (person/vehicle, person/person, vehicle/vehicle) with
`CENTER_DISTANCE`/`IOU`/`HYBRID` strategies, spatial API + WebSocket
`zone_event`/`proximity_event`, and a Zones page with a polygon editor. Zone
membership and proximity are **image-space approximations, never meters**.
V07 adds the **quality inspection framework** — PG-persisted inspection
profiles, normalized inspection regions (rectangle/polygon), a reusable defect
category catalog with per-profile associations, a configurable decision policy
(`PASS`/`FAIL`/`REVIEW`/`ERROR` — never a silent PASS), in-memory sessions and
quality events (inspection-level + observation-level `DEFECT_DETECTED`), quality
API + WebSocket `quality_event`/`quality_result`, and a Quality page with a
region editor. V07 is the **framework, not a trained defect model**: no
specialized weights are required or downloaded.
V08 adds the **autonomous perception engine** — PG-persisted perception
profiles, relative scene understanding from V04 tracks (no second tracker),
deterministic scene classification and OpenCV lane baselines with honest
confidence, image-space motion/trajectory estimation, relative-depth
abstraction (`NOT_CONFIGURED` by default), collision-risk analysis with
estimated-or-null TTC, a relative bird's-eye view, perception API + WebSocket
`autonomous_perception`/`collision_risk`/`lane_event`, and an Autonomous page
with lane overlay and Relative BEV canvas. V08 reports **relative geometry
and estimates, never meters or certified collision times**.
**V03 = Detection. V04 = Tracking. V05 = Industrial Safety Intelligence.
V06 = Restricted Zones & Advanced Proximity. V07 = Quality Inspection.
V08 = Autonomous Perception.**
V09 adds the **event & risk intelligence engine** — an orchestration layer
above V05/V06/V07/V08 that normalizes domain events into canonical
`UnifiedEvent`s, correlates them into `RiskCluster`s on shared
identity/location/time, and scores everything with explainable risk factors
(`severity`, `persistence`, `correlation`, `confidence`). Scores are
normalized operational heuristics, never probabilities; there are no
suppression or incident-management endpoints (V10 owns those). Read-only
intelligence APIs + WebSocket `intelligence_event`/`risk_cluster`/
`risk_update`, and an Intelligence dashboard with timeline, cluster cards,
and live feed.
**V09 = Event & Risk Intelligence.**
**V03 = Detection. V04 = Tracking. V05 = Industrial Safety Intelligence.
V06 = Restricted Zones & Advanced Proximity. V07 = Quality Inspection.
V08 = Autonomous Perception. V09 = Event & Risk Intelligence.**
V10 adds the **incident management layer** — an operational layer above V09
that turns eligible risk clusters into tracked incidents (`INC-YYYY-XXXXXX`)
with an explicit lifecycle (OPEN → ACKNOWLEDGED/INVESTIGATING → MITIGATED →
RESOLVED → CLOSED, terminal; no reopen, never auto-close), operator
assignment/escalation/notes, resolution reasons, evidence metadata, and an
append-only timeline. Automatic creation dedupes on
`(camera_id, source_cluster_id)`; quiet OPEN incidents auto-resolve after a
configurable grace. Six PostgreSQL tables (Alembic `005`), 16 REST endpoints
+ 7 WebSocket message types, and filterable `/incidents` + `/incidents/[id]`
pages with state-gated actions. No authentication/RBAC (V16 owns that).
**V10 = Incident Management.**
V11 hardens the **FastAPI + WebSocket backend**: central application
lifecycle (`CREATED → INITIALIZING → READY → DRAINING → STOPPED`), real
`/live` + `/ready` (200/503) + component `/health` diagnostics, a stable
error envelope with a code registry, request IDs honored and echoed,
structured logging, managed-worker supervision with heartbeats, a
lifecycle-boundary WebSocket manager (subscriptions, bounded prioritized
queues, heartbeat, graceful shutdown), settings-driven CORS with
production fail-fast, JSON body caps, and atomic incident transactions.
No Redis, no auth/RBAC, no new domain features — resilience only.
**V11 = Backend Hardening.**
V12 adds the **PostgreSQL + Redis data layer**: pooled, timeout-bounded
database access; durable operational event history + transactional outbox
(Alembic `006`); a local-first event bus (V05–V10 genuine events) with
opt-in Redis pub/sub distribution; lifecycle-owned Redis with
required/optional policy; Redis-aware health/readiness; and retention
cleanup. No cache, no new models, no auth/RBAC — reliability only.
**V12 = Data Reliability.**

## Features (V12)

- Explicit PostgreSQL pool configuration (size/overflow/timeout/recycle/connect timeout) with health-checked connections; SQLite dev/test path unchanged; engine dispose on shutdown
- Durable operational event history (`operational_events`, Alembic `006`): canonical V09 unified events for incident-linked members, idempotent on event id and source identity — never frames, detections, or tracks
- Transactional outbox (`event_outbox`): event row + delivery intent commit together; managed publisher drains with bounded batches, exponential-backoff retries, and observably dead intents after exhausting attempts
- Local-first event bus for genuine V05–V10 events (versioned envelopes reusing existing contracts, size-bounded, duplicate-suppressed) with opt-in Redis pub/sub distribution; subscribers never republish; redelivery-safe idempotent consumers
- Worker stages publish new-or-changed domain events (failure-isolated, skipped with no listeners); incident lifecycle queues durable intents; remote changes ingest idempotently into the WS feed without hot-loop changes
- Lifecycle-owned Redis (bounded timeouts, ping-verified start, idempotent close, secret-free logs); required mode fails startup and reports 503, optional mode degrades honestly, distributed mode never silently falls back to local
- Redis/eventbus health components, Redis-aware readiness, pool telemetry in DB metadata, retention cleanup on the sweep path
- V10 pagination and all V01–V11 contracts preserved byte-for-byte
- Documented non-claims: no cache, no Redis Streams/locks, no auth/RBAC (V16), Pub/Sub is notification transport — never storage or guaranteed delivery

## Features (V14)

- Historical analytics over durable records only: incidents (full lifecycle timestamps) + canonical event history; quality inspection outcomes honestly unavailable (results are not persisted)
- `GET /api/v1/analytics/summary` (replaces the V01 stub; bare path stays 200), `trends` (UTC hour/day/week buckets), `breakdowns` (bounded groupings), `export` (CSV with BOM, quoting, formula-injection mitigation, 5000-row cap)
- Definitions documented per metric (created vs currently-open, terminal timestamps, resolution denominators); missing data unavailable, never zero; truncated sources flagged
- `/analytics` page: presets 24h/7d/30d/custom, Recharts line/bars with table alternatives, per-panel isolation, stale-on-filter-change, CSV download with progress/error states
- Additive `007` time indexes (EXPLAIN-proven); no cache, no summary tables, no new persistence pipelines
- Documented non-claims: no FPS/uptime/latency history, no inspection pass rates, no PDF/scheduled reports, no Redis cache

## Features (V11)

- Central `ApplicationRuntime` lifecycle with ordered startup/shutdown phases, invalid-transition rejection, and idempotent shutdown
- `GET /live` (process alive), `GET /ready` (200 ready / 503 not-ready via required checks: runtime, database `SELECT 1`, workers), `GET /health` + `GET /api/v1/health` (12 lightweight component diagnostics, secret-free)
- Stable `{"error": {...}}` envelope with a centralized code registry; V10 `invalid_transition`/`invalid_state` preserved byte-for-byte; domain exceptions mapped centrally (422/404/409/503/500, no stack-trace leaks)
- Inbound `X-Request-ID` honored when sane (bounded, sanitized) else regenerated; echoed on every response including errors; per-request context for logging (no identity — V16)
- Managed-worker contract (states, snapshots, heartbeats, stale detection, bounded supervision); per-camera workers report heartbeats without thread-loop rewrites
- WebSocket lifecycle boundary: registration, opt-in subscriptions (default feed unchanged), bounded prioritized per-client queues (lifecycle messages never silently dropped), heartbeat, safe disconnect, bounded graceful shutdown; all 22 V01–V10 wire types unchanged
- Settings-driven CORS (wildcard+credentials rejected everywhere; production requires explicit origins; violations fail startup), JSON body caps (413 + envelope), OpenAPI summaries
- Single-transaction incident lifecycle moves (state + timeline commit together); request sessions commit/rollback/close correctly; workers use independent sessions
- V10 pagination contract preserved byte-for-byte (`{incidents, total, page, page_size}` — no `has_next`)
- Documented non-claims: no Redis broker, no auth/RBAC (V16), no production rate limiting, no K8s/observability deployment, no new domain models

## Features (V10)
- Operational incidents from V09 risk clusters: `INC-YYYY-XXXXXX` numbering (atomic counter), category precedence (AUTONOMOUS→COLLISION, QUALITY→QUALITY, SPATIAL→SPATIAL, SAFETY→SAFETY), priority inherited from cluster, dedupe on `(camera_id, source_cluster_id)` backed by a partial unique index
- Explicit lifecycle OPEN → ACKNOWLEDGED/INVESTIGATING → MITIGATED → RESOLVED → CLOSED (terminal; no REOPENED, never auto-close); violations are HTTP 409 with structured `{code, current_status, attempted_status}`
- Operator actions: assignment with history, escalation to any priority with mandatory reason (up or down), notes/findings/actions/observations, mitigation and resolution reasons, terminal closure with reason
- Auto-resolve only for OPEN incidents after a configurable grace once the cluster goes quiet; acknowledgement and investigation are operator-owned
- Evidence metadata only (type/URI/frame/description/checksum) — V10 uploads nothing; deletion leaves a timeline entry; timeline is append-only across 14 event types
- 16 REST endpoints (list with status/priority/severity/category/camera/assignee/risk/time filters + pagination, manual create, detail, PATCH title/description/metadata, 9 actions, evidence CRUD) under `/api/v1/incidents`
- WS `incident_created` / `incident_updated` / `incident_status_changed` / `incident_assigned` / `incident_resolved` / `incident_closed` / `incident_evidence_added` with bounded payloads; all V01–V09 channels preserved
- Incidents pages: filterable paginated queue with manual creation, detail with summary/risk/timeline/linked events/evidence/assignment and state-gated action buttons
- Six PostgreSQL tables (`incidents`, `incident_events`, `incident_timeline`, `incident_evidence`, `incident_assignments`, `incident_counters`); Alembic `005_create_incident_management`; `INCIDENTS_*` config in `.env.example`
- Documented non-claims: no auth/RBAC (V16), no risk re-scoring, no cross-camera identity

## Features (V09)

- Canonical `UnifiedEvent` model (source-preserving IDs, camera, domain, taxonomy type, severity, lifecycle, tracks/objects, location, evidence)
- Seven-domain taxonomy (SAFETY/SPATIAL/QUALITY/AUTONOMOUS active; TRACKING/PERCEPTION/SYSTEM reserved, never synthesized)
- Deterministic adapters per active domain (SPATIAL split by rule metadata, V06 precedent); PASS results and missing identity handled honestly
- Deterministic `RiskEngine`: documented formula, clamped scores, named factors with contributions, configurable ordered thresholds
- Priority mapping (`NONE→P4 … CRITICAL→P0`) with HIGH/CRITICAL severity floor
- Correlation on shared identity or co-located affinity inside the time window — same camera alone never links; per-camera clusters only
- Lifecycle with grace (ACTIVE→RESOLVED, passive SUPPRESSED mirror, no oscillation); bounded memory with deterministic eviction
- `GET /api/v1/intelligence/status` (dependency availability, totals, config), per-camera events/clusters/risk endpoints — read-only, bounded
- WS `intelligence_event` / `risk_cluster` / `risk_update` added without changing any V01–V08 message
- Intelligence page: engine status, highest-risk banner, domain filter, cluster cards with factors, timeline, live feed with reconnect + polling fallback
- Documented non-claims: heuristic scores (not probabilities/forecasts), no incident management, no cross-camera identity

## Features (V08)

- Camera-scoped perception profiles in PostgreSQL (`autonomous_perception_profiles`; Alembic `004_create_autonomous_perception_profiles`)
- `SceneClassifier` / `LaneDetector` / `DepthEstimator` ABCs + scripted fixtures (explicit outputs, refused in production) + honest `NOT_CONFIGURED` degradation
- Perceived objects reuse V04 track IDs; timestamped motion primitives (velocity/acceleration/direction/approach) with NaN/zero-delta guards
- Deterministic baselines: heuristic scene classifier, OpenCV edge+Hough lanes (normalized polylines), constant-velocity trajectories, canonical-pair collision risks
- TTC present only with closing motion + depth (`null` otherwise — no division by zero); missing inputs yield `UNKNOWN` risk, never fabricated probabilities
- Relative BEV (`lateral=(x−0.5)×2`, `longitudinal=1−y`) with objects, lanes, trajectories, risk flags — labeled relative everywhere
- Perception events with deduped ACTIVE/RESOLVED lifecycle: `COLLISION_RISK`, `LANE_DEPARTURE_RISK`, `OBJECT_APPROACH`, `OBJECT_CROSSING`, `SCENE_CHANGE`
- `GET /api/v1/autonomous/status` (per-subsystem availability incl. explicit depth `NOT_CONFIGURED`), profile CRUD, bounded latest/events endpoints
- WS `autonomous_perception` / `collision_risk` / `lane_event` added without changing any V02–V07 message
- Autonomous page: availability badges (never zero-for-missing), profile management, object table, lane overlay, Relative BEV canvas, risk list, event feed
- Documented non-claims: no certified driving/ADAS safety, no meters/depth/coordinates, uncalibrated scores, no image storage

## Features (V07)

- Camera-scoped profiles in PostgreSQL (`inspection_profiles`, `inspection_regions`, `defect_categories`, `inspection_profile_defect_categories`; Alembic `003_create_quality_inspection`)
- `InspectionModel` ABC + scripted fixture adapter (explicit test observations, never random, never a real model; refused in production)
- Honest no-model behavior: an inspection attempt without a configured model decides `ERROR` (`INSPECTION_MODEL_NOT_CONFIGURED`), never PASS
- `DecisionPolicy` with configurable fail/review thresholds, fail severities, required regions, and missing-evidence behavior; every decision carries a human-readable reason
- Observation filtering: model capability set, per-profile category allowlist, category review thresholds, uncatalogued-code placeholders, bounded observation count
- Quality events with V05-style lifecycle (dedupe, stable IDs, grace resolution, suppression) in a separate domain: `QUALITY_FAIL`/`QUALITY_REVIEW`/`QUALITY_ERROR` + per-defect `DEFECT_DETECTED`
- `GET /api/v1/quality/status`, profile + category CRUD, bounded latest/results/events endpoints; runtime results never touch PostgreSQL
- WS `quality_event` / `quality_result` added without changing any V02–V06 message
- Quality page: profile management, defect-category selection, normalized region editor, latest decision with observations, event list with suppression
- Documented non-claims: framework only (no defect-detection claims), uncalibrated confidence scores, no image storage, operator-supplied product IDs only

## Features (V06)

- Camera-scoped zones in PostgreSQL (`zones` table, Alembic `002_create_zones`); normalized `[0,1]` polygons with server-side validation
- Image-space membership via bbox bottom-center (documented ground-contact heuristic) → `RESTRICTED_ZONE_ENTRY` / `RESTRICTED_ZONE_EXIT` / `ZONE_DWELL`
- Dwell timers per zone (`SPATIAL_DEFAULT_DWELL_SECONDS`, per-zone override) that never leave events stuck (disappearance + grace purge)
- Proximity relationships person/vehicle, person/person, vehicle/vehicle with `CENTER_DISTANCE`, `IOU`, or `HYBRID` strategy, canonical ordered pair identity, bounded pair enumeration
- Spatial rules reuse the V05 event lifecycle (dedup, one stable `event_id`, grace resolution, suppression) — no parallel event system
- `GET /api/v1/spatial/status`, zone CRUD + `GET /api/v1/cameras/{id}/zones/state`; runtime state stays in memory
- WS `zone_event` / `proximity_event` added without changing `stream_status`, `frame`, `stream_error`, `detection`, `tracking`, `safety_event`
- Zones page: normalized SVG polygon editor (add/undo/clear, create/edit/toggle/delete), engine status, membership overlay, spatial event list
- Documented non-claims: image-space only (no calibration/depth), no physical distance, uncalibrated confidence scores

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
TARGET_PROCESSING_FPS, FRAME_SKIP, BUFFER_SIZE`,
plus V05 safety (`SAFETY_*`) and V06 spatial (`SPATIAL_*`) keys.

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
- **V03** — AI inference & detection (V03 = detection, V04 = tracking)
- **V04** — multi-object tracking
- **V05** — safety intelligence foundations
- **V06** — restricted zones & advanced proximity
- **V07** — quality inspection framework
- **V08** — autonomous perception foundation
- **V09** — event & risk intelligence
- **V10** — incident management (this release)
- **V11+** — trained models, analytics
