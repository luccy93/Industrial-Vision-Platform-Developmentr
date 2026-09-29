# Project Constitution — Industrial AI Vision & Safety Intelligence Platform

Version: V01 (foundation). Binding for all future volumes unless explicitly amended.

## 1. Architecture Principles

1. **Modular architecture** — `backend/app/{core,api,domain,services,infrastructure}` with
   strict one-way dependencies (`api → services → domain`; `core` has no inward deps).
2. **Separation of concerns** — ingestion, inference, tracking, safety/quality/perception,
   risk, incident, and delivery evolve independently behind typed interfaces.
3. **API-first design** — every capability is consumable via versioned REST (`/api/v1`)
   and, where realtime, WebSocket. No hidden UI-only logic.
4. **Real-time processing** — hot path is frame → detect → track → assess → emit with
   bounded latency budgets (defined per volume).
5. **Async processing where appropriate** — I/O-bound work (streams, DB, Redis, WS fan-out)
   is async; CPU/GPU-bound CV work is isolated in workers/pools (later volumes).
6. **Configuration-driven behavior** — no hardcoded thresholds, URLs, or credentials.
   All behavior flows from `backend/app/core/config.py` + environment.
7. **Hardware abstraction** — camera sources, model devices (`cpu/cuda`), and stores are
   behind interfaces so development runs on CPU while production can use GPU.
8. **Testability** — deterministic unit + integration tests; external systems (PG/Redis/
   cameras/models) are stubbed or health-checked, never faked as passing.
9. **Observability** — structured logs (`timestamp, level, module, message, exc_info`),
   health/readiness endpoints, and (later) metrics/traces.
10. **Security** — no secrets in code or logs; validated inputs (Pydantic); least-privilege
    access; production error responses never leak stack traces.
11. **Scalability** — stateless API; stateful stream/CV state lives in Redis/storage so
    replicas can scale horizontally in later volumes.

## 2. Engineering Principles

- **Strong typing** — Pydantic v2 domain contracts; mypy-clean backend; strict TS frontend.
- **Clear interfaces** — small public surfaces, explicit request/response schemas.
- **Reusable components** — shared domain models in `backend/app/domain/`; shared UI
  primitives in `frontend/components/ui/`.
- **Deterministic tests** — seeded, hermetic, no wall-clock/network flakes.
- **Structured logging** — JSON-friendly key/values via stdlib logging; secret redaction.
- **Explicit error handling** — typed `AppError` hierarchy mapped to stable HTTP problem
  responses; unexpected errors become `500` without internals.
- **No hardcoded secrets** — `.env.example` documents; `.env` is gitignored.
- **Maintainable code** — small focused functions, consistent naming, no dead code.
- **Production-oriented design** — health/readiness, graceful lifespan, Docker-first.

## 3. Configuration Strategy

- Single `Settings` object (`pydantic-settings`), `APP_ENV ∈ {development, testing, production}`.
- Required keys documented in `.env.example` (see §V01 scope). Production overrides via env.
- `testing` env must run without external PG/Redis/GPU.

## 4. Testing Strategy

- `pytest`: `tests/unit` (config, schemas, errors) + `tests/integration` (health, startup).
- Frontend: `tsc --noEmit` + `next build` as V01 gates.
- No fake green: failures block commits/push.

## 5. Logging Strategy

- Fields: `timestamp, level, logger/module, message, exception`.
- Never log: passwords, API keys, tokens, DB credentials, secrets.
- Human-readable in dev, JSON-parseable shape in prod (formatter switch planned V02).

## 6. Error-Handling Strategy

- Categories: `ConfigurationError, ValidationError, CameraError, StreamError,
  InferenceError, StorageError, ServiceUnavailableError`.
- HTTP mapping: 400/422 validation, 404 not found, 503 unavailable, 500 fallback.
- Envelope: `{error: {code, message, details?, request_id?}}`.

## 7. API Versioning

- All product APIs under `/api/v1`. Breaking changes require `/api/v2`.
- Health probes (`/health`, `/ready`, `/api/v1/health`) are unversioned contract + versioned alias.

## 8. Real-Time Processing Principles (future volumes)

- Frames never block the API event loop; backpressure + drop policies are explicit.
- Detections/tracks/events are immutable records flowing downstream.
- WebSocket is a delivery plane, not a compute plane.

## 9. Amendment Rule

Changes to this constitution require a docs PR updating this file + `docs/ARCHITECTURE.md`.
