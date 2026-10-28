# Docker & GPU Deployment (V17)

Deploy the existing platform — no architecture changes, no contract
changes — as a reproducible Docker stack: CPU by default, NVIDIA GPU
opt-in. Business logic, API shapes, and V16 security behavior are
untouched; only packaging, orchestration, and deployment docs are new.

## Topology

| Service | Image | Responsibility |
|---|---|---|
| `postgres` | `postgres:16-alpine` | Durable store; internal-only; `postgres-data` volume |
| `redis` | `redis:7-alpine` | Optional transport; internal-only; `redis-data` volume |
| `migrate` | backend image, one-shot | `alembic upgrade head` from the V16 schema; gates `api` |
| `api` | `backend/Dockerfile` (CPU) | FastAPI, **single uvicorn worker** (lifespan threads must not duplicate) |
| `web` | `frontend/Dockerfile` (standalone) | Next.js shell on loopback `:3000` |

Networks: `frontend` (web ↔ api) and `backend` (api ↔ postgres/redis).
Only the web shell is published (`127.0.0.1:3000`). PostgreSQL/Redis
have no published ports; the API is internal (loopback `:8000` via the
dev overlay, or a reverse proxy in production).

## Commands

```bash
docker compose -f compose.yaml config                       # validate CPU config
docker compose -f compose.yaml -f compose.gpu.yaml config   # validate GPU overlay
docker compose -f compose.yaml up --build -d                # CPU default
docker compose -f compose.yaml -f compose.dev.yaml up --build -d   # + loopback debug ports
docker compose -f compose.yaml -f compose.gpu.yaml up --build -d  # NVIDIA opt-in
docker compose -f compose.yaml ps                           # service + health state
docker compose -f compose.yaml logs --tail=100 api          # sanitized app logs
docker compose -f compose.yaml down                         # stop, keep volumes
```

Destructive (deletes persisted volumes — explicit warning required):

```bash
docker compose -f compose.yaml down -v   # WARNING: deletes postgres-data + redis-data
```

## Startup ordering and health

1. `postgres` healthy (`pg_isready`) → `migrate` runs `alembic upgrade
   head` → must exit 0 (`service_completed_successfully`).
2. `api` starts only after migration; its Compose healthcheck polls
   `/ready` (dependency-aware per V11), so `web` waits for a truly
   ready backend (`service_healthy`, 60 s start period for model warmup).
3. `redis` ordering is `service_started` because Redis is optional by
   default (`REDIS_ENABLED=false`, `EVENT_BUS_MODE=local`); set both
   explicitly for distributed mode.

`/live` stays trivial (process alive; used by the image
`HEALTHCHECK`). `/ready` gates traffic. Optional integrations follow
V11 required/optional policy — a missing optional Redis/SMTP/webhook
never invalidates readiness.

## Environment

`.env` (gitignored, optional) overrides safe Compose defaults; explicit
`environment:` entries win. Container-to-container traffic uses service
DNS (`postgres:5432`, `redis:6379`, `http://api:8000`) — never
`localhost`. `API_INTERNAL_URL=http://api:8000` lets the Next.js server
layer verify V16 sessions; browsers use the baked `NEXT_PUBLIC_*` URLs.

Production `.env` sketch (placeholders only — never commit real values):

```bash
APP_ENV=production
POSTGRES_USER=ivp_app
POSTGRES_PASSWORD=<strong-generated>
POSTGRES_DB=industrial_vision
CORS_ALLOWED_ORIGINS=https://ops.example.com
CORS_ALLOW_CREDENTIALS=true
NEXT_PUBLIC_API_URL=https://ops.example.com/api
NEXT_PUBLIC_WS_URL=wss://ops.example.com
MODEL_DEVICE=cpu
```

Production startup fails fast on wildcard origins, missing origins,
`CORS_ALLOW_CREDENTIALS=false`, or `AUTH_COOKIE_SECURE=false`
(`Secure` cookies are automatic in production). Rebuild `web` whenever
`NEXT_PUBLIC_*` values change — they bake at build time and must never
carry secrets.

## Migrations

```bash
docker compose -f compose.yaml run --rm migrate               # explicit rerun
docker compose -f compose.yaml exec api alembic -c backend/alembic.ini current   # verify revision
```

Head: `010_add_notification_mute` (single head enforced by tests).
Migrations run exactly once per deploy from the dedicated job — never
from every API replica. A failed job blocks `api` with a clear
dependency error instead of starting an incompatible backend.

## Administrator bootstrap (V16 CLI in containers)

```bash
docker compose -f compose.yaml exec api python -m backend.app.auth.bootstrap --email ops@example.com
# password via secure prompt; refuses if an admin exists; nothing printed
```

Run only after `migrate` succeeds and `api` is healthy.

## GPU deployment (opt-in, CUDA 12.6)

Prerequisites: NVIDIA drivers (≥550 recommended), NVIDIA Container
Toolkit, and an explicit device choice (`GPU_COUNT`, default 1).

```bash
nvidia-smi                                                     # host sees the GPU
docker compose -f compose.yaml -f compose.gpu.yaml up --build -d
docker compose -f compose.yaml exec api python -c "import torch; print(torch.__version__, torch.cuda.is_available())"
```

The GPU image (`backend/Dockerfile.gpu`) is the same app/Python with
CUDA-enabled PyTorch (`torch==2.13.0`, `torchvision==0.28.0`, cu126
index — both verified to exist; CPU `requirements.txt` is otherwise
unchanged). `MODEL_DEVICE=cuda`; explicit `cuda` without CUDA raises a
structured error, `auto` falls back to CPU visibly in status. The CPU
stack never touches NVIDIA drivers or runtime. Live GPU inference was
**not** validated in V17 (no hardware in the validation environment) —
only configuration, dependency resolution, and CPU independence.

### Release GPU verification and runtime honesty (V23/V24)

For a release deployment, use the digest-pinned GPU overlay
(`compose.gpu.release.yaml`) and a production verification report. The
report proves the GPU *artifact* (registry digest, pull proof, attestation,
SBOM); it does **not** prove the GPU *runtime*. The report therefore keeps
`artifact_status.gpu.state` separate from
`artifact_status.gpu.runtime_state` / `runtime_verified`.

V24 `gpu-qualify` produces runtime evidence on the GPU host. It proves
`nvidia-smi` reports a device and driver, Docker registers the `nvidia`
container runtime, and the digest-pinned `api-gpu` image starts with
`--gpus all` and reports CUDA devices:

```powershell
python -m tools.release.cli gpu-qualify `
  --manifest release-manifest.json `
  --execute `
  --output gpu-runtime.json
```

Without `--execute` every check is `NOT_RUN`; `--skip-container` cannot
produce a verified report.

```powershell
python -m tools.release.cli preflight `
  --manifest release-manifest.json `
  --repo-root . `
  --gpu `
  --output deployment-preflight.json

python -m tools.release.cli verify-deploy `
  --manifest release-manifest.json `
  --report release-verification.json --require-verified `
  --preflight-report deployment-preflight.json `
  --running --check-logs --gpu

$env:IVP_SMOKE_PASSWORD="<smoke-user-password>"
python -m tools.release.cli smoke `
  --api-url https://ops.example.com/api `
  --web-url https://ops.example.com `
  --username smoke@example.com `
  --manifest release-manifest.json `
  --tag v1.2.3 --commit <40-hex> `
  --output gpu-deployment-smoke.json
```

Only mark GPU runtime as verified after all of these succeed on the GPU host:

1. `nvidia-smi` shows the device (recorded by `gpu-qualify`).
2. `gpu-qualify --execute` proves Docker's NVIDIA runtime and a CUDA-capable
   container start for the digest-pinned image.
3. The GPU stack is running, the preflight is `PASS`, and the smoke report is
   `PASS`.
4. A real inference request completes with `MODEL_DEVICE=cuda`.

If any step is missing, report `runtime_state: NOT_RUN` (or `UNAVAILABLE`)
with a reason. Never convert a missing GPU into a pass. The GitHub-hosted
release runner has no NVIDIA GPU, so its manifest records
`gpu_runtime_smoke: not_run`.

## Models

Weights are deployment artifacts, never baked into images: mount
`./models:/code/models:ro` (default `MODEL_PATH=models/yolo11n.pt`).
Missing weights raise an explicit error with download instructions —
never silent, never fake detections.

## Persistence, backup, shutdown

- PostgreSQL data lives in `postgres-data` (survives `down` and
  restarts; restart preserves all database-backed records).
- A volume is not a backup: `docker compose -f compose.yaml exec
  postgres pg_dump -U $POSTGRES_USER $POSTGRES_DB > backup.sql` and
  restore with `psql < backup.sql` after recreating an empty database.
- `api` runs one worker; SIGTERM drives the bounded lifespan shutdown
  (WebSocket drain, worker `stop(timeout=5)`, engine close). The
  outbox/delivery model stays at-least-once authoritative — restarts
  redeliver, never lose persisted work, and never duplicate durable
  notifications beyond documented retry semantics.
- Restart policy `unless-stopped` (long-running services); `migrate`
  uses `no`. Logs rotate (`10m` × 3). API memory limit 4G (Compose
  `deploy.limits`; informational outside Swarm — see Compose docs).

## Security posture

- Non-root runtime (`appuser` / `node`); no Docker socket, deathost
  mounts, privileged flags, or added capabilities.
- No secrets in images, layers, build args, logs, or Git: `.env` is
  gitignored and excluded from build contexts; `.env.example` holds
  placeholders only; SMTP/webhook/DB credentials are redacted from
  logs by the existing hygiene rules.
- V16 behavior preserved: `Secure`+`HttpOnly`+`SameSite=Lax` cookies,
  CSRF/origin enforcement, ticket-scoped WebSockets, bootstrap and
  audit flows unchanged. The deployment adds no auth bypasses.
- Reverse-proxy guidance: terminate TLS at the proxy, forward to
  `web:3000` (pages) and `api:8000` (API/WS) on the Compose networks,
  preserve `Host`/`X-Forwarded-*` only from trusted proxies
  (`AUTH_TRUSTED_PROXIES`), and keepcookie/CSRF semantics end to end.

## Troubleshooting

| Symptom | Check |
|---|---|
| `api` unhealthy / never ready | `logs api`; `migrate` exit code; `pg_isready` via `exec postgres`; `DATABASE_URL` DNS name |
| `migrate` fails | `exec api alembic -c backend/alembic.ini current`; divergent DB → restore/migrate manually |
| CSRF/cookie errors in browser | `CORS_ALLOWED_ORIGINS` matches page origin; credentials true; `Secure` only over HTTPS |
| WS ticket 4401 loop | clock skew (30 s TTL); `API_INTERNAL_URL` reachable from `web`; session expiry (15 min idle) |
| GPU requested but CPU selected | `nvidia-smi` on host; Toolkit installed; `MODEL_DEVICE=cuda`; torch `+cu126` in image |
| Missing model weights | mount `./models`; explicit `ModelNotFoundError` names the expected path |
| Permissions on Linux | bind-mounted `models/` readable by UID 1000 (`appuser`); `chown` or `:ro` as needed |

## Limitations

- No TLS termination, autoscaling, or multi-host orchestration in
  scope (reverse proxy + orchestrator own those layers).
- Resource `limits` are enforced only by compatible runtimes
  (informational under plain `docker compose up`).
- Single API worker/replica: horizontal API scaling is unsafe today
  (background threads would duplicate); documented, not changed.
- GPU inference smoke-tested only where hardware exists (skipped in V17 and
  V23 validation); V23 verifies the GPU artifact separately from runtime.
- `torch>=2.0`/`ultralytics>=8.0` remain range pins upstream; the GPU
  image pins its CUDA pair explicitly.
