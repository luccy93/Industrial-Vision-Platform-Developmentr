# Docker & GPU Deployment (V17)

> Foundation snapshot (Commit 01). Service lifecycle, security
> hardening, GPU workflow, and validation results complete in
> Commits 02–03.

## Topology

| Service | Image | Role |
|---|---|---|
| `postgres` | `postgres:16-alpine` | Durable store, internal-only, named volume |
| `redis` | `redis:7-alpine` | Optional transport, internal-only |
| `migrate` | backend image (one-shot) | `alembic upgrade head`, gates `api` |
| `api` | `backend/Dockerfile` (CPU) | FastAPI, single worker, internal |
| `web` | `frontend/Dockerfile` (standalone) | Next.js shell, loopback-published |

Networks: `frontend` (web, api), `backend` (api, postgres, redis).

## Commands

```bash
docker compose -f compose.yaml up --build            # CPU default
docker compose -f compose.yaml -f compose.dev.yaml up --build     # + loopback debug ports
docker compose -f compose.yaml -f compose.gpu.yaml up --build     # NVIDIA opt-in
```

## Images

- Backend: multi-stage `python:3.11-slim-bookworm`, non-root `appuser`,
  `/live` healthcheck, exec-form single-worker uvicorn. No `.env`,
  tests, or caches baked in.
- GPU: same app with CUDA 12.6 torch (`torch==2.13.0`,
  `torchvision==0.28.0`, cu126 index, index-verified).
- Frontend: `npm ci` → `standalone` runner as `node` user,
  `node server.js`, build-arg `NEXT_PUBLIC_*` (never secrets).

## Environment

`.env` (gitignored, optional) overrides safe Compose defaults. Service
DNS (`postgres`, `redis`, `api`) is used container-to-container;
`API_INTERNAL_URL=http://api:8000` lets the Next.js server layer verify
sessions. `MODEL_DEVICE=cpu` default; `cuda` only under the GPU overlay.
