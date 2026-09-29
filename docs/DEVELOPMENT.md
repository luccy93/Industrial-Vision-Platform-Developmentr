# Development Guide (V01)

## Prerequisites

- Python 3.11+ (3.12 recommended), pip
- Node.js 20+, npm
- Docker + Docker Compose v2
- Git

## Backend — local (without Docker)

```powershell
copy .env.example .env
pip install -r backend/requirements.txt -r backend/requirements-dev.txt
uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000
# Health:
#   http://localhost:8000/health
#   http://localhost:8000/ready
#   http://localhost:8000/api/v1/health
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
# Backend (from repo root):
pytest backend/tests -v
# Frontend gates:
cd frontend; npm run typecheck; npm run build
```

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
