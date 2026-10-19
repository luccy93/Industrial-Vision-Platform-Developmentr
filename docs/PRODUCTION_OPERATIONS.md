# Production Operations (V20)

How to configure, deploy, probe, drain, and recover the platform in
production. V20 hardens existing behavior — it adds no new domain features
and changes no API/WebSocket contracts.

## Configuration policy

Production is **strict**; development and testing stay **permissive**. Every
rule below is enforced by `Settings.validate_startup()`, which runs both when
the app is constructed and at the top of the lifespan, so an invalid
configuration fails startup instead of degrading silently.

| Setting | Production rule |
|---|---|
| `APP_ENV` | Must be `production` explicitly (never inferred from hostname). |
| `CORS_ALLOWED_ORIGINS` | At least one explicit origin; wildcard `*` rejected; every entry must be a real origin (`scheme://host[:port]`, no path/query/fragment/credentials). |
| `CORS_ALLOW_CREDENTIALS` | Must be `true` with explicit origins so browser sessions work. |
| `DATABASE_URL` | Must be PostgreSQL (`postgresql+psycopg2://…`), never empty, with a **non-default password** (placeholders like `postgres`, `changeme`, `password`, `ivp`, `test`, `example`, … are rejected). The password lives inside the DSN — there is no separate field. |
| `METRICS_ACCESS` | Must be `internal` (loopback / monitoring network only); public scraping is rejected. |
| `AUTH_TRUSTED_PROXIES` | When set, every entry must be a valid IP or CIDR. |
| `ALERTING_WEBHOOK_URLS` | Each destination must be `http(s)://host`; invalid entries raise a `ConfigurationError` whose message never echoes the path/query (which may carry a token). |
| Logging | `LOG_FORMAT` defaults to `json` in production. |
| Cookies | Session cookies are `Secure` in production (HTTPS assumed). |

Development/testing keep localhost origins, SQLite, and Redis disabled with
no extra configuration — none of the production-only rules apply there.

A **temporary dependency outage** (database/Redis unreachable) is *not* a
configuration error: it is reported honestly by readiness/health and the app
stays up in a degraded state. A **wrong or insecure configuration** prevents
startup.

## Secrets

- Real credentials belong in the environment (`DATABASE_URL`,
  `POSTGRES_PASSWORD`, `ALERTING_SMTP_PASSWORD`, `ALERTING_WEBHOOK_SECRET`),
  never in the repo. `.env` and `.env.*` are gitignored; `.env.example`
  holds placeholders only.
- Credentials are excluded from `repr(settings)` (`repr=False`) and the
  logging filter redacts Bearer/Basic/Digest authorization values, cookie/
  CSRF/WS-ticket values, DSN passwords, RTSP passwords, structured extras,
  and exception tracebacks.
- The compose stack **requires** an explicit `POSTGRES_PASSWORD` (no weak
  default); the API rejects a weak password at startup in production.

```powershell
copy .env.example .env
# Set a strong POSTGRES_PASSWORD and a production DATABASE_URL:
#   postgresql+psycopg2://ivp:<strong-password>@postgres:5432/industrial_vision
docker compose -f compose.yaml up --build
```

## Health and readiness

| Endpoint | Meaning |
|---|---|
| `GET /live` | Process is alive (never expensive). |
| `GET /ready` | 200 when all **required** checks pass, else 503. Required: runtime, database `SELECT 1`, supervised workers. Redis is required only in required-distributed mode. |
| `GET /health`, `GET /api/v1/health` | Component diagnostics (secret-free). |
| `GET /metrics` | Prometheus scrape; `internal` access only. See `docs/OBSERVABILITY.md`. |

Use `/live` for container liveness and `/ready` for readiness/load-balancer
gating. Do not gate traffic on `/health`.

## Startup and shutdown

- **Startup** validates configuration first (fail fast), warms best-effort
  schema/config, then starts the outbox publisher, Redis subscriber (when
  distributed), and the alerting evaluator/delivery workers.
- **Shutdown** is ordered and idempotent: new sockets are refused, WebSockets
  drain (bounded), then the runtime runs its shutdown phases — stream and
  inference supervisors are stopped exactly once (no duplicate stop), the
  event bus (publisher/subscriber/alerting workers) is stopped, Redis is
  closed, and the database engine is disposed. `dispose_engine` also clears
  the session-factory cache so a disposed engine is never reused.
- The lifespan wraps startup **and** teardown in `try/finally`, so a
  partial-startup failure still tears down any threads already started —
  a failed boot never leaves orphaned workers.

## Database, migrations, backup

- Alembic owns the production schema; `init_db()` is a dev/test convenience
  only (and now disposes its temporary engine).
- Migrations run as a one-shot `migrate` service before the API in compose.
- There is a **single head** (`alembic heads`); verify before upgrading.
- Backups: use `pg_dump`/`pg_restore` (or managed snapshots) against the
  PostgreSQL service. Never run `docker compose down -v` in production — it
  deletes the `postgres-data` volume. Restart with `docker compose restart`
  or `up -d` to preserve volumes.

```powershell
# Rolling restart without touching data:
docker compose -f compose.yaml up -d --build
# Backup (example):
docker compose exec postgres pg_dump -U ivp industrial_vision > backup.sql
```

## Deploy modes

- CPU (default): `docker compose -f compose.yaml up --build`.
- GPU: add `-f compose.gpu.yaml` on a CUDA host with the NVIDIA Container
  Toolkit.
- Local debug ports: add `-f compose.dev.yaml` (loopback-only).
- Monitoring: add `-f compose.monitoring.yaml` (Prometheus + Grafana, with
  healthchecks and log rotation). Requires `GRAFANA_ADMIN_PASSWORD`.

Full container details: `docs/DOCKER_GPU_DEPLOYMENT.md`.

## Frontend security headers

The web image applies a security-header baseline: a two-stage CSP
(`Content-Security-Policy-Report-Only` by default; set `CSP_ENFORCE=true`
build arg to enforce), `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`,
`X-Permitted-Cross-Domain-Policies: none`, and a restrictive
`Permissions-Policy`. HSTS is **opt-in** (`HSTS_ENABLED=true`) and should
only be enabled once HTTPS termination is confirmed. `poweredByHeader` is
disabled. The API applies its own baseline headers, plus HSTS in production.
