# Authentication & RBAC (V16)

Opaque server-side sessions, backend-enforced roles, single-use WebSocket
tickets. The frontend is usability only — FastAPI authorizes everything.

## Architecture

- **Sessions.** Login mints a cryptographically random 256-bit opaque
  token; only its SHA-256 digest is stored (`user_sessions`). The raw
  token travels in an `HttpOnly; SameSite=Lax; Path=/` cookie (`Secure`
  in production). Rotation on every login and on credential/privilege
  changes (prior sessions revoked). Idle 15 min, absolute 12 h.
  `Path=/` (not `/api`) so the browser also presents the cookie to the
  Next.js server layer for DAL verification in same-origin deployments;
  state-changing requests are still gated by the CSRF header.
- **CSRF.** Per-session token, digest on the session row, required in
  `X-CSRF-Token` on state-changing authenticated requests (constant-time
  compare). Rotation on login, password change, and `POST /auth/csrf`.
  Login is the documented exemption (origin-checked + rate-limited).
- **Origin policy.** A global middleware rejects cross-origin browser
  state changes outside `CORS_ALLOWED_ORIGINS`; credentialed CORS stays
  restricted to explicit origins (wildcard + credentials fails startup
  in every environment; production additionally requires explicit
  origins and `CORS_ALLOW_CREDENTIALS=true`).
- **WebSocket tickets.** Authenticated, CSRF-protected `POST /ws-ticket`
  mints a 30 s single-use ticket (digest-persisted, atomically consumed
  exactly once, scoped `operations` / `camera:{id}`), passed as
  `?ticket=`. Connections close `4401` (no/invalid ticket) or `4403`
  (revoked); live connections revalidate every 30 s and drop within
  60 s of revocation. Tickets are never logged and are useless as REST
  credentials.
- **Passwords.** Argon2id (salted), 15–128 chars, Unicode/spaces allowed,
  no composition rules, no routine rotation, shipped common-password
  blocklist (offline; online breach-corpus checks are a limitation).
  Failures are generic (`Invalid email or password.`).
- **Throttle (DB-backed, cross-worker).** 5 failures / 15 min per account
  → escalating delays (1, 2, 4, …) capped at 15 min; 30 / 15 min per IP;
  no permanent lockout. Client IP = direct peer unless the peer is an
  explicitly configured trusted proxy (`AUTH_TRUSTED_PROXIES`). Raw IPs
  are hashed (truncated SHA-256), never stored.
- **Step-up.** User create / role change / deactivate / revoke-others
  require authentication within the last 10 min (`403
  recent_auth_required`). Forced-change users are gated to the auth
  endpoints until the change succeeds (`403 password_change_required`).
- **Last admin.** Demote/deactivate guards are single-statement
  conditional UPDATEs — concurrent requests cannot jointly remove the
  final active administrator. Deactivation and role demotion revoke all
  of that user's sessions; password change revokes all except current.
- **Audit.** `auth_audit` records bootstrap, user create/role/activate,
  forced resets, revocations, logins, password changes (sanitized;
  never credentials, hashes, tokens, or tickets).

## Role / permission matrix

| Capability | ADMIN | OPERATOR | VIEWER |
|---|---|---|---|
| Read dashboards, ops, analytics (incl. CSV), incidents, notifications | Yes | Yes | Yes |
| Incident lifecycle + evidence (create→close) | Yes | Yes | No |
| Camera start/stop (stop: confirm + reason, audited) | Yes | Yes | No |
| Time-limited notification mute (≤480 min; detection/history continue) | Yes | Yes | No |
| Camera CRUD, zones, profiles, defect categories, suppression, alert rules, delivery retry | Yes | No | No |
| User admin, role changes, activation, session revocation (+ 10 min step-up) | Yes | No | No |

`401` = missing/invalid authentication; `403` = authenticated but
lacking permission (or forced-change / step-up gate).

## Endpoint paths and contracts

- `POST /api/v1/auth/login` `{email, password}` → `{user, csrf_token,
  session_expires_at, must_change_password}` + cookie. Failures: generic
  `401 invalid_credentials`; throttled: `429 too_many_attempts` +
  `Retry-After`.
- `POST /api/v1/auth/logout` → `{ok:true}` + revoke + clear cookie
  (idempotent).
- `GET /api/v1/auth/me` → `{user, session_expires_at}` or `401`.
- `POST /api/v1/auth/csrf` → `{csrf_token}` (session + origin).
- `POST /api/v1/auth/change-password` `{current_password, new_password}`
  → `{ok:true}`; wrong current: `422 invalid_current_password`; policy:
  `422 password_too_short|password_too_long|password_blocklisted`.
- `POST /api/v1/auth/ws-ticket` `{scope}` → `{ticket, scope,
  expires_at}` (`operations` or `camera:{id}`, camera must exist).
- `GET /api/v1/auth/users` (list), `POST` (create, forced-change set),
  `GET/PATCH /{id}` (`extra=forbid`; role/active/reset), `POST
  /{id}/revoke-sessions` → `{ok, revoked}`. All ADMIN; mutations need
  step-up; last-admin violations → `409 last_admin`.
- `POST /api/v1/alerting/notifications/{id}/mute` `{minutes: 1–480}`
  → notification with `muted_until` (OPERATOR+). Delivery worker skips
  muted rows (left pending, no attempt consumed); detection, history,
  and analytics continue.
- Public (unchanged V11): `/`, `/health`, `/live`, `/ready`,
  `/api/v1/health`, docs. Everything else requires a session.

## Bootstrap

No registration endpoint, no default accounts, no seeding on startup.
Migrate first, then run against the real database:

```bash
python -m backend.app.auth.bootstrap --email ops@example.com
# password via secure prompt (twice); refuses if an admin exists
```

Docker: run the same command in the backend container with the
production `DATABASE_URL`. Tests use the `bootstrap_admin()` service
path directly (never the CLI, never printed secrets).

## Frontend

- `/login` (validated, loading, sanitized errors), `/change-password`
  (forced + self-service), `/users` (ADMIN table/create/role/activate/
  revoke).
- `AuthProvider` holds identity + CSRF only (in-memory; no browser
  storage). `apiFetch` sends cookies + CSRF, dispatches
  `ivp:unauthorized` on 401 → provider clears state and routes to
  `/login?next=` (validated same-origin); 403 renders access-denied.
- Layers: middleware presence-check redirect → root-layout DAL
  verification (`lib/auth/dal.ts`: live `/me`, `no-store`, forwarded
  cookie; forced-change and `/users` role gates) → FastAPI authority.
  No route-group file moves (documented deviation: 12 pages use
  relative imports + colocated tests; identical guarantees via
  middleware + layout DAL + backend).
- Sockets reuse `useOperationsSocket`/`useIntelligenceSocket` with a
  stable `getTicket(scope)` (fresh ticket per connect/reconnect;
  backoff without opening rejected sockets). Envelopes, dedup, queue
  bounds unchanged.

## Configuration

See `.env.example` (V16 block). Production fails startup on:
`AUTH_COOKIE_SECURE=false`, wildcard CORS origins, missing origins,
missing `CORS_ALLOW_CREDENTIALS=true`, bad `AUTH_COOKIE_SAMESITE`,
or `AUTH_PASSWORD_MIN_LENGTH > MAX`.

## Migration

`009_create_auth` (`users`, `user_sessions`, `ws_tickets`,
`login_attempts`, `auth_audit`) follows `008_create_alerting`;
`010_add_notification_mute` adds `notifications.muted_until`. Single
head. Upgrade/downgrade covered by `test_auth_migration.py` (009 cycle)
— extend for 010 in hardening.

## Testing

```bash
python -m pytest backend/tests/unit/test_auth_foundation.py backend/tests/integration/test_auth_repository.py backend/tests/integration/test_auth_migration.py -q
python -m pytest backend/tests -q
ruff check backend
python -m mypy backend/app/auth backend/app/models/auth_orm.py
cd frontend && npm run test:run && npm run typecheck && npm run build
```

Live PostgreSQL `alembic check` requires a local service; report as
skipped when unavailable (as in V15). No MFA/SSO/federation,
per-camera tenant isolation, or pen-test certification — documented
limitations. Route inventory + concurrency + WS + frontend suites land
in Commit 03 with the final validation report.
