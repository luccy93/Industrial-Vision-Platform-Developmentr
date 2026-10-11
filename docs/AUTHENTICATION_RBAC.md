# Authentication & RBAC (V16)

> Foundation snapshot (Commit 01). Endpoint contracts, bootstrap commands,
> and deployment guidance land with Commit 02; the final validation report
> lands with Commit 03.

## Architecture

- **Opaque server-side sessions.** Login mints a cryptographically random
  256-bit token; only its SHA-256 digest is stored (`user_sessions`).
  The raw token travels in an `HttpOnly; SameSite=Lax; Path=/` cookie
  (`Secure` in production). Nothing reusable lives in browser storage.
- **Session-bound CSRF.** A per-session CSRF token (digest on the session
  row) is required in `X-CSRF-Token` on state-changing authenticated
  requests, compared in constant time.
- **Single-use WebSocket tickets.** Short-lived (30s), digest-persisted,
  atomically consumed exactly once; scoped (`operations`, `camera:{id}`).
- **Argon2id passwords.** 15–128 chars, Unicode/spaces allowed, no
  composition rules, shipped common-password blocklist.

## Role / permission matrix

| Capability | ADMIN | OPERATOR | VIEWER |
|---|---|---|---|
| Read dashboards, ops, analytics, incidents, notifications | Yes | Yes | Yes |
| Incident lifecycle + evidence | Yes | Yes | No |
| Camera start/stop | Yes | Yes | No |
| Time-limited notification mute | Yes | Yes | No |
| Camera CRUD, zones, profiles, suppression, alert rules, delivery retry | Yes | No | No |
| User admin, role changes, deactivation, session revocation | Yes | No | No |

Sensitive user operations additionally require authentication within the
previous 10 minutes (`403 recent_auth_required` otherwise).

## Policy defaults

Session idle 15 min / absolute 12 h, rotation on login and credential /
privilege changes. Login throttle: 5 failures / 15 min per account with
escalating delays capped at 15 min; 30 / 15 min per IP; no permanent
lockout. Client IPs are hashed (truncated SHA-256), never stored raw.
No logs carry passwords, hashes, session tokens, CSRF values, or tickets.

## Migration

`009_create_auth` follows `008_create_alerting` (single head). Tables:
`users`, `user_sessions`, `ws_tickets`, `login_attempts`, `auth_audit`.
Upgrade/downgrade covered by `test_auth_migration.py`.

## Testing (foundation)

```bash
python -m pytest backend/tests/unit/test_auth_foundation.py backend/tests/integration/test_auth_repository.py backend/tests/integration/test_auth_migration.py -q
ruff check backend/app/auth backend/app/models/auth_orm.py
```
