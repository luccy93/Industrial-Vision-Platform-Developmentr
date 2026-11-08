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
- V29 centralizes detection in `backend/app/core/redaction.py`. Logging and
  release evidence share the same policy, including prefixed environment names
  (`POSTGRES_PASSWORD`, `IVP_POSTGRES_PASSWORD`, `SERVICE_API_TOKEN`,
  `GITHUB_APP_PRIVATE_KEY`), JSON/YAML-like structured fields, URL credentials,
  authorization/cookie/custom headers, and private-key blocks.
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

## Release images and digest deployment (V22/V23)

A strict stable SemVer tag (`vMAJOR.MINOR.PATCH`) publishes **api**, **web**
and **api-gpu** to GHCR. Tags are `v<version>` and `sha-<short-sha>`; `latest`
is intentionally not published. The release manifest records the digest,
image ID, SBOM and attestation for each image; deploy by digest.

```powershell
$env:IVP_API_IMAGE="ghcr.io/<owner>/<repo>/api@sha256:<digest>"
$env:IVP_WEB_IMAGE="ghcr.io/<owner>/<repo>/web@sha256:<digest>"
docker compose -f compose.yaml -f compose.release.yaml pull
docker compose -f compose.yaml -f compose.release.yaml up -d
```

For a CUDA host, use `compose.gpu.release.yaml` with
`IVP_CPU_API_IMAGE`, `IVP_GPU_API_IMAGE` and `IVP_WEB_IMAGE`. Do not add
`compose.gpu.yaml` (it restores local builds and defeats digest pinning).

The release workflow re-runs every gate (tests, ruff, eslint, typecheck,
frontend build, pip-audit, npm audit, gitleaks, trivy), builds all three
images, scans them (blocking at CRITICAL/HIGH with a fix available), re-pulls
each by digest and compares image IDs, then publishes SBOMs and GitHub
attestations. The GitHub Release records the results.

Verify before deploying and re-scan what you pulled:

```powershell
gh attestation verify oci://ghcr.io/<owner>/<repo>/api@sha256:<digest> `
  --repo <owner>/<repo>
docker save -o api.tar ghcr.io/<owner>/<repo>/api@sha256:<digest>
docker run --rm -v "${PWD}:/imgs" -v trivy-cache:/root/.cache/trivy `
  ghcr.io/aquasecurity/trivy@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222 `
  image --input /imgs/api.tar --scanners vuln --severity CRITICAL,HIGH `
  --ignore-unfixed --exit-code 1
```

Rollback is a digest change: redeploy the previous manifest's digests. Do not
reverse migrations automatically; restore the pre-upgrade backup if the older
application is incompatible with the current schema. Never move or delete a
release tag. Full procedure: `docs/RELEASES.md`.

### Verification and recovery gates (V23)

A verification report authorizes deployment only when it is bound to the exact
manifest bytes and release subject, uses the `production` profile, has
`overall_state: PASS`, has `verified` and `production_verified` both `true`,
and has `PASS` CPU and GPU artifact states. Check it before deploying:

```powershell
python -m tools.release.cli check-report `
  --report release-verification.json `
  --manifest release-manifest.json `
  --require-production
```

After `docker compose ... up -d`, verify the resolved configuration and the
running stack:

```powershell
python -m tools.release.cli verify-deploy `
  --manifest release-manifest.json `
  --report release-verification.json --require-verified `
  --running --check-logs
```

This rejects mutable tags and local `build:` definitions, requires Compose to
resolve exactly the manifest digests, compares each running container's image
ID with the manifest, and optionally scans recent service logs for credential
patterns. Findings name the pattern type only; secret values are never
printed. Treat any `FAIL` as a deployment failure and roll back.

Run the post-deployment smoke with a dedicated account:

```powershell
$env:IVP_SMOKE_PASSWORD="<smoke-user-password>"
python -m tools.release.cli smoke `
  --api-url https://ops.example.com/api `
  --web-url https://ops.example.com `
  --username smoke@example.com `
  --output deployment-smoke.json
```

The smoke covers `/live`, `/ready`, security headers, invalid-credential
rejection, positive login and `/me`, a CSRF-protected WebSocket ticket, an
unauthenticated socket (must close with `4401`), an authenticated socket, and
frontend headers. Missing credentials or a missing web URL produce required
`NOT_RUN` checks, so the report cannot be `verified`. Passwords are read from
the environment and never appear in the report.

For rollback, generate a plan from the previous manifest and its production
report:

```powershell
python -m tools.release.cli rollback-plan `
  --manifest previous-release-manifest.json `
  --report previous-release-verification.json `
  --current-manifest release-manifest.json `
  --backup-file before-rollback.sql `
  --output rollback-plan.txt
```

`--allow-unverified` is an emergency-only bypass; it prints a warning and
requires independent digest verification. The plan never reverses migrations
automatically, never deletes the PostgreSQL volume, and never moves or reuses
a release tag.

Evidence states are `PASS`, `FAIL`, `NOT_RUN`, `UNAVAILABLE`, and `SIMULATED`.
Only `PASS` is success. A missing tool, network, credential, or GPU is
reported honestly rather than converted into a pass.

Base images (`node:20-alpine`, `python:3.11-slim-bookworm`) are not
digest-pinned, so a rebuild may pull new base packages; the image scan is the
control that surfaces that before a deployment. Gate list, severity policy and
the accepted-risk register: `docs/SECURITY_SCANNING.md`.

### Live infrastructure verification (V28)

Before a separately authorized staging deployment, V28 can inspect the external
release infrastructure read-only. The live profile checks the GitHub tag,
release, assets, and workflow run; GHCR digests and platform metadata; GitHub
attestations and local SBOM/scan evidence; bounded DNS/TCP/TLS/HTTPS/WSS
reachability; an existing Docker context; and rollback prerequisites.

```powershell
python -m tools.release.cli staging-readiness `
  --manifest release-artifacts/release-manifest.json `
  --target staging-target.json `
  --previous-manifest previous-manifest.json `
  --previous-verification-report previous-release-verification.json `
  --rollback-evidence rollback-rehearsal.json `
  --artifacts-dir release-artifacts `
  --migration-report migration-compatibility.json `
  --backup-documentation docs/BACKUP_RESTORE.md `
  --docker-host staging-east `
  --connectivity-timeout 10 `
  --execute-live `
  --output release-artifacts/staging-readiness.json
```

The target is never inferred. It must state exactly that it is an explicitly
authorized staging environment and is not production, list every allowed
hostname, and declare production hostnames. A target that fails this policy is
not contacted. Connectivity uses only the target URLs, a 1-60 second timeout,
certificate and hostname validation, and no port scanning. `--docker-host`
names an existing Docker context; only read-only `version`, `context inspect`,
`compose version`, `ps`, and `info` commands run.

A V28 `PASS` is preparation evidence only. It never authorizes deployment and
does not replace V24 production qualification. Missing credentials, a missing
release, an unreachable registry, an unreachable Docker daemon, or absent
staging evidence is reported as `UNAVAILABLE` or `NOT_RUN`, never converted
into a pass. See
[V28_LIVE_INFRASTRUCTURE_VERIFICATION.md](V28_LIVE_INFRASTRUCTURE_VERIFICATION.md).

### Credential and evidence retention hardening (V29)

V29 applies one credential policy before diagnostic data is persisted:

- Release report writers serialize through `dump_sanitized_json` and compute
  SHA-256 over the exact stored sanitized bytes. A hash is never taken over an
  unsanitized payload and attached to a sanitized file.
- Readiness evidence that is clean is retained byte-for-byte with its original
  hash. A secret-bearing input is not bound and still produces the existing
  `evidence-retention` blocker. A separately named
  `<kind>-<sanitized_digest[:12]>-redacted<ext>` diagnostic copy may be written
  for review; it is not evidence and never reuses the original hash.
- Unparseable JSON evidence is rejected rather than copied. Oversized and
  non-UTF-8 inputs are not retained.
- The logging filter redacts arguments before formatting the message, then
  stores the sanitized final message, so placeholders such as `token=%s` do
  not break formatting. A pre-set `exc_text` is sanitized as well.

Use environment-variable indirection in evidence and configuration. If a
retention blocker appears, remove the secret from the source document and
re-run; do not copy the raw file into the evidence directory. Rotate any
credential that may have been written before V29. See
[V29_EVIDENCE_RETENTION_SECURITY.md](V29_EVIDENCE_RETENTION_SECURITY.md).

### Evidence integrity and tamper detection (V30)

V30 adds an optional, separate integrity sidecar and append-only JSONL audit
chain. Existing reports are not modified and keep their existing
`schema_version`. Verification is read-only and never repairs, rewrites,
quarantines, or deletes evidence.

```powershell
# Create the sidecar and audit chain once, after the report is final.
python -m tools.release.cli seal-evidence `
  --report release-artifacts/staging-readiness.json `
  --evidence-root release-artifacts/readiness-evidence

# Re-read the evidence and verify every binding.
python -m tools.release.cli verify-evidence `
  --report release-artifacts/staging-readiness.json `
  --manifest release-manifest.json

# Anchor the chain and verify against the trusted checkpoint later.
python -m tools.release.cli checkpoint-evidence `
  --audit release-artifacts/staging-readiness.audit.jsonl `
  --output release-artifacts/staging-readiness.checkpoint.json
python -m tools.release.cli verify-audit `
  --audit release-artifacts/staging-readiness.audit.jsonl `
  --checkpoint release-artifacts/staging-readiness.checkpoint.json
```

Exit codes are `0` for `PASS`, `1` for `FAIL`, `2` for `UNAVAILABLE`, `3` for
`NOT_RUN`, and `4` for an invalid invocation. Missing evidence or a check that
could not run is never converted into a pass. A local hash chain is
tamper-evident, not immutable: an attacker with write access to both the
evidence and the chain can recompute every hash. Store checkpoints somewhere
the evidence producer cannot rewrite. See
[V30_EVIDENCE_INTEGRITY_AND_TAMPER_DETECTION.md](V30_EVIDENCE_INTEGRITY_AND_TAMPER_DETECTION.md).

### Signed evidence checkpoints and trust anchoring (V31)

V31 adds optional Ed25519-signed checkpoints and an explicit offline trust-key
lifecycle. The V30 sidecar and audit chain remain the integrity layer; V31
establishes producer-key trust only through a separately configured trust store
or a separately supplied public-key fingerprint. A checkpoint-supplied public
key is never trusted merely because the checkpoint claims it is trusted.

```powershell
# Generate an offline key and export only its public descriptor.
python tools/manage_evidence_trust.py generate-key `
  --key-id evidence-2026-01 `
  --private-key keys/evidence-2026-01.pem `
  --public-key keys/evidence-2026-01.pub.json

# Create and populate a trust store that the evidence producer cannot rewrite.
python tools/manage_evidence_trust.py init-store --store trust-store.json
python tools/manage_evidence_trust.py register-key `
  --store trust-store.json `
  --public-key keys/evidence-2026-01.pub.json `
  --activated-at 2026-11-01T00:00:00Z

# Sign a checkpoint after the V30 sidecar and audit chain are final.
python -m tools.release.cli sign-checkpoint `
  --audit release-artifacts/staging-readiness.audit.jsonl `
  --report release-artifacts/staging-readiness.json `
  --integrity release-artifacts/staging-readiness.integrity.json `
  --private-key keys/evidence-2026-01.pem `
  --key-id evidence-2026-01 --sequence 1 `
  --output release-artifacts/staging-readiness.signed-checkpoint.json

# Verify with independent trust material and optional replay state.
python -m tools.release.cli verify-evidence `
  --report release-artifacts/staging-readiness.json `
  --integrity release-artifacts/staging-readiness.integrity.json `
  --audit release-artifacts/staging-readiness.audit.jsonl `
  --checkpoint release-artifacts/staging-readiness.signed-checkpoint.json `
  --trust-store trust-store.json `
  --trust-state trust-state.json
```

`--update-trust-state` is an explicit write and only runs after a `PASS` with a
verified signed checkpoint. Verification is read-only by default. A signed
checkpoint without trust material is `UNAVAILABLE` (exit `2`), never `PASS`. A
local trust state detects replay within its recorded history but is not
independently monotonic; V31 reports `assurance: "reduced"` and never calls
local state an external anchor. No external trust-anchor service, cloud KMS,
GitHub API, registry, staging system, or production endpoint is contacted.

Before rotating, register the replacement public key explicitly, activate it,
and revoke the old key. Historical checkpoints verify under the configured
`allow_before_revocation` or `deny` policy. Never commit or store a private key
with evidence. See
[V31_SIGNED_EVIDENCE_AND_TRUST_ANCHORING.md](V31_SIGNED_EVIDENCE_AND_TRUST_ANCHORING.md).

### Transparency log and independent checkpoint anchoring (V32)

V32 adds an optional append-only JSONL transparency log that stores only V31
signed-checkpoint references and digests, RFC 6962/9162 Merkle inclusion and
consistency proofs, Ed25519-signed tree heads, a separate local transparency
trust state, and a provider-neutral anchor interface. The V30 integrity sidecar,
V31 signed checkpoints, trust store, and evidence trust state are unchanged.

```powershell
# Create the log and append a verified V31 signed-checkpoint reference.
python -m tools.transparency_log init-log `
  --log release-artifacts/transparency.jsonl `
  --log-id evidence-log `
  --timestamp 2026-01-01T00:00:00Z
python -m tools.transparency_log append-checkpoint `
  --log release-artifacts/transparency.jsonl `
  --checkpoint release-artifacts/staging-readiness.signed-checkpoint.json `
  --timestamp 2026-01-07T00:00:01Z
python -m tools.transparency_log verify-log `
  --log release-artifacts/transparency.jsonl

# Create and verify an inclusion proof and a consistency proof.
python -m tools.transparency_log create-inclusion-proof `
  --log release-artifacts/transparency.jsonl `
  --leaf-index 0 `
  --output release-artifacts/inclusion-0.json
python -m tools.transparency_log create-consistency-proof `
  --log release-artifacts/transparency.jsonl `
  --old-tree-size 3 `
  --output release-artifacts/consistency-3.json

# Sign a tree head with a key registered for transparency_tree_head_signing.
python -m tools.transparency_log create-tree-head `
  --log release-artifacts/transparency.jsonl `
  --private-key keys/transparency-2026-01.pem `
  --key-id transparency-2026-01 `
  --output release-artifacts/transparency-tree-head.json `
  --timestamp 2026-01-09T00:00:00Z

# Verify the tree head and explicitly advance the separate trust state on PASS.
python -m tools.transparency_log verify-tree-head `
  --tree-head release-artifacts/transparency-tree-head.json `
  --trust-store trust-store.json `
  --trust-state transparency-state.json `
  --update-trust-state `
  --state-updated-at 2026-01-10T00:00:00Z
```

`--update-trust-state` is an explicit write and only runs after a `PASS`;
verification is read-only by default. A missing log, proof, receipt, tree head,
or trust material is `UNAVAILABLE` (exit `2`), never `PASS`. The separate
transparency trust state detects replay, tree-size rollback, root conflicts,
duplicate tree-head IDs, missing consistency proofs, and timestamp regression.
Failed verification never overwrites previously trusted tree-head state. A
newer timestamp alone is not consistency evidence.

The only shipped provider is a local deterministic test provider. Its receipts
are always `SIMULATED`; `anchor-tree-head` requires explicit `--provider-key`
and `--receipt-dir` and otherwise reports `NOT_CONFIGURED` (exit `2`). An
unavailable provider reports `UNAVAILABLE` (exit `2`). No provider fallback is
performed. `EXTERNAL_VERIFIED` is reserved for a future genuinely configured and
verified external provider; V32 ships none, contacts no external transparency
service, cloud KMS, GitHub API, registry, staging system, or production
endpoint, and never claims external anchoring. See
[V32_TRANSPARENCY_LOG_AND_INDEPENDENT_ANCHORING.md](V32_TRANSPARENCY_LOG_AND_INDEPENDENT_ANCHORING.md).

### Continuous integrity monitoring (V33)

V33 runs the V30–V32 verifiers continuously without modifying any protected
artifact. It is offline/local by default and writes only its isolated SQLite
monitoring store.

```powershell
# Point the auditor at read-only copies of the V30-V32 inputs.
$env:INTEGRITY_EVIDENCE_REPORT="release-artifacts/staging-readiness.json"
$env:INTEGRITY_EVIDENCE_INTEGRITY="release-artifacts/staging-readiness.integrity.json"
$env:INTEGRITY_EVIDENCE_AUDIT="release-artifacts/staging-readiness.audit.jsonl"
$env:INTEGRITY_EVIDENCE_CHECKPOINT="release-artifacts/staging-readiness.signed-checkpoint.json"
$env:INTEGRITY_TRANSPARENCY_LOG="release-artifacts/transparency.jsonl"
$env:INTEGRITY_TREE_HEADS_DIR="release-artifacts/tree-heads"
$env:INTEGRITY_INCLUSION_PROOFS_DIR="release-artifacts/inclusion"
$env:INTEGRITY_CONSISTENCY_PROOFS_DIR="release-artifacts/consistency"
$env:INTEGRITY_TRANSPARENCY_TRUST_STORE="trust-store.json"
$env:INTEGRITY_MONITORING_DB_URL="sqlite:///./var/integrity-monitoring.db"

# Optional bounded scheduler (opt-in; default off).
$env:INTEGRITY_SCHEDULER_ENABLED="true"
$env:INTEGRITY_SCHEDULER_INTERVAL_SECONDS="300"
```

Manual runs use `POST /api/v1/integrity/audits` with explicit scopes or
`FULL`. `GET /api/v1/integrity/status`, `/summary`, `/audits`,
`/audits/{id}`, `/findings`, and `/history` are authenticated reads; starting
or cancelling an audit requires `ADMIN` or `OPERATOR`
(`integrity_audit_run`). The `/integrity` dashboard shows the same data.

A confirmed failure is always `FAIL`; unconfigured or unavailable scopes
produce `PARTIAL`/`UNAVAILABLE`, never `PASS`. Findings and notifications pass
through V29 redaction. Alerting is opt-in and creates pending delivery rows; it
never claims channel delivery success. No external transparency service, cloud
KMS, GitHub, registry, staging, or production endpoint is contacted, and V33
never claims external anchoring. Shared-store deployments must point every
worker/API process at the same SQLite file for cross-process duplicate
prevention. See
[V33_CONTINUOUS_INTEGRITY_MONITORING.md](V33_CONTINUOUS_INTEGRITY_MONITORING.md).

## Frontend security headers

The web image applies a security-header baseline: a two-stage CSP
(`Content-Security-Policy-Report-Only` by default; set `CSP_ENFORCE=true`
build arg to enforce), `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`,
`X-Permitted-Cross-Domain-Policies: none`, and a restrictive
`Permissions-Policy`. HSTS is **opt-in** (`HSTS_ENABLED=true`) and should
only be enabled once HTTPS termination is confirmed. `poweredByHeader` is
disabled. The API applies its own baseline headers, plus HSTS in production.
