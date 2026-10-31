# V27 Cross-Platform Readiness Compatibility

V27 hardens the V26 staging readiness path without changing what readiness
means. It makes the report schema accept honest incomplete preflight reports
and makes prerequisite discovery reliable on Windows and POSIX hosts. It does
not deploy, publish, tag, dispatch a workflow, run a migration, mutate staging
or production, or authorize any release action.

## Why V27 exists

V26 could produce a legitimate non-`PASS` preflight report when a target,
manifest, previous release evidence, GitHub credentials, a Docker daemon, or
GPU hardware was absent. The report was honest, but the published JSON Schema
still required complete PASS-shaped values, so the report failed schema
validation before `check-readiness` could explain the real blockers.

V27 also removes an implicit POSIX assumption from tool probes. On Windows,
Node.js and npm are commonly exposed through `.cmd` shims. Invoking a shim
directly can fail or require shell interpolation. V27 resolves the executable
first and invokes Windows shims through `cmd.exe` with an argument list.

## Report compatibility

The schema version and profile remain unchanged:

```json
{
  "schema_version": 1,
  "profile": "staging_readiness"
}
```

The schema is conditional:

- A non-`PASS` report may contain `null` for `staging_target`, repository
  identity strings, release identity fields, and each of the five evidence
  bindings. Release digest entries may be missing. `ready` must be `false`.
- A `PASS` report remains strict. It requires a complete staging target, a
  complete release subject and all required image digests, a resolved
  repository commit, all five `PASS` bindings, retained evidence, at least 47
  checks, no required non-`PASS` check, no preflight/live-mode contradiction,
  and `ready: true`.
- `production_qualified` is always `false`, and deployment is always
  unauthorized and unperformed.

Schema validity is not a readiness gate. `check-readiness` continues to
revalidate the complete report at runtime, including mandatory check names,
manifest binding, evidence hashes, target evidence, aggregate state, and the
exact report SHA-256 when supplied. A schema-valid non-`PASS` report is still
rejected by `check-readiness`.

## Cross-platform tool discovery

Readiness probes resolve a command before execution:

- the requested name is looked up first;
- on Windows, `name.cmd` and `name.bat` are tried when the requested name has
  no suffix;
- a fallback shim must be a real file;
- `.cmd` and `.bat` shims are invoked through
  `%COMSPEC% /d /s /v:off /c call <resolved-shim> <args...>`;
- every command is passed as an argument list, never interpolated into a shell
  command string;
- unsafe Windows metacharacters are rejected rather than escaped;
- probes use bounded timeouts and report only sanitized failure categories.

This applies to Node.js and npm, Docker CLI/daemon/Compose, GitHub CLI, and
NVIDIA tooling. The readiness report preserves distinct outcomes instead of
collapsing them into a single unavailable state:

| Condition | Reported state |
| --- | --- |
| npm shim resolved and version probe succeeds | `PASS` |
| npm shim missing, version probe fails, or times out | `UNAVAILABLE` |
| Docker CLI present, daemon unreachable | CLI `PASS`, daemon `UNAVAILABLE` |
| Docker Compose plugin absent | `UNAVAILABLE` |
| GitHub CLI present but token only configured, not verified | CLI `PASS`, auth `UNAVAILABLE` |
| GPU optional and not probed | `NOT_RUN` |
| GPU required but hardware/runtime absent | `UNAVAILABLE` |

A credential environment variable proves only that a value is present. It does
not prove authentication. A GPU `NOT_RUN` on a CPU target does not imply GPU
readiness.

## Offline validation

The V27 tests are deterministic and offline. They do not require GitHub, GHCR,
a Docker daemon, staging access, credentials, or NVIDIA hardware. The Windows
shim tests inject a platform name, resolver, environment, and command runner so
they behave the same on every CI host.

```bash
pytest backend/tests/unit/test_release_readiness.py -q
python -m ruff check tools/release/readiness.py backend/tests/unit/test_release_readiness.py
python -m ruff format --check tools/release/readiness.py backend/tests/unit/test_release_readiness.py
```

The schema tests validate both a real incomplete preflight report and a
generated V26 `PASS` report with the offline `jsonschema` validator. They also
confirm that malformed incomplete reports, contradictory flags, missing PASS
bindings, and PASS reports with null required values are rejected.

## Compatibility with V22-V26

- V22/V23 verification and attestation contracts are unchanged.
- V24 qualification profiles, deployment preflight, rollback rehearsal, and GPU
  evidence requirements are unchanged.
- V25 staging target validation, staging qualification, and mutation
  authorization are unchanged. V27 only makes a non-`PASS` readiness report
  schema-valid; it does not relax any V25 gate.
- V26 readiness check names, mandatory checks, evidence retention, runtime
  validation, and deployment prohibition are unchanged.
- A readiness `PASS` remains preparation evidence only. It is not production
  qualification and does not authorize deployment.

## Current live-evidence status

The V27 implementation environment still has no live release evidence:

- `gh` is not installed and `GH_TOKEN` / `GITHUB_TOKEN` are unset;
- the Docker CLI is present but the daemon is unreachable;
- no staging target, previous release evidence, rollback evidence, or smoke
  credentials are available;
- no NVIDIA GPU or `nvidia-smi` is available.

The honest result remains a non-`PASS` readiness report with explicit
`UNAVAILABLE` or `NOT_RUN` checks and blockers. No live GitHub, GHCR, Docker,
staging, GPU, release, publication, workflow, deployment, or migration action
was performed for V27.
