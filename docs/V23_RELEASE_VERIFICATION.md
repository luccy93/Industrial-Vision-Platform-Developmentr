# V23 Production Release Verification and Recovery

V23 makes release verification independent from the release pipeline and gives
operators a safe way to deploy, smoke, and roll back a digest-pinned release.
It does not create a release tag, publish a hosted image, or claim a live
production deployment.

V24 builds on this evidence with live release qualification: see
`docs/V24_LIVE_RELEASE_QUALIFICATION.md`. V23 remains the artifact-verification
contract. V24 does not reinterpret `production_verified` or upgrade missing
deployment, rollback-rehearsal, or GPU-runtime evidence.

## Delivered

- **Independent verification** (`tools/release/verification.py`): git tag and
  branch identity, placeholder-digest rejection, registry digest resolution,
  pull-by-digest image-ID proof, `gh attestation verify` with signer and
  source-repository constraints, local DSSE bundle checks, SBOM predicate
  binding, and separate CPU/GPU artifact status.
- **Deployment gating** (`tools/release/deployment.py`): production report
  validation bound to the exact manifest bytes and release subject, Compose
  digest pinning, rejection of local `build:` definitions, running-container
  image-ID comparison, credential-pattern log scanning, and a rollback plan
  that preserves data.
- **Post-deployment smoke** (`tools/release/smoke.py`): `/live`, `/ready`,
  security headers, invalid-credential rejection, positive login and `/me`,
  CSRF-protected WebSocket ticket, unauthenticated socket close `4401`,
  authenticated socket, and frontend headers. Missing inputs are required
  `NOT_RUN`, never success.
- **Publication recovery** (`tools/release/publication.py`): JSONL events with
  `push_started`, `pushed`, and `failed`; `complete`, `partial`, and `failed`
  reports; unknown, failed-only, and missing images; explicit recovery
  guidance that never reuses a tag or deletes a volume.
- **Workflow gates** (`.github/workflows/release.yml`): production
  verification after manifest generation, publication reporting with
  `if: always()`, release-job re-verification plus production-report and
  complete-publication gates, attached verification/publication reports, and a
  recovery job on failure. Existing action SHA pins and security gates are
  preserved.

## Evidence states

| State | Meaning | May authorize production? |
| --- | --- | --- |
| `PASS` | Check ran and matched independently observed facts. | Yes, when every required gate passes. |
| `FAIL` | Check ran and contradicted the manifest or policy. | No. |
| `NOT_RUN` | Required check did not execute. | No. |
| `UNAVAILABLE` | Required tool, network, registry, or hardware was absent. | No. |
| `SIMULATED` | Fixture-only evidence. | No. |

A production report authorizes deployment only when it is bound to the exact
manifest (`manifest_sha256`), matches the release tag/commit/repository, uses
the `production` profile, has `overall_state: PASS`, has `verified` and
`production_verified` both `true`, and has `PASS` CPU and GPU artifact states.
GPU runtime is tracked separately and is never inferred from artifact success.

## Validation performed

- 86 release-related tests passed: verification (31), deployment/report/log/
  rollback (19), smoke (9), publication (11), and workflow assertions (16).
- Full backend suite: 1312 passed, 1 skipped, 5 deselected.
- `ruff format --check backend tools` and `ruff check backend tools` passed
  (361 files).
- Frontend lint, typecheck, 93 tests, and production build passed.
- `python -m tools.release.cli audit-workflows --root .` passed; release
  actions remain SHA-pinned and `release.yml` parses.
- Static workflow tests cover the production verification gate, `always()`
  publication reporting, release-job report/publication gates, the recovery
  job, and sanitized `api_gpu_*` outputs.

## Not run or unavailable

These are honest gaps, not passes:

- **Registry and attestation verification**: the GitHub CLI (`gh`) is not
  installed on the validation host, and no GHCR credentials or hosted release
  exist. `gh attestation verify`, live digest resolution, and pull-by-digest
  proof remain `UNAVAILABLE`.
- **Container deployment and smoke**: the Docker daemon is unavailable, so a
  digest-pinned Compose deployment, running-container image-ID comparison,
  log scanning, smoke run, and rollback rehearsal remain `NOT_RUN`.
- **GPU runtime**: no NVIDIA GPU or `nvidia-smi` is present. GPU artifact
  status can be validated statically, but `runtime_state` remains `NOT_RUN`.

No release tag, GitHub Release, GHCR push, attestation, or production
deployment was created by this volume.

## Safety properties

- A local, simulated, partial, or unavailable verification never authorizes a
  deployment.
- Rollback requires a production report for the target manifest unless the
  operator explicitly passes `--allow-unverified`; that path prints a warning
  and requires independent digest verification.
- Rollback redeploys previous digests, takes a backup, never reverses Alembic
  migrations automatically, never runs `docker compose down -v`, and never
  moves, deletes, or reuses a release tag.
- Publication completion requires every expected image to have a proven
  `pushed` event with a valid digest and no evidence errors, unknown images,
  failed-only images, or missing images.
- Smoke reports never contain the supplied password and never turn missing
  credentials or a missing web URL into a verified result.

## Limitations

- The first live release has not run; workflow semantics, GHCR permissions, and
  attestation publication are validated statically and locally only.
- Registry and attestation checks depend on network access, GHCR credentials,
  and a GitHub CLI that supports artifact attestations.
- Deployment checks depend on a working Docker daemon and a reachable stack.
- GPU acceleration requires host-level runtime validation in addition to the
  artifact verification recorded here.
