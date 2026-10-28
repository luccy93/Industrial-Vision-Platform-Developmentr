# Releases and Supply Chain (V22/V23/V24)

V22 makes a release something that can be verified, not assumed. A strict
stable SemVer tag triggers a fail-closed pipeline that validates the tag and
commit, re-runs every V21 gate, scans the images, publishes **api**, **web**
and **api-gpu** to GHCR, records digests, produces SPDX SBOMs, attaches
GitHub attestations, and writes a manifest into the GitHub Release.

V23 adds an independent verification layer and a safe recovery path. The
pipeline now re-verifies the published digests and attestations after
publication, records whether publication was complete, partial, or failed,
and refuses to create the GitHub Release unless a production verification
report authorizes the exact manifest. Deployment and rollback tooling can
require that report, inspect a running stack, scan logs for leaked
credentials, and print a data-preserving rollback plan. Evidence is reported
as `PASS`, `FAIL`, `NOT_RUN`, `UNAVAILABLE`, or `SIMULATED`; only `PASS` is
success.

V24 adds live release qualification. `qualify` binds the exact manifest bytes,
verification report, publication digests, deployment evidence, rollback
rehearsal, and GPU runtime into one report. The CI release gate consumes an
artifact-scoped qualification; production qualification additionally requires
a real deployment, a passing rollback rehearsal, verified GPU runtime, and
explicit operator authorization. Qualification never upgrades missing
evidence to success.

No release tag has been created by these volumes. The workflow is validated
statically and locally; the first tag push is the first live end-to-end run.
The full V23 evidence record is in `docs/V23_RELEASE_VERIFICATION.md`; V24
qualification evidence is recorded in
`docs/V24_LIVE_RELEASE_QUALIFICATION.md`.

## Version policy

Only annotated tags matching `^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$`
are accepted.

| Accepted | Rejected |
| --- | --- |
| `v1.0.0`, `v1.2.3`, `v2.0.0` | `1.2.3` (no `v`) |
| | `v1.2` or `v1.2.3.4` |
| | `v1.2.3-rc.1`, `v1.2.3+build.5` |
| | `v01.2.3`, `v1.02.3` |
| | `latest`, `release-1.2.3` |

Increment rules:

- **PATCH** (`v1.2.3` -> `v1.2.4`): bug fixes, dependency/security updates,
  documentation and CI changes with no API/behavior break.
- **MINOR** (`v1.2.3` -> `v1.3.0`): backward-compatible features, additive
  endpoints, new optional configuration.
- **MAJOR** (`v1.2.3` -> `v2.0.0`): breaking API/schema/configuration changes.

Tags are immutable. Never delete, move, or re-point a release tag; never reuse
a version. Duplicate releases and existing GHCR version tags fail validation
before anything is built.

`latest` is deliberately **not** published. The only image tags are
`v<MAJOR.MINOR.PATCH>` and `sha-<7-character-commit>`. Deployments should use
the digest recorded in the release manifest.

## Cutting a release

Prerequisites: the commit is already on `origin/main`, `ci` is green, and the
version follows the increment rules above.

```powershell
git fetch origin
git switch main
git pull --ff-only
git tag -a v1.2.3 -m "v1.2.3"
git push origin v1.2.3
```

The tag must point at a commit reachable from `origin/main`; the workflow
verifies both the tag-to-commit mapping and the ancestry, and refuses to
publish if GitHub cannot prove that no release or matching image tag exists.

Protect tags in repository settings (restrict updates and deletions) so the
policy is enforced outside the workflow as well.

## What the workflow does

`.github/workflows/release.yml` runs four sequential jobs with least
privilege:

1. **validate** (`contents: read`, `packages: read`) - checks the tag grammar,
   tag/commit identity, and `origin/main` reachability; queries GitHub for an
   existing release or matching GHCR tags (any non-404 API failure blocks).
2. **gates** (`contents: read`) - the same blocking gates as `ci`: backend
   tests and ruff, frontend lint/typecheck/tests/build, pip-audit, npm audit
   (production dependencies), gitleaks, trivy filesystem/IaC, and the workflow
   pinning audit.
3. **publish** (`contents: read`, `packages: write`, `id-token: write`,
   `attestations: write`) - builds all three images with OCI source/revision/
   version labels, scans **all** of them at CRITICAL/HIGH with a fix available,
   and only then pushes. Each digest is read back from the registry, the image
   is re-pulled by digest, and the image ID is compared with the local build
   before the manifest accepts it. SBOMs are generated from the published
   digest, and provenance + SBOM attestations are pushed to the registry.
4. **release** (`contents: write`) - re-validates the manifest, generates
   change notes, and creates the GitHub Release with `--verify-tag`, attaching
   the manifest, SBOMs, attestation bundles and scan logs.

Any failure in `validate`, `gates`, a scan, or before the first push stops the
release without publishing images. Once a tag is pushed it is never moved; if
publishing fails after the tag exists, fix forward with the next PATCH tag.

## Artifacts and the manifest

| Artifact | Location |
| --- | --- |
| Images | `ghcr.io/<owner>/<repo>/{api,web,api-gpu}:v<version>` and `:sha-<short>` |
| Manifest | `release-manifest.json` on the GitHub Release |
| SBOMs | `{api,web,api-gpu}.spdx.json` (SPDX 2.3 JSON) |
| Attestation bundles | `*.provenance.jsonl`, `*.sbom-attestation.jsonl` |
| Scan evidence | `*.scan.txt`, `*.push.log`, `trivy-version.txt` |
| Workflow artifact | `release-artifacts` (90-day retention) |

The manifest validates:

- exact tag/commit/repository and workflow run identity;
- exactly the three required images with expected repositories and tags;
- recorded digest and the pull-by-digest image-ID proof;
- clean trivy image scans (CRITICAL/HIGH, `--ignore-unfixed`) with evidence
  hashes and scanner version;
- SBOM and attestation evidence hashes;
- GPU publication, with `runtime_smoke` equal to `passed` or `not_run` plus a
  reason.

`release/release-manifest.schema.json` documents the same shape;
`backend/tests/unit/test_release_manifest.py` keeps schema and code aligned.

## Verify a release

```bash
gh attestation verify oci://ghcr.io/<owner>/<repo>/api@sha256:<digest> \
  --repo <owner>/<repo>
gh attestation verify oci://ghcr.io/<owner>/<repo>/api@sha256:<digest> \
  --repo <owner>/<repo> \
  --predicate-type https://spdx.dev/Document
```

The exact commands for every image are in the release manifest and the release
notes. A successful verification proves which workflow, commit and repository
built the image; it does not by itself prove the image is vulnerability-free
(that is the recorded scan and your own re-scan).

To re-check the manifest locally:

```powershell
python -m tools.release.cli validate `
  --manifest release-manifest.json `
  --tag v1.2.3 --commit <40-hex>
```

## Independent release verification (V23)

`verify` re-derives release facts instead of trusting the manifest. It checks
the git tag/branch identity, rejects placeholder digests, resolves each image
in the registry, pulls every image by digest and compares the resulting image
ID, runs `gh attestation verify` with signer and source-repository
constraints, checks the local DSSE bundles, and binds each SBOM predicate to
the recorded digest. CPU and GPU artifacts are reported separately.

```powershell
python -m tools.release.cli verify `
  --manifest release-manifest.json `
  --artifacts-dir release-artifacts `
  --tag v1.2.3 --commit <40-hex> `
  --profile production --repo-root . --main-ref origin/main `
  --output release-verification.json
```

Evidence states are deliberate:

| State | Meaning |
| --- | --- |
| `PASS` | The check ran and matched independently observed facts. |
| `FAIL` | The check ran and contradicted the manifest or policy. |
| `NOT_RUN` | A required check did not execute (for example, missing credentials). |
| `UNAVAILABLE` | The tool, network, registry, or hardware needed for the check was absent. |
| `SIMULATED` | Fixture-only evidence; never valid for production verification. |

`NOT_RUN`, `UNAVAILABLE`, and `SIMULATED` are **not** success. A production
report authorizes deployment only when all of these hold:

- `schema_version` is current, `manifest_sha256` matches the exact manifest
  bytes, and the subject tag/commit/repository match the manifest release;
- `profile` is `production`, `overall_state` is `PASS`, and `verified` and
  `production_verified` are both `true`;
- `artifact_status.cpu.state` and `artifact_status.gpu.state` are `PASS`.

GPU runtime is tracked separately. `artifact_status.gpu.runtime_state` may be
`NOT_RUN` on a host without NVIDIA hardware; that is honest and does not
pretend the GPU was exercised. Verify runtime on the GPU host before relying
on acceleration.

Use the report as a deployment gate:

```powershell
python -m tools.release.cli check-report `
  --report release-verification.json `
  --manifest release-manifest.json `
  --require-production
```

The report schema is `release/release-verification.schema.json`.

## Live release qualification (V24)

Verification answers "are these artifacts genuine?" Qualification answers a
narrower deployment question: "may this exact manifest be deployed under this
profile and scope?" It consumes the V23 report rather than re-trusting the
manifest, and binds every input by SHA-256.

| Profile | Intended use | Required evidence |
| --- | --- | --- |
| `local_validation` | Offline or CI artifact gate | V23 report with `verified: true`, genuine DSSE bundles, SBOM/scan/digest checks, GPU artifact present |
| `staging_qualification` | Staging deployment | Production V23 report, complete publication, attestation trust, bound deployment report; GPU runtime only with `--require-gpu-runtime` |
| `production_qualification` | Production readiness | Staging requirements plus `full` scope, passing rollback rehearsal, verified GPU runtime, explicit authorization |

Scopes add evidence in order:

- `artifact`: manifest, verification, per-image digest/SBOM/scan/bundle hashes;
  publication is required with `--require-live-evidence` or any non-local
  profile.
- `deployment`: adds a deployment report bound to the same manifest bytes and
  subject, plus a bound preflight report when supplied.
- `full`: adds an executed rollback rehearsal with `executed: true`,
  `state: PASS`, and `verified: true`. `production_qualified` requires `full`.

```powershell
# Probe the host before claiming evidence you cannot produce.
python -m tools.release.cli qualify-prerequisites `
  --repo-root . --profile production_qualification --scope full `
  --tag v1.2.3 --commit <40-hex> `
  --artifacts-dir release-artifacts `
  --verification-report release-artifacts/release-verification.json `
  --publication-report release-artifacts/publication-report.json `
  --deployment-report release-artifacts/deployment-report.json `
  --rehearsal-report release-artifacts/rollback-rehearsal.json `
  --gpu-report release-artifacts/gpu-runtime.json `
  --production-authorized `
  --output release-artifacts/qualification-prerequisites.json

python -m tools.release.cli qualify `
  --manifest release-artifacts/release-manifest.json `
  --artifacts-dir release-artifacts `
  --profile production_qualification --scope full `
  --verification-report release-artifacts/release-verification.json `
  --publication-report release-artifacts/publication-report.json `
  --deployment-report release-artifacts/deployment-report.json `
  --rehearsal-report release-artifacts/rollback-rehearsal.json `
  --gpu-report release-artifacts/gpu-runtime.json `
  --tag v1.2.3 --commit <40-hex> --repository <owner>/<repo> `
  --repo-root . --main-ref origin/main `
  --output release-artifacts/release-qualification.json

python -m tools.release.cli check-qualification `
  --report release-artifacts/release-qualification.json `
  --manifest release-artifacts/release-manifest.json `
  --verification-report release-artifacts/release-verification.json `
  --publication-report release-artifacts/publication-report.json `
  --require-production
```

The qualification report binds:

- the exact manifest SHA-256 and subject tag, commit, and repository;
- the verification report hash, its manifest hash, profile, state, and
  `production_verified`;
- the publication report hash, completeness, and per-image digests;
- deployment, rollback-rehearsal, and GPU-runtime report hashes;
- every image digest, SBOM, scan log, provenance bundle, and SBOM
  attestation bundle hash.

`production_qualified` is true only when all of these hold: profile is
`production_qualification`, scope is `full`, every required check is `PASS`,
the V23 report has `production_verified: true`, the rollback rehearsal
verified the previous and target digests, and GPU runtime is verified on the
target host.

The CI `qualify` job runs `local_validation`/`artifact` with
`--require-live-evidence` after publication. It gates the GitHub Release but
never claims production qualification; the release job still requires the V23
production report. Deployment, rollback, and GPU qualification must be
produced on the real target hosts.

Report schema: `release/release-qualification.schema.json`.

## Deploy by digest

The release overlays remove every `build:` definition and require explicit
digest-pinned images. CPU:

```powershell
$env:IVP_API_IMAGE="ghcr.io/<owner>/<repo>/api@sha256:<cpu-digest>"
$env:IVP_WEB_IMAGE="ghcr.io/<owner>/<repo>/web@sha256:<web-digest>"
docker compose -f compose.yaml -f compose.release.yaml pull
docker compose -f compose.yaml -f compose.release.yaml up -d
```

GPU (the migration service uses the CPU api digest):

```powershell
$env:IVP_CPU_API_IMAGE="ghcr.io/<owner>/<repo>/api@sha256:<cpu-digest>"
$env:IVP_GPU_API_IMAGE="ghcr.io/<owner>/<repo>/api-gpu@sha256:<gpu-digest>"
$env:IVP_WEB_IMAGE="ghcr.io/<owner>/<repo>/web@sha256:<web-digest>"
docker compose -f compose.yaml -f compose.gpu.release.yaml pull
docker compose -f compose.yaml -f compose.gpu.release.yaml up -d
```

Do not add `compose.gpu.yaml` to a release deployment: that overlay restores a
local `build:` definition and defeats digest pinning. Do not run `down -v`:
it deletes the PostgreSQL volume.

Verify the resolved configuration and the running stack before accepting the
deployment:

```powershell
python -m tools.release.cli preflight `
  --manifest release-manifest.json `
  --repo-root . `
  --previous-manifest previous-manifest.json `
  --output deployment-preflight.json

python -m tools.release.cli verify-deploy `
  --manifest release-manifest.json `
  --report release-verification.json --require-verified `
  --preflight-report deployment-preflight.json `
  --running --check-logs
```

`preflight` resolves the digest-pinned Compose configuration, parses the
Alembic revision graph without executing migrations, requires exactly one head
with no missing parents, rejects automatic `alembic downgrade` in deployment
files, proves PostgreSQL data is mounted on a named volume, and requires the
generated rollback plan to take a `pg_dump` backup without deleting the volume.
It reports `UNAVAILABLE` when Docker cannot resolve Compose; it never treats a
missing check as a pass.

`verify-deploy` rejects mutable tags and local `build:` definitions, requires
the manifest digests to be exactly what Compose resolves, compares running
container image IDs with the manifest, can scan recent service logs for
credential patterns, and rejects a preflight report that is not bound to the
same manifest bytes and subject. Findings report pattern names only; matched
values are never printed.

Then run the independent HTTP/auth/WebSocket smoke:

```powershell
$env:IVP_SMOKE_PASSWORD="<smoke-user-password>"
python -m tools.release.cli smoke `
  --api-url https://ops.example.com/api `
  --web-url https://ops.example.com `
  --username smoke@example.com `
  --manifest release-manifest.json `
  --tag v1.2.3 --commit <40-hex> `
  --output deployment-smoke.json
```

When `--manifest` is supplied, the smoke report records the exact manifest
SHA-256 and release subject, so qualification can reject a smoke report reused
for different release bytes. The password is read from `IVP_SMOKE_PASSWORD`,
never from the command line. Missing credentials or a missing web URL produce
required `NOT_RUN` checks, so the report can never claim a verified deployment.
An unauthenticated WebSocket that stays open, or an authenticated socket that
is refused, is a hard failure. See `docs/PRODUCTION_OPERATIONS.md` for the
operational flow.

## Rollback rehearsal (V24)

A rollback plan is not a rollback rehearsal. `rehearse-rollback` executes the
full sequence on the target host: deploy the previous release by digest,
verify it, smoke it, deploy the target release by digest, verify it, smoke it,
redeploy the previous digests, then verify and smoke the restored stack. It
requires independent production verification reports for both releases, smoke
credentials, and Docker. If target verification fails, target smoke is skipped
and the rollback is still attempted so recovery is proven; the rehearsal
remains `FAIL`.

```powershell
$env:IVP_SMOKE_PASSWORD="<smoke-user-password>"
python -m tools.release.cli rehearse-rollback `
  --manifest release-manifest.json `
  --previous-manifest previous-manifest.json `
  --target-report release-verification.json `
  --previous-report previous-release-verification.json `
  --smoke-api-url https://staging.example.com/api `
  --smoke-web-url https://staging.example.com `
  --smoke-username smoke@example.com `
  --execute --evidence-dir rehearsal-evidence `
  --output rollback-rehearsal.json
```

Without `--execute` every step is `NOT_RUN`. Evidence written by the rehearsal
is listed with its SHA-256 in the report, and the report binds both the target
and previous manifest hashes, subjects, and digests. `full` scope qualification
requires `executed: true`, `state: PASS`, and `verified: true`.

## GPU runtime validation

The GPU image is built, scanned, SBOM'd, attested and published like the CPU
images. The GitHub-hosted release runner has no NVIDIA GPU, so the manifest
records:

```
gpu_runtime_smoke: not_run
gpu_runtime_smoke_reason: GPU infrastructure unavailable on the GitHub-hosted release runner
```

That is an honest gap, not a pass. Before relying on the GPU image, qualify the
runtime on a CUDA host with the NVIDIA Container Toolkit:

```powershell
python -m tools.release.cli gpu-qualify `
  --manifest release-manifest.json `
  --execute `
  --output gpu-runtime.json
```

`gpu-qualify` proves `nvidia-smi` reports a device and driver, Docker registers
the `nvidia` container runtime, and the digest-pinned `api-gpu` image starts
with `--gpus all` and reports CUDA devices. Without `--execute` every check is
`NOT_RUN`; a missing driver or runtime is `UNAVAILABLE` or `FAIL`, never a pass.
`--skip-container` intentionally cannot produce a verified report.

Then start the GPU release stack, require a production verification report,
and run the smoke tool on the GPU host:

```powershell
python -m tools.release.cli verify-deploy `
  --manifest release-manifest.json `
  --report release-verification.json --require-verified `
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

The production report proves the GPU *artifact*; it does not prove GPU
*runtime*. Only the host smoke and a real inference request do. Report
`runtime_verified: false` until both succeed.

## Rollback

Rollback is a deployment action, not a tag action. The tooling requires a
production verification report for the target release, unless an operator
explicitly accepts an unverified emergency rollback:

```powershell
python -m tools.release.cli rollback-plan `
  --manifest previous-release-manifest.json `
  --report previous-release-verification.json `
  --current-manifest release-manifest.json `
  --backup-file before-rollback.sql `
  --output rollback-plan.txt
```

For a documented emergency only, add `--allow-unverified`; the plan then
starts with a warning and requires independent digest verification.

The plan always:

1. Identifies the previous manifest's digests (GitHub Release or your recorded
   deployment manifest).
2. Re-runs the deploy commands with the previous digest values.
3. Takes a database backup before changing the stack.
4. Does **not** reverse Alembic migrations automatically. If the previous
   application is incompatible with the current schema, restore the database
   from the backup taken before the upgrade (see
   `docs/PRODUCTION_OPERATIONS.md`).
5. Never runs `docker compose down -v`.
6. Never moves or deletes the bad release tag. If the release itself is wrong,
   publish the fix as the next PATCH version.

## Failure and recovery

| Failure point | State | Recovery |
| --- | --- | --- |
| validate/gates/scan before push | No new images | Fix, then push a new tag; the failed tag may be deleted only by an administrator, and the version is still considered consumed |
| Push starts but digest proof fails | Image may exist; publication report marks it unknown | Inspect GHCR before retrying; never overwrite the tag; fix forward with the next PATCH tag |
| One image pushes, another fails | Publication report is `partial` | Keep the previous verified deployment; publish the fix as the next PATCH version |
| Push succeeds, SBOM/attestation/manifest fails | Some or all new tags exist, no GitHub Release | Fix forward with the next PATCH tag; never overwrite the pushed tags |
| Production verification fails | Images and manifest exist, no GitHub Release | Treat as a failed release; inspect the report and fix forward |
| Release job fails after images are attested | Images and manifest artifact exist, no Release | Re-run the failed job (same workflow run); if the release itself was partially created, fix forward |
| Bad image discovered later | Release exists | Deploy the previous digest; publish a fixed PATCH release |

The publish job always records a publication report, even on failure:

```powershell
python -m tools.release.cli publication-report `
  --events published-images.jsonl `
  --tag v1.2.3 --repository <owner>/<repo> `
  --output publication-report.json
```

Statuses are `complete`, `partial`, and `failed`. `complete` requires every
expected image to have a proven `pushed` event with a valid digest, no
evidence errors, and no unknown, failed-only, or missing images. A
`push_started` event without a proven digest is *unknown*, not absent. The
`recovery` job prints the same guidance in the workflow summary. The
`concurrency` group serializes runs for the same tag and never cancels a
release in progress.

## Local validation

```powershell
# Policy and pinning audit
python -m tools.release.cli audit-workflows --root .

# Static release/compose tests
pytest backend/tests/integration/test_release_workflow.py `
       backend/tests/unit/test_release_manifest.py `
       backend/tests/unit/test_release_identity.py -q

# V23 verification, deployment, smoke, and publication tests
pytest backend/tests/unit/test_release_verification.py `
       backend/tests/unit/test_release_deployment.py `
       backend/tests/unit/test_release_smoke.py `
       backend/tests/unit/test_release_publication.py `
       backend/tests/integration/test_release_workflow.py -q

# V24 qualification and prerequisite probes
pytest backend/tests/unit/test_release_qualification.py `
       backend/tests/unit/test_release_prerequisites.py `
       backend/tests/unit/test_release_preflight.py `
       backend/tests/unit/test_release_rehearsal.py `
       backend/tests/unit/test_release_gpu.py -q

# Digest overlays resolve without a daemon
$env:IVP_API_IMAGE="ghcr.io/example/api@sha256:<64-hex>"
$env:IVP_WEB_IMAGE="ghcr.io/example/web@sha256:<64-hex>"
docker compose -f compose.yaml -f compose.release.yaml config
```

## Local validation evidence (V23)

V23 was validated without creating a tag, publishing an image, or claiming a
live release:

- **Release tests**: 86 release-related tests passed (verification,
  deployment/report gating, smoke, publication, and workflow assertions).
- **Full backend suite**: 1312 passed, 1 skipped, 5 deselected.
- **Lint/format**: `ruff format --check backend tools` and
  `ruff check backend tools` passed (361 files).
- **Frontend**: lint, typecheck, 93 tests, and the production build passed.
- **Workflow audit**: `python -m tools.release.cli audit-workflows --root .`
  passed; every release action remains SHA-pinned, and `release.yml` parses.
- **Workflow semantics**: static tests assert the production verification gate
  runs after manifest generation, publication reporting runs with
  `if: always()`, the release job requires a production report and complete
  publication, the recovery job explains safe recovery, and `api-gpu` outputs
  are sanitized to `api_gpu_*` keys.
- **Not executed locally**: live GHCR resolution, `gh attestation verify`,
  `docker pull` by digest, digest-pinned Compose deployment, container smoke,
  and rollback rehearsal. The Docker daemon and GitHub CLI are unavailable on
  this host, so those checks remain `UNAVAILABLE`/`NOT_RUN`. No NVIDIA GPU is
  present, so GPU runtime remains `NOT_RUN`.

These are validation results for the tooling and static workflow, not proof of
a hosted release.

## Local validation evidence (V22)

The release path was exercised locally without creating a git tag:

- **Builds**: `backend/Dockerfile`, `frontend/Dockerfile` and
  `backend/Dockerfile.gpu` built from this commit. The GPU image imports
  `torch 2.13.0+cu126` / `torchvision 0.28.0+cu126`; `torch.cuda.is_available()`
  is `False` on this host, so runtime GPU smoke remains **NOT RUN**.
- **Scans/SBOMs**: trivy 0.76.0 image scans of api, web and api-gpu reported
  zero CRITICAL/HIGH vulnerabilities with a fix available; SPDX JSON SBOMs were
  generated from the published digests.
- **Digest association**: all three images were pushed to a local Docker
  registry, re-pulled by digest after removing local tags, and their image IDs
  matched the built IDs.
- **Manifest**: `tools.release.cli generate` and `validate` accepted the
  locally observed inputs for api/web/api-gpu. Provenance and SBOM
  attestation bundles were **simulated placeholders** in this local run; real
  bundles are only produced by `actions/attest` with the workflow's OIDC
  identity.
- **Digest deployment**: `compose.yaml` + `compose.release.yaml` started from
  the locally pushed digests and passed the existing 22-check container smoke
  (health, auth, frontend headers, WebSocket authorization); the stack was
  stopped with `docker compose down` (no `-v`).
- **Gates**: full backend suite passed (1237 passed, 1 skipped); frontend
  lint/typecheck/93 tests/build passed; pip-audit, production npm audit,
  gitleaks, trivy filesystem/IaC, and all six Compose configs passed. A latent
  BEV bug (an `UNKNOWN` collision-risk assessment raised instead of meaning
  "unavailable") was found and fixed during this validation.

No real GHCR push, GitHub attestation, or GitHub Release was performed.

## Known limitations

- The first live release has not run; workflow semantics, GHCR permissions and
  attestation publication are validated statically and locally only.
- Live registry digest resolution, pull-by-digest proof, and
  `gh attestation verify` require network access, GHCR credentials, and a
  working GitHub CLI; they remain `UNAVAILABLE` on hosts without them.
- Digest-pinned deployment, running-container image-ID comparison, log
  scanning, smoke, and rollback rehearsal require a Docker daemon; they remain
  `NOT_RUN` on hosts without one.
- GPU artifact verification and GPU runtime verification are separate. A
  production report can prove the GPU image exists while `runtime_state`
  remains `NOT_RUN`; never present that as GPU acceleration success.
- V24 production qualification requires a real digest-pinned deployment, a
  passing rollback rehearsal, and verified GPU runtime. Those evidence files
  cannot be produced on a host without a Docker daemon and NVIDIA runtime, so
  `production_qualified` remains `false` until they are recorded on the target
  hosts.
- The hosted runner's disk must fit three images (including CUDA torch); the
  workflow frees space and fails before building if less than 20 GiB is free.
  Peak usage remains a residual risk until observed on a real run.
- Base images remain tag-pinned; a rebuild may pull new base packages. The
  blocking image scan is the control.
- Attestation verification requires GitHub CLI support for artifact
  attestations and network access to the registry/GitHub API.
- `latest` is intentionally absent; tooling that expects it must be changed.
