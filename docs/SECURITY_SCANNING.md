# Security Scanning and Release Gates (V21, extended in V22)

V21 turns "we meant to scan" into "the pipeline scans and fails". Every gate
below runs **both** on a developer machine and in CI, with the same tools and
the same thresholds, so a red CI job is reproducible locally. V22 adds
supply-chain controls on top: every workflow action is pinned to a commit SHA,
scanner images are pinned by digest, and published images carry SBOMs and
GitHub attestations (see `docs/RELEASES.md`).

## Why this volume

The V20 upgrade left three things unproven:

1. The frontend lint gate was not runnable. `next lint` is deprecated in
   Next 15 and prompts for setup, so CI could never run it unattended.
2. No dependency, container or secret scanner had ever been executed against
   this repository - the risk register was assumptions, not measurements.
3. There was no release path: no tag automation, no published images, no
   recorded image digests.

## The gate set

| Gate | Blocking | Severity | Where |
| --- | --- | --- | --- |
| Backend tests (`pytest`) | yes | - | `ci` / `backend` |
| Backend lint (`ruff check`, `ruff format --check`) | yes | - | `ci` / `backend` |
| Frontend lint (`eslint . --max-warnings=0`) | yes | any warning | `ci` / `frontend` |
| Frontend typecheck + tests + build | yes | - | `ci` / `frontend` |
| Python dependency audit (`pip-audit`) | yes | any | `ci` / `security` |
| Frontend dependency audit (`npm audit --omit=dev`) | yes | high+ | `ci` / `security` |
| Secret scan (`gitleaks`) | yes | any | `ci` / `security` |
| Filesystem + IaC scan (`trivy fs`) | yes | CRITICAL, HIGH | `ci` / `security` |
| Image scan (`trivy image`, api + web) | yes | CRITICAL, HIGH | `ci` / `image-scan` |
| Release image scan (`trivy image`, api + web + api-gpu) | yes | CRITICAL, HIGH | `release` / `publish` |
| Workflow pinning audit (actions + scanner images) | yes | unpinned | `ci` / `security`, `release` / `gates` |
| Release (tag `v*`) | yes | same gates + GHCR publish + SBOM/attestation | `release` workflow |

`mypy` stays informational (pre-existing type errors are outside this volume's
scope). All scanners ignore findings without a published fix
(`--ignore-unfixed`): an advisory without a fix cannot be remediated by a
dependency bump, only by replacing the component, which is a different
decision.

## Local runs (PowerShell)

```powershell
# Frontend lint gate (noninteractive, strict)
cd frontend; npm run lint

# Python dependency audit (prod + dev requirement sets)
python -m pip install pip-audit
python -m pip_audit -r backend/requirements.txt --progress-spinner off
python -m pip_audit -r backend/requirements-dev.txt --progress-spinner off

# Frontend dependency audit (production dependency tree only)
cd frontend; npm audit --omit=dev --audit-level=high

# Secret scan (full git history, secrets redacted; digest-pinned)
docker run --rm -v "${PWD}:/repo" `
  ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f `
  git /repo --redact --no-banner

# Filesystem + IaC scan (Dockerfile / Compose misconfiguration + lockfiles)
docker run --rm -v "${PWD}:/repo" -v trivy-cache:/root/.cache/trivy `
  ghcr.io/aquasecurity/trivy@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222 `
  fs --scanners vuln,misconfig `
  --severity CRITICAL,HIGH --ignore-unfixed --exit-code 1 /repo

# Workflow action/image pinning audit
python -m tools.release.cli audit-workflows --root .
```

Notes for Windows hosts:

- A `trivy fs` scan of the live working tree is slow through a Docker bind
  mount (`node_modules`, `.next`, model weights). Scan a clean export instead:
  `git archive --format=tar -o src.tar HEAD`, extract it to a temp folder and
  mount that folder.
- `trivy image` reads a saved image tar:
  `docker save -o image.tar <image>` then
  `trivy image --input image.tar --severity CRITICAL,HIGH --ignore-unfixed`.

## Findings register (V21)

Everything below was found by these scanners in V21 and remediated in the same
volume. The register is the audit trail; the image scans now report clean.

| Finding | Scanner | Severity | Resolution |
| --- | --- | --- | --- |
| Bundled npm/corepack CLI (`tar`, `minimatch`, `pacote`, `sigstore`, `ip-address`) in the web runtime image | trivy image | 1 CRITICAL, 21 HIGH | The runner executes `node server.js` only. `npm`, `npx` and `corepack` are deleted from the runner stage (`frontend/Dockerfile`). |
| Alpine base packages in the web runtime image | trivy image | 4 HIGH | `apk upgrade --no-cache` in the runner stage. |
| `setuptools` (path traversal, CVE-2025-47273) and its vendored `jaraco.context` / `wheel` copies in the api image | trivy image | 2 HIGH | Packaging libs pinned to `setuptools>=78.1.1,<81` and `wheel`; the `<81` ceiling keeps `pkg_resources` importable (setuptools 81 removed it). |
| `pip` vendored copies of `msgpack`, `urllib3` and `setuptools` in the api image | trivy image | 5 HIGH | `pip` is removed from both the system interpreter and `/opt/venv` in the runtime stage; the service never installs packages at runtime. |
| `pillow` 12.3.0 (CVE-2026-112403 and the 2026-1123xx / 2026-1128xx series) | trivy image | 1 CRITICAL, 6 HIGH | `pillow>=13.0.0` declared explicitly in `backend/requirements.txt` (it arrives transitively through `ultralytics`). |
| `urllib3` 2.7.0 (CVE-2026-97687, CVE-2026-97689) | trivy image | 2 HIGH | `urllib3>=2.8.0,<3` declared explicitly (transitive through `requests`). |
| Python, Dockerfiles, npm lockfile, 62-commit history | pip-audit, trivy fs, gitleaks | - | No findings. |

Both production images now scan clean at CRITICAL/HIGH with a fix available:

```
api image : 0 vulnerabilities (debian 12.15 base + 104 python packages)
web image : 0 vulnerabilities (alpine 3.23.4 base + application packages)
```

V22 re-validated all release artifacts with trivy 0.76.0 after hardening
`backend/Dockerfile.gpu` to the same install-time tooling treatment:
`api`, `web` and `api-gpu` each reported 0 CRITICAL/HIGH vulnerabilities with
a fix available, and SPDX JSON SBOMs were generated for all three. The GPU
image is now a first-class release artifact; its scan is blocking before any
push.

## Accepted risks

### Dev-only frontend advisories (15)

`npm audit --omit=dev` reports **0** findings for the production dependency
tree. The full audit (dev dependencies included) reports 15 advisories that
cannot be fixed without breaking changes:

| Root package | Advisories | Severity | Why it is accepted |
| --- | --- | --- | --- |
| `vitest` (with `vite`, `vite-node`, `tinypool`, `esbuild`, `@vitest/mocker`) | 6 | 2 critical, 3 high, 1 moderate | Fix requires `vitest@5` (major). The advisory is in the test runner's worker pool, which never executes untrusted input. Re-evaluate when vitest 5 is adopted. |
| `tailwindcss` (with `braces`, `chokidar`, `micromatch`, `postcss-selector-parser`) | 5 | 4 high, 1 moderate | Fix requires `tailwindcss@4` (major, different config/postcss pipeline). Build-time only; the generated CSS is what ships. |
| `eslint-config-next` (with `@next/eslint-plugin-next`, `fast-glob`) | 3 | 3 high | The only offered fix is a **downgrade** to 14.2.35, which would undo the V20 Next.js upgrade. Lint-time only. |
| `postcss-nested` | 1 | moderate | `npm audit fix` (non-breaking) does not change the resolved tree; the advisory has no compatible fix. |

Review trigger: any bump of `vitest`, `tailwindcss` or `eslint-config-next`
must re-run `npm audit` and update this table.

### Floating base images

`node:20-alpine` and `python:3.11-slim-bookworm` are not digest-pinned, so a
rebuild can pull new base packages. The image-scan gate is the control that
makes this visible: a new base release with a CRITICAL/HIGH advisory fails
`ci` / `image-scan` before it reaches a deployment.

### Third-party action pinning

Every `uses:` reference in `.github/workflows/*.yml` is pinned to a full
40-character commit SHA; version comments record the human-readable release.
The `audit-workflows` step fails CI and the release `gates` job on an
unpinned action. `.github/dependabot.yml` opens weekly PRs for action updates
so pins do not silently age. Local actions (`./...`) are exempt, and scanner
container images must be digest-pinned (`name@sha256:<64 hex>`).

Dependabot cannot update the SHA of a Docker image used by `docker run`; the
digest pins in the workflows are updated manually with the release note.

## Release automation (V22)

Pushing a strict stable SemVer tag (`vMAJOR.MINOR.PATCH`) runs
`.github/workflows/release.yml`:

1. `validate` - tag grammar, tag/commit identity, `origin/main` reachability,
   and a fail-closed GitHub check that no release or matching GHCR tag exists.
2. `gates` - the same backend/frontend/security gates as `ci`, plus the
   workflow pinning audit.
3. `publish` - builds **api**, **web** and **api-gpu**, scans all three
   (blocking at CRITICAL/HIGH with a fix available), then pushes
   `v<version>` + `sha-<short-sha>` to
   `ghcr.io/<owner>/<repo>/{api,web,api-gpu}`. It re-pulls each image by
   digest and compares image IDs, generates SPDX SBOMs, and pushes GitHub
   provenance and SBOM attestations.
4. `release` - re-validates the manifest and creates the GitHub Release with
   `--verify-tag`, attaching the manifest, SBOMs, attestation bundles and scan
   logs.

`latest` is not published. Deploy by digest, not by a version tag; see
`docs/RELEASES.md` for verification, GPU runtime validation (recorded as
`not_run` on the hosted runner) and rollback.
