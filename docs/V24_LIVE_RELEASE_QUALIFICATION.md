# V24 Live Release Qualification and Production Readiness

V24 adds a final qualification gate between "the release pipeline finished" and
"this exact release may be deployed". It consumes the immutable release
manifest and the V23 verification evidence, then binds every additional input by
SHA-256. A report cannot be reused for different manifest bytes, a different
tag, commit, or repository.

## Status

| Item | State | Detail |
| --- | --- | --- |
| V24 implementation | Complete | Qualification, deployment, rehearsal, and GPU evidence tooling plus tests |
| Deterministic/offline validation | Complete | 1391 backend tests passed (1 skipped), 93 frontend tests passed, frontend lint/typecheck/build, Ruff, and workflow pin audit |
| Live artifact verification | `NOT_RUN` | No authorized release tag, workflow run, or `release-artifacts/` in this environment |
| Genuine GitHub attestation trust | `UNAVAILABLE` | `gh` is not installed and `GH_TOKEN` / `GITHUB_TOKEN` are unset |
| Digest-pinned deployment | `NOT_RUN` | Docker CLI is present but the daemon is unavailable |
| Rollback rehearsal | `NOT_RUN` | Requires a Docker host, target and previous production reports, and smoke credentials |
| GPU runtime qualification | `UNAVAILABLE` | No NVIDIA GPU and no `nvidia-smi` in this environment |
| `production_qualified` | `false` | Required live evidence is unavailable; no production claim is made |

No release tag was created, moved, or deleted. No image was published, no
GitHub Release was created, no production deployment was performed, and no
destructive operation was executed.

## Why V23 is not enough

V23 proves that the published artifacts are genuine: immutable digests, SBOMs,
scan evidence, DSSE bundles, and GitHub attestations. It does not prove that a
particular host actually ran those digests, that rollback recovers service, or
that the GPU container can reach CUDA. V24 adds those deployment and recovery
facts without weakening or reinterpreting V23.

The V23 `release-verification.schema.json` remains version 2, and
`check-report` is unchanged. V24 adds new version 1 schemas:

- `release/release-qualification.schema.json`
- `release/deployment-report.schema.json`
- `release/deployment-preflight.schema.json`
- `release/rollback-rehearsal.schema.json`
- `release/gpu-runtime.schema.json`

## Profiles and scopes

| Profile | Intended use | Required evidence |
| --- | --- | --- |
| `local_validation` | Offline or CI artifact gate | V23 report with `verified: true`, genuine DSSE bundles, SBOM/scan/digest checks, GPU artifact present |
| `staging_qualification` | Staging deployment | Production V23 report, complete publication, attestation trust, bound deployment report; GPU runtime only with `--require-gpu-runtime` |
| `production_qualification` | Production readiness | Staging requirements plus `full` scope, a GPU deployment, an executed rollback rehearsal with hash-verifiable evidence, and container-level GPU runtime proof |

| Scope | Adds |
| --- | --- |
| `artifact` | Manifest, verification, per-image digest/SBOM/scan/bundle hashes; publication with `--require-live-evidence` or any non-local profile |
| `deployment` | Deployment report bound to the same manifest and subject; digest-pinned Compose, bound preflight, running services, and running image IDs |
| `full` | Executed rollback rehearsal with all nine steps `PASS`, target/previous digest bindings, and matching evidence hashes |

`production_qualified` is true only when **all** of the following hold:

1. Profile is `production_qualification` and scope is `full`.
2. Every required qualification check is `PASS`.
3. The V23 report is a production report with `production_verified: true`.
4. The publication report proves every required digest was published.
5. The deployment report is bound to the manifest, proves the GPU overlay
   (`gpu: true`), a bound preflight, the running `api` and `web` services, and
   running image IDs that match the manifest.
6. The rollback rehearsal has `executed: true`, `state: PASS`,
   `verified: true`, all nine steps `PASS`, distinct target and previous
   digests, and evidence files whose SHA-256 values match.
7. The GPU runtime report has `executed: true`, `state: PASS`,
   `verified: true`, `runtime: nvidia`, `container_cuda: true`, and the exact
   digest-pinned `api-gpu` image.
8. `check-qualification --require-production` revalidates the report and, when
   report paths are supplied, rejects changed report bytes.

`NOT_RUN`, `UNAVAILABLE`, and `SIMULATED` are evidence states, never successes.
A missing check is a failure, not an implicit pass.

## CI behavior

The `qualify` job runs after `publish` and before `release`. It executes
`local_validation` with `artifact` scope and `--require-live-evidence`, then
uploads `release-qualification.json`; the release job downloads and attaches
that report. The CI gate never claims `production_qualification` because the
GitHub-hosted runner has no target deployment host, no GPU, and no authorized
production credentials. Production qualification must be produced on the real
target hosts.

## Operator sequence

The full command reference is in `docs/RELEASES.md`. The evidence must be
produced in this order so every later report can bind the earlier ones:

```powershell
# 1. Probe the host and record what is genuinely available.
python -m tools.release.cli qualify-prerequisites `
  --repo-root . --profile production_qualification --scope full `
  --tag v1.2.3 --commit <40-hex> `
  --artifacts-dir release-artifacts `
  --verification-report release-artifacts/release-verification.json `
  --publication-report release-artifacts/publication-report.json `
  --deployment-report release-artifacts/deployment-report.json `
  --rehearsal-report release-artifacts/rehearsal/rollback-rehearsal.json `
  --gpu-report release-artifacts/gpu-runtime.json `
  --production-authorized `
  --output release-artifacts/qualification-prerequisites.json

# 2. Deploy the exact digests, then prove preflight, running state, and smoke.
python -m tools.release.cli preflight `
  --manifest release-artifacts/release-manifest.json `
  --repo-root . --gpu `
  --previous-manifest previous-manifest.json `
  --output release-artifacts/deployment-preflight.json

python -m tools.release.cli verify-deploy `
  --manifest release-artifacts/release-manifest.json `
  --report release-artifacts/release-verification.json --require-verified `
  --preflight-report release-artifacts/deployment-preflight.json `
  --running --check-logs --gpu

$env:IVP_SMOKE_PASSWORD="<smoke-user-password>"
python -m tools.release.cli smoke `
  --api-url https://ops.example.com/api `
  --web-url https://ops.example.com `
  --username smoke@example.com `
  --manifest release-artifacts/release-manifest.json `
  --tag v1.2.3 --commit <40-hex> `
  --output release-artifacts/deployment-smoke.json

# 3. Prove recovery by executing the full rollback sequence.
python -m tools.release.cli rehearse-rollback `
  --manifest release-artifacts/release-manifest.json `
  --previous-manifest previous-manifest.json `
  --target-report release-artifacts/release-verification.json `
  --previous-report previous-release-verification.json `
  --smoke-api-url https://staging.example.com/api `
  --smoke-web-url https://staging.example.com `
  --smoke-username smoke@example.com `
  --execute --evidence-dir release-artifacts/rehearsal `
  --output release-artifacts/rehearsal/rollback-rehearsal.json

# 4. Prove the GPU runtime on the GPU host.
python -m tools.release.cli gpu-qualify `
  --manifest release-artifacts/release-manifest.json `
  --execute `
  --output release-artifacts/gpu-runtime.json

# 5. Produce and independently recheck the qualification report.
python -m tools.release.cli qualify `
  --manifest release-artifacts/release-manifest.json `
  --artifacts-dir release-artifacts `
  --profile production_qualification --scope full `
  --verification-report release-artifacts/release-verification.json `
  --publication-report release-artifacts/publication-report.json `
  --deployment-report release-artifacts/deployment-report.json `
  --rehearsal-report release-artifacts/rehearsal/rollback-rehearsal.json `
  --gpu-report release-artifacts/gpu-runtime.json `
  --tag v1.2.3 --commit <40-hex> --repository <owner>/<repo> `
  --repo-root . --main-ref origin/main `
  --output release-artifacts/release-qualification.json

python -m tools.release.cli check-qualification `
  --report release-artifacts/release-qualification.json `
  --manifest release-artifacts/release-manifest.json `
  --verification-report release-artifacts/release-verification.json `
  --publication-report release-artifacts/publication-report.json `
  --deployment-report release-artifacts/deployment-report.json `
  --rehearsal-report release-artifacts/rehearsal/rollback-rehearsal.json `
  --gpu-report release-artifacts/gpu-runtime.json `
  --require-production
```

`rehearse-rollback --execute` requires both `--evidence-dir` and `--output`,
and the evidence directory must contain the report. Qualification resolves
evidence paths relative to the report directory, so a report copied away from
its evidence cannot qualify.

## Environment evidence

The V24 work was implemented and validated in an environment where the live
prerequisites were genuinely unavailable:

- Docker CLI is installed, but `docker info` fails because the daemon is not
  running. Deployment, smoke, rollback rehearsal, and container GPU checks
  therefore cannot be executed here.
- `gh` is not installed, and neither `GH_TOKEN` nor `GITHUB_TOKEN` is set.
  Genuine `gh attestation verify` and bundle-signature trust are
  `UNAVAILABLE`, not `PASS`.
- `nvidia-smi` is absent and there is no NVIDIA GPU. GPU runtime qualification
  is `UNAVAILABLE`; the GPU artifact checks still run offline.
- There is no authorized release tag, no GitHub Release, no
  `release-artifacts/` directory, and no production or staging endpoint in this
  environment. Source identity, publication, deployment, and recovery
  evidence are `NOT_RUN`.

These states are recorded honestly. No tool output, test, or document in V24
converts them into success.

## Blockers to live qualification

1. An authorized release tag and a completed release workflow run with
   `release-artifacts/` containing the manifest, SBOMs, scans, bundles, and
   V23 report.
2. A GitHub token and `gh` CLI for genuine attestation verification and
   publication evidence.
3. A Docker host with a running daemon and the target Compose files for
   preflight, digest-pinned deployment, smoke, and rollback rehearsal.
4. A GPU host with an NVIDIA driver, `nvidia-smi`, and the NVIDIA Container
   Toolkit for `gpu-qualify`.
5. Staging and production URLs plus a smoke account whose password is supplied
   through `IVP_SMOKE_PASSWORD`.
6. Explicit authorization before creating a release, publishing images,
   deploying, or rehearsing rollback against shared infrastructure.

## Hardening added in V24

- Qualification now requires the exact deployment checks that prove preflight,
  running services, and running image IDs; a deployment report with only a
  top-level `PASS` is rejected.
- A `full` scope report requires an executed rehearsal, all nine steps `PASS`,
  distinct target and previous digests, and evidence files whose hashes match.
  An unexecuted or copied report cannot qualify.
- A production GPU report must prove the `nvidia` runtime,
  `container_cuda: true`, and the manifest's `api-gpu` digest.
- `check-qualification` revalidates production bindings and evidence hashes and
  can reject deployment, rehearsal, or GPU reports whose bytes changed after
  qualification.
- Rehearsal execution requires a durable evidence directory colocated with the
  report, preventing a report that can never be qualified.
- Tests cover unexecuted rehearsal, missing/tampered evidence, digest mismatch,
  missing steps, CPU-only deployment, failed or missing preflight checks, GPU
  `container_cuda: false`, unexecuted GPU evidence, and changed production
  reports.
