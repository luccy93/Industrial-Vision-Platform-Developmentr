# V25 Controlled Staging Qualification and Evidence Collection

V25 adds a controlled staging qualification path on top of the V24 release
qualification gate. It answers one narrow question: may this exact release be
exercised on one named staging target, and what evidence proves it? It does not
promote a release to production. Staging evidence never sets
`production_qualified`.

## Status

| Item | State | Detail |
| --- | --- | --- |
| V25 staging control plane | Complete | Explicit target contract, fail-closed validation, preflight-only default, exact-name mutation authorization |
| Release evidence collection | Complete | Local hashes plus live GitHub Release, GHCR digest, provenance/SBOM attestation, SBOM, and scan evidence when `--execute` is authorized |
| Migration compatibility | Complete | Static Alembic graph validation, single-head and non-destructive-upgrade checks, previous-release binding |
| Controlled deployment and smoke | Complete | Digest-pinned Compose deployment, running-stack verification, `/health`, auth, and WebSocket reconnect checks |
| Rollback rehearsal with migration safety | Complete | Nine-step rehearsal gated on migration compatibility; the rehearsal records a bound `migration-safety` check |
| GPU runtime and inference | Complete | Optional NVIDIA runtime qualification plus structured CUDA inference inside the digest-pinned GPU image |
| Offline staging tests | Complete | 28 staging tests plus migration, rehearsal, evidence, inference, deployment, and smoke suites; all run without network or credentials |
| Live staging tests | Opt-in | `pytest -m live`; every test skips with the exact missing tool or environment variable and never reports missing evidence as a pass |
| Live GitHub/GHCR/attestation evidence | `UNAVAILABLE` | `gh` is not installed and `GH_TOKEN` / `GITHUB_TOKEN` are unset in this environment |
| Live staging deployment and smoke | `NOT_RUN` | No authorized staging target, deployment host, or smoke credentials exist in this environment |
| Rollback rehearsal on staging | `NOT_RUN` | Requires an authorized staging target and a previous release manifest |
| GPU runtime and inference on staging | `NOT_RUN` | No NVIDIA host or GPU runtime is available here |
| Production qualification | Not claimed | Staging reports always set `production_qualified` to `false` |

`NOT_RUN`, `UNAVAILABLE`, and `SIMULATED` never satisfy a required staging
check. A report with any required non-`PASS` check has `staging_qualified:
false`.

## Target contract

A staging run consumes one explicit JSON target validated against
`release/staging-target.schema.json`. The target must:

* set `environment` to exactly `staging`;
* use a lowercase staging `name` that does not contain production markers;
* bind `release.tag`, `release.commit`, and `release.source_repository` to the
  immutable manifest;
* use `https://` for API and web URLs and `wss://` for the WebSocket URL;
* contain no embedded credentials, query strings, or fragments;
* name a password environment variable instead of containing a password;
* reference Compose files, an optional previous manifest, and an optional
  previous production verification report by relative paths that stay inside
  the repository.

Production environments, production-like names, production-like hostnames, and
credentials embedded in URLs are rejected before any command runs.

Example shape (values are illustrative, not a real deployment):

```json
{
  "schema_version": 1,
  "name": "staging-east-1",
  "environment": "staging",
  "release": {
    "tag": "v1.2.3",
    "commit": "0123456789abcdef0123456789abcdef01234567",
    "source_repository": "owner/repository"
  },
  "api_url": "https://api.staging.example.test",
  "web_url": "https://web.staging.example.test",
  "ws_url": "wss://ws.staging.example.test",
  "smoke_username": "smoke@example.test",
  "smoke_password_env": "IVP_SMOKE_PASSWORD",
  "compose_project": "ivp-staging",
  "compose_files": ["compose.release.yaml"],
  "gpu": false,
  "previous_manifest": "previous-manifest.json",
  "previous_verification_report": "previous-release-verification.json"
}
```

## Modes

| Invocation | Mode | Behaviour |
| --- | --- | --- |
| `staging-qualify` | `preflight` | Validates the target and manifest, runs migration compatibility, and runs deployment preflight. No live probe and no mutation. |
| `staging-qualify --execute` | `live-read` | Adds read-only Docker and GitHub CLI probes and collects release evidence. No mutation. |
| `staging-qualify --execute --authorize <target-name>` | `authorized-mutation` | Required before any deployment mutation. The authorization value must exactly equal the target `name`. |

`--authorize` without `--execute` is rejected. An authorization value that does
not exactly match the target name is rejected before any command runs. The
resolved target name, environment, URLs, release subject, and image digests are
printed before any execution.

## Evidence chain

The staging report binds every component report by file name and SHA-256, and
binds every report to the exact manifest bytes. A binding is only usable when
its state is `PASS`; required bindings are:

* `preflight`;
* `verification` (the independent production verification report);
* `publication` (GitHub Release plus GHCR, attestation, SBOM, and scan
  evidence);
* `migration`;
* `deployment`;
* `smoke`;
* `gpu_runtime` and `gpu_inference` when the target or request requires GPU
  evidence;
* `rehearsal` when `--require-rollback` is set.

The publication binding must prove a published, non-draft, non-prerelease
GitHub Release whose URL belongs to the manifest repository. A local-only
report can be inspected with `check-evidence --allow-local`, but it cannot
authorize staging.

### Release evidence

`collect-evidence` hashes the local SBOM and scan artifacts, embeds the
independent verification report, and, when `--execute` is supplied, queries:

* the GitHub Release for the exact tag and repository;
* GHCR image digests for every required image;
* provenance and SBOM attestations, including bundle signature checks;
* the registry image IDs observed by the verification run.

A missing `gh`, registry access, token, release, or attestation is reported as
`UNAVAILABLE` or `FAIL`; it is never converted to `PASS`.

### Migration compatibility

`migration-compatibility` parses the Alembic revision graph without executing a
migration. It requires:

* a complete revision graph with exactly one head;
* no destructive schema operations in `upgrade()`;
* a documented `downgrade()` for every revision (informational);
* a previous release manifest that is valid, distinct, and bound to the target
  release when one is supplied.

`check-migration` re-verifies the report subject, manifest hash, state, and
required checks before staging can use it.

### Controlled deployment and smoke

`deploy_release` re-resolves the digest-pinned Compose configuration, requires a
production verification report and a bound preflight report, pulls by digest,
starts the stack, and verifies the running container image IDs against the
manifest. A failed pull or `up` stops the deployment sequence.

Post-deployment smoke checks call `/health`, prove authentication, and verify
WebSocket reconnect behaviour. Missing credentials, a missing URL, or a failed
check is a required non-`PASS` state, so the staging report cannot qualify.

### Rollback rehearsal with migration safety

The optional `--require-rollback` path needs a previous manifest and a previous
production verification report. Before the nine-step rehearsal starts, staging
requires the migration compatibility binding to be `PASS`, and passes the
migration report into the rehearsal. The rehearsal records a required
`migration-safety` check bound to the target manifest. A failing or unbound
migration report prevents execution and leaves every rehearsal step `NOT_RUN`.

The rehearsal itself deploys the previous release, verifies and smokes it,
deploys and verifies the target, then redeploys the previous digests and
verifies the restored stack. It never reverses Alembic migrations
automatically and never deletes the PostgreSQL volume; recovery relies on the
pre-upgrade backup described in `docs/PRODUCTION_OPERATIONS.md`.

### GPU runtime and inference

When the target has `gpu: true` or `--require-gpu-runtime` is supplied, staging
qualifies the NVIDIA driver and Docker GPU runtime and runs a structured
inference smoke inside the digest-pinned GPU image. Both reports are bound to
the manifest, and a `NOT_RUN` or `UNAVAILABLE` result blocks staging
qualification.

## Qualification gate

`check-staging` verifies a report produced by `staging-qualify`:

* the report is bound to the supplied manifest bytes;
* the report subject matches the manifest release;
* the target is staging and not production-like;
* the mode is `authorized-mutation` and `authorized` is true;
* the overall state is `PASS` and every required check is `PASS`;
* every required evidence binding is `PASS` and still matches its recorded
  SHA-256;
* the publication binding proves a published GitHub Release;
* `production_qualified` is `false`.

A preflight-only or live-read report never passes this gate. Neither does a
report whose evidence is `NOT_RUN`, `UNAVAILABLE`, or `SIMULATED`.

### Report re-validation

The gate does not trust the report's own summary. It re-opens every bound
evidence file and re-runs the authoritative validator for the verification,
publication, migration, and GPU inference payloads. It also checks that every
component payload carries the manifest release subject and that target URLs are
still `https://` / `wss://`, credential-free, and staging-only. Evidence paths
must be plain file names inside the evidence directory; a binding that tries to
escape the directory is rejected before any file is read. A payload that says
`PASS` while its contents prove `UNAVAILABLE`, `NOT_RUN`, or a mismatched
subject is rejected.

## Live test opt-in

The live tests are excluded from ordinary CI:

```text
pytest -m live backend/tests/live -q
```

They require real infrastructure and never invent evidence. Each test skips
with the exact missing prerequisite names:

| Test | Required prerequisites |
| --- | --- |
| `test_live_release_evidence_collection` | `IVP_LIVE_MANIFEST`, `IVP_LIVE_ARTIFACTS_DIR`, `gh`, and `GH_TOKEN` or `GITHUB_TOKEN` |
| `test_live_staging_qualification` | the above, `IVP_LIVE_STAGING_TARGET`, `IVP_LIVE_MUTATION_AUTHORIZED=1`, and `IVP_LIVE_AUTHORIZE` exactly equal to the target `name` |
| `test_live_gpu_inference` | `IVP_LIVE_GPU_MANIFEST` and `nvidia-smi` |

The mutation test has two independent gates: the `live` marker selects it, and
`IVP_LIVE_MUTATION_AUTHORIZED=1` plus the exact target-name authorization is
required before `staging-qualify --execute --authorize` runs. A test that runs
fails unless live evidence is `PASS`; it never converts an unavailable
prerequisite into a pass.

### Deterministic window boundaries

The alerting evaluator opts into an inclusive end boundary when it reads the
event window, so an event whose `first_seen` equals the evaluation reference
time is evaluated in the same cycle. Analytics history queries keep the strict
exclusive boundary by default. Regression tests cover both behaviours, replacing
the timing-dependent alerting failures instead of skipping or weakening them.

## V27 compatibility note

V27 changes only the V26 readiness report schema and its tool probes. It does
not change the V25 staging target contract, staging modes, required checks,
mutation authorization, evidence binding, or the `check-staging` gate. A V26
readiness report that is incomplete and non-`PASS` may now be schema-valid, but
`check-readiness` still rejects it and V25 staging qualification still requires
its own complete evidence. V27 never converts readiness into staging
qualification or production qualification. See
[V27_CROSS_PLATFORM_READINESS.md](V27_CROSS_PLATFORM_READINESS.md).

## Current limitations

The execution and evidence code is implemented and covered by offline tests,
but this environment cannot produce live evidence:

* `gh` is not installed and `GH_TOKEN` / `GITHUB_TOKEN` are unset, so GitHub
  Release, GHCR, and attestation evidence is `UNAVAILABLE`;
* the Docker CLI is present but the daemon is not reachable, so a live
  deployment or running-stack verification cannot run;
* `nvidia-smi` is absent, so GPU runtime and inference evidence is `NOT_RUN`;
* no authorized staging target, previous verification report, or smoke
  credentials exist here;
* no live deployment, image publication, tag creation, GitHub Release, registry
  mutation, rollback rehearsal, or destructive database operation was performed
  while implementing this phase.

Those checks remain required and must be executed on a real staging host with a
separate, explicit authorization.
