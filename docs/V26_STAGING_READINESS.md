# V26 Staging Infrastructure Readiness

V26 answers one question only: **is this checkout, host, release binding, and
explicit staging target prepared for a future, separately authorized staging
qualification run?**

It does not deploy, publish, tag, dispatch a workflow, run a migration, modify
a database or volume, or authorize any production action. A readiness report is
preparation evidence, not a deployment authorization and not production
qualification.

## Status vocabulary

Every check records one of the existing evidence states:

| State | Meaning |
| --- | --- |
| `PASS` | The prerequisite was verified for the stated scope. |
| `FAIL` | The prerequisite was inspected and is wrong or unsafe. |
| `NOT_RUN` | The check was not evaluated. |
| `UNAVAILABLE` | The check could not be performed because a tool, service, credential, or target is absent. |
| `SIMULATED` | The result came from simulated test data. It never satisfies a required readiness gate. |

`NOT_RUN`, `UNAVAILABLE`, and `SIMULATED` never satisfy a required readiness
check. A readiness report is `PASS` only when every required check is `PASS`
and every required evidence binding is retained and intact.

`PASS` is scoped: it means the prerequisite was verified, not that the release
is production-qualified. Every report records `production_qualified: false` and:

```json
"deployment": {
  "authorized": false,
  "performed": false,
  "statement": "No deployment was authorized or performed by this readiness assessment. Readiness is not deployment authorization and does not prove production qualification."
}
```

## Modes

| Mode | How to select | What it does |
| --- | --- | --- |
| `preflight` | Default | Local inspection only. No GitHub, GHCR, staging, or production contact. |
| `live-read-only` | `--execute-live` | Adds bounded read-only probes such as `gh auth status`, a GitHub Release read, a GHCR manifest read, and TCP reachability checks. |

Default CI and local validation use `preflight`. The report states the mode and
each check states whether it used `local`, `live-read-only`, or `simulated`
inspection. Live probes are read-only; they never push, pull a deployment,
dispatch a workflow, or mutate a target.

## Required inputs

Readiness never invents a target or a release. A report can only become `PASS`
when all of these are explicitly supplied:

| Input | CLI flag | Purpose |
| --- | --- | --- |
| Staging target | `--target` | Explicit target definition validated against `release/staging-target.schema.json`. |
| Release manifest | `--manifest` | Immutable tag, commit, repository, and image digests. |
| Previous release manifest | `--previous-manifest` | Known-good release that rollback must restore. It must be distinct from the target release. |
| Previous production verification | `--previous-verification-report` | V23/V24 report bound to the previous manifest bytes. |
| Rollback rehearsal evidence | `--rollback-evidence` | Executed V24 rehearsal bound to both the target and previous manifests. |

Optional identity bindings are `--tag`, `--commit`, `--repository`, and
`--branch`. When supplied, they must match the manifest and the checkout. The
default main reference is `origin/main`.

## Report contract

`release/staging-readiness.schema.json` is the machine-readable contract. A
report contains:

- `schema_version` (`1`) and `profile` (`staging_readiness`);
- `generated_at`, `mode`, repository identity, and release identity;
- the optional explicit staging target summary;
- `gpu_required` and `gpu_ready`, kept separate;
- `state` and `ready`;
- `production_qualified: false`;
- the explicit no-deployment statement;
- every check with `name`, `category`, `state`, `required`, `mode`, `detail`,
  and `command`;
- retained evidence entries with `kind`, `path`, `sha256`, and `state`;
- one binding per required input (`target`, `manifest`, `previous_manifest`,
  `previous_verification`, `rollback_evidence`);
- `blockers`, `limitations`, and `next_steps`.

The report never embeds credential values, tokens, passwords, cookies, private
keys, or secret environment values. It records only whether a named environment
variable is present. Evidence files that appear to contain secret assignments
or private-key material are not copied into the evidence directory.

## Check categories

| Category | Examples |
| --- | --- |
| `repository` | repository identity, HEAD commit, branch, clean worktree, reachability from main, release tag resolution |
| `release` | manifest validity, immutable non-placeholder digests, previous release, previous production verification, rollback evidence |
| `tooling` | git, Python, pytest, Ruff, Node.js, npm, Docker CLI, Docker daemon, Docker Compose |
| `github` | GitHub CLI, GitHub auth configuration, GHCR auth configuration, optional network probes |
| `target` | explicit target, staging environment, HTTPS/WSS URLs, production exclusion, release binding, smoke configuration, credential presence |
| `deployment` | Compose files, digest-pinned Compose resolution, service pins, PostgreSQL, Redis, named volumes, health endpoints, loopback ports, environment references |
| `gpu` | GPU profile, NVIDIA hardware, driver, container runtime, and `api-gpu` digest |

A Docker CLI installation without a reachable daemon is reported as
`UNAVAILABLE`, never `PASS`. A credential environment variable that exists but
was not validated in the selected mode is not treated as proof of working
authentication.

## Staging target policy

The target is always explicit. Validation rejects:

- a missing target (it is never inferred from Compose, the manifest, or the
  hostname);
- an environment other than exactly `staging`;
- production-like names or hosts (`prod`, `production`, `prd`);
- non-HTTPS API/web URLs and non-WSS WebSocket URLs;
- embedded URL credentials, query strings, and fragments;
- unknown fields and unsafe `compose_files` paths;
- a release binding that does not match the manifest;
- a missing smoke username or an invalid `smoke_password_env` name;
- Compose files that escape the repository root or do not exist.

The target file never contains the smoke password. The password is read from
the named environment variable at execution time; readiness only reports
whether that variable is present.

## GPU readiness is separate

CPU readiness does not imply GPU readiness. GPU checks are optional for a CPU
target and are reported as optional `NOT_RUN` limitations. They become required
when the target sets `"gpu": true` or the operator passes `--require-gpu`.
Missing NVIDIA hardware, driver, container runtime, or an immutable `api-gpu`
digest blocks a GPU-required readiness report. A CPU `PASS` never claims GPU
acceleration or GPU production qualification.

## Integrity and fail-closed behavior

`check-readiness` revalidates the report instead of trusting its summary. It
fails closed on:

- an unknown report, check, evidence, binding, repository, release, target, or
  deployment field;
- a wrong schema version or profile;
- a missing required check or a required check that is not `PASS`;
- a `SIMULATED` required check, or a preflight report containing live checks;
- contradictory `state`, `ready`, `gpu_required`, `gpu_ready`, or check states;
- a report whose manifest hash, subject, or digests do not match the supplied
  manifest;
- a changed evidence file or a binding that does not match its evidence;
- a target summary that does not match the retained target evidence;
- changed report bytes when `--report-sha256` is supplied;
- any claim of production qualification or deployment authorization.

Evidence is retained under content-addressed names and every binding is
rehashed. A report cannot be reused for different manifest bytes, a different
target, a different release subject, or a different previous release.

## Commands

```bash
# Offline preflight: local inspection only.
python -m tools.release.cli staging-readiness \
  --manifest release-artifacts/release-manifest.json \
  --target staging-target.json \
  --previous-manifest previous-manifest.json \
  --previous-verification-report previous-release-verification.json \
  --rollback-evidence rollback-rehearsal.json \
  --output release-artifacts/staging-readiness.json

# Opt in to bounded read-only live probes.
python -m tools.release.cli staging-readiness \
  --manifest release-artifacts/release-manifest.json \
  --target staging-target.json \
  --previous-manifest previous-manifest.json \
  --previous-verification-report previous-release-verification.json \
  --rollback-evidence rollback-rehearsal.json \
  --execute-live \
  --output release-artifacts/staging-readiness.json

# Gate on the exact report bytes.
python -m tools.release.cli check-readiness \
  --report release-artifacts/staging-readiness.json \
  --manifest release-artifacts/release-manifest.json \
  --report-sha256 <sha256>
```

`staging-readiness` exits non-zero when the report is not `PASS`.
`check-readiness` exits non-zero on any validation error. A passing readiness
gate prints that deployment still requires a separate authorization and does
not prove production qualification.

## Relationship to V22-V25

- V22/V23 release verification and attestation contracts are unchanged.
- V24 qualification profiles, deployment preflight, rollback rehearsal, and GPU
  runtime evidence are unchanged.
- V25 staging target validation, evidence binding, and mutation authorization
  are unchanged.
- V26 consumes V24/V25 evidence as input. It does not create releases, tags,
  workflow runs, deployments, or staging mutations.
- Readiness `PASS` does not satisfy V24 production evidence requirements and
  does not authorize a deployment. V24 production qualification remains a
  separate, stricter gate.

## Current environment expectations

On a host without `gh`, GitHub/GHCR credentials, a reachable Docker daemon, a
staging target, previous release evidence, or an NVIDIA GPU, the honest result
is a non-`PASS` readiness report with `UNAVAILABLE` or `NOT_RUN` checks and
explicit blockers. That is expected and must not be weakened into a pass. The
next safe actions are listed in the report's `next_steps`.
