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
| `production_qualification` | Production readiness | Staging requirements plus `full` scope, a GPU deployment, an executed rollback rehearsal with hash-verifiable evidence, and container-level GPU runtime proof |

Scopes add evidence in order:

- `artifact`: manifest, verification, per-image digest/SBOM/scan/bundle hashes;
  publication is required with `--require-live-evidence` or any non-local
  profile.
- `deployment`: adds a deployment report bound to the same manifest bytes and
  subject. The report must prove digest-pinned Compose configuration, a bound
  preflight, the running `api` and `web` services, and running image IDs that
  match the manifest. A `production_qualification` deployment must also use the
  GPU overlay (`gpu: true`).
- `full`: adds an executed rollback rehearsal with `executed: true`,
  `state: PASS`, `verified: true`, all nine steps `PASS`, target and previous
  digest bindings, and evidence files whose SHA-256 values match the report.
  `production_qualified` requires `full`.

```powershell
# Probe the host before claiming evidence you cannot produce.
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
the V23 report has `production_verified: true`, the deployment used the GPU
overlay, the rollback rehearsal executed all nine steps and verified distinct
target and previous digests, the GPU runtime report proves the `nvidia`
runtime and `container_cuda: true`, and every referenced evidence file still
matches its recorded SHA-256.

`check-qualification --require-production` revalidates the qualification
report's production bindings and, when report paths are supplied, rejects any
report whose bytes changed after qualification. A `PASS` in a summary field is
not enough: missing, unexecuted, `NOT_RUN`, `UNAVAILABLE`, or `SIMULATED`
evidence can never satisfy a required production check.

The CI `qualify` job runs `local_validation`/`artifact` with
`--require-live-evidence` after publication. It gates the GitHub Release but
never claims production qualification; the release job still requires the V23
production report. Deployment, rollback, and GPU qualification must be
produced on the real target hosts.

Report schema: `release/release-qualification.schema.json`.

## Staging infrastructure readiness (V26)

V26 adds a readiness assessment that is deliberately separate from
qualification and deployment. It inspects the repository checkout, installed
tools, the explicit staging target, the release manifest, Compose
configuration, previous known-good release evidence, and rollback rehearsal
evidence. It never tags, publishes, deploys, dispatches a workflow, or mutates
staging or production.

```bash
python -m tools.release.cli staging-readiness \
  --manifest release-artifacts/release-manifest.json \
  --target staging-target.json \
  --previous-manifest previous-manifest.json \
  --previous-verification-report previous-release-verification.json \
  --rollback-evidence rollback-rehearsal.json \
  --output release-artifacts/staging-readiness.json

python -m tools.release.cli check-readiness \
  --report release-artifacts/staging-readiness.json \
  --manifest release-artifacts/release-manifest.json \
  --report-sha256 <sha256>
```

The default mode is an offline preflight. `--execute-live` adds bounded
read-only GitHub, GHCR, and network probes. `PASS` means only that every
required prerequisite was verified for the stated scope. A readiness report
always records `production_qualified: false` and
`deployment: {authorized: false, performed: false}`; it never authorizes a
deployment. See [V26_STAGING_READINESS.md](V26_STAGING_READINESS.md).

## Cross-platform readiness compatibility (V27)

V27 fixes two V26 operational gaps without weakening any release gate:

- `release/staging-readiness.schema.json` now validates legitimate incomplete
  non-`PASS` reports with nullable staging-target, repository identity, release
  identity, and binding values. `PASS` remains strict: complete target,
  release subject and digests, resolved repository identity, all five `PASS`
  bindings, retained evidence, at least 47 checks, no required non-`PASS`
  check, and `ready: true`.
- Readiness tool discovery now handles Windows `.cmd`/`.bat` shims through
  `cmd.exe` with argument lists, bounded timeouts, rejected unsafe
  metacharacters, and sanitized failures. Node.js, npm, Docker
  CLI/daemon/Compose, GitHub CLI, and NVIDIA tooling keep distinct
  `PASS`/`UNAVAILABLE`/`NOT_RUN` outcomes.

`check-readiness` still revalidates the full report at runtime, so a
schema-valid incomplete report is not a passing gate. V24 production
qualification, V25 staging qualification and mutation authorization, and V26
readiness checks are unchanged. V27 adds offline compatibility and tooling
tests and the `jsonschema` development dependency; no live GitHub, GHCR,
Docker, staging, GPU, release, publication, workflow, deployment, or migration
action is part of V27. See
[V27_CROSS_PLATFORM_READINESS.md](V27_CROSS_PLATFORM_READINESS.md).

## Live infrastructure verification (V28)

V28 extends readiness with an explicitly authorized, read-only inspection of
the external release infrastructure. In live mode it verifies the GitHub tag,
release, assets, and workflow run; the published GHCR digests and platform
metadata; GitHub attestations and local SBOM/scan evidence; bounded DNS, TCP,
TLS, HTTPS, and WSS reachability of an explicit staging target; an existing
Docker context; and rollback prerequisites.

```bash
python -m tools.release.cli staging-readiness \
  --manifest release-artifacts/release-manifest.json \
  --target staging-target.json \
  --previous-manifest previous-manifest.json \
  --previous-verification-report previous-release-verification.json \
  --rollback-evidence rollback-rehearsal.json \
  --artifacts-dir release-artifacts \
  --migration-report migration-compatibility.json \
  --backup-documentation docs/BACKUP_RESTORE.md \
  --docker-host staging-east \
  --connectivity-timeout 10 \
  --execute-live \
  --output release-artifacts/staging-readiness.json
```

The target must contain the exact staging statement, list every allowed
hostname, and declare production hostnames. A target that fails that policy is
never contacted. Connectivity is limited to the target URLs with a 1-60 second
timeout, certificate and hostname validation, and no port scanning.
`--docker-host` names an existing Docker context and only read-only `version`,
`context inspect`, `compose version`, `ps`, and `info` commands are executed.

V28 keeps `schema_version: 1`, adds the optional `inspection_profile: "v28"`
marker and optional `live_inspection`, `migration_report`, and
`backup_documentation` bindings. Preflight reports leave those bindings null;
live reports retain secret-free evidence. A readiness `PASS` remains
preparation evidence only and never authorizes a deployment. See
[V28_LIVE_INFRASTRUCTURE_VERIFICATION.md](V28_LIVE_INFRASTRUCTURE_VERIFICATION.md).

## Credential and evidence retention hardening (V29)

V29 centralizes credential detection and redaction in
`backend/app/core/redaction.py`. Backend logging and every release report writer
share the policy, so prefixed environment names, JSON/YAML-like structured
fields, URL credentials, authorization/cookie/custom headers, private-key
blocks, logs, and exception tracebacks are handled consistently.

Report writers sanitize before writing and compute SHA-256 over the exact
stored sanitized bytes. Readiness evidence that is clean is retained
byte-for-byte with its original hash. A secret-bearing input is not bound and
still produces the existing `evidence-retention` blocker; a separately named
`<kind>-<sanitized_digest[:12]>-redacted<ext>` diagnostic copy may be written
for operators, but it is not evidence and never reuses the original hash.
Unparseable JSON is rejected rather than retained.

V29 keeps `schema_version: 1`, the V22-V28 evidence contracts, check names,
action SHA pins, and release gates unchanged. It does not create a tag, release,
workflow run, deployment, or infrastructure mutation. See
[V29_EVIDENCE_RETENTION_SECURITY.md](V29_EVIDENCE_RETENTION_SECURITY.md).

## Evidence integrity and tamper detection (V30)

V30 adds an optional integrity sidecar and an append-only JSONL audit chain
without changing any V23-V29 report schema. The sidecar binds the exact report
bytes to deterministic SHA-256 evidence records, the evidence root, and the
audit-chain head. The chain records `EVIDENCE_CREATED`, `EVIDENCE_VERIFIED`,
`EVIDENCE_MODIFIED`, `EVIDENCE_MISSING`, `EVIDENCE_REPLACED`,
`EVIDENCE_REJECTED`, `EVIDENCE_PATH_INVALID`, `MANIFEST_BINDING_MISMATCH`, and
`AUDIT_CHAIN_INVALID`.

```powershell
python -m tools.release.cli seal-evidence `
  --report release-artifacts/staging-readiness.json `
  --evidence-root release-artifacts/readiness-evidence

python -m tools.release.cli verify-evidence `
  --report release-artifacts/staging-readiness.json `
  --manifest release-manifest.json

python -m tools.release.cli verify-audit `
  --audit release-artifacts/staging-readiness.audit.jsonl `
  --checkpoint release-artifacts/staging-readiness.checkpoint.json
```

Verification covers report and evidence existence, readability, size, SHA-256,
identifier consistency, safe path resolution, traversal and symlink escape,
manifest binding, audit continuity, schema compatibility, and redacted
diagnostics. Outcomes are `PASS`, `FAIL`, `UNAVAILABLE`, and `NOT_RUN`; missing
evidence or an unavailable check is never a pass. Verification is read-only and
does not repair, rewrite, quarantine, or delete evidence. Exit codes are `0`,
`1`, `2`, `3`, and `4` for invalid invocation.

A local hash chain is tamper-evident, not immutable. An attacker with write
access to both the evidence and the entire chain can recompute every hash.
Checkpoints are explicit local files or an injected provider; no external
anchor is contacted by default. Store a checkpoint where the evidence producer
cannot rewrite it if termination evidence matters. See
[V30_EVIDENCE_INTEGRITY_AND_TAMPER_DETECTION.md](V30_EVIDENCE_INTEGRITY_AND_TAMPER_DETECTION.md).

## Signed evidence checkpoints and trust anchoring (V31)

V31 adds optional Ed25519-signed checkpoints on top of the unchanged V30
integrity sidecar and audit chain. Signed checkpoints are separate
`schema_version: 2` files with a deterministic canonical payload, an explicit
domain prefix, an Ed25519-only algorithm allowlist, an exact-payload signature,
and a key identity resolved from a separately configured trust store or trusted
fingerprint. V30 unsigned checkpoints remain `schema_version: 1` and verify
unchanged.

```powershell
python tools/manage_evidence_trust.py generate-key `
  --key-id evidence-2026-01 `
  --private-key keys/evidence-2026-01.pem `
  --public-key keys/evidence-2026-01.pub.json

python tools/manage_evidence_trust.py init-store --store trust-store.json
python tools/manage_evidence_trust.py register-key `
  --store trust-store.json `
  --public-key keys/evidence-2026-01.pub.json `
  --activated-at 2026-11-01T00:00:00Z

python -m tools.release.cli sign-checkpoint `
  --audit release-artifacts/staging-readiness.audit.jsonl `
  --report release-artifacts/staging-readiness.json `
  --integrity release-artifacts/staging-readiness.integrity.json `
  --private-key keys/evidence-2026-01.pem `
  --key-id evidence-2026-01 --sequence 1 `
  --output release-artifacts/staging-readiness.signed-checkpoint.json

python -m tools.release.cli verify-evidence `
  --report release-artifacts/staging-readiness.json `
  --integrity release-artifacts/staging-readiness.integrity.json `
  --audit release-artifacts/staging-readiness.audit.jsonl `
  --checkpoint release-artifacts/staging-readiness.signed-checkpoint.json `
  --trust-store trust-store.json `
  --trust-state trust-state.json
```

Verification requires independent trust material; a missing trust store or
fingerprint is `UNAVAILABLE` (exit `2`), never `PASS`. The trust store supports
key IDs, public keys, fingerprints, purpose, allowed algorithms, policy version,
activation, expiration, revocation, and historical-revocation policy. The local
trust state detects replay and rollback within its recorded history but is not
independently monotonic; V31 reports `assurance: "reduced"` in that case.
`--require-independent-freshness` requires a separately supplied external
reference and otherwise returns `NOT_RUN` (exit `3`). No external service is
contacted and no external anchoring is claimed. V30 exit codes remain `0`/`1`/
`2`/`3`/`4`, and all diagnostics pass through V29 redaction. See
[V31_SIGNED_EVIDENCE_AND_TRUST_ANCHORING.md](V31_SIGNED_EVIDENCE_AND_TRUST_ANCHORING.md).

## Transparency log and independent checkpoint anchoring (V32)

V32 adds an optional append-only JSONL transparency log, RFC 6962/9162 Merkle
inclusion and consistency proofs, Ed25519-signed tree heads, a separate local
transparency trust state, and a provider-neutral anchor interface. It consumes
V31 signed checkpoints without changing their payload semantics and adds only
the key purpose `transparency_tree_head_signing` to the existing V31 trust
store. V30 unsigned checkpoints and V31 signed checkpoints verify unchanged.

```powershell
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

python -m tools.transparency_log create-tree-head `
  --log release-artifacts/transparency.jsonl `
  --private-key keys/transparency-2026-01.pem `
  --key-id transparency-2026-01 `
  --output release-artifacts/transparency-tree-head.json `
  --timestamp 2026-01-09T00:00:00Z

python -m tools.transparency_log verify-tree-head `
  --tree-head release-artifacts/transparency-tree-head.json `
  --trust-store trust-store.json `
  --trust-state transparency-state.json `
  --consistency-proof release-artifacts/consistency-3.json `
  --update-trust-state `
  --state-updated-at 2026-01-10T00:00:00Z
```

Merkle leaves use RFC 6962 domain separation: `SHA256(0x00 || leaf)` for leaves
and `SHA256(0x01 || left || right)` for internal nodes, with the documented
empty root `SHA256(b"")`. Inclusion proofs bind tree size, leaf index, leaf
digest, sibling path, log ID, algorithm, and expected root. Consistency proofs
cover empty-to-empty, empty-to-nonempty, single-leaf growth, power-of-two and
non-power-of-two transitions, and multiple appends.

The separate `transparency_trust_state` detects tree-size and root rollback,
conflicting roots and heads, duplicate tree-head IDs, stale or invalid receipts,
missing consistency proofs, inconsistent growth, and split-view evidence.
Failed verification never overwrites previously trusted tree-head state, and a
newer timestamp alone is not consistency evidence. The local state is
tamper-evident, not independently monotonic; V32 reports `assurance: "reduced"`
in that case.

The only shipped anchor provider is a local deterministic test provider whose
receipts are `SIMULATED`; `anchor-tree-head` requires explicit `--provider-key`
and `--receipt-dir` and otherwise reports `NOT_CONFIGURED` (exit `2`). An
unavailable provider reports `UNAVAILABLE` (exit `2`), and there is no silent
fallback. `EXTERNAL_VERIFIED` is reserved for a future genuinely configured and
verified external provider. V32 ships none, contacts no external transparency
service, cloud KMS, GitHub API, registry, staging system, or production
endpoint, and never claims external anchoring. Exit codes remain `0`/`1`/`2`/
`3`/`4`, and all diagnostics pass through V29 redaction. See
[V32_TRANSPARENCY_LOG_AND_INDEPENDENT_ANCHORING.md](V32_TRANSPARENCY_LOG_AND_INDEPENDENT_ANCHORING.md).

## Continuous integrity monitoring (V33)

V33 adds an offline continuous-audit subsystem on top of V30–V32. It reuses
the existing evidence, signed-checkpoint/trust, and transparency verifiers; it
does not duplicate cryptography and never writes, repairs, or re-signs
protected artifacts. Only an isolated SQLite monitoring store is written.

```powershell
# Manual bounded audit (ADMIN/OPERATOR); returns the terminal run summary.
$body = @{ scopes = @("FULL") } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://localhost:8000/api/v1/integrity/audits `
  -ContentType application/json -Body $body -WebSession $session

# Authenticated reads (all roles).
Invoke-RestMethod http://localhost:8000/api/v1/integrity/status -WebSession $session
Invoke-RestMethod http://localhost:8000/api/v1/integrity/findings -WebSession $session
```

Scopes are `EVIDENCE`, `SIGNED_CHECKPOINTS`, `TRANSPARENCY_LOG`, `TREE_HEADS`,
`INCLUSION_PROOFS`, `CONSISTENCY_PROOFS`, `TRUST_STATE`, and `FULL`. Outcomes
are `PASS`, `FAIL`, `PARTIAL`, `UNAVAILABLE`, and `NOT_RUN`; a confirmed
signature/integrity failure can never be reported as `PASS`, and unconfigured
inputs are never treated as passing. Findings carry stable IDs, severity,
reason codes, safe artifact identifiers, UTC timestamps, sanitized
explanations, verification sources, and recommended actions.

The scheduler is opt-in (`INTEGRITY_SCHEDULER_ENABLED=true`), bounded by
`INTEGRITY_SCHEDULER_INTERVAL_SECONDS`, and uses durable schedule slots plus
stale-run recovery and retention pruning. Manual runs are bounded by scope
count, batch artifacts, concurrent runs, timeout, retries, findings, API page
size, and retention. Duplicate runs are prevented with a durable lease;
idempotency keys replay the original run. Cross-process cancellation is not
claimed.

Alerting is opt-in and sanitized: per-finding dedup plus a correlated
cooldown, with notifications created as `pending` for the existing delivery
worker — never a false delivery-success claim. Metrics are bounded and include
runs, duration, findings, artifacts, scope failures, scheduler outcomes, last
success, running audits, and `external_anchor_configured` (always `0` offline).
The `/integrity` dashboard shows overview, trust state, findings, history, and
per-run detail with honest loading/empty/unavailable/error states.

V33 contacts no external transparency service, cloud KMS, GitHub API,
registry, staging system, or production endpoint and never claims external
anchoring. The monitoring store is SQLite; every worker/API process that needs
cross-process duplicate prevention must share the same file. See
[V33_CONTINUOUS_INTEGRITY_MONITORING.md](V33_CONTINUOUS_INTEGRITY_MONITORING.md).

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
  --execute --evidence-dir release-artifacts/rehearsal `
  --output release-artifacts/rehearsal/rollback-rehearsal.json
```

`--execute` requires both `--evidence-dir` and `--output`, and the evidence
directory must be the directory that contains the report. Qualification
resolves each evidence path relative to the rehearsal report, so a report
copied away from its evidence cannot qualify. Without `--execute` every step
is `NOT_RUN`. Evidence written by the rehearsal is listed with its SHA-256 in
the report, and the report binds both the target and previous manifest hashes,
subjects, and digests. `full` scope qualification requires `executed: true`,
`state: PASS`, `verified: true`, all nine steps `PASS`, and matching evidence
hashes.

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
- V29 redaction is pattern- and name-based, not universal data-loss prevention.
  Unknown proprietary formats, secrets split across fields or lines, encrypted
  or encoded blobs, and binary, oversized, or non-UTF-8 evidence may not be
  detected. A stored hash proves the integrity of the stored bytes, not the
  absence of every possible secret.

## V34 release impact

V34 adds an additive Alembic revision, `011_create_forensics`, creating only
forensic case-management tables after `010_add_notification_mute`. Existing
V10–V33 tables and artifacts are untouched; `downgrade()` drops only the V34
tables. No release tag, image publication, workflow dispatch, or deployment is
part of V34.

New runtime configuration is additive: `FORENSIC_ENABLED`,
`FORENSIC_EVIDENCE_ROOT`, `FORENSIC_EXPORT_DIR`,
`FORENSIC_EXPORT_INCLUDE_EVIDENCE_BYTES`, `FORENSIC_EXPORT_MAX_FILES`,
`FORENSIC_EXPORT_MAX_BYTES`, `FORENSIC_MAX_CORRELATION_FINDINGS`, and the
`FORENSIC_ALERT_*` settings. Deployments must run the migration before enabling
the `/forensics` workspace. No credentials, private keys, evidence bytes, or
generated forensic packages are committed to the repository.

V34 is preparation and incident-response tooling, not production
qualification. A clean forensic verification proves only that the configured
read-only checks passed; it does not authorize a deployment and does not
replace V24 production qualification. The custody chain is local, and no
external transparency anchoring is claimed. See
[V34_INTEGRITY_INCIDENT_RESPONSE_AND_FORENSICS.md](V34_INTEGRITY_INCIDENT_RESPONSE_AND_FORENSICS.md).

## V35 release impact

V35 adds an additive Alembic revision, `012_create_governance`, creating only
governance policy, retention evaluation, legal-hold, disposition, export
approval, and access-audit tables after `011_create_forensics`. Existing
V01–V34 tables, evidence references, custody records, export IDs, paths,
hashes, and semantics are untouched; `downgrade()` drops only the V35 tables.
No release tag, image publication, workflow dispatch, or deployment is part of
V35.

New runtime configuration is additive: `GOVERNANCE_ENABLED`,
`GOVERNANCE_RETENTION_BATCH_LIMIT`, `GOVERNANCE_PAGE_SIZE`,
`GOVERNANCE_AUDIT_PAGE_SIZE`, `GOVERNANCE_LEGAL_HOLD_REQUIRES_APPROVAL`,
`GOVERNANCE_REPORT_UPCOMING_DAYS`, `GOVERNANCE_REPORT_MAX_ROWS`,
`GOVERNANCE_ALERTING_ENABLED`, and `GOVERNANCE_ALERT_COOLDOWN_SECONDS`.
Deployments must run the migration before enabling `/governance`.

V35 establishes governance and compliance readiness, not legal compliance or
regulatory certification. The default policy has no invented retention
duration; organizations must configure and document their own values.
Retention evaluation is manual and bounded. No automatic physical evidence
deletion, automatic legal-hold release, or automatic disposition approval
exists. A disposition approval authorizes only a future, separately scoped
process. Export approval does not prove external delivery or recipient
validation. Governance audit is local and self-digested; no external immutable
storage or trust anchor is claimed. See
[V35_FORENSIC_GOVERNANCE_RETENTION_AND_COMPLIANCE.md](V35_FORENSIC_GOVERNANCE_RETENTION_AND_COMPLIANCE.md).

## V36 release impact

V36 adds an additive Alembic revision, `013_create_governance_automation`,
creating only governance schedule, job, job-event, and snapshot tables after
`012_create_governance`. Existing V01–V35 tables, evidence references, custody
records, export IDs, paths, hashes, and semantics are untouched; `downgrade()`
drops only the V36 tables. No release tag, image publication, workflow
dispatch, or deployment is part of V36.

New runtime configuration is additive: `GOVERNANCE_AUTOMATION_ENABLED`,
`GOVERNANCE_AUTOMATION_POLL_SECONDS`,
`GOVERNANCE_AUTOMATION_LEASE_SECONDS`,
`GOVERNANCE_AUTOMATION_MAX_ATTEMPTS`,
`GOVERNANCE_AUTOMATION_RETRY_BASE_SECONDS`,
`GOVERNANCE_AUTOMATION_RETRY_MAX_SECONDS`,
`GOVERNANCE_AUTOMATION_JOB_TIMEOUT_SECONDS`,
`GOVERNANCE_AUTOMATION_MAX_PENDING_JOBS`, and
`GOVERNANCE_AUTOMATION_MAX_JOBS_PER_TICK`. Deployments must run the migration
before enabling automation.

V36 is opt-in and disabled by default. It schedules non-destructive retention
evaluation, deduplicated review reminders, local compliance snapshots, and
health checks. It never deletes evidence, automatically releases a legal hold,
automatically approves or rejects a disposition, or generates a forensic
export. Reminder delivery depends on existing V15 GOVERNANCE alert rules and
is reported as local queue state, not an external delivery guarantee.
Compliance snapshots are local self-digested SUMMARY records, not regulatory
certification, immutable storage, or external trust anchors. See
[V36_GOVERNANCE_AUTOMATION_AND_COMPLIANCE_OPERATIONS.md](V36_GOVERNANCE_AUTOMATION_AND_COMPLIANCE_OPERATIONS.md).
