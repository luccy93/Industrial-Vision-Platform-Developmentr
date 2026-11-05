# V30 Evidence Integrity and Tamper Detection

V30 adds an optional, separate evidence-integrity layer on top of the V23-V29
release reports. It records deterministic SHA-256 evidence records, binds them
to the exact report bytes and optional release manifest, and maintains an
append-only JSONL audit chain. Verification is read-only and reports what it
observed without repairing, rewriting, quarantining, or deleting anything.

V30 is an integrity-monitoring volume. It does not deploy, publish, tag,
release, dispatch a workflow, run a migration, or mutate shared infrastructure.
It keeps every existing report schema, including `schema_version: 1`, unchanged.
The integrity sidecar is a new optional file; it is never injected into a V23-V29
report.

## Trust model

The controls in V30 are **tamper-evident**, not tamper-proof.

- SHA-256 proves that the bytes being read match an expected digest. It does
  not prove who produced the bytes, whether they are truthful, or whether the
  complete evidence set was retained.
- The audit chain links each record to its predecessor. Editing, reordering,
  deleting, or inserting a record breaks the chain unless the attacker
  recomputes every following hash.
- An attacker who can write both the evidence and the entire audit chain can
  recompute a self-consistent chain. A local hash chain cannot defend against
  that attacker.
- A checkpoint provides stronger termination evidence only when it is stored
  somewhere the attacker cannot also rewrite, for example a separate system,
  a write-once store, or an independently controlled repository.
- V30 does not contact an external timestamp authority, transparency log, or
  signing service by default. Checkpoints are explicit local files or an
  injected `CheckpointProvider`.

Do not describe a V30 `PASS` as proof that evidence is authentic or immutable.
It means the verifier re-read the evidence and the configured integrity inputs
and found no contradiction within the stated trust boundary.

## Artifacts

V30 creates two new files and never modifies the report or the evidence:

| Artifact | Default path | Purpose |
| --- | --- | --- |
| Integrity sidecar | `<report-stem>.integrity.json` | Binds the report bytes, evidence records, and audit-chain head. |
| Audit chain | `<report-stem>.audit.jsonl` | Append-only ordered events with per-record hashes. |
| Checkpoint | operator-supplied | Optional trusted termination record for the audit chain. |

The sidecar schema is
[`release/evidence-integrity.schema.json`](../release/evidence-integrity.schema.json),
with `schema_version: 1` and `profile: "evidence_integrity"`. Existing report
schemas and their version numbers are untouched.

### Integrity sidecar

The sidecar contains:

- `report`: the report's relative path, SHA-256, `schema_version`, and `profile`;
- `parent_id`: `report:sha256:<64-hex>`;
- `evidence_root`: the relative evidence root, or `"."`;
- `evidence`: one deterministic record per evidence path and digest;
- `audit`: the audit-chain relative path, SHA-256, record count, head hash, and
  optional checkpoint binding;
- `authorized_reuse`: explicit digests permitted to appear at more than one
  path, with a reason;
- `limitations`: the trust-boundary statements reproduced in verification
  output.

Each evidence record contains `evidence_id`, `kind`, `path`, `sha256`, `size`,
`created_at`, `schema_version`, and `parent_id`. The `parent_id` binds every
record to the exact report digest.

### Canonical records

Records are deterministic so that independent runs over the same inputs
produce the same bytes:

- Canonical JSON is compact, sorted by key, UTF-8, and ASCII-escaped
  (`ensure_ascii=True`, separators `(",", ":")`, no trailing newline).
- Timestamps normalize to `YYYY-MM-DDTHH:MM:SSZ`; offsets are converted to UTC
  and fractional seconds are discarded.
- `record_hash` is the SHA-256 of the canonical record excluding
  `record_hash` itself.
- `event_id` is derived from all fields except `event_id` and `record_hash`.
- The genesis `previous_record_hash` is `sha256:` followed by 64 zeros.
- Audit lines are canonical JSON, one record per line, with a final newline.

## Audit events

The audit chain supports these event types:

| Event | Emitted when |
| --- | --- |
| `EVIDENCE_CREATED` | Sealing records an evidence binding. Its outcome must be `PASS`. |
| `EVIDENCE_VERIFIED` | A verification check succeeds, or an explicit verification event is recorded. |
| `EVIDENCE_MODIFIED` | Size or content differs from the expected record. |
| `EVIDENCE_MISSING` | The evidence path does not exist. |
| `EVIDENCE_REPLACED` | The digest differs while the size matches, or no size was recorded. |
| `EVIDENCE_REJECTED` | The evidence is malformed, unsupported, unreadable, a directory, or a redacted diagnostic copy. |
| `EVIDENCE_PATH_INVALID` | The path is unsafe, escapes the root, or resolves through a symlink/junction below the root. |
| `MANIFEST_BINDING_MISMATCH` | The report, sidecar, audit binding, or release manifest disagree. |
| `AUDIT_CHAIN_INVALID` | The chain is structurally invalid, discontinuous, or does not match its checkpoint. |

Verification outcomes are `PASS`, `FAIL`, `UNAVAILABLE`, and `NOT_RUN`.
Missing evidence, an unreadable file, a missing sidecar, an unreachable
checkpoint, or a check that could not run is never converted into `PASS`.
Aggregation uses the precedence `FAIL` > `UNAVAILABLE` > `NOT_RUN` > `PASS`
over required checks. Optional checks such as an unrequested checkpoint are
reported as `NOT_RUN` and do not by themselves fail a run.

## Verification coverage

`verify-evidence` evaluates, as applicable:

- **Report existence and readability.** A missing report is `UNAVAILABLE`; a
  malformed JSON report is `UNAVAILABLE` or `FAIL` with no guessed data.
- **Report digest and schema compatibility.** An expected report digest is
  compared exactly; any positive integer `schema_version` is accepted for
  backward compatibility with V23-V29.
- **Evidence existence, readability, size, and SHA-256.** The exact stored
  bytes are re-hashed. Files over 1 GiB are reported as `UNAVAILABLE` rather
  than read without bound.
- **Identifier consistency.** Reusing an identifier for a different path or
  digest, binding one path to two digests, or reusing content under multiple
  identifiers without explicit authorization is a conflict.
- **Path safety.** Relative POSIX paths only; absolute paths, drive letters,
  alternate data streams, backslashes, empty components, `.`/`..`, control
  characters, trailing separators, and Windows reserved device names are
  rejected. Symlinks and junctions below the evidence root are rejected after
  resolution. The evidence root itself may be a symlink; containment is checked
  against its resolved location.
- **Sidecar binding.** The sidecar must be bound to the exact report bytes,
  schema, profile, and path. Its evidence records must match the report's
  evidence references in both directions.
- **Audit continuity.** Sequence numbers, previous-record links, event IDs,
  record hashes, canonical timestamps, allowed fields, and checkpoint
  termination are verified.
- **Audit incidents.** A chain that records a failed verification, missing
  evidence, modification, replacement, rejection, path violation, manifest
  mismatch, or chain invalidation is reported as an incident and fails the
  overall result.
- **Release-manifest binding.** When a release manifest is supplied, its exact
  digest and its `release` subject (tag, commit, repository) must match the
  report. A mismatch is `MANIFEST_BINDING_MISMATCH`; a missing manifest is
  `UNAVAILABLE`.
- **Redacted diagnostics.** Verification output is sanitized. Sidecar metadata
  that would require redaction is rejected at seal time rather than persisted.

Verification opens files read-only. It may update filesystem access times, but
it does not change content, names, permissions, or existence.

## CLI

The read-only verification entry point is:

```powershell
python -m tools.release.cli verify-evidence --report release-artifacts/staging-readiness.json
python -m tools.verify_evidence --report release-artifacts/staging-readiness.json
```

The thin `tools/verify_evidence.py` wrapper accepts the same options as
`verify-evidence`. Add `--json` for machine-readable output, `--manifest` to
check release-manifest binding, `--integrity`/`--audit` to name non-default
sidecar paths, and `--checkpoint` to require a trusted termination record.

Verify one evidence file directly:

```powershell
python -m tools.release.cli verify-evidence `
  --evidence release-artifacts/readiness-evidence/target.json `
  --expected-sha256 sha256:<64-hex> `
  --expected-size 1234
```

Verify or checkpoint an audit chain:

```powershell
python -m tools.release.cli verify-audit `
  --audit release-artifacts/staging-readiness.audit.jsonl `
  --checkpoint release-artifacts/staging-readiness.checkpoint.json

python -m tools.release.cli checkpoint-evidence `
  --audit release-artifacts/staging-readiness.audit.jsonl `
  --output release-artifacts/staging-readiness.checkpoint.json `
  --source "independent-review"
```

Sealing is an explicit write operation. It creates new files only, refuses to
overwrite an existing sidecar or audit chain, and never modifies the report or
evidence:

```powershell
python -m tools.release.cli seal-evidence `
  --report release-artifacts/staging-readiness.json `
  --evidence-root release-artifacts/readiness-evidence `
  --integrity release-artifacts/staging-readiness.integrity.json `
  --audit release-artifacts/staging-readiness.audit.jsonl
```

Use `--authorized-reuse sha256:<64-hex>` only when the same content is
legitimately retained under more than one path. Same-path aliases are merged
automatically. Sealing requires at least one supported evidence reference and a
report with a positive integer `schema_version` and a non-empty `profile`;
otherwise it fails before writing any file. `--timestamp` exists for
deterministic tests and controlled runs; production operators should normally
let the tool use the current UTC time.

Exit codes are stable:

| Outcome | Exit code |
| --- | --- |
| `PASS` | 0 |
| `FAIL` | 1 |
| `UNAVAILABLE` | 2 |
| `NOT_RUN` | 3 |
| Invalid invocation | 4 |

A nonzero exit code means the evidence is not verified. Do not pipe the command
through a wrapper that discards its exit status.

## Operational workflow

1. Produce the V23-V29 report and its retained evidence as usual.
2. Seal once, after the report and evidence are final:
   `seal-evidence --report ... --evidence-root ...`.
3. Store the sidecar and audit chain with the report.
4. Verify before relying on the evidence:
   `verify-evidence --report ... --manifest ...`.
5. Record a checkpoint with `checkpoint-evidence` and move it to a location the
   evidence producer cannot rewrite.
6. Re-verify later with `--checkpoint` and compare the exit code.
7. If verification fails, preserve the files and investigate. V30 will not
   repair, quarantine, or delete them. A failed check is evidence of a problem,
   not an instruction to regenerate silently.

If evidence is legitimately regenerated, seal a new report under new sidecar
and audit paths. Do not overwrite the prior chain; the old chain is part of the
audit history.

## Compatibility with V23-V29

- All existing report schemas and `schema_version` values are unchanged.
- V29 credential redaction is preserved. Report writers still sanitize before
  hashing, and V30 audit details are sanitized before hashing. Sealing fails
  closed if sidecar metadata would require redaction.
- Verification without a sidecar remains supported: report evidence is checked
  directly and `integrity-manifest` is `NOT_RUN`.
- Verification without an audit chain is supported when no audit was requested
  or discovered; an explicitly requested missing audit is `UNAVAILABLE`.
- Readiness reports default to the `readiness-evidence/` directory; other
  reports default to the report's directory.
- Existing V26-V29 readiness binding names, check names, and blocker semantics
  are unchanged.
- No database migration, API change, workflow dispatch, deployment,
  publication, tag, release, or infrastructure mutation is part of V30.
- A V30 `PASS` is preparation evidence only. It does not authorize a
  deployment or replace V24 production qualification.

## Validation

The V30 tests use synthetic temporary evidence only. They never contact a
registry, release service, network endpoint, or real credential.

```powershell
python -m pytest backend/tests/unit/test_v30_evidence_integrity.py -q

python -m pytest `
  backend/tests/unit/test_v29_evidence_retention.py `
  backend/tests/unit/test_v29_adversarial.py `
  backend/tests/unit/test_v29_redaction.py `
  backend/tests/unit/test_release_readiness.py `
  backend/tests/unit/test_release_v28_hardening.py -q

python -m ruff check backend tools
python -m ruff format --check backend tools
python -m compileall -q backend/app backend/tests tools
```

The focused suite covers deterministic record hashing, canonical JSON,
timestamp normalization, every audit event type, sequence gaps, duplicate and
reordered records, broken links, duplicate event IDs, checkpoint truncation and
extension, report and evidence tampering, missing and unreadable evidence,
identifier conflicts, sidecar/report disagreement, path traversal, absolute
paths, drive letters, backslashes, reserved names, symlink escape (when the host
permits synthetic symlinks), manifest binding, V29 redaction regression,
redacted-diagnostic rejection, CLI exit codes, schema validation, and
false-positive resistance.

On a Windows host without symlink privilege, the two synthetic symlink tests
skip. The path policy is still exercised by traversal, absolute-path, drive,
backslash, and reserved-name cases; a skipped symlink test is not a pass and
should be run on a host that permits symlink creation when that guarantee
matters.

## Known limitations

- A local hash chain is tamper-evident, not immutable. An attacker with write
  access to the evidence and the entire chain can recompute every hash. Only an
  independently protected checkpoint or external anchor changes that boundary.
- SHA-256 proves byte equality under the assumption that SHA-256 is
  collision-resistant. It does not prove authenticity, provenance, or
  completeness.
- V30 does not sign records. A signature or attestation layer would be needed
  to bind evidence to a producer identity.
- The audit chain has no multi-writer lock. `append_audit_event` verifies the
  existing chain before appending, but a concurrent writer can still race the
  read-check-append sequence. Serialize writers operationally.
- Verification is best-effort against a hostile writer with concurrent access.
  Descriptor metadata is compared before and after hashing where supported, but
  platforms without descriptor-relative path walking cannot eliminate
  check-then-open races.
- Path containment is checked after resolving the evidence root. If the root
  itself is a symlink, the resolved root is the containment boundary.
- Files over 1 GiB are not hashed by default; they are reported as
  `UNAVAILABLE`. Reports and integrity sidecars over 16 MiB, and audit chains
  over 16 MiB or 100,000 records, are rejected as unsupported.
- V30 does not inspect evidence contents for secrets. V29 redaction covers
  logging and report persistence; it is not a content scanner for arbitrary
  retained files.
- A checkpoint is only as trustworthy as its storage. Copying it next to the
  audit chain preserves convenience but not protection against an attacker who
  can rewrite both.
- Windows junction and reparse-point behavior varies by host and privilege.
  Run the symlink/junction tests on the target platform when those guarantees
  are part of an acceptance decision.
