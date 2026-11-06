# V31 Signed Evidence Checkpoints and Trust Anchoring

V31 adds producer authentication on top of the V30 integrity layer. A V30
sidecar proves that retained bytes still match recorded SHA-256 digests and that
the local audit chain is internally consistent. It does not prove who produced a
checkpoint. V31 signs an exact canonical checkpoint with Ed25519 and verifies it
against a separately configured trust store or a separately supplied public-key
fingerprint.

V31 is additive and offline by default. It does not contact an external
trust-anchor service, cloud KMS, GitHub API, GHCR, staging system, or production
endpoint. It creates no tag, release, image, workflow dispatch, deployment,
migration, rollback, or shared-infrastructure mutation. All V23-V30 report
schemas, check names, and exit-code semantics remain intact.

## Trust model

A V31 `PASS` means the verifier established all of the following within the
stated boundary:

- the retained report and evidence still match the V30 integrity sidecar and
  audit chain;
- the signed checkpoint's canonical payload is internally consistent and bound
  to the exact report bytes, integrity-manifest bytes, and audit-chain terminal
  state;
- the checkpoint signature verifies over the exact domain-separated payload;
- the signing key resolves to an explicitly configured trust-store entry or a
  separately supplied trusted fingerprint;
- the key was active at the checkpoint creation time, its purpose allows
  evidence checkpoint signing, its allowed algorithms include Ed25519, and it
  is not revoked or expired under the configured historical policy;
- the checkpoint is not a replay or rollback according to the configured local
  trust state or a separately supplied external reference.

It does **not** prove that the evidence is truthful, complete, correctly
collected, or produced by an honest operator. A signature proves possession of a
private key over an exact payload. Trust comes from the independent key
configuration, not from the checkpoint's self-asserted public key.

A public key copied inside a checkpoint is an untrusted candidate. V31 never
trusts it merely because the checkpoint claims it is trusted. If no trust store
or trusted fingerprint is supplied, signed-checkpoint verification is
`UNAVAILABLE`, never `PASS`.

A local trust-state file detects replay and rollback within its own recorded
history, but it is not independently monotonic. An attacker who can rewrite the
evidence, the audit chain, and the trust-state file can also rewrite the
sequence it records. V31 reports `assurance: "reduced"` in that case and never
describes local state as external anchoring.

## Signed checkpoint

Signed checkpoints are written as a separate JSON file and are never injected
into a V23-V30 report. The schema is
[`release/signed-checkpoint.schema.json`](../release/signed-checkpoint.schema.json),
with `schema_version: 2` and `profile: "evidence_checkpoint_signed"`. V30
unsigned checkpoints remain `schema_version: 1` and keep their original
behavior.

The signed payload fields are:

| Field | Meaning |
| --- | --- |
| `schema_version` | `2` |
| `profile` | `"evidence_checkpoint_signed"` |
| `checkpoint_id` | Deterministic `chk-<32-hex>` derived from the other payload fields |
| `evidence_report_id` | `report:sha256:<64-hex>` of the exact report bytes |
| `audit_chain_terminal_hash` | V30 terminal record hash |
| `audit_chain_terminal_event_id` | V30 terminal event identifier |
| `audit_chain_terminal_timestamp` | Canonical terminal audit timestamp |
| `audit_record_count` | Positive audit record count |
| `evidence_manifest_digest` | SHA-256 of the exact integrity-sidecar bytes |
| `checkpoint_sequence` | Positive monotonic sequence |
| `created_at` | Canonical UTC checkpoint creation time |
| `key_id` | Operator-assigned trust-store key identifier |
| `public_key_fingerprint` | `sha256:<64-hex>` over the raw 32-byte public key |
| `public_key` | Unpadded base64url Ed25519 public key |
| `signature_algorithm` | `"ed25519"` only |

The complete file adds `payload_digest`, `signature_encoding` (`"hex"`), and
`signature` (128 lowercase hex characters). Unknown, missing, duplicate, or
ambiguous fields are rejected. Checkpoint identifiers, sequence values, and
timestamps are validated before any signature operation.

### Canonicalization and domain separation

The signed bytes are exactly:

```text
b"industrial-vision-platform:evidence-checkpoint:v1\x00" + canonical_json
```

`canonical_json` is UTF-8 JSON with sorted keys, compact separators, ASCII
escaping, and no trailing newline. The domain prefix is mandatory. A signature
over the canonical payload without the prefix does not verify. `payload_digest`
is the SHA-256 of the domain-separated bytes. The checkpoint identifier is the
SHA-256 of every other payload field in canonical form.

### Algorithms

Ed25519 is the only accepted signature algorithm in V31. It is deterministic,
compact, and available through the maintained `cryptography` package
(`cryptography>=42.0,<50`). Unknown algorithms are rejected before any
signature operation. Verification never regenerates, repairs, or re-signs a
checkpoint.

## Trust store

The trust store is a strict, separately configured JSON document. Its schema is
[`release/trust-store.schema.json`](../release/trust-store.schema.json), with
`schema_version: 1`, `profile: "evidence_trust_store"`, a `policy_version`, a
`historical_revocation_policy` (`allow_before_revocation` or `deny`), and an
explicit `keys` list.

Each trusted key records:

- `key_id`;
- `public_key` in unpadded base64url;
- `fingerprint` as `sha256:<64 lowercase hex>` over the raw 32-byte key;
- `purpose` (`evidence_checkpoint_signing`);
- `allowed_algorithms` (currently only `ed25519`);
- `activated_at`, optional `expires_at`, optional `revoked_at`, and an optional
  sanitized `revocation_reason`.

The store rejects duplicate key identifiers, duplicate fingerprints, unknown
fields, malformed encodings, mismatched fingerprints, unsupported algorithms or
purposes, invalid timestamps, expiration before activation, revocation before
activation, and a revocation reason without a revocation time.

Key status is evaluated at the checkpoint creation time, not at verification
wall-clock time:

| Status | Result |
| --- | --- |
| Active | `PASS` |
| Not yet active | `FAIL` with `TRUST_KEY_NOT_YET_VALID` |
| Expired before creation | `FAIL` with `TRUST_KEY_EXPIRED` |
| Revoked before creation | `FAIL` with `TRUST_KEY_REVOKED` |
| Revoked after creation, policy `allow_before_revocation` | `PASS` with `historical: true` and a limitation |
| Revoked after creation, policy `deny` | `FAIL` with `TRUST_KEY_REVOKED` |
| Unknown key or fingerprint | `FAIL` with `TRUST_KEY_UNKNOWN` / `TRUST_KEY_UNTRUSTED` |
| Missing store or fingerprint | `UNAVAILABLE` with `TRUST_STORE_MISSING` |

A replacement key is never auto-trusted. Generating or exporting a new key does
not modify a trust store. Rotation is an explicit operation that registers the
replacement public key and optionally revokes the old key.

## Key lifecycle

The offline key manager is `tools/manage_evidence_trust.py`. It never prints,
logs, or serializes private-key material.

```powershell
# Generate a local unencrypted Ed25519 PKCS#8 key and public descriptor.
python tools/manage_evidence_trust.py generate-key `
  --key-id evidence-2026-01 `
  --private-key keys/evidence-2026-01.pem `
  --public-key keys/evidence-2026-01.pub.json

# Create an empty trust store.
python tools/manage_evidence_trust.py init-store --store trust-store.json

# Explicitly trust the public key.
python tools/manage_evidence_trust.py register-key `
  --store trust-store.json `
  --public-key keys/evidence-2026-01.pub.json `
  --activated-at 2026-11-01T00:00:00Z

# Lifecycle operations.
python tools/manage_evidence_trust.py activate-key `
  --store trust-store.json --key-id evidence-2026-01 `
  --activated-at 2026-11-01T00:00:00Z
python tools/manage_evidence_trust.py expire-key `
  --store trust-store.json --key-id evidence-2026-01 `
  --expires-at 2027-01-01T00:00:00Z
python tools/manage_evidence_trust.py revoke-key `
  --store trust-store.json --key-id evidence-2026-01 `
  --revoked-at 2027-01-01T00:00:00Z --reason "scheduled rotation"
python tools/manage_evidence_trust.py rotate-key `
  --store trust-store.json `
  --public-key keys/evidence-2027-01.pub.json `
  --old-key-id evidence-2026-01 `
  --activated-at 2027-01-01T00:00:00Z `
  --revoke-at 2027-01-01T00:00:00Z

# Inspect the public trust material.
python tools/manage_evidence_trust.py show-store --store trust-store.json
```

Private keys are written with an exclusive create and `0600` permissions on
POSIX. On Windows the tool uses best-effort platform permissions and reports
`platform_default`; POSIX mode bits are not available there. Never commit a
private key, paste one into a report, or store one in an evidence directory.
Use synthetic keys only in tests.

## Creating and verifying signed checkpoints

Create a signed checkpoint only after the V30 audit chain and sidecar are final:

```powershell
python -m tools.release.cli sign-checkpoint `
  --audit release-artifacts/staging-readiness.audit.jsonl `
  --report release-artifacts/staging-readiness.json `
  --integrity release-artifacts/staging-readiness.integrity.json `
  --private-key keys/evidence-2026-01.pem `
  --key-id evidence-2026-01 `
  --sequence 1 `
  --output release-artifacts/staging-readiness.signed-checkpoint.json
```

Verification extends `verify-evidence` without breaking V30 behavior:

```powershell
python -m tools.release.cli verify-evidence `
  --report release-artifacts/staging-readiness.json `
  --integrity release-artifacts/staging-readiness.integrity.json `
  --audit release-artifacts/staging-readiness.audit.jsonl `
  --checkpoint release-artifacts/staging-readiness.signed-checkpoint.json `
  --trust-store trust-store.json `
  --trust-state trust-state.json
```

New options:

| Option | Purpose |
| --- | --- |
| `--trust-store PATH` | Independently configured trust store |
| `--trusted-key-fingerprint SHA256` | Separately supplied trusted fingerprint; establishes key identity only |
| `--trust-state PATH` | Local monotonic reference for replay/rollback detection |
| `--update-trust-state` | Explicitly append a verified checkpoint to `--trust-state` after `PASS` |
| `--require-signed-checkpoint` | Fail unless a signed checkpoint verifies |
| `--require-independent-freshness` | Require an independently supplied external reference |

`--update-trust-state` requires `--trust-state` and is an invalid invocation
(exit `4`) otherwise. Verification itself is read-only by default. The state is
updated only after a `PASS` with a verified signed checkpoint; a replay or
failure never appends a new entry.

If a signed checkpoint is supplied without trust material, the result is
`UNAVAILABLE` (exit `2`), never `PASS`. If an unsigned checkpoint is supplied
with `--require-signed-checkpoint`, the result is `FAIL` (exit `1`). Audit-only
verification (`verify-audit`) rejects a signed checkpoint with
`SIGNED_CHECKPOINT_REQUIRES_REPORT` because it cannot establish report or
manifest binding.

## Verification coverage

V31 verification covers, in order:

1. V30 report, evidence, integrity-sidecar, manifest-binding, audit-continuity,
   incident, and redaction checks.
2. Signed-checkpoint schema, exact fields, checkpoint ID, canonical payload
   digest, algorithm allowlist, and signature encoding.
3. Independent key resolution through the trust store or trusted fingerprint.
4. Key purpose, allowed algorithm, activation, expiration, revocation, and
   historical revocation policy.
5. Exact-payload Ed25519 signature verification.
6. Report-byte, integrity-manifest-byte, and audit-terminal binding.
7. Checkpoint timestamp consistency with the terminal audit record.
8. Sequence, replay, duplicate, decreasing, terminal-hash, manifest-digest,
   conflicting-checkpoint, chain-truncation, and timestamp-regression checks
   against the trust state.
9. Optional external-anchor reference comparison.
10. Human-readable or JSON output with structured reason codes.

Structured reason codes include `CHECKPOINT_SCHEMA_INVALID`,
`CHECKPOINT_SIGNATURE_MISMATCH`, `CHECKPOINT_PAYLOAD_DIGEST_MISMATCH`,
`CHECKPOINT_ID_MISMATCH`, `CHECKPOINT_SEQUENCE_INVALID`,
`CHECKPOINT_TIMESTAMP_INVALID`, `CHECKPOINT_REPLAY`,
`CHECKPOINT_SEQUENCE_DUPLICATE`, `CHECKPOINT_SEQUENCE_DECREASING`,
`CHECKPOINT_ID_REUSED`, `CHECKPOINT_CONFLICT`, `AUDIT_HASH_ROLLBACK`,
`MANIFEST_DIGEST_ROLLBACK`, `CHAIN_TRUNCATION`, `TRUST_STORE_MISSING`,
`TRUST_STORE_INVALID`, `TRUST_KEY_UNKNOWN`, `TRUST_KEY_UNTRUSTED`,
`TRUST_KEY_REVOKED`, `TRUST_KEY_EXPIRED`, `TRUST_KEY_NOT_YET_VALID`,
`TRUST_KEY_ALGORITHM_DISALLOWED`, `TRUST_KEY_PURPOSE_INVALID`,
`TRUST_FINGERPRINT_MISMATCH`, `TRUST_STATE_MISSING`, `TRUST_STATE_INVALID`,
`SIGNED_CHECKPOINT_REQUIRES_REPORT`, `INDEPENDENT_FRESHNESS_UNAVAILABLE`, and
`EXTERNAL_ANCHOR_UNCONFIGURED`.

Exit codes remain V30-compatible: `0` `PASS`, `1` `FAIL`, `2` `UNAVAILABLE`,
`3` `NOT_RUN`, and `4` invalid invocation. All diagnostics pass through the V29
redaction policy before they are printed or serialized. Private-key blocks,
credentials, authorization headers, and synthetic test sentinels are not
included in checkpoint, trust-store, trust-state, or verification output.

## Replay, rollback, and freshness

The trust state is a separate strict JSON document with a self-digest. Its
schema is [`release/trust-state.schema.json`](../release/trust-state.schema.json).
Each entry records the report ID, checkpoint ID, sequence, audit record count,
terminal audit hash, manifest digest, creation time, and key ID.

When a trust state is configured, V31 rejects:

- a checkpoint already recorded at the same sequence (`CHECKPOINT_REPLAY`);
- a checkpoint identifier reused at a different sequence (`CHECKPOINT_ID_REUSED`);
- a sequence below the latest recorded sequence (`CHECKPOINT_SEQUENCE_DECREASING`);
- a duplicate sequence with a different checkpoint (`CHECKPOINT_SEQUENCE_DUPLICATE`);
- fewer audit records than recorded (`AUDIT_HASH_ROLLBACK`);
- a changed terminal hash without a new record (`AUDIT_HASH_ROLLBACK`);
- a manifest digest that returns to an earlier recorded value
  (`MANIFEST_DIGEST_ROLLBACK`);
- conflicting checkpoints at the same record count (`CHECKPOINT_CONFLICT`);
- a creation timestamp earlier than the recorded checkpoint
  (`CHECKPOINT_TIMESTAMP_INCONSISTENT`).

A new checkpoint may re-attest the same terminal audit state at a higher
sequence, for example after a key rotation. It must still advance the sequence
and satisfy the timestamp and manifest rules.

Without a trust state, replay protection is limited to the current invocation.
V31 returns `PASS` with `assurance: "reduced"` and the explicit reason code
`TRUST_STATE_MISSING`; it never claims independent monotonic protection.

## External trust anchor

V31 defines a small `ExternalTrustAnchor` protocol with `describe()` and
`fetch_reference()` methods. It ships no live implementation and contacts no
network service. A caller may inject a local test double or a future
independently protected implementation. When no anchor is supplied, the result
records `status: "UNCONFIGURED"` and `EXTERNAL_ANCHOR_UNCONFIGURED`; V31 does not
claim that external anchoring was created or verified.

When a supplied anchor returns a matching reference, the result may report
`assurance: "independent"`. That assurance describes only the caller-supplied
reference comparison. It does not retroactively create an external anchor,
publish a checkpoint, or contact a service.

## Operational workflow

1. Produce the V23-V30 report, evidence, integrity sidecar, and audit chain.
2. Generate an offline key and export its public descriptor.
3. Register the public key in a trust store that is stored separately from the
   evidence producer's writable area.
4. Sign a checkpoint with an explicit positive sequence.
5. Verify with `--trust-store` and, when available, `--trust-state`.
6. After a `PASS`, optionally update the trust state explicitly with
   `--update-trust-state`.
7. Store the trust store and trust state where the evidence producer cannot
   rewrite them. Treat the private key as a secret.
8. Before rotating, register the replacement public key explicitly, activate it,
   and revoke the old key. Verify historical checkpoints under the configured
   `allow_before_revocation` or `deny` policy.
9. If verification fails, preserve the evidence, checkpoint, trust store, trust
   state, and logs for investigation. V31 never repairs, rewrites, quarantines,
   or deletes them.

## Compatibility with V23-V30

- V23-V30 report schemas and `schema_version` values are unchanged.
- V30 unsigned checkpoints remain `schema_version: 1` and verify exactly as
  before when no signed-checkpoint options are supplied.
- V30 `verify-evidence` and `verify-audit` behavior is preserved; signed
  checkpoint handling is additive.
- V29 redaction remains the single policy for logs and diagnostics.
- V31 adds no database migration, API change, workflow dispatch, deployment,
  publication, tag, release, or infrastructure mutation.
- `cryptography` is declared in `backend/requirements.txt`; the release tools
  import it lazily and fail closed if it is unavailable.

## Validation

All V31 tests use synthetic temporary keys, evidence, reports, manifests, audit
chains, trust stores, and trust states. They never contact a registry, release
service, network endpoint, cloud KMS, or real credential.

```powershell
python -m pytest backend/tests/unit/test_v31_signed_evidence.py -q
python -m pytest backend/tests/unit/test_v30_evidence_integrity.py -q
python -m ruff check backend tools
python -m ruff format --check backend tools
python -m compileall -q backend/app backend/tests tools
```

The focused suite covers canonicalization and domain separation, exact-payload
signatures, unknown algorithms, malformed and mismatched signatures, duplicate
JSON fields, invalid timestamps and sequences, checkpoint/report/manifest/audit
binding, trust-store validation, key purpose and algorithm allowlists,
activation, expiration, revocation, rotation, historical verification,
replacement-key non-auto-trust, replay, duplicate and decreasing sequences,
reused checkpoint IDs, terminal-hash and manifest rollback, conflicting
checkpoints, chain truncation, timestamp inconsistencies, reduced assurance,
the external-anchor local test double, V30 regression, CLI exit codes, V29
redaction, and private-key non-disclosure. On a Windows host the POSIX
permission test skips; a skipped test is not a pass and should be run on a host
that supports POSIX modes when that guarantee matters.

## Known limitations

- A signature proves possession of a private key over an exact payload, not that
  the evidence is truthful, complete, or correctly collected.
- Trust is only as strong as the independently configured trust store or
  fingerprint. A checkpoint-supplied public key is never trusted by itself.
- A local trust state is tamper-evident, not independently monotonic. An
  attacker with write access to the evidence, audit chain, and trust state can
  rewrite all of them. Only an independently protected external reference
  changes that boundary.
- V31 ships no external anchor implementation and contacts no external service.
  External anchoring remains unconfigured and unused.
- Private keys are unencrypted PKCS#8 PEM files. V31 has no passphrase or
  hardware-backed key flow. Protect the key file with operating-system access
  controls and offline storage.
- Ed25519 is the only algorithm. Algorithm agility is intentionally absent.
- V31 does not inspect evidence contents for secrets. V29 redaction covers logs
  and diagnostics, not arbitrary retained files.
- Verification is best-effort against a hostile writer with concurrent access.
  Serialize writers operationally.
- A V31 `PASS` is preparation evidence only. It does not authorize a deployment
  or replace V24 production qualification.
