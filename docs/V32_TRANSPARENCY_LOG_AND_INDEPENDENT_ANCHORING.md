# V32 Transparency Log and Independent Checkpoint Anchoring

V32 adds a deterministic append-only transparency log, RFC 6962/9162 Merkle
inclusion and consistency proofs, Ed25519-signed tree heads, a separate local
tree-head trust state, and a provider-neutral anchoring interface. It builds on
the unchanged V30 integrity layer and the V31 signed-checkpoint layer.

V32 is offline by default and ships no external transparency service, cloud KMS,
GitHub API integration, registry client, staging connector, or production
endpoint. It creates no tag, release, image, workflow dispatch, deployment,
migration, rollback, or shared-infrastructure mutation. The only anchor provider
is a local deterministic test provider whose receipts are always `SIMULATED`.
V32 never claims that external anchoring occurred.

## Trust model

A V32 `PASS` means the verifier established the following within the stated
boundary:

- the JSONL transparency log is well formed, hash-linked, strictly ordered, and
  free of duplicate entry or checkpoint identifiers;
- the Merkle root recomputed from the stored entries matches the expected root;
- an inclusion proof binds one leaf digest, index, tree size, log ID, algorithm,
  and root;
- a consistency proof binds an older tree size and root to a newer tree size and
  root under the append-only rules;
- a signed tree head has the expected schema, canonical payload digest,
  Ed25519-only signature, trusted key, valid key purpose, and valid key
  lifecycle status at the tree-head timestamp;
- a receipt binds the provider, log, tree size, Merkle root, tree-head digest,
  receipt timestamp, and authenticated provider evidence; and
- any configured local transparency trust state admits the tree head as a
  non-regressing, non-conflicting continuation.

A V32 `PASS` does **not** prove that the underlying evidence is truthful,
complete, or correctly collected. It proves consistency and authentication of
the records that were actually supplied. It is preparation evidence only and
does not authorize a deployment or replace V24 production qualification.

Assurance is reported explicitly:

- `local-only` — the local log verified; no signed tree head was established.
- `reduced` — a signed tree head verified, but the local transparency trust
  state is absent or not independently protected.
- `simulated` — a local test provider receipt verified. This is a synthetic
  local anchor and never external or independent anchoring.
- `external` is reserved for a future genuinely configured and verified
  external provider. V32 never emits it.

## V31 integration

V32 consumes V31 signed checkpoints without changing their payload semantics.
The V30 unsigned checkpoint remains `schema_version: 1`; the V31 signed
checkpoint remains `schema_version: 2` with profile `evidence_checkpoint_signed`
and domain prefix
`b"industrial-vision-platform:evidence-checkpoint:v1\x00"`.

The transparency log stores only a reference to each signed checkpoint:

- checkpoint identifier;
- checkpoint sequence;
- SHA-256 digest of the full canonical signed-checkpoint document; and
- log entry metadata.

It never stores the checkpoint body, private keys, credentials, raw evidence, or
external service tokens.

V32 adds one key purpose to the existing V31 trust store:

```
transparency_tree_head_signing
```

V31 evidence-checkpoint verification still requires
`evidence_checkpoint_signing`. A key registered for tree-head signing is not
accepted for evidence checkpoints, and vice versa. Trust stores remain strict:
unknown fields, duplicate key IDs, duplicate fingerprints, unsupported
algorithms, malformed timestamps, and unsupported purposes are rejected.

A tree-head-supplied public key is an untrusted candidate. It is accepted only
when its fingerprint matches a V31 trust-store key with the transparency
purpose, or a separately supplied trusted fingerprint pin.

## Transparency log

The log is a UTF-8, LF-only JSONL file. The first line is a header; every
following line is one checkpoint reference. CRLF line endings, a missing final
newline, invalid UTF-8, duplicate JSON fields, excess nesting depth, and
oversized lines are rejected.

The header schema is
[`release/transparency-log-header.schema.json`](../release/transparency-log-header.schema.json):

```json
{
  "schema_version": 1,
  "profile": "evidence_transparency_log",
  "log_id": "local-evidence-log",
  "hash_algorithm": "sha256",
  "merkle_algorithm": "rfc6962-sha256-v1",
  "created_at": "2026-01-01T00:00:00Z"
}
```

Each entry is defined by
[`release/transparency-log-entry.schema.json`](../release/transparency-log-entry.schema.json)
and contains `entry_index`, `entry_id`, `entry_type`
(`CHECKPOINT_APPENDED`), `checkpoint_id`, `checkpoint_sequence`,
`checkpoint_digest`, `previous_entry_digest`, and `timestamp`.

Entries are chained: the first entry links to the all-zero SHA-256 genesis
digest, and each later entry links to the canonical digest of its predecessor.
Entry IDs are derived from canonical entry fields. Checkpoint IDs must be unique
within the log, entry indices must be contiguous from zero, checkpoint
sequences must strictly increase, and entry timestamps must not regress.

`append-checkpoint` validates the checkpoint document and the log tail in
`O(1)` bounded space. `verify-log` re-reads the entire log in `O(n)` time and
verifies the header, every chain link, ordering, uniqueness, and the recomputed
Merkle root. Appending is never treated as full verification.

The log is append-only by convention and hash-linked. It is not independently
immutable: an attacker with write access to the log can rewrite it. Only a
separately protected tree head or external anchor changes that boundary.

## Merkle tree convention

V32 uses RFC 6962/9162 with SHA-256:

| Element | Definition |
| --- | --- |
| Empty tree root | `SHA256(b"")` = `sha256:e3b0c442...b855` |
| Leaf hash | `SHA256(0x00 \|\| leaf_bytes)` |
| Internal node hash | `SHA256(0x01 \|\| left_hash \|\| right_hash)` |
| Largest power of two | `k`, the largest power of two strictly smaller than `n` |
| Split | left subtree `[0, k)`, right subtree `[k, n)` |

Domain separation prevents a leaf from being interpreted as an internal node and
vice versa. The convention handles:

- **empty** — the documented empty root, tree size 0;
- **single leaf** — the leaf hash is the root;
- **odd and non-power-of-two** — recursive split at the largest power of two
  strictly smaller than the subtree size, matching RFC 6962;
- **duplicate leaves** — permitted as distinct positions; proofs bind the leaf
  index, so identical bytes at different indices are not interchangeable; and
- **invalid input** — non-bytes leaves, oversized leaves, excessive leaf count,
  unknown algorithm identifiers, malformed digests, negative or out-of-range
  indices, and malformed sibling lists are rejected before hashing.

The tree memoizes each subtree root once. Building is `O(n)` time and `O(n)`
memory; each proof uses `O(log n)` memoized nodes. Generating every inclusion
proof is `O(n log n)` rather than rebuilding the tree per proof.

## Inclusion proofs

An inclusion proof is a separate strict JSON document defined by
[`release/merkle-inclusion-proof.schema.json`](../release/merkle-inclusion-proof.schema.json).
It records the schema version, profile `merkle_inclusion_proof`, algorithm
`rfc6962-sha256-v1`, log ID, tree size, leaf index, leaf digest, ordered sibling
path with left/right positions, and expected root.

Verification rejects:

- malformed or noncanonical JSON, duplicate fields, or excess nesting;
- an unknown or missing algorithm;
- a tree size outside `1..100000` or a leaf index outside the tree;
- a wrong log ID, tree size, root, or leaf digest;
- a sibling path with the wrong length or direction sequence;
- too many siblings or an oversized proof; and
- a modified leaf or modified sibling that does not reconstruct the root.

Supplying the original leaf bytes is optional; when supplied, the verifier also
recomputes the leaf hash and binds it to the proof.

## Consistency proofs

A consistency proof is defined by
[`release/merkle-consistency-proof.schema.json`](../release/merkle-consistency-proof.schema.json).
It records the schema version, profile `merkle_consistency_proof`, algorithm,
log ID, old and new tree sizes, old and new roots, and the RFC 6962 proof nodes.

V32 generates and verifies the standard append-only transitions:

- empty to empty (trivially consistent, empty proof);
- empty to nonempty (trivially consistent, empty proof);
- single-leaf growth;
- power-of-two transitions; and
- non-power-of-two transitions and multiple appends.

Verification rejects modified, reordered, missing, or replaced historical
leaves; wrong old or new roots; wrong sizes; truncated or extended proofs;
impossible transitions such as a new size smaller than the old size or a
nonempty old tree with an empty proof; unknown algorithms; malformed JSON; and
resource-limit violations.

A consistency proof establishes that the newer tree is an append-only extension
of the older tree. It does not establish that either tree is complete or that
the log operator is honest about unseen leaves.

## Signed tree heads

A tree head is an Ed25519-signed document defined by
[`release/transparency-tree-head.schema.json`](../release/transparency-tree-head.schema.json).
It contains:

- schema version and profile `transparency_tree_head_signed`;
- derived `tree_head_id` (`sth-...`);
- log ID, tree size, and Merkle root;
- timestamp;
- hash algorithm `sha256` and signature algorithm `ed25519`;
- key ID, public key fingerprint, and candidate public key;
- canonical payload digest; and
- signature encoding `hex` and the signature.

The signature covers the exact canonical payload with the domain prefix
`b"industrial-vision-platform:transparency-tree-head:v1\x00"`. Canonicalization
uses sorted keys, compact separators, UTF-8, and no trailing newline.

Verification requires a V31 trust store or a separately supplied fingerprint.
It enforces the transparency key purpose, Ed25519-only algorithms, exact field
sets, identifier derivation, payload digest, signature encoding, activation,
expiration, revocation, historical-revocation policy, and key-status evaluation
at the tree-head timestamp.

Tree heads are validated in strict sequence when a local trust state is
configured. A newer timestamp alone is never accepted as evidence of
consistency.

## Transparency trust state

The local transparency trust state is a separate strict JSON document defined by
[`release/transparency-trust-state.schema.json`](../release/transparency-trust-state.schema.json).
It is deliberately distinct from the V31 evidence trust state. Each entry
records the log ID, tree-head ID, tree size, Merkle root, tree-head digest,
timestamp, and key ID. The document carries a self-digest.

With a configured state, V32 detects and rejects:

- `TREE_HEAD_REPLAY` — the exact tree head was already recorded;
- `TREE_SIZE_ROLLBACK` — the tree size is smaller than the recorded size;
- `TREE_ROOT_CONFLICT` — the same tree size has a different root;
- `TREE_HEAD_DUPLICATE` — a tree-head ID was reused with different contents;
- `TREE_HEAD_CONFLICT` — conflicting heads exist for one log;
- `TREE_HEAD_TIMESTAMP_REGRESSION` — the timestamp is earlier than recorded;
- `CONSISTENCY_PROOF_MISSING` — growth was claimed without a consistency proof;
- `CONSISTENCY_PROOF_INVALID` — the supplied proof does not connect the
  recorded root to the new root; and
- split-view evidence — conflicting heads for the same log or a head that
  contradicts the recorded monotonic reference.

The state advances only after a `PASS` evaluation. Failed verification never
overwrites previously trusted tree-head state. An identical state update is
idempotent and does not rewrite the file. A newer timestamp by itself never
advances trust.

The state is tamper-evident through its self-digest, not independently
monotonic. An attacker with write access to the log, tree heads, and state can
rewrite all of them. V32 reports `assurance: "reduced"` in that case and never
calls the local state an external anchor.

## Anchor providers

V32 defines a provider-neutral `AnchorProvider` interface with capabilities for:

- submitting a tree head and receiving a receipt;
- retrieving and verifying a receipt;
- retrieving a previously anchored tree head; and
- retrieving a consistency proof.

Each provider publishes explicit capability metadata: provider ID, provider
type, anchor status, external and independent flags, assurance level, and which
retrieval operations are supported.

The only shipped provider is `LocalTestAnchorProvider`:

- it requires an explicit Ed25519 key, receipt directory, and key ID;
- it writes receipts and optional tree heads/proofs to local directories;
- it is idempotent for identical resubmissions;
- it refuses a different tree head for the same log and tree size; and
- it always reports `anchor_status: "SIMULATED"`, `external: false`, and
  `independent: false`.

Provider status semantics are fixed:

| Status | Meaning |
| --- | --- |
| `SIMULATED` | A local deterministic test provider produced synthetic evidence. Never external trust. |
| `NOT_CONFIGURED` | No provider was configured or required. Exit code `2` where a provider is required. |
| `UNAVAILABLE` | A configured provider could not be contacted or failed. Never converted to success. |
| `EXTERNAL_VERIFIED` | Reserved for a genuinely configured and verified external provider. V32 ships none and never emits this status. |

There is no silent provider fallback. Requesting an unavailable provider fails
closed; it does not downgrade to the local test provider.

## Receipts

A receipt is defined by
[`release/transparency-anchor-receipt.schema.json`](../release/transparency-anchor-receipt.schema.json).
It records the receipt ID, provider ID and type, anchor status, log ID, tree
size, Merkle root, tree-head ID and digest, receipt timestamp, signature
algorithm, key ID, public key fingerprint, candidate public key, payload digest,
signature encoding, and signature.

The signature covers the exact canonical payload with the domain prefix
`b"industrial-vision-platform:transparency-anchor-receipt:v1\x00"`.

Offline receipt verification checks schema, exact fields, identifier
derivation, provider and log binding, tree size, root, tree-head digest,
signature, expected provider ID, trusted provider fingerprint, and freshness.
Freshness uses an explicit `now`; without it, freshness is `NOT_RUN` and not
required. A receipt older than 7 days is `RECEIPT_STALE`; a timestamp more than
300 seconds in the future is `RECEIPT_TIMESTAMP_INVALID`.

A `local_test` receipt may only be `SIMULATED`. An `external` receipt may only
be `EXTERNAL_VERIFIED` at the schema level, but runtime verification refuses that
claim with `PROVIDER_NOT_CONFIGURED` unless an external provider is genuinely
configured and verified. The CLI never sets that flag.

Receipts are authenticated evidence from the provider. A simulated receipt is
not independent evidence and must not be described as external anchoring.

## CLI

The offline CLI is invoked as a module:

```powershell
python -m tools.transparency_log --help
```

Direct script invocation fails because `backend` is not on `sys.path`; use the
module form.

### Initialize and append

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
```

### Tree heads, inclusion, and consistency

```powershell
python -m tools.transparency_log create-tree-head `
  --log release-artifacts/transparency.jsonl `
  --private-key keys/transparency-2026-01.pem `
  --key-id transparency-2026-01 `
  --output release-artifacts/transparency-tree-head.json `
  --timestamp 2026-01-09T00:00:00Z

python -m tools.transparency_log create-inclusion-proof `
  --log release-artifacts/transparency.jsonl `
  --leaf-index 0 `
  --output release-artifacts/inclusion-0.json

python -m tools.transparency_log create-consistency-proof `
  --log release-artifacts/transparency.jsonl `
  --old-tree-size 3 `
  --output release-artifacts/consistency-3.json

python -m tools.transparency_log verify-inclusion `
  --proof release-artifacts/inclusion-0.json `
  --expected-root sha256:<root> `
  --log-id evidence-log `
  --tree-size 6

python -m tools.transparency_log verify-consistency `
  --proof release-artifacts/consistency-3.json `
  --expected-old-root sha256:<old-root> `
  --expected-new-root sha256:<new-root> `
  --log-id evidence-log `
  --old-tree-size 3 `
  --new-tree-size 6
```

### Verify a signed tree head and update state

```powershell
python -m tools.transparency_log verify-tree-head `
  --tree-head release-artifacts/transparency-tree-head.json `
  --trust-store trust-store.json `
  --trust-state transparency-state.json `
  --consistency-proof release-artifacts/consistency-3.json `
  --update-trust-state `
  --state-updated-at 2026-01-10T00:00:00Z
```

`--update-trust-state` is an explicit write and only runs after a `PASS`.
Verification is read-only by default. Using `--update-trust-state` without
`--trust-state` fails closed with `TRANSPARENCY_STATE_MISSING` and exit `4`.
`--require-trust-state` turns a missing state into an unavailable result rather
than reduced assurance.

### Anchor and verify a receipt

```powershell
python -m tools.transparency_log provider-status `
  --provider local-test `
  --provider-key keys/transparency-2026-01.pem `
  --receipt-dir release-artifacts/receipts

python -m tools.transparency_log anchor-tree-head `
  --tree-head release-artifacts/transparency-tree-head.json `
  --provider-key keys/transparency-2026-01.pem `
  --receipt-dir release-artifacts/receipts `
  --timestamp 2026-01-09T00:00:05Z

python -m tools.transparency_log verify-receipt `
  --receipt release-artifacts/receipts/rcpt-<id>.json `
  --tree-head release-artifacts/transparency-tree-head.json `
  --provider-id local-test-anchor `
  --now 2026-01-10T00:00:00Z
```

`anchor-tree-head --json` emits a wrapper with `outcome`, `anchor_status`,
`assurance`, `external_anchor`, `external_anchoring`, `provider_id`,
`provider_type`, `receipt_path`, and the nested receipt. A local test provider
reports `anchor_status: SIMULATED` and `external_anchoring: false`.

### Status report

```powershell
python -m tools.transparency_log status `
  --log release-artifacts/transparency.jsonl `
  --tree-head release-artifacts/transparency-tree-head.json `
  --receipt release-artifacts/receipts/rcpt-<id>.json `
  --trust-store trust-store.json `
  --now 2026-01-10T00:00:00Z
```

The status report is deterministic, redacted, and explicit about assurance,
provider status, external anchoring, component outcomes, and limitations.

## Exit codes and redaction

Exit codes remain V30/V31-compatible:

| Code | Meaning |
| --- | --- |
| `0` | `PASS` |
| `1` | `FAIL` |
| `2` | `UNAVAILABLE` |
| `3` | `NOT_RUN` |
| `4` | Invalid invocation |

A missing log, proof, receipt, tree head, or trust material is `UNAVAILABLE`
(exit `2`), never `PASS`. A failed or tampered proof is `FAIL` (exit `1`). A
check that could not run is `NOT_RUN` (exit `3`). Usage errors map to exit `4`.

All diagnostics pass through the V29 redaction policy before printing or
serialization. Private-key blocks, credentials, authorization headers, and
synthetic test sentinels are not included in log, tree-head, receipt, state, or
status output.

## Resource limits

V32 bounds resource use to avoid denial of service and quadratic behavior:

| Limit | Value |
| --- | --- |
| Log entries | 100,000 |
| Log bytes | 64 MiB |
| Log line bytes | 64 KiB |
| Tree-head document | 1 MiB |
| Proof document | 1 MiB |
| Receipt document | 1 MiB |
| Transparency state document | 16 MiB |
| Transparency state entries | 10,000 |
| Merkle leaves | 100,000 |
| Proof siblings | 64 |
| Leaf bytes | 64 KiB |
| JSON nesting depth | 16 |
| Receipt age | 7 days |
| Receipt clock skew | 300 seconds |

Log reading is linear. Tree construction is linear. Proof verification is
logarithmic in tree size. Full `verify-log` is linear and is never run
implicitly by an append.

## Operational workflow

1. Produce the V23-V30 report, evidence, integrity sidecar, and audit chain.
2. Produce and verify the V31 signed checkpoint with independent trust material.
3. Create the transparency log and append the signed-checkpoint reference.
4. Verify the complete log and create a signed tree head.
5. Create inclusion and consistency proofs for the tree sizes that matter.
6. Verify the tree head with the transparency trust store and local trust state.
7. After a `PASS`, explicitly update the trust state if monotonic local tracking
   is required.
8. Optionally submit the tree head to the local deterministic test provider and
   verify the simulated receipt offline.
9. Store the log, tree heads, proofs, receipts, trust store, and trust state
   where the evidence producer cannot rewrite them.
10. Before rotating, register the replacement tree-head public key explicitly,
    activate it, and revoke the old key. Verify historical tree heads under the
    configured revocation policy.
11. If verification fails, preserve all artifacts and logs for investigation.
    V32 never repairs, rewrites, quarantines, or deletes them.

Never commit or store a private key with evidence. V32 uses unencrypted PKCS#8
PEM keys and provides no passphrase or hardware-backed flow; protect keys with
operating-system access controls and offline storage.

## Compatibility with V23-V31

- V23-V31 report, checkpoint, trust-store, and trust-state schemas and
  `schema_version` values are unchanged.
- V30 unsigned checkpoints remain `schema_version: 1` and verify exactly as
  before.
- V31 signed checkpoints remain `schema_version: 2` with unchanged profile,
  fields, domain prefix, and payload semantics.
- V31 trust-store and trust-state formats are unchanged; the transparency key
  purpose is an additive enum value.
- V31 evidence verification still requires the evidence-checkpoint purpose and
  does not accept a tree-head key.
- V30 and V31 verification behavior, check names, and exit codes are preserved.
- V29 redaction remains the single policy for logs and diagnostics.
- V32 adds no database migration, API change, workflow dispatch, deployment,
  publication, tag, release, or infrastructure mutation.
- `cryptography` remains the Ed25519 provider and is imported lazily by the
  release tools; missing cryptography fails closed.

## Validation

All V32 tests use synthetic temporary keys, checkpoints, logs, proofs, tree
heads, receipts, trust stores, and trust states. They never contact a registry,
release service, network endpoint, cloud KMS, external transparency service, or
real credential.

```powershell
python -m pytest backend/tests/unit/test_v32_transparency_log.py -q
python -m pytest backend/tests/unit/test_v32_inclusion_consistency.py -q
python -m pytest backend/tests/unit/test_v32_transparency_hardening.py -q

python -m pytest `
  backend/tests/unit/test_v30_evidence_integrity.py `
  backend/tests/unit/test_v31_signed_evidence.py -q

python -m ruff check backend tools
python -m ruff format --check backend tools
python -m compileall -q backend/app backend/tests tools
```

The focused suite covers Merkle domain separation, empty and single-leaf trees,
odd and non-power-of-two sizes, duplicate leaves, exhaustive inclusion proofs,
all consistency transitions through size 8, 256-leaf proofs, malformed and
tampered proofs, reordered and replaced history, signed tree heads, trust-store
purpose separation, key activation/expiration/revocation/historical policy,
strict JSON and duplicate fields, resource limits, trust-state duplicates and
conflicts, rollback/replay/timestamp/root conflicts, failed-update state
preservation, split-view detection, receipt signatures and freshness, provider
idempotency and conflicts, local provider status, unconfigured and unavailable
providers, external-claim refusal, V29 redaction, private-key non-disclosure,
CLI exit codes, Windows and POSIX paths with spaces and Unicode, and CRLF
rejection.

On a Windows host the POSIX private-key permission test skips; a skipped test is
not a pass and should be run on a host that supports POSIX modes when that
guarantee matters.

## Known limitations

- A Merkle tree and proofs prove consistency of the supplied leaves and roots.
  They do not prove that the log operator included every checkpoint, withheld no
  leaves, or told every observer the same view.
- The local transparency log and local transparency trust state are
  tamper-evident, not independently immutable or monotonic. An attacker with
  write access to all local artifacts can rewrite the log, tree heads, receipts,
  and state consistently. Only an independently protected external reference
  changes that boundary.
- V32 ships no external anchor provider and contacts no external service. The
  local test provider is synthetic; its receipts are `SIMULATED` and are not
  independent trust.
- A signed tree head proves possession of a trusted private key over an exact
  payload. It does not prove that the underlying evidence is truthful or
  complete.
- Trust is only as strong as the independently configured trust store or
  fingerprint pin. A tree-head-supplied public key is never trusted by itself.
- Ed25519 is the only signature algorithm and SHA-256/RFC 6962 is the only
  Merkle algorithm. Algorithm agility is intentionally absent.
- The log has no multi-writer lock. `append_checkpoint` validates the tail
  before appending, but a concurrent writer can race the read-check-append
  sequence. Serialize writers operationally.
- Verification is best-effort against a hostile writer with concurrent access.
  Serialize writers and store trust material outside the producer's writable
  area.
- V32 does not inspect evidence contents for secrets. V29 redaction covers logs
  and diagnostics, not arbitrary retained files.
- A V32 `PASS` is preparation evidence only. It does not authorize a deployment
  or replace V24 production qualification.
