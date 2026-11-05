# V29 Evidence Retention Security

V29 hardens credential handling in two places that previously had separate,
partial policies: backend logging and release evidence retention. The goal is
that a credential-shaped value is treated the same way whether it appears in a
log record, an exception traceback, a release report, or a readiness evidence
file.

V29 is a security hardening volume. It does not deploy, publish, tag, release,
dispatch a workflow, run a migration, or mutate shared infrastructure. It keeps
`schema_version: 1`, the existing evidence contracts, the V22-V28 release
gates, and the existing API surface unchanged.

## Central policy

`backend/app/core/redaction.py` is the single source of truth. Backend logging
imports it directly, and the release tools import it from the repository root.
There is no second regex set in the logging filter or in individual report
writers.

| Function | Purpose |
| --- | --- |
| `redact_text` | Sanitize free-form text, URLs, headers, YAML-like text, and private-key blocks. |
| `redact_structure` | Recursively sanitize mappings, lists, tuples, bytes, and strings. |
| `dump_sanitized_json` | Serialize a sanitized payload; the returned bytes are the bytes to persist and hash. |
| `sanitize_json_document` | Parse, sanitize, and re-serialize a JSON document; invalid JSON raises `RedactionError`. |
| `is_sensitive_name` | Classify field and environment names while preserving metadata names. |
| `is_sensitive_header` | Classify HTTP header names. |
| `scan_text` / `contains_sensitive_material` | Detect supported credential categories without echoing values. |

The consistent marker is `[REDACTED]`. Re-redacting already-redacted content is
idempotent.

## Detection coverage

V29 detects the following supported forms:

- **Environment and assignment names.** `PASSWORD`, `PASSWD`, `PASSPHRASE`,
  `SECRET`, `TOKEN`, `CREDENTIAL`, `COOKIE`, `AUTHORIZATION`, `API_KEY`,
  `ACCESS_KEY`, `PRIVATE_KEY`, `SIGNING_KEY`, `ENCRYPTION_KEY`, and `PAT`,
  including prefixed and concatenated names such as `POSTGRES_PASSWORD`,
  `IVP_POSTGRES_PASSWORD`, `PROD_DATABASE_PASSWORD`, `SERVICE_API_TOKEN`,
  `GITHUB_APP_PRIVATE_KEY`, `AWS_SECRET_ACCESS_KEY`, and `CLIENT_SECRET`.
  Forms include `KEY=value`, `KEY: value`, `export KEY=value`, `.env` text,
  YAML mappings, and list entries.
- **Structured content.** Nested JSON objects, arrays, quoted JSON keys,
  escaped JSON embedded in a log line, Python-like dictionaries, and nested
  log `extra` values.
- **YAML-like text.** Mapping values, indented blocks, and `|`/`>` block
  scalars. This is a text heuristic, not a full YAML parser.
- **URLs.** Userinfo with a colon, percent-encoded userinfo, and passwords that
  contain a raw `@`. Query credentials such as `access_token`, `auth`,
  `api_key`, `secret`, `access_key`, `secret_key`, `credential`, `password`,
  `session`, `signature`, and cloud signature parameters are redacted.
  Ordinary bare usernames such as `https://deploy.user@example.test` are
  preserved.
- **HTTP headers.** `Authorization`, `Proxy-Authorization`, `Cookie`,
  `Set-Cookie`, `X-API-Key`, `Private-Token`, and custom `X-...` token,
  secret, or auth headers, including underscore variants such as `X_API_KEY`.
  For `Authorization`, the `Basic`, `Bearer`, `Digest`, `Negotiate`, and
  `NTLM` scheme names are preserved while the credential is replaced.
- **Logs and exceptions.** Log messages, positional and mapping arguments,
  structured extras, stack information, formatted tracebacks, and a pre-set
  `exc_text` value. The filter redacts arguments before formatting the message,
  then stores the sanitized final message, so placeholders such as `token=%s`
  are not consumed and formatting cannot fail because of redaction.
- **Private keys.** Complete PEM/OpenSSH private-key blocks and unterminated
  blocks that begin with a private-key header are removed entirely.
- **Well-known token formats.** GitHub tokens and fine-grained PATs, AWS
  access-key IDs, JWTs, Stripe keys, Slack tokens, and Google API keys are
  detected even without a surrounding field name.

## False-positive policy

V29 deliberately preserves metadata and non-sensitive identifiers:

- `repository_id`, `key_id`, `public_key_fingerprint`, `token_count`,
  `password_policy`, `api_key_required`, `deployment_id`, `release_id`,
  `smoke_password_env`, `authorization_header`, `private_key_id`, and
  `secret_name` are not treated as credentials.
- Metadata suffixes such as `_ID`, `_NAME`, `_ENV`, `_POLICY`, `_REQUIRED`,
  `_FINGERPRINT`, `_URL`, `_HOST`, `_PORT`, `_PATH`, and `_COUNT` are
  preserved unless the name also carries an explicit low-entropy credential
  hash such as `PASSWORD_HASH`.
- A bare URL username is not a credential. `https://user.name@example.test`
  and `https://deploy.user@example.test` remain unchanged.
- Release command text such as `gh attestation verify --source-digest <sha>`
  is not mistaken for a Digest authorization credential.
- Existing `[REDACTED]` markers and `****` placeholders do not re-trigger
  detection.

A field that is genuinely named like a credential is still redacted even if a
particular deployment uses it for harmless text. The policy favors protection
over preserving ambiguous names.

## Evidence retention

### Sanitize before persistence

Every release report writer now serializes through `dump_sanitized_json`
before writing. This includes readiness, verification, deployment, preflight,
publication, smoke, qualification, staging, rehearsal, migration, GPU,
inference, evidence, and CLI JSON output. The hash is then computed from the
exact stored sanitized bytes. A hash is never taken over an unsanitized
payload and attached to a sanitized file.

The readiness live-inspection file is sanitized the same way before it is
written. Its binding hash covers the sanitized bytes on disk.

### Readiness inputs

`_retain_evidence` in `tools/release/readiness.py` applies the policy before a
file becomes evidence:

- A clean structured input is parsed, found unchanged by
  `redact_structure`, and retained byte-for-byte under its content-addressed
  name. Its recorded SHA-256 is the hash of the original and stored bytes,
  which are identical.
- A structured input containing a detected secret is **not bound**. It is not
  added to the report evidence list, and its original digest is not reused.
  A separately named diagnostic copy may be written as
  `<kind>-<sanitized_digest[:12]>-redacted<ext>`. That name and its contents
  derive from the sanitized bytes, and the copy is never added to the report
  evidence list.
- A text or Markdown input containing a detected secret follows the same
  rule: no binding, a separately named sanitized diagnostic copy, and no
  original hash reuse.
- A JSON-looking file that cannot be parsed is rejected. No raw copy is
  written. This is the fail-closed path for structured evidence.
- An oversized or non-UTF-8 input is not retained.

A secret-bearing readiness input therefore still produces the existing
`evidence-retention: <kind>` blocker and a null binding. V28's readiness
semantics are preserved: a readiness `PASS` requires all required bindings,
and a secret-bearing original can never satisfy one.

### Hash integrity

The integrity rule is simple: **the hash identifies exactly the bytes that were
stored.**

- Report writers hash the sanitized file after writing it.
- Live-inspection bindings hash the sanitized live-inspection file.
- Clean evidence retains its original bytes and therefore its original hash.
- A redacted diagnostic is named from the first 12 hex characters of the
  sanitized SHA-256 and is distinct from the original file. Tests verify that
  its full digest differs from the original digest.
- `check-readiness` continues to re-hash retained evidence and rejects a
  changed file or a binding that does not match its evidence.

## Operational guidance

- Keep real credentials in the environment or a secret manager. Evidence files
  should reference an environment-variable name, not contain the value.
- If a retention blocker appears, remove the secret from the source document
  and re-run. Do not copy the raw file into the evidence directory.
- A redacted diagnostic is for operator review only. It is not evidence and
  must not be cited as proof that the original input was safe.
- Rotate any credential that may have been written to a log or evidence file
  before V29. Redaction prevents future persistence; it cannot undo a prior
  disclosure.

## Validation

The V29 tests are deterministic and offline. They use synthetic sentinels only
and never contact GitHub, GHCR, Docker, staging, production, or a GPU.

```bash
python -m pytest \
  backend/tests/unit/test_v29_redaction.py \
  backend/tests/unit/test_v29_evidence_retention.py \
  backend/tests/unit/test_v29_adversarial.py -q

python -m pytest \
  backend/tests/unit/test_v20_logging_redaction.py \
  backend/tests/unit/test_release_readiness.py \
  backend/tests/unit/test_release_v28_hardening.py \
  backend/tests/unit/test_release_v28_inspection.py \
  backend/tests/unit/test_release_v28_live.py \
  backend/tests/unit/test_release_evidence.py -q

python -m ruff check backend tools
python -m ruff format --check backend tools
python -m compileall -q backend/app backend/tests tools
```

The adversarial suite covers prefixed environment names, quoted and escaped
JSON keys, nested structures, YAML-like block scalars, URL userinfo and query
credentials, authorization/cookie/custom headers, private-key blocks, log
messages and extras, tracebacks, pre-set exception text, evidence retention,
hash integrity, and false-positive resistance.

## Compatibility with V22-V28

- V22/V23 verification, publication, and attestation contracts are unchanged.
- V24 qualification profiles, deployment preflight, rollback rehearsal, and GPU
  runtime evidence requirements are unchanged.
- V25 staging target validation, staging qualification, mutation authorization,
  and migration report contracts are unchanged.
- V26/V27 readiness check names, schema compatibility, tool discovery, and
  deployment prohibition are unchanged.
- V28 live inspection, the optional `inspection_profile: "v28"` marker, and its
  three optional bindings are unchanged.
- No database migration, API change, workflow dispatch, deployment,
  publication, tag, release, or infrastructure mutation is part of V29.
- A readiness `PASS` remains preparation evidence only. It is not production
  qualification and does not authorize a deployment.

## V30 follow-up

V30 adds an optional integrity sidecar and append-only audit chain on top of
these unchanged V23-V29 reports. It does not add fields to `schema_version: 1`
reports and it does not change V29 redaction behavior. V30 audit details are
sanitized with the same central policy before they are hashed, verification
output is sanitized, and sealing fails closed if sidecar metadata would require
redaction. A secret-bearing readiness input still follows the V29 rule: it is
not bound, it produces the `evidence-retention` blocker, and any separately
named diagnostic copy is not evidence. See
[V30_EVIDENCE_INTEGRITY_AND_TAMPER_DETECTION.md](V30_EVIDENCE_INTEGRITY_AND_TAMPER_DETECTION.md).

## Known limitations

V29 is a pattern- and name-based control, not a universal data-loss-prevention
system.

- Unknown proprietary credential formats, secrets split across lines or
  fields, encrypted or encoded blobs, and credentials that appear only as
  opaque random strings without a recognized name or format may not be
  detected.
- Structured parsing is JSON-specific. YAML-like text uses heuristics, not a
  full YAML parser. Binary files, oversized files, and files that are not
  valid UTF-8 are not inspected or retained.
- A detected secret prevents binding, but a sanitized diagnostic copy may
  remain on disk for operator review. It is not evidence and should be handled
  as sensitive operational material.
- A hash proves the integrity of the stored bytes. It does not prove that the
  bytes contain no secret, especially for an unrecognized format.
- Redaction is applied at the logging and evidence-persistence boundaries. It
  does not scan external secret stores, third-party services, or historical
  files that were written before V29.
- V29 performs no live infrastructure verification. V28 remains the opt-in
  read-only inspection layer.
