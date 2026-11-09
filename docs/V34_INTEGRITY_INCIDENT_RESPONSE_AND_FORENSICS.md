# V34 Integrity Incident Response and Forensics

V34 turns confirmed V33 integrity findings into a durable, auditable incident
response workflow without copying, moving, repairing, re-signing, or re-hashing
any protected V29–V33 artifact. It is case management plus evidence-referencing
and local tamper-evidence — not a new cryptographic verifier.

## Non-negotiable guarantees

- **Original evidence is never mutated.** A forensic case stores identifiers,
  relative paths, expected hashes, and sanitized metadata. The V30 evidence
  files, V31 checkpoints/trust material, V32 transparency artifacts, and V33
  monitoring records remain the source of truth and are only read.
- **No duplicated implementations.** Incidents come from V10, notifications and
  delivery rows from V15, authentication/RBAC from V16, redaction from V29,
  evidence verification from V30, trust/signature verification from V31,
  transparency verification from V32, and findings/audit runs from V33.
- **Only confirmed failures can become confirmed incidents.** `UNAVAILABLE`,
  `NOT_RUN`, and `SIMULATED` findings are never promoted to a confirmed
  security incident. Operational findings such as
  `EXTERNAL_ANCHOR_UNCONFIGURED` are also never promoted.
- **Repeated findings do not create duplicate cases.** Correlation is
  deterministic and idempotent per finding; repeated findings with the same
  identity update the existing case instead of creating another.
- **No silent closure.** A later passing check does not resolve or close an
  older unresolved critical finding. Resolution requires an explicit
  authorized transition and, for unresolved critical findings, explicit
  acknowledgement. Only `ADMIN` holds the dedicated close capability.
- **No false external-anchor claim.** The custody ledger is a local,
  append-only hash chain. Every API response and export reports
  `LOCAL_HASH_CHAIN_ONLY`, `external_anchor_claimed=false`, and the
  external-anchoring limitation unless a real provider is configured and
  independently verified.
- **No secrets or evidence bytes.** Notes, actions, metadata, notifications,
  and default exports are sanitized through V29. Credential-shaped note
  content is rejected before redaction. Evidence bytes are excluded from
  exports by default and are only included when policy explicitly allows it.

## Architecture and reuse

| Component | Responsibility |
| --- | --- |
| `backend/app/forensics/constants.py` | Stable case types, statuses, transitions, classifications, reason-code sets, export constants, and assurance text. |
| `backend/app/forensics/correlation.py` | Deterministic finding classification, case type/severity/priority, correlation dimensions, and correlation key. |
| `backend/app/forensics/custody.py` | Canonical JSON, SHA-256, hash-chained custody events, and read-only chain verification. |
| `backend/app/forensics/repository.py` | Durable PostgreSQL/SQLAlchemy persistence for cases, correlations, evidence references, observations, custody, notes/revisions, actions, assignments, incident links, exports, verification runs, and notification state. |
| `backend/app/forensics/verification.py` | Read-only verification of custody, file hashes, V33 findings/audit runs, and V10 incidents. |
| `backend/app/forensics/export.py` | Deterministic ZIP build and verification with a manifest and per-member/root digests. |
| `backend/app/forensics/alerting.py` | V15 forensic notification integration with dedup, cooldown, severity mapping, and pending-delivery semantics. |
| `backend/app/forensics/service.py` | Orchestration: correlation, incident creation/linking, transitions, notes, actions, verification, exports, notifications. |
| `backend/app/models/forensic_orm.py` | V34 ORM tables in the primary application database. |
| `backend/alembic/versions/011_create_forensics.py` | Additive migration after `010_add_notification_mute`; downgrade removes only V34 tables. |
| `backend/app/api/v1/forensics.py` | Authenticated `/api/v1/forensics/...` APIs and capability enforcement. |
| `frontend/app/forensics/page.tsx` | `/forensics` workspace with honest loading/empty/partial/error states. |

V34 deliberately uses the primary application database (PostgreSQL in
production) because case management, RBAC, incidents, and notifications are
transactional application concerns. V33 findings and audit runs remain in the
isolated SQLite monitoring store and are read-only inputs.

## Case types, statuses, and workflow

Case types:

`EVIDENCE_TAMPERING`, `CHECKPOINT_COMPROMISE`, `SIGNATURE_FAILURE`,
`TRANSPARENCY_CONFLICT`, `TRUST_KEY_COMPROMISE`, `CHAIN_OF_CUSTODY_FAILURE`,
`FORENSIC_REVIEW`, `OTHER`.

Statuses:

`OPEN`, `TRIAGED`, `INVESTIGATING`, `CONTAINMENT_RECOMMENDED`,
`AWAITING_REVIEW`, `RESOLVED`, `CLOSED`.

Forward transitions are explicit:

```
OPEN -> TRIAGED -> INVESTIGATING -> CONTAINMENT_RECOMMENDED -> AWAITING_REVIEW -> RESOLVED -> CLOSED
                         \-> AWAITING_REVIEW
AWAITING_REVIEW -> INVESTIGATING
```

Reopening (`RESOLVED`/`CLOSED` -> `OPEN`) is never implicit. It requires an
explicit authorized request with a reason and is recorded as its own custody
event. Skipping states, unknown statuses, and stale `expected_version` values
are rejected.

`RESOLVED` and `CLOSED` require the dedicated `forensic_case_close` capability
(ADMIN). If a case has unresolved `CRITICAL` correlations, resolution returns
`409` unless `acknowledge_critical_findings=true` is supplied. Unverified
evidence also blocks resolution unless explicitly acknowledged. A later PASS
does not clear an unresolved finding automatically.

## Correlation and incident promotion

Classification is deterministic:

| Classification | Meaning | Promotable |
| --- | --- | --- |
| `CONFIRMED_FAILURE` | Concrete V30–V32 integrity failure (for example `EVIDENCE_MODIFIED`, `CHECKPOINT_SIGNATURE_INVALID`, `TREE_HEAD_INVALID`). | Yes |
| `SUSPICIOUS` | Missing or invalid input that merits review but is not proof of tampering. | No automatic confirmed incident |
| `UNAVAILABLE` | Required source or verifier unavailable. | Never |
| `NOT_RUN` | Timeout, cancellation, interruption, or execution error. | Never |
| `SIMULATED` | Source marker indicates a simulation/local test. | Never |
| `OPERATIONAL` | Expected operational condition (for example unconfigured external anchor). | Never |

A finding whose `verification_source` contains `SIMULATED`, `SIMULATION`, or
`LOCAL_TEST` is always classified `SIMULATED`, even when its reason code is a
confirmed-failure code.

Correlation identity is based on stable dimensions — evidence identifier,
checkpoint/log/manifest identifiers, reason code, and related incident — not on
the audit-run ID alone, so a repeated finding in a later audit run maps to the
same case. `finding_id` remains unique per correlation row, so replaying the
same finding is a duplicate and creates nothing.

When a confirmed failure is correlated:

1. The originating V33 finding is referenced by ID and expected canonical hash.
2. A case is created or the existing case is updated.
3. A V10 `SECURITY` incident is created with `source=FORENSIC` and metadata
   pointing back to the case, finding, audit run, and correlation key, or an
   already linked/originating incident receives a timeline note.
4. A sanitized V15 `FORENSIC` notification is evaluated.

Suspicious findings can be correlated into review cases but never create a
confirmed security incident automatically.

## Evidence references and read-only verification

Each evidence reference records:

- `artifact_type` (`V33_FINDING`, `V33_AUDIT_RUN`, `EVIDENCE_FILE`,
  `SIGNED_CHECKPOINT`, `TRUST_STATE`, `TRANSPARENCY_LOG`, `TREE_HEAD`,
  `INCLUSION_PROOF`, `CONSISTENCY_PROOF`, `RECEIPT`, `INCIDENT`, and related
  types);
- a safe relative path or source identifier;
- expected and observed SHA-256;
- source audit-run/finding IDs where applicable;
- capture timestamp and verification outcome.

Path traversal, absolute paths, drive/stream prefixes, missing required
digests, and unknown artifact types are rejected. Verification is read-only:

- file references are hashed under the configured evidence root;
- V33 findings/audit runs are compared with their canonical JSON hash;
- V10 incidents are checked for existence;
- unsupported artifact types are reported `NOT_RUN`, never `PASS`;
- a case with no references is `NOT_RUN`/`PARTIAL`, not a clean pass.

## Chain of custody

Custody events are append-only. Each event contains:

`event_id`, `case_id`, `sequence`, `event_type`, `timestamp`, `actor_id`,
`actor_role`, `artifact_id`, `previous_hash`, `event_hash`, and sanitized
metadata.

`event_hash` is SHA-256 over canonical JSON of the event payload. The first
event links to a 64-zero genesis hash. The case stores the current event count
and head hash; each new event advances both in the same transaction.

Verification checks sequence contiguity, duplicate sequences, previous-hash
links, recomputed payload hashes, actor metadata, unsafe metadata, recorded
count, and recorded head. Results are `PASS`, `FAIL`, `UNAVAILABLE`, or
`NOT_RUN` with stable reason codes such as `CUSTODY_EVENT_HASH_INVALID`,
`CUSTODY_PREVIOUS_HASH_INVALID`, `CUSTODY_SEQUENCE_GAP`,
`CUSTODY_CHAIN_TRUNCATED`, `CUSTODY_HEAD_MISMATCH`, and
`FORENSIC_CUSTODY_CHAIN_INVALID`.

The chain is tamper-evident relative to the application database. It is not an
immutable log, is not externally anchored, and does not protect against an
attacker who can rewrite both the ledger and the case head.

## Notes, actions, assignments, and incident links

- Notes support types `OBSERVATION`, `ANALYSIS`, `HYPOTHESIS`, `ACTION`,
  `CONCLUSION`, and `HANDOVER`, with `INTERNAL`/`RESTRICTED` visibility.
- Every note edit appends a revision row; prior content is retained and exposed
  read-only through `GET .../notes/{note_id}/revisions`.
- Stale note edits (`expected_version`) return `409`.
- Operator actions record `action_type`, description, related finding IDs,
  result (`RECORDED`, `SUCCESS`, `FAILED`, `PENDING`, `NOT_APPLICABLE`), and an
  optional approval reference.
- Assignments record the previous/current assignee, actor, reason, and time.
- Incident links reference existing V10 incidents; V34 never copies or rewrites
  the incident record.

All mutations append custody events and commit atomically.

## Deterministic forensic exports

Exports are ZIP packages built in the configured export directory, which must
not be inside the protected evidence root. The default package contains:

`case.json`, `incident-reference.json`, `findings.json`, `audit-runs.json`,
`evidence-references.json`, `custody-ledger.json`, `investigation-notes.json`,
`operator-actions.json`, `verification-report.json`, `assignments.json`,
`manifest.json`, and `manifest.sha256`.

Properties:

- deterministic member order, timestamps, canonical JSON, and compression;
- the same case content produces the same archive SHA-256;
- `manifest.json` records every member's size and SHA-256 plus the root digest;
- `manifest.sha256` records the manifest digest;
- verification checks archive digest, member digests/sizes, manifest digest,
  root digest, required members, and unsafe paths;
- original evidence bytes are excluded by default. Including them requires
  `FORENSIC_EXPORT_INCLUDE_EVIDENCE_BYTES=true` and a configured evidence root,
  and each byte file must still match its recorded digest or the export is
  refused.

Export generation, download, and verification require the dedicated
`forensic_export` capability (ADMIN). Exports are not external attestations;
`external_anchor_claimed` remains `false`.

## API and RBAC

All routes require an authenticated session. Capabilities:

| Capability | ADMIN | OPERATOR | VIEWER |
| --- | --- | --- | --- |
| `read` (all forensic reads) | Yes | Yes | Yes |
| `forensic_case_write` (create/correlate/transition/assign/note/action/evidence/link) | Yes | Yes | No |
| `forensic_verify` (read-only case verification) | Yes | Yes | No |
| `forensic_case_close` (resolve/close/reopen) | Yes | No | No |
| `forensic_export` (create/download/verify exports) | Yes | No | No |

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/forensics/status` | Workspace status, summary, V33 source state, assurance. |
| `GET` | `/api/v1/forensics/summary` | Case counts by status/severity/type. |
| `GET` | `/api/v1/forensics/cases` | Paginated/filterable case list. |
| `POST` | `/api/v1/forensics/cases` | Open a manual case (optional idempotency key). |
| `GET` | `/api/v1/forensics/cases/{case_id}` | Full case detail including custody and latest verification. |
| `GET` | `/api/v1/forensics/cases/{case_id}/custody` | Custody events plus verification. |
| `GET` | `/api/v1/forensics/cases/{case_id}/timeline` | Ordered custody timeline. |
| `GET` | `/api/v1/forensics/cases/{case_id}/exports` | Export records for the case. |
| `POST` | `/api/v1/forensics/correlate` | Correlate selected findings or an audit run. |
| `POST` | `/api/v1/forensics/cases/{case_id}/correlate` | Correlate findings into one case. |
| `POST` | `/api/v1/forensics/cases/{case_id}/transition` | Explicit authorized status transition. |
| `POST` | `/api/v1/forensics/cases/{case_id}/assign` | Assign/unassign. |
| `POST` | `/api/v1/forensics/cases/{case_id}/notes` | Add a sanitized note. |
| `GET` | `/api/v1/forensics/cases/{case_id}/notes/{note_id}/revisions` | Read note edit history. |
| `PATCH` | `/api/v1/forensics/cases/{case_id}/notes/{note_id}` | Edit a note with version check. |
| `POST` | `/api/v1/forensics/cases/{case_id}/actions` | Record an operator action. |
| `POST` | `/api/v1/forensics/cases/{case_id}/evidence` | Add an evidence reference. |
| `POST` | `/api/v1/forensics/cases/{case_id}/incidents` | Link an existing V10 incident. |
| `POST` | `/api/v1/forensics/cases/{case_id}/verify` | Run read-only verification and record observations. |
| `POST` | `/api/v1/forensics/cases/{case_id}/exports` | Build a deterministic export. |
| `GET` | `/api/v1/forensics/exports/{export_id}` | Download an export (ADMIN). |
| `POST` | `/api/v1/forensics/exports/{export_id}/verify` | Verify an export (ADMIN). |
| `GET` | `/api/v1/forensics/findings` | List V33 findings available for correlation. |

Responses never expose absolute evidence paths, database URLs, protected
bytes, credentials, or private keys. Not-found cases/exports/notes return
`404`; transition/version/resolution/acknowledgement conflicts return `409`;
validation and policy refusals return `422`.

## Notifications

V15 alert rules may use the `FORENSIC` domain and event types
`FORENSIC_CASE_OPENED`, `FORENSIC_CASE_ESCALATED`,
`FORENSIC_CASE_RESOLVED`, `FORENSIC_CASE_CLOSED`,
`FORENSIC_CUSTODY_FAILURE`, and `FORENSIC_EXPORT_FAILURE`.

- Severity mapping uses the case severity; the minimum threshold is
  `FORENSIC_ALERT_MIN_SEVERITY`.
- Dedup is keyed by rule + case + event + case version/finding; replaying the
  same event creates no duplicate notification.
- A correlated cooldown key enforces `FORENSIC_ALERT_COOLDOWN_SECONDS`.
- Payloads are sanitized and linked to the V10 incident ID where available.
- Delivery rows are created `pending` for the existing V15 delivery worker.
  V34 never claims a channel delivered successfully.

## Persistence and migration

V34 adds fourteen additive tables through Alembic revision
`011_create_forensics` (down revision `010_add_notification_mute`):

`forensic_cases`, `forensic_case_counters`, `forensic_correlations`,
`forensic_incident_links`, `forensic_evidence_references`,
`forensic_evidence_observations`, `forensic_custody_events`, `forensic_notes`,
`forensic_note_revisions`, `forensic_actions`, `forensic_assignments`,
`forensic_exports`, `forensic_verification_runs`, and
`forensic_notification_state`.

Case numbers use the V10-style atomic yearly counter
(`CASE-YYYY-XXXXXX`). `downgrade()` drops only V34 tables and leaves V10–V33
schema and data untouched. The migration is tested through upgrade → downgrade
→ upgrade on SQLite.

## Configuration

```dotenv
FORENSIC_ENABLED=true
FORENSIC_EVIDENCE_ROOT=            # defaults to INTEGRITY_EVIDENCE_ROOT
FORENSIC_EXPORT_DIR=               # defaults under ./var/forensic-exports
FORENSIC_EXPORT_INCLUDE_EVIDENCE_BYTES=false
FORENSIC_EXPORT_MAX_FILES=64       # 1-1024
FORENSIC_EXPORT_MAX_BYTES=52428800 # 1 KiB-1 GiB
FORENSIC_MAX_CORRELATION_FINDINGS=500
FORENSIC_ALERTING_ENABLED=false
FORENSIC_ALERT_MIN_SEVERITY=HIGH
FORENSIC_ALERT_COOLDOWN_SECONDS=3600
```

Startup validation refuses evidence-byte export when no evidence root is
configured and refuses an export directory inside the protected evidence root.

## Dashboard

`/forensics` provides:

- workspace status, V33 source state, and case metrics;
- an explicit local-only assurance banner;
- case list filters (status/severity/search) and pagination;
- V33 findings with selection and explicit correlation;
- correlation statistics showing skipped unavailable/not-run/simulated/
  operational findings and never implying promotion;
- case detail: status, custody verification, evidence references, correlated
  findings, linked incidents, notes, exports, and custody timeline;
- explicit transition controls, with close/reopen restricted to ADMIN;
- read-only verification with honest PASS/FAIL/PARTIAL/UNAVAILABLE/NOT_RUN
  reporting and reason codes;
- ADMIN-only export generation/download/verification;
- loading, empty, partial, unavailable, and error states. A failed request is
  never rendered as a pass or as stale data.

## Operations

1. Investigate findings in `/integrity`; confirm the failure and its source.
2. Correlate confirmed findings in `/forensics` or with
   `POST /api/v1/forensics/correlate`.
3. Triage the case (`OPEN` → `TRIAGED` → `INVESTIGATING`), add notes and
   operator actions, and reference supporting evidence by ID/hash.
4. Run read-only verification and review custody verification. `PARTIAL` or
   `UNAVAILABLE` is not a clean bill.
5. Recommend containment explicitly if appropriate; move to `AWAITING_REVIEW`.
6. Resolve with a summary only after review. Unresolved critical findings
   require explicit acknowledgement. Close is ADMIN-only.
7. If new evidence appears after closure, reopen explicitly with a reason.
8. Generate a references-only export for handover. Verify the export before
   relying on it.

Never edit the V34 database, custody rows, or protected artifacts to force a
pass. Never treat a local custody chain as externally anchored.

## Limitations

- The custody chain is local and tamper-evident only relative to the
  application database; it is not externally anchored or independently
  immutable.
- Verification re-hashes current bytes and compares recorded digests; it does
  not prove authenticity at capture time and does not re-implement V31
  signature or V32 transparency verification.
- A matching file digest proves the bytes match the reference, not that the
  file is the only copy or that the evidence root was never compromised.
- V29 redaction is pattern/name-based. Unknown secret formats, encoded blobs,
  and secrets split across fields may not be detected; credential-shaped note
  content is rejected, but this is not universal DLP.
- Evidence-byte export is opt-in and policy-gated; the default export is
  references/hashes/metadata only.
- Windows hosts skip POSIX permission/symlink tests; skipped checks are never
  reported as passed.
- No external transparency provider is configured or independently verified;
  all assurance is `LOCAL_HASH_CHAIN_ONLY`.

## Validation

```powershell
python -m pytest backend/tests/unit/test_v34_forensics.py `
  backend/tests/integration/test_v34_forensics_api.py `
  backend/tests/integration/test_v34_migration.py -q
python -m pytest backend/tests/unit/test_v33_integrity_audit.py `
  backend/tests/unit/test_v33_integrity_alerting.py `
  backend/tests/integration/test_v33_integrity_api.py -q
python -m ruff check backend
python -m ruff format --check backend
python -m compileall -q backend
cd frontend
npm run lint
npm run typecheck
npm run test:run
npm run build
```

The focused tests cover classification/promotion rules, deterministic
correlation and dedup, custody tamper detection, export determinism and
tamper/path rejection, evidence-byte policy, explicit transitions, unresolved
critical closure blocking, note revision history, credential-shaped note
rejection, API/RBAC separation including the dedicated export capability, V15
forensic dedup/cooldown/pending delivery, and migration upgrade/downgrade.
