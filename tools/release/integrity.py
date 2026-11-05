"""V30 deterministic evidence records and append-only audit chains.

The integrity layer is deliberately separate from the V23-V29 report formats.
Existing reports keep ``schema_version: 1`` and their exact field sets; V30
adds an optional sidecar integrity manifest and a JSONL audit chain instead of
silently extending published report shapes.

Canonicalization rules
----------------------

* Records are serialized as UTF-8 JSON with sorted keys, compact separators
  (``","`` and ``":"``), ``ensure_ascii=True``, and no trailing newline.
* Timestamps are normalized to UTC with second precision and the literal
  ``Z`` suffix (``YYYY-MM-DDTHH:MM:SSZ``).
* A record hash covers every field except ``record_hash``.
* An event identifier is derived from every field except ``event_id`` and
  ``record_hash``, so an edited payload no longer matches its identifier.
* Audit chain files are UTF-8 JSONL. Each record is one canonical line followed
  by ``\\n``.

Trust boundary
--------------

A local hash chain is tamper-evident, not immutable. An attacker who can write
both the evidence and the entire chain can recompute every hash. Stronger
guarantees require an independently protected checkpoint or external trusted
storage. This module never contacts an external anchor by default; callers must
explicitly supply a :class:`CheckpointProvider`.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Protocol

from backend.app.core.redaction import (
    contains_sensitive_material,
    redact_structure,
    redact_text,
)
from tools.release.identity import DIGEST_PATTERN
from tools.release.manifest import sha256_file, utc_now_iso
from tools.release.verification import FAIL, NOT_RUN, PASS, UNAVAILABLE

INTEGRITY_SCHEMA_VERSION = 1
INTEGRITY_PROFILE = "evidence_integrity"
AUDIT_SCHEMA_VERSION = 1
AUDIT_PROFILE = "evidence_audit_chain"

EVIDENCE_CREATED = "EVIDENCE_CREATED"
EVIDENCE_VERIFIED = "EVIDENCE_VERIFIED"
EVIDENCE_MODIFIED = "EVIDENCE_MODIFIED"
EVIDENCE_MISSING = "EVIDENCE_MISSING"
EVIDENCE_REPLACED = "EVIDENCE_REPLACED"
EVIDENCE_REJECTED = "EVIDENCE_REJECTED"
EVIDENCE_PATH_INVALID = "EVIDENCE_PATH_INVALID"
MANIFEST_BINDING_MISMATCH = "MANIFEST_BINDING_MISMATCH"
AUDIT_CHAIN_INVALID = "AUDIT_CHAIN_INVALID"

AUDIT_EVENT_TYPES = (
    EVIDENCE_CREATED,
    EVIDENCE_VERIFIED,
    EVIDENCE_MODIFIED,
    EVIDENCE_MISSING,
    EVIDENCE_REPLACED,
    EVIDENCE_REJECTED,
    EVIDENCE_PATH_INVALID,
    MANIFEST_BINDING_MISMATCH,
    AUDIT_CHAIN_INVALID,
)

#: The chain is verified only against these four stable outcomes. ``SIMULATED``
#: is intentionally absent: simulated evidence never enters an integrity chain.
AUDIT_OUTCOMES = (PASS, FAIL, UNAVAILABLE, NOT_RUN)

GENESIS_PREVIOUS_HASH = "sha256:" + ("0" * 64)
MAX_AUDIT_BYTES = 16 * 1024 * 1024
MAX_AUDIT_RECORDS = 100_000
MAX_INTEGRITY_BYTES = 16 * 1024 * 1024
MAX_VERIFY_BYTES = 1024 * 1024 * 1024

TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
CONTROL_CHARACTER = re.compile(r"[\x00-\x1f\x7f]")
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:-]{1,512}$")
SAFE_KIND = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
REDACTED_DIAGNOSTIC_MARKER = "-redacted"

EVIDENCE_RECORD_FIELDS = (
    "evidence_id",
    "kind",
    "path",
    "sha256",
    "size",
    "created_at",
    "schema_version",
    "parent_id",
)

AUDIT_RECORD_FIELDS = (
    "schema_version",
    "sequence",
    "event_id",
    "event_type",
    "timestamp",
    "outcome",
    "evidence_id",
    "evidence",
    "previous_record_hash",
    "record_hash",
    "details",
)

CHECKPOINT_FIELDS = (
    "schema_version",
    "record_count",
    "final_record_hash",
    "final_event_id",
    "final_timestamp",
    "source",
)

_WINDOWS_RESERVED = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{index}" for index in range(1, 10)}
    | {f"lpt{index}" for index in range(1, 10)}
)


class IntegrityError(ValueError):
    """An integrity record or canonicalization request is invalid."""


class AuditChainError(RuntimeError):
    """The audit chain could not be read, appended, or trusted."""

    def __init__(self, message: str, *, verification: AuditVerification | None = None) -> None:
        super().__init__(message)
        self.verification = verification


class EvidencePathError(ValueError):
    """An evidence path is unsafe or cannot be inspected."""

    def __init__(self, detail: str, *, code: str = EVIDENCE_PATH_INVALID) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


class EvidenceChangedDuringVerification(RuntimeError):
    """The file changed while it was being hashed."""


def canonical_json_bytes(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON bytes for hashing and JSONL records."""
    try:
        text = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise IntegrityError("integrity metadata cannot be serialized deterministically") from exc
    return text.encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    """Return a release-style ``sha256:<hex>`` digest for *data*."""
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def normalize_timestamp(value: str | datetime) -> str:
    """Normalize a timestamp to UTC second precision.

    Timezone-aware ISO-8601 strings are converted to UTC. Naive strings and
    naive datetimes are rejected: an unqualified timestamp cannot be compared
    deterministically with UTC audit records.
    """
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise IntegrityError("timestamps must include an explicit timezone")
        return value.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    if not isinstance(value, str) or not value:
        raise IntegrityError("timestamp must be a non-empty string or datetime")
    if TIMESTAMP_PATTERN.fullmatch(value):
        try:
            datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError as exc:
            raise IntegrityError("timestamp is not a valid UTC instant") from exc
        return value
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise IntegrityError("timestamp is not valid ISO-8601") from exc
    if parsed.tzinfo is None:
        raise IntegrityError("timestamps must include an explicit timezone")
    return parsed.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_text(value: Any, *, field_name: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value:
        raise IntegrityError(f"{field_name} must be a non-empty string")
    if CONTROL_CHARACTER.search(value):
        raise IntegrityError(f"{field_name} contains a control character")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise IntegrityError(f"{field_name} contains unsupported characters")
    return value


def validate_relative_path(value: Any) -> str:
    """Validate a portable, relative evidence path and return it normalized.

    The policy is intentionally stricter than the host filesystem:

    * only ``/`` separators are accepted;
    * absolute paths, drive-qualified paths, UNC paths, ``..``, ``.``, empty
      components, trailing separators, colons, and NUL/control characters are
      rejected;
    * Windows reserved device names and components ending in a dot or space
      are rejected so the same record behaves identically on Windows and POSIX.
    """
    if not isinstance(value, str) or not value:
        raise EvidencePathError("evidence path must be a non-empty relative path")
    if len(value) > 4096:
        raise EvidencePathError("evidence path is too long")
    if CONTROL_CHARACTER.search(value):
        raise EvidencePathError("evidence path contains a control character")
    if "\\" in value:
        raise EvidencePathError("evidence path must use '/' separators")
    if ":" in value:
        raise EvidencePathError("evidence path must not contain a drive or alternate stream")
    if value.endswith("/"):
        raise EvidencePathError("evidence path must name a file, not a directory")
    if "//" in value:
        raise EvidencePathError("evidence path must not contain empty components")
    if value == "." or value.startswith("./") or value.endswith("/.") or "/./" in value:
        raise EvidencePathError("evidence path must not contain '.' components")
    if value == ".." or value.startswith("../") or value.endswith("/..") or "/../" in value:
        raise EvidencePathError("evidence path must not contain '..' components")
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if posix.is_absolute() or windows.is_absolute() or windows.drive:
        raise EvidencePathError("evidence path must be relative")
    parts = posix.parts
    if not parts:
        raise EvidencePathError("evidence path must not be empty")
    for part in parts:
        if part in ("", ".", ".."):
            raise EvidencePathError("evidence path must not contain '.' or '..' components")
        if part.endswith((" ", ".")):
            raise EvidencePathError("evidence path components must not end with a dot or space")
        if part.split(".", 1)[0].lower() in _WINDOWS_RESERVED:
            raise EvidencePathError("evidence path uses a reserved Windows device name")
    return "/".join(parts)


def validate_relative_directory(value: Any) -> str:
    """Validate a relative evidence-root directory; ``"."`` is allowed."""
    if value == ".":
        return "."
    return validate_relative_path(value)


def is_redacted_diagnostic_path(value: str) -> bool:
    """Return whether a path is a V29 sanitized diagnostic copy.

    V29 names diagnostic copies ``<kind>-<digest[:12]>-redacted<ext>``. Such a
    copy is never evidence and must never be accepted as the original input.
    """
    if not isinstance(value, str):
        return False
    name = value.rsplit("/", 1)[-1].lower()
    return REDACTED_DIAGNOSTIC_MARKER in name


def resolve_evidence_path(root: Path, relative: str) -> Path:
    """Resolve *relative* under *root* without allowing an escape.

    Every path component below the root is checked for a symbolic link or
    Windows junction. The final resolved path must remain inside the resolved
    root. The root itself may be a symlink (common for temporary directories);
    components below it may not.
    """
    normalized = "." if relative == "." else validate_relative_path(relative)
    root = Path(root)
    try:
        root_resolved = root.resolve(strict=True)
    except OSError as exc:
        raise EvidencePathError("evidence root is missing or unreadable", code=UNAVAILABLE) from exc
    if not root_resolved.is_dir():
        raise EvidencePathError("evidence root is not a directory", code=UNAVAILABLE)

    if normalized == ".":
        return root_resolved

    current = root
    for part in PurePosixPath(normalized).parts:
        current = current / part
        try:
            if current.is_symlink():
                raise EvidencePathError("evidence path contains a symbolic link")
            is_junction = getattr(current, "is_junction", None)
            if callable(is_junction) and is_junction():
                raise EvidencePathError("evidence path contains a junction")
        except OSError as exc:
            raise EvidencePathError("evidence path could not be inspected", code=UNAVAILABLE) from exc

    candidate = root / PurePosixPath(normalized)
    try:
        resolved = candidate.resolve(strict=False)
    except OSError as exc:
        raise EvidencePathError("evidence path could not be resolved", code=UNAVAILABLE) from exc
    if not resolved.is_relative_to(root_resolved):
        raise EvidencePathError("evidence path escapes the configured evidence root")
    return resolved


def normalized_path_key(path: Path) -> str:
    """Return a case-normalized key for duplicate-path detection."""
    try:
        resolved = path.resolve(strict=False)
    except OSError:
        resolved = path
    return os.path.normcase(os.path.abspath(str(resolved)))


@dataclass(frozen=True)
class EvidenceRecord:
    """Metadata identifying exact evidence bytes.

    No evidence content, credential, or secret is stored in this record.
    """

    evidence_id: str
    kind: str
    path: str
    sha256: str
    size: int
    created_at: str
    schema_version: int = INTEGRITY_SCHEMA_VERSION
    parent_id: str | None = None

    def __post_init__(self) -> None:
        _safe_text(self.evidence_id, field_name="evidence_id", pattern=SAFE_IDENTIFIER)
        _safe_text(self.kind, field_name="kind", pattern=SAFE_KIND)
        object.__setattr__(self, "path", validate_relative_path(self.path))
        if not isinstance(self.sha256, str) or DIGEST_PATTERN.fullmatch(self.sha256) is None:
            raise IntegrityError("evidence sha256 must be sha256:<64 lowercase hex>")
        if isinstance(self.size, bool) or not isinstance(self.size, int) or self.size < 0:
            raise IntegrityError("evidence size must be a non-negative integer")
        object.__setattr__(self, "created_at", normalize_timestamp(self.created_at))
        if self.schema_version != INTEGRITY_SCHEMA_VERSION:
            raise IntegrityError(f"evidence schema_version must be {INTEGRITY_SCHEMA_VERSION}")
        if self.parent_id is not None:
            _safe_text(self.parent_id, field_name="parent_id", pattern=SAFE_IDENTIFIER)
        for field_name, value in (
            ("evidence_id", self.evidence_id),
            ("kind", self.kind),
            ("path", self.path),
            ("parent_id", self.parent_id),
        ):
            if value is not None and contains_sensitive_material(value):
                raise IntegrityError(f"{field_name} contains unsupported sensitive material")

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "kind": self.kind,
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "created_at": self.created_at,
            "schema_version": self.schema_version,
            "parent_id": self.parent_id,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> EvidenceRecord:
        if not isinstance(payload, Mapping):
            raise IntegrityError("evidence record must be a mapping")
        if sorted(payload) != sorted(EVIDENCE_RECORD_FIELDS):
            raise IntegrityError("evidence record has unexpected or missing fields")
        return cls(
            evidence_id=payload.get("evidence_id"),
            kind=payload.get("kind"),
            path=payload.get("path"),
            sha256=payload.get("sha256"),
            size=payload.get("size"),
            created_at=payload.get("created_at"),
            schema_version=payload.get("schema_version"),
            parent_id=payload.get("parent_id"),
        )


def _contains_unsanitized_text(value: Any) -> bool:
    """Return whether any sanitized string value still looks like a credential."""
    if isinstance(value, str):
        return contains_sensitive_material(value)
    if isinstance(value, Mapping):
        return any(_contains_unsanitized_text(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_unsanitized_text(item) for item in value)
    return False


def sanitize_details(details: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return redacted, JSON-safe diagnostic details.

    The function fails closed if a supported credential pattern survives
    redaction. It never echoes the offending value.
    """
    if details is None:
        return {}
    if not isinstance(details, Mapping):
        raise IntegrityError("audit details must be a mapping")
    cleaned = redact_structure(dict(details))
    if not isinstance(cleaned, dict):
        raise IntegrityError("audit details could not be sanitized")
    if _contains_unsanitized_text(cleaned):
        raise IntegrityError("audit details contain unsupported sensitive material")
    return cleaned


def derive_event_id(record: Mapping[str, Any]) -> str:
    """Derive a deterministic event identifier from the record payload."""
    payload = {key: value for key, value in record.items() if key not in ("event_id", "record_hash")}
    digest = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    return f"evt-{digest[:24]}"


def record_hash(record: Mapping[str, Any]) -> str:
    """Compute the canonical hash of an audit record excluding ``record_hash``."""
    payload = {key: value for key, value in record.items() if key != "record_hash"}
    return sha256_bytes(canonical_json_bytes(payload))


def build_audit_record(
    *,
    sequence: int,
    event_type: str,
    timestamp: str | datetime,
    outcome: str,
    previous_record_hash: str = GENESIS_PREVIOUS_HASH,
    evidence: EvidenceRecord | Mapping[str, Any] | None = None,
    evidence_id: str | None = None,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one deterministic audit record with its event and record hashes."""
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
        raise IntegrityError("audit sequence must be a non-negative integer")
    if event_type not in AUDIT_EVENT_TYPES:
        raise IntegrityError(f"unsupported audit event type: {event_type!r}")
    if outcome not in AUDIT_OUTCOMES:
        raise IntegrityError(f"unsupported audit outcome: {outcome!r}")
    if not isinstance(previous_record_hash, str) or DIGEST_PATTERN.fullmatch(previous_record_hash) is None:
        raise IntegrityError("previous_record_hash must be sha256:<64 lowercase hex>")
    if evidence is not None:
        if not isinstance(evidence, EvidenceRecord):
            evidence = EvidenceRecord.from_dict(evidence)
        if evidence_id is not None and evidence_id != evidence.evidence_id:
            raise IntegrityError("evidence_id does not match the embedded evidence record")
        evidence_id = evidence.evidence_id
    elif evidence_id is not None:
        _safe_text(evidence_id, field_name="evidence_id", pattern=SAFE_IDENTIFIER)
    if event_type == EVIDENCE_CREATED and evidence is None:
        raise IntegrityError("EVIDENCE_CREATED requires an evidence record")
    if event_type != AUDIT_CHAIN_INVALID and evidence_id is None:
        raise IntegrityError(f"{event_type} requires an evidence identifier")

    record: dict[str, Any] = {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "sequence": sequence,
        "event_type": event_type,
        "timestamp": normalize_timestamp(timestamp),
        "outcome": outcome,
        "evidence_id": evidence_id,
        "evidence": evidence.to_dict() if evidence is not None else None,
        "previous_record_hash": previous_record_hash,
        "details": sanitize_details(details),
    }
    record["event_id"] = derive_event_id(record)
    record["record_hash"] = record_hash(record)
    return record


def build_audit_chain(events: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Build a complete chain from event keyword mappings."""
    records: list[dict[str, Any]] = []
    previous = GENESIS_PREVIOUS_HASH
    for sequence, event in enumerate(events):
        if not isinstance(event, Mapping):
            raise IntegrityError("audit event must be a mapping")
        payload = dict(event)
        for derived in ("sequence", "previous_record_hash", "event_id", "record_hash"):
            payload.pop(derived, None)
        record = build_audit_record(
            sequence=sequence,
            previous_record_hash=previous,
            **payload,
        )
        records.append(record)
        previous = record["record_hash"]
    return records


def render_audit_chain(records: Sequence[Mapping[str, Any]]) -> bytes:
    """Render records as canonical JSONL bytes."""
    return b"".join(canonical_json_bytes(record) + b"\n" for record in records)


def read_audit_chain(path: Path) -> list[dict[str, Any]]:
    """Read a JSONL audit chain with bounded size and record count."""
    path = Path(path)
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise AuditChainError("audit chain is missing or unreadable") from exc
    if size > MAX_AUDIT_BYTES:
        raise AuditChainError("audit chain exceeds the maximum supported size")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise AuditChainError("audit chain is unreadable") from exc
    if not raw:
        return []
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AuditChainError("audit chain is not valid UTF-8") from exc
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if any(line == "" for line in lines):
        raise AuditChainError("audit chain contains a blank record")
    if len(lines) > MAX_AUDIT_RECORDS:
        raise AuditChainError("audit chain exceeds the maximum supported record count")
    records: list[dict[str, Any]] = []
    for line in lines:
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AuditChainError("audit chain contains malformed JSON") from exc
        if not isinstance(payload, dict):
            raise AuditChainError("audit chain record is not a JSON object")
        records.append(payload)
    return records


def write_audit_chain(
    path: Path,
    records: Sequence[Mapping[str, Any]],
    *,
    overwrite: bool = False,
) -> bytes:
    """Write a complete audit chain, refusing to overwrite by default."""
    path = Path(path)
    if path.exists() and not overwrite:
        raise AuditChainError("refusing to overwrite an existing audit chain")
    data = render_audit_chain(records)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise AuditChainError("audit chain could not be written") from exc
    return data


def append_audit_event(
    path: Path,
    *,
    event_type: str,
    timestamp: str | datetime | None = None,
    outcome: str = PASS,
    evidence: EvidenceRecord | Mapping[str, Any] | None = None,
    evidence_id: str | None = None,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Append one event after verifying the existing chain.

    The append is not protected against multiple concurrent writers. It fails
    closed rather than appending to a chain that is already invalid.
    """
    path = Path(path)
    records: list[dict[str, Any]] = []
    previous = GENESIS_PREVIOUS_HASH
    if path.exists():
        verification = verify_audit_chain(path)
        if verification.outcome != PASS:
            raise AuditChainError(
                "refusing to append to an invalid audit chain",
                verification=verification,
            )
        try:
            records = read_audit_chain(path)
        except AuditChainError:
            raise
        if records:
            previous = str(records[-1].get("record_hash"))
    record = build_audit_record(
        sequence=len(records),
        event_type=event_type,
        timestamp=timestamp or utc_now_iso(),
        outcome=outcome,
        previous_record_hash=previous,
        evidence=evidence,
        evidence_id=evidence_id,
        details=details,
    )
    line = canonical_json_bytes(record) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("ab") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise AuditChainError("audit event could not be appended") from exc
    return record


@dataclass(frozen=True)
class AuditProblem:
    """One sanitized audit-chain verification problem."""

    code: str
    detail: str
    sequence: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "detail": redact_text(self.detail)[:500],
            "sequence": self.sequence,
        }


@dataclass
class AuditVerification:
    """Result of verifying a complete audit chain."""

    outcome: str
    record_count: int
    head: str | None
    anchored: bool
    checkpoint: dict[str, Any] | None
    problems: list[AuditProblem] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    event_counts: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "record_count": self.record_count,
            "head": self.head,
            "anchored": self.anchored,
            "checkpoint": self.checkpoint,
            "problems": [problem.to_dict() for problem in self.problems],
            "limitations": [redact_text(item)[:500] for item in self.limitations],
            "event_counts": dict(sorted(self.event_counts.items())),
        }


class CheckpointProvider(Protocol):
    """Explicit external checkpoint interface.

    Implementations may read a protected file, a secrets manager, or an
    external service. The integrity module never contacts one unless the caller
    supplies an instance.
    """

    def fetch(self) -> Mapping[str, Any]:
        """Return a checkpoint mapping."""


def validate_checkpoint(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and normalize a trusted checkpoint."""
    if not isinstance(payload, Mapping):
        raise IntegrityError("checkpoint must be a mapping")
    unknown = set(payload) - set(CHECKPOINT_FIELDS)
    if unknown:
        raise IntegrityError("checkpoint has unexpected fields")
    if payload.get("schema_version") != 1:
        raise IntegrityError("checkpoint schema_version must be 1")
    count = payload.get("record_count")
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise IntegrityError("checkpoint record_count must be a positive integer")
    final_hash = payload.get("final_record_hash")
    if not isinstance(final_hash, str) or DIGEST_PATTERN.fullmatch(final_hash) is None:
        raise IntegrityError("checkpoint final_record_hash must be sha256:<64 lowercase hex>")
    event_id = payload.get("final_event_id")
    if not isinstance(event_id, str) or not event_id:
        raise IntegrityError("checkpoint final_event_id must be a non-empty string")
    timestamp = normalize_timestamp(payload.get("final_timestamp"))
    source = payload.get("source")
    if source is not None:
        _safe_text(source, field_name="checkpoint source")
        source = redact_text(source)[:500]
    return {
        "schema_version": 1,
        "record_count": count,
        "final_record_hash": final_hash,
        "final_event_id": event_id,
        "final_timestamp": timestamp,
        "source": source,
    }


def load_checkpoint(path: Path) -> dict[str, Any]:
    """Load and validate a local trusted checkpoint file."""
    path = Path(path)
    try:
        if path.stat().st_size > MAX_INTEGRITY_BYTES:
            raise IntegrityError("checkpoint exceeds the maximum supported size")
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise AuditChainError("checkpoint is missing or unreadable") from exc
    except json.JSONDecodeError as exc:
        raise IntegrityError("checkpoint is not valid JSON") from exc
    return validate_checkpoint(payload)


def create_checkpoint(
    source: Path | Sequence[Mapping[str, Any]],
    *,
    source_label: str | None = None,
) -> dict[str, Any]:
    """Create a checkpoint from a valid chain."""
    verification = verify_audit_chain(source)
    if verification.outcome != PASS:
        raise AuditChainError(
            "cannot checkpoint an invalid audit chain",
            verification=verification,
        )
    records = read_audit_chain(Path(source)) if isinstance(source, (str, Path)) else list(source)
    last = records[-1]
    return validate_checkpoint(
        {
            "schema_version": 1,
            "record_count": len(records),
            "final_record_hash": last["record_hash"],
            "final_event_id": last["event_id"],
            "final_timestamp": last["timestamp"],
            "source": source_label,
        }
    )


def write_checkpoint(path: Path, checkpoint: Mapping[str, Any], *, overwrite: bool = False) -> None:
    """Write a checkpoint file, refusing to overwrite by default."""
    path = Path(path)
    if path.exists() and not overwrite:
        raise AuditChainError("refusing to overwrite an existing checkpoint")
    payload = validate_checkpoint(checkpoint)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    except OSError as exc:
        raise AuditChainError("checkpoint could not be written") from exc


def _checkpoint_from_provider(provider: CheckpointProvider) -> dict[str, Any]:
    try:
        payload = provider.fetch()
    except Exception as exc:  # noqa: BLE001 - the provider is an explicit trust boundary
        raise AuditChainError(f"external checkpoint provider failed: {redact_text(str(exc))[:200]}") from exc
    return validate_checkpoint(payload)


def _audit_event_errors(record: Mapping[str, Any], sequence: int) -> list[AuditProblem]:
    problems: list[AuditProblem] = []
    event_type = record.get("event_type")
    outcome = record.get("outcome")
    evidence = record.get("evidence")
    evidence_id = record.get("evidence_id")
    if event_type not in AUDIT_EVENT_TYPES:
        problems.append(
            AuditProblem(AUDIT_CHAIN_INVALID, "audit record has an unsupported event type", sequence)
        )
    if outcome not in AUDIT_OUTCOMES:
        problems.append(
            AuditProblem(AUDIT_CHAIN_INVALID, "audit record has an unsupported outcome", sequence)
        )
    if event_type == EVIDENCE_CREATED:
        if not isinstance(evidence, Mapping):
            problems.append(
                AuditProblem(AUDIT_CHAIN_INVALID, "creation event has no evidence record", sequence)
            )
        if outcome != PASS:
            problems.append(
                AuditProblem(AUDIT_CHAIN_INVALID, "creation event outcome must be PASS", sequence)
            )
    if event_type != AUDIT_CHAIN_INVALID and not isinstance(evidence_id, str):
        problems.append(AuditProblem(AUDIT_CHAIN_INVALID, "audit event has no evidence identifier", sequence))
    if evidence is not None:
        try:
            parsed = EvidenceRecord.from_dict(evidence)
        except IntegrityError:
            problems.append(AuditProblem(AUDIT_CHAIN_INVALID, "audit evidence record is malformed", sequence))
        else:
            if parsed.evidence_id != evidence_id:
                problems.append(
                    AuditProblem(
                        AUDIT_CHAIN_INVALID,
                        "audit evidence identifier does not match its record",
                        sequence,
                    )
                )
    details = record.get("details")
    if not isinstance(details, Mapping):
        problems.append(AuditProblem(AUDIT_CHAIN_INVALID, "audit details must be a mapping", sequence))
    else:
        try:
            cleaned = sanitize_details(details)
        except IntegrityError:
            problems.append(
                AuditProblem(
                    AUDIT_CHAIN_INVALID,
                    "audit details contain unsupported sensitive material",
                    sequence,
                )
            )
        else:
            if cleaned != dict(details):
                problems.append(
                    AuditProblem(AUDIT_CHAIN_INVALID, "audit details are not sanitized", sequence)
                )
    return problems


def verify_audit_chain(
    source: Path | str | Sequence[Mapping[str, Any]],
    *,
    checkpoint: Mapping[str, Any] | None = None,
    checkpoint_provider: CheckpointProvider | None = None,
) -> AuditVerification:
    """Verify a chain from its first record through its final record.

    Detects altered records, deleted/reordered/duplicated records, invalid
    previous-hash links, inconsistent event metadata, and checkpoint mismatch.
    A local chain is reported as internally consistent but not externally
    anchored unless a checkpoint is supplied.
    """
    if checkpoint is not None and checkpoint_provider is not None:
        return AuditVerification(
            outcome=FAIL,
            record_count=0,
            head=None,
            anchored=False,
            checkpoint=None,
            problems=[
                AuditProblem(
                    AUDIT_CHAIN_INVALID,
                    "both a checkpoint and a checkpoint provider were supplied",
                )
            ],
        )
    if checkpoint_provider is not None:
        try:
            checkpoint = _checkpoint_from_provider(checkpoint_provider)
        except (AuditChainError, IntegrityError) as exc:
            return AuditVerification(
                outcome=UNAVAILABLE,
                record_count=0,
                head=None,
                anchored=False,
                checkpoint=None,
                problems=[AuditProblem(AUDIT_CHAIN_INVALID, str(exc))],
                limitations=["external checkpoint could not be obtained"],
            )
    if checkpoint is not None:
        try:
            checkpoint = validate_checkpoint(checkpoint)
        except IntegrityError as exc:
            return AuditVerification(
                outcome=FAIL,
                record_count=0,
                head=None,
                anchored=False,
                checkpoint=None,
                problems=[AuditProblem(AUDIT_CHAIN_INVALID, str(exc))],
            )

    records: list[dict[str, Any]]
    if isinstance(source, (str, Path)):
        try:
            records = read_audit_chain(Path(source))
        except AuditChainError as exc:
            return AuditVerification(
                outcome=UNAVAILABLE,
                record_count=0,
                head=None,
                anchored=checkpoint is not None,
                checkpoint=checkpoint,
                problems=[AuditProblem(AUDIT_CHAIN_INVALID, str(exc))],
            )
    else:
        records = [dict(record) if isinstance(record, Mapping) else record for record in source]

    problems: list[AuditProblem] = []
    event_counts: dict[str, int] = {}
    if not records:
        problems.append(AuditProblem(AUDIT_CHAIN_INVALID, "audit chain is empty"))

    previous = GENESIS_PREVIOUS_HASH
    previous_timestamp: str | None = None
    seen_events: set[str] = set()
    for index, record in enumerate(records):
        if not isinstance(record, Mapping):
            problems.append(AuditProblem(AUDIT_CHAIN_INVALID, "audit record is not a mapping", index))
            continue
        if sorted(record) != sorted(AUDIT_RECORD_FIELDS):
            problems.append(
                AuditProblem(
                    AUDIT_CHAIN_INVALID,
                    "audit record has unexpected or missing fields",
                    index,
                )
            )
        if record.get("schema_version") != AUDIT_SCHEMA_VERSION:
            problems.append(AuditProblem(AUDIT_CHAIN_INVALID, "audit record schema_version is not 1", index))
        sequence = record.get("sequence")
        if isinstance(sequence, bool) or not isinstance(sequence, int):
            problems.append(AuditProblem(AUDIT_CHAIN_INVALID, "audit sequence is not an integer", index))
        elif sequence != index:
            problems.append(
                AuditProblem(
                    AUDIT_CHAIN_INVALID,
                    "audit sequence is missing, duplicated, or reordered",
                    index,
                )
            )
        event_type = record.get("event_type")
        if isinstance(event_type, str):
            event_counts[event_type] = event_counts.get(event_type, 0) + 1
        try:
            timestamp = normalize_timestamp(record.get("timestamp"))
        except IntegrityError:
            problems.append(AuditProblem(AUDIT_CHAIN_INVALID, "audit timestamp is invalid", index))
        else:
            if timestamp != record.get("timestamp"):
                problems.append(
                    AuditProblem(AUDIT_CHAIN_INVALID, "audit timestamp is not canonical UTC", index)
                )
            if previous_timestamp is not None and timestamp < previous_timestamp:
                problems.append(AuditProblem(AUDIT_CHAIN_INVALID, "audit timestamps are out of order", index))
            previous_timestamp = timestamp
        event_id = record.get("event_id")
        if not isinstance(event_id, str) or not event_id:
            problems.append(AuditProblem(AUDIT_CHAIN_INVALID, "audit event identifier is missing", index))
        elif event_id in seen_events:
            problems.append(AuditProblem(AUDIT_CHAIN_INVALID, "audit event identifier is duplicated", index))
        else:
            seen_events.add(event_id)
            expected_event_id = derive_event_id(record)
            if event_id != expected_event_id:
                problems.append(
                    AuditProblem(
                        AUDIT_CHAIN_INVALID,
                        "audit event metadata does not match its identifier",
                        index,
                    )
                )
        previous_hash = record.get("previous_record_hash")
        if not isinstance(previous_hash, str) or DIGEST_PATTERN.fullmatch(previous_hash) is None:
            problems.append(AuditProblem(AUDIT_CHAIN_INVALID, "audit previous-record hash is invalid", index))
        elif previous_hash != previous:
            problems.append(
                AuditProblem(
                    AUDIT_CHAIN_INVALID,
                    "audit previous-record hash does not link to the prior record",
                    index,
                )
            )
        stored_hash = record.get("record_hash")
        if not isinstance(stored_hash, str) or DIGEST_PATTERN.fullmatch(stored_hash) is None:
            problems.append(AuditProblem(AUDIT_CHAIN_INVALID, "audit record hash is invalid", index))
        else:
            expected_hash = record_hash(record)
            if stored_hash != expected_hash:
                problems.append(
                    AuditProblem(
                        AUDIT_CHAIN_INVALID,
                        "audit record hash does not match its payload",
                        index,
                    )
                )
            previous = stored_hash
        problems.extend(_audit_event_errors(record, index))

    head = None
    if records:
        last_record = records[-1]
        if isinstance(last_record, Mapping):
            last_hash = last_record.get("record_hash")
            if isinstance(last_hash, str):
                head = last_hash
    anchored = checkpoint is not None
    limitations = [
        "A local audit chain is tamper-evident, not immutable: an attacker with write access "
        "to both the evidence and the chain can recompute every hash.",
    ]
    if checkpoint is None:
        limitations.append(
            "No trusted checkpoint was supplied; chain termination and external anchoring were not checked."
        )
    else:
        if len(records) != checkpoint["record_count"]:
            if len(records) < checkpoint["record_count"]:
                detail = "audit chain ended before the trusted checkpoint"
            else:
                detail = "audit chain contains records beyond the trusted checkpoint"
            problems.append(AuditProblem(AUDIT_CHAIN_INVALID, detail))
        if head != checkpoint["final_record_hash"]:
            problems.append(
                AuditProblem(AUDIT_CHAIN_INVALID, "audit chain head does not match the trusted checkpoint")
            )
        if records:
            last = records[-1]
            if isinstance(last, Mapping):
                if last.get("event_id") != checkpoint["final_event_id"]:
                    problems.append(
                        AuditProblem(
                            AUDIT_CHAIN_INVALID,
                            "audit chain final event does not match the trusted checkpoint",
                        )
                    )
                if last.get("timestamp") != checkpoint["final_timestamp"]:
                    problems.append(
                        AuditProblem(
                            AUDIT_CHAIN_INVALID,
                            "audit chain final timestamp does not match the trusted checkpoint",
                        )
                    )

    outcome = FAIL if problems else PASS
    return AuditVerification(
        outcome=outcome,
        record_count=len(records),
        head=head,
        anchored=anchored,
        checkpoint=checkpoint,
        problems=problems,
        limitations=limitations,
        event_counts=dict(sorted(event_counts.items())),
    )


@dataclass(frozen=True)
class FileDigest:
    """Stable metadata for bytes read from one evidence file."""

    sha256: str
    size: int
    mtime_ns: int
    inode: int
    device: int


def hash_evidence_file(path: Path, *, max_bytes: int = MAX_VERIFY_BYTES) -> FileDigest:
    """Hash a regular file through a descriptor and reject mid-read changes.

    ``O_NOFOLLOW`` is used where the platform supports it, and the descriptor's
    metadata is compared before and after the read. The path is re-stat'ed after
    closing. These checks reduce, but do not eliminate, check-then-open races on
    platforms without descriptor-relative path walking.
    """
    path = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise EvidencePathError("evidence file could not be opened", code=UNAVAILABLE) from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise EvidencePathError("evidence path is not a regular file", code=EVIDENCE_REJECTED)
        if before.st_size > max_bytes:
            raise EvidencePathError(
                "evidence file exceeds the verification size limit",
                code=UNAVAILABLE,
            )
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > max_bytes:
                raise EvidencePathError(
                    "evidence file exceeds the verification size limit",
                    code=UNAVAILABLE,
                )
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    if (
        before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_ino != after.st_ino
        or before.st_dev != after.st_dev
        or size != after.st_size
    ):
        raise EvidenceChangedDuringVerification("evidence file changed during verification")
    try:
        final = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise EvidenceChangedDuringVerification("evidence file disappeared during verification") from exc
    if (
        final.st_size != after.st_size
        or final.st_mtime_ns != after.st_mtime_ns
        or final.st_ino != after.st_ino
        or final.st_dev != after.st_dev
    ):
        raise EvidenceChangedDuringVerification("evidence file was replaced during verification")
    return FileDigest(
        sha256=f"sha256:{digest.hexdigest()}",
        size=size,
        mtime_ns=after.st_mtime_ns,
        inode=after.st_ino,
        device=after.st_dev,
    )


def evidence_record_for_file(
    *,
    evidence_id: str,
    kind: str,
    root: Path,
    relative_path: str,
    parent_id: str | None,
    created_at: str | datetime | None = None,
) -> EvidenceRecord:
    """Hash an existing evidence file and return its deterministic record."""
    resolved = resolve_evidence_path(root, relative_path)
    if not resolved.is_file():
        raise EvidencePathError("evidence file is missing", code=EVIDENCE_MISSING)
    digest = hash_evidence_file(resolved)
    return EvidenceRecord(
        evidence_id=evidence_id,
        kind=kind,
        path=validate_relative_path(relative_path),
        sha256=digest.sha256,
        size=digest.size,
        created_at=normalize_timestamp(created_at or utc_now_iso()),
        parent_id=parent_id,
    )


def sha256_path(path: Path) -> str:
    """Hash a file using the existing release helper (for non-security paths)."""
    return sha256_file(Path(path))


def summarize_chain(records: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Return a compact, sanitized chain summary."""
    items = list(records)
    if not items:
        return {"record_count": 0, "head": None, "event_counts": {}}
    counts: dict[str, int] = {}
    for record in items:
        event_type = str(record.get("event_type"))
        counts[event_type] = counts.get(event_type, 0) + 1
    return {
        "record_count": len(items),
        "head": items[-1].get("record_hash"),
        "event_counts": dict(sorted(counts.items())),
    }
