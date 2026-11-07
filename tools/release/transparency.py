"""V32 append-only transparency log, signed tree heads, receipts, and providers.

The V32 transparency layer is deliberately separate from V30 evidence integrity
and V31 checkpoint authenticity:

* V30 proves retained evidence still matches its recorded digests and that the
  local audit chain is internally consistent.
* V31 proves who produced a checkpoint through an Ed25519 signature and an
  independently configured trust store.
* V32 proves that a checkpoint reference is included in an append-only log and
  that later tree heads are consistent with earlier tree heads.

A local transparency log is **not** independently immutable. An attacker who can
rewrite the log, the signed tree heads, the local trust state, and the local
receipt store can rewrite all of them. V32 reports reduced assurance unless a
genuinely configured and verified external provider supplies an independent
receipt. V32 ships only a local deterministic test provider; it never contacts a
network service, cloud KMS, GitHub, GHCR, staging system, or production endpoint,
and it never describes a simulated receipt as external anchoring.

The log stores checkpoint references and cryptographic digests only. It never
stores a private key, credential, raw evidence body, or external service token.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from backend.app.core.redaction import redact_structure, redact_text
from tools.release.identity import DIGEST_PATTERN
from tools.release.integrity import (
    IntegrityError,
    canonical_json_bytes,
    normalize_timestamp,
    sha256_bytes,
)
from tools.release.manifest import utc_now_iso
from tools.release.merkle import (
    EMPTY_ROOT,
    MAX_MERKLE_LEAVES,
    MAX_PROOF_BYTES,
    MERKLE_ALGORITHM,
    ConsistencyProof,
    InclusionProof,
    MerkleError,
    MerkleTree,
    loads_strict,
    validate_json_depth,
    verify_consistency_proof,
)
from tools.release.trust import (
    KEY_PURPOSE_TRANSPARENCY_TREE_HEAD,
    SIGNATURE_ALGORITHM,
    SUPPORTED_SIGNATURE_ALGORITHMS,
    KeyStatus,
    TrustError,
    TrustStore,
    TrustUnavailable,
    decode_public_key,
    encode_public_key,
    evaluate_key_status,
    load_private_key,
    load_signed_checkpoint,
    load_trust_store,
    public_key_fingerprint,
)
from tools.release.verification import FAIL, NOT_RUN, PASS, UNAVAILABLE

TRANSPARENCY_LOG_SCHEMA_VERSION = 1
TRANSPARENCY_LOG_PROFILE = "evidence_transparency_log"
TRANSPARENCY_LOG_ENTRY_PROFILE = "evidence_transparency_log_entry"
TRANSPARENCY_LOG_ENTRY_TYPE_CHECKPOINT = "CHECKPOINT_APPENDED"
TRANSPARENCY_LOG_ENTRY_TYPES = (TRANSPARENCY_LOG_ENTRY_TYPE_CHECKPOINT,)
TRANSPARENCY_LOG_HASH_ALGORITHM = "sha256"
TRANSPARENCY_LOG_MERKLE_ALGORITHM = MERKLE_ALGORITHM
TRANSPARENCY_LOG_GENESIS_PREVIOUS = "sha256:" + ("0" * 64)

TREE_HEAD_SCHEMA_VERSION = 1
TREE_HEAD_PROFILE = "transparency_tree_head_signed"
TREE_HEAD_DOMAIN = b"industrial-vision-platform:transparency-tree-head:v1\x00"
TREE_HEAD_SIGNATURE_ENCODING = "hex"
TREE_HEAD_PAYLOAD_FIELDS = (
    "schema_version",
    "profile",
    "tree_head_id",
    "log_id",
    "tree_size",
    "merkle_root",
    "timestamp",
    "hash_algorithm",
    "signature_algorithm",
    "key_id",
    "public_key_fingerprint",
    "public_key",
)
TREE_HEAD_FIELDS = (
    *TREE_HEAD_PAYLOAD_FIELDS,
    "payload_digest",
    "signature_encoding",
    "signature",
)

TRANSPARENCY_STATE_SCHEMA_VERSION = 1
TRANSPARENCY_STATE_PROFILE = "transparency_trust_state"
TRANSPARENCY_STATE_ENTRY_FIELDS = (
    "log_id",
    "tree_head_id",
    "tree_size",
    "merkle_root",
    "tree_head_digest",
    "timestamp",
    "key_id",
)
TRANSPARENCY_STATE_FIELDS = (
    "schema_version",
    "profile",
    "updated_at",
    "tree_heads",
    "state_digest",
)

RECEIPT_SCHEMA_VERSION = 1
RECEIPT_PROFILE = "transparency_anchor_receipt"
RECEIPT_DOMAIN = b"industrial-vision-platform:transparency-anchor-receipt:v1\x00"
RECEIPT_PAYLOAD_FIELDS = (
    "schema_version",
    "profile",
    "receipt_id",
    "provider_id",
    "provider_type",
    "anchor_status",
    "log_id",
    "tree_size",
    "merkle_root",
    "tree_head_id",
    "tree_head_digest",
    "receipt_timestamp",
    "signature_algorithm",
    "key_id",
    "public_key_fingerprint",
    "public_key",
)
RECEIPT_FIELDS = (
    *RECEIPT_PAYLOAD_FIELDS,
    "payload_digest",
    "signature_encoding",
    "signature",
)
PROVIDER_PROFILE = "transparency_anchor_provider"
PROVIDER_TYPE_LOCAL_TEST = "local_test"
PROVIDER_TYPE_EXTERNAL = "external"

ANCHOR_SIMULATED = "SIMULATED"
ANCHOR_NOT_CONFIGURED = "NOT_CONFIGURED"
ANCHOR_UNAVAILABLE = "UNAVAILABLE"
ANCHOR_EXTERNAL_VERIFIED = "EXTERNAL_VERIFIED"
ANCHOR_STATUSES = (
    ANCHOR_SIMULATED,
    ANCHOR_NOT_CONFIGURED,
    ANCHOR_UNAVAILABLE,
    ANCHOR_EXTERNAL_VERIFIED,
)

MAX_LOG_BYTES = 64 * 1024 * 1024
MAX_LOG_ENTRIES = MAX_MERKLE_LEAVES
MAX_LOG_LINE_BYTES = 64 * 1024
MAX_TREE_HEAD_BYTES = 1024 * 1024
MAX_RECEIPT_BYTES = 1024 * 1024
MAX_TRANSPARENCY_STATE_BYTES = 16 * 1024 * 1024
MAX_TRANSPARENCY_STATE_ENTRIES = 10_000
MAX_RECEIPT_AGE_SECONDS = 7 * 24 * 60 * 60
MAX_RECEIPT_CLOCK_SKEW_SECONDS = 300
DEFAULT_LOG_ID = "local-evidence-log"

SAFE_LOG_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
SAFE_KEY_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
SAFE_PROVIDER_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
CHECKPOINT_ID_PATTERN = re.compile(r"^chk-[0-9a-f]{32}$")
LOG_ENTRY_ID_PATTERN = re.compile(r"^tle-[0-9a-f]{32}$")
TREE_HEAD_ID_PATTERN = re.compile(r"^sth-[0-9a-f]{32}$")
RECEIPT_ID_PATTERN = re.compile(r"^rcpt-[0-9a-f]{32}$")
PUBLIC_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
SIGNATURE_HEX_PATTERN = re.compile(r"^[0-9a-f]{128}$")
CONTROL_CHARACTER = re.compile(r"[\x00-\x1f\x7f]")
TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

# Stable reason codes. They are additive to the V30/V31 exit-code contract.
TRANSPARENCY_LOG_SCHEMA_INVALID = "TRANSPARENCY_LOG_SCHEMA_INVALID"
TRANSPARENCY_LOG_HEADER_INVALID = "TRANSPARENCY_LOG_HEADER_INVALID"
TRANSPARENCY_LOG_ENTRY_INVALID = "TRANSPARENCY_LOG_ENTRY_INVALID"
TRANSPARENCY_LOG_INDEX_INVALID = "TRANSPARENCY_LOG_INDEX_INVALID"
TRANSPARENCY_LOG_CHAIN_INVALID = "TRANSPARENCY_LOG_CHAIN_INVALID"
TRANSPARENCY_LOG_DUPLICATE = "TRANSPARENCY_LOG_DUPLICATE"
TRANSPARENCY_LOG_SEQUENCE_INVALID = "TRANSPARENCY_LOG_SEQUENCE_INVALID"
TRANSPARENCY_LOG_TIMESTAMP_INVALID = "TRANSPARENCY_LOG_TIMESTAMP_INVALID"
TRANSPARENCY_LOG_TOO_LARGE = "TRANSPARENCY_LOG_TOO_LARGE"
TRANSPARENCY_LOG_UNAVAILABLE = "TRANSPARENCY_LOG_UNAVAILABLE"
TRANSPARENCY_LOG_TREE_HEAD_MISMATCH = "TRANSPARENCY_LOG_TREE_HEAD_MISMATCH"
TREE_HEAD_SCHEMA_INVALID = "TREE_HEAD_SCHEMA_INVALID"
TREE_HEAD_ID_MISMATCH = "TREE_HEAD_ID_MISMATCH"
TREE_HEAD_PAYLOAD_DIGEST_MISMATCH = "TREE_HEAD_PAYLOAD_DIGEST_MISMATCH"
TREE_HEAD_ALGORITHM_UNKNOWN = "TREE_HEAD_ALGORITHM_UNKNOWN"
TREE_HEAD_SIGNATURE_MALFORMED = "TREE_HEAD_SIGNATURE_MALFORMED"
TREE_HEAD_SIGNATURE_MISMATCH = "TREE_HEAD_SIGNATURE_MISMATCH"
TREE_HEAD_KEY_UNKNOWN = "TREE_HEAD_KEY_UNKNOWN"
TREE_HEAD_KEY_UNTRUSTED = "TREE_HEAD_KEY_UNTRUSTED"
TREE_HEAD_KEY_PURPOSE_INVALID = "TREE_HEAD_KEY_PURPOSE_INVALID"
TREE_HEAD_KEY_REVOKED = "TREE_HEAD_KEY_REVOKED"
TREE_HEAD_KEY_EXPIRED = "TREE_HEAD_KEY_EXPIRED"
TREE_HEAD_KEY_NOT_YET_VALID = "TREE_HEAD_KEY_NOT_YET_VALID"
TREE_HEAD_KEY_ALGORITHM_DISALLOWED = "TREE_HEAD_KEY_ALGORITHM_DISALLOWED"
TREE_HEAD_REPLAY = "TREE_HEAD_REPLAY"
TREE_HEAD_DUPLICATE = "TREE_HEAD_DUPLICATE"
TREE_HEAD_CONFLICT = "TREE_HEAD_CONFLICT"
TREE_ROOT_CONFLICT = "TREE_ROOT_CONFLICT"
TREE_SIZE_ROLLBACK = "TREE_SIZE_ROLLBACK"
TREE_HEAD_TIMESTAMP_REGRESSION = "TREE_HEAD_TIMESTAMP_REGRESSION"
CONSISTENCY_PROOF_MISSING = "CONSISTENCY_PROOF_MISSING"
CONSISTENCY_PROOF_INVALID = "CONSISTENCY_PROOF_INVALID"
TRANSPARENCY_STATE_INVALID = "TRANSPARENCY_STATE_INVALID"
TRANSPARENCY_STATE_MISSING = "TRANSPARENCY_STATE_MISSING"
TREE_HEAD_TRUST_STORE_MISSING = "TREE_HEAD_TRUST_STORE_MISSING"
RECEIPT_SCHEMA_INVALID = "RECEIPT_SCHEMA_INVALID"
RECEIPT_ID_MISMATCH = "RECEIPT_ID_MISMATCH"
RECEIPT_PAYLOAD_DIGEST_MISMATCH = "RECEIPT_PAYLOAD_DIGEST_MISMATCH"
RECEIPT_PROVIDER_MISMATCH = "RECEIPT_PROVIDER_MISMATCH"
RECEIPT_LOG_MISMATCH = "RECEIPT_LOG_MISMATCH"
RECEIPT_TREE_SIZE_MISMATCH = "RECEIPT_TREE_SIZE_MISMATCH"
RECEIPT_ROOT_MISMATCH = "RECEIPT_ROOT_MISMATCH"
RECEIPT_TREE_HEAD_MISMATCH = "RECEIPT_TREE_HEAD_MISMATCH"
RECEIPT_SIGNATURE_MALFORMED = "RECEIPT_SIGNATURE_MALFORMED"
RECEIPT_SIGNATURE_MISMATCH = "RECEIPT_SIGNATURE_MISMATCH"
RECEIPT_STALE = "RECEIPT_STALE"
RECEIPT_TIMESTAMP_INVALID = "RECEIPT_TIMESTAMP_INVALID"
RECEIPT_UNSIGNED = "RECEIPT_UNSIGNED"
RECEIPT_STATUS_INVALID = "RECEIPT_STATUS_INVALID"
PROVIDER_NOT_CONFIGURED = "PROVIDER_NOT_CONFIGURED"
PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
PROVIDER_UNKNOWN = "PROVIDER_UNKNOWN"


class TransparencyError(ValueError):
    """A transparency-log, tree-head, receipt, or provider request is invalid."""

    def __init__(self, message: str, *, reason_code: str = TRANSPARENCY_LOG_SCHEMA_INVALID) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class TransparencyUnavailable(TransparencyError):
    """A required transparency input is missing or unreadable."""


class TransparencyInvalid(TransparencyError):
    """A transparency input exists but is malformed."""


class TransparencyConflict(TransparencyError):
    """A transparency operation conflicts with recorded or configured state."""


class ProviderUnavailable(TransparencyError):
    """A configured provider could not be reached or read."""


class ProviderUnknown(TransparencyError):
    """A provider name is not supported."""


def _canonical_bytes(value: Any) -> bytes:
    try:
        return canonical_json_bytes(value)
    except IntegrityError as exc:
        raise TransparencyInvalid("metadata cannot be serialized deterministically") from exc


def _safe_text(
    value: Any,
    *,
    field_name: str,
    pattern: re.Pattern[str] | None = None,
    reason_code: str = TRANSPARENCY_LOG_SCHEMA_INVALID,
) -> str:
    if not isinstance(value, str) or not value:
        raise TransparencyInvalid(f"{field_name} must be a non-empty string", reason_code=reason_code)
    if CONTROL_CHARACTER.search(value):
        raise TransparencyInvalid(f"{field_name} contains a control character", reason_code=reason_code)
    if pattern is not None and pattern.fullmatch(value) is None:
        raise TransparencyInvalid(f"{field_name} contains unsupported characters", reason_code=reason_code)
    return value


def _timestamp(value: Any, *, field_name: str, reason_code: str = TRANSPARENCY_LOG_TIMESTAMP_INVALID) -> str:
    try:
        normalized = normalize_timestamp(value)
    except IntegrityError as exc:
        raise TransparencyInvalid(
            f"{field_name} is not a valid UTC timestamp", reason_code=reason_code
        ) from exc
    if normalized != value:
        raise TransparencyInvalid(
            f"{field_name} must be canonical UTC with second precision", reason_code=reason_code
        )
    return normalized


def _digest(value: Any, *, field_name: str, reason_code: str = TRANSPARENCY_LOG_SCHEMA_INVALID) -> str:
    if not isinstance(value, str) or DIGEST_PATTERN.fullmatch(value) is None:
        raise TransparencyInvalid(f"{field_name} must be sha256:<64 lowercase hex>", reason_code=reason_code)
    return value


def _int(
    value: Any,
    *,
    field_name: str,
    minimum: int,
    maximum: int | None = None,
    reason_code: str = TRANSPARENCY_LOG_SCHEMA_INVALID,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise TransparencyInvalid(f"{field_name} must be an integer >= {minimum}", reason_code=reason_code)
    if maximum is not None and value > maximum:
        raise TransparencyInvalid(f"{field_name} exceeds the supported maximum", reason_code=reason_code)
    return value


def _exact_fields(
    payload: Mapping[str, Any], expected: tuple[str, ...], *, label: str, reason_code: str
) -> None:
    if sorted(payload) != sorted(expected):
        raise TransparencyInvalid(f"{label} has unexpected or missing fields", reason_code=reason_code)


def _read_json_strict(
    path: Path,
    *,
    label: str,
    max_bytes: int,
    invalid_reason: str,
    missing_reason: str,
) -> dict[str, Any]:
    path = Path(path)
    try:
        if not path.is_file():
            raise TransparencyUnavailable(f"{label} is missing or unreadable", reason_code=missing_reason)
        size = path.stat().st_size
    except OSError as exc:
        raise TransparencyUnavailable(
            f"{label} is missing or unreadable", reason_code=missing_reason
        ) from exc
    if size > max_bytes:
        raise TransparencyInvalid(f"{label} exceeds the maximum supported size", reason_code=invalid_reason)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise TransparencyUnavailable(f"{label} is unreadable", reason_code=missing_reason) from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TransparencyInvalid(f"{label} is not valid UTF-8", reason_code=invalid_reason) from exc
    try:
        payload = loads_strict(text)
    except MerkleError as exc:
        raise TransparencyInvalid(f"{label} is not valid JSON", reason_code=invalid_reason) from exc
    if not isinstance(payload, dict):
        raise TransparencyInvalid(f"{label} must be a JSON object", reason_code=invalid_reason)
    try:
        validate_json_depth(payload)
    except MerkleError as exc:
        raise TransparencyInvalid(
            f"{label} nesting depth exceeds the supported limit", reason_code=invalid_reason
        ) from exc
    return payload


def _write_json_atomic(path: Path, payload: Mapping[str, Any], *, overwrite: bool, mode: int) -> None:
    path = Path(path)
    if path.exists() and not overwrite:
        raise TransparencyConflict("refusing to overwrite an existing file")
    try:
        data = json.dumps(payload, allow_nan=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    except (TypeError, ValueError) as exc:
        raise TransparencyInvalid("metadata cannot be serialized deterministically") from exc
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except OSError as exc:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise TransparencyError("file could not be written atomically") from exc


# ---------------------------------------------------------------------------
# Append-only transparency log
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TransparencyLogHeader:
    """Strict header for one append-only transparency log."""

    log_id: str
    created_at: str
    schema_version: int = TRANSPARENCY_LOG_SCHEMA_VERSION
    profile: str = TRANSPARENCY_LOG_PROFILE
    hash_algorithm: str = TRANSPARENCY_LOG_HASH_ALGORITHM
    merkle_algorithm: str = TRANSPARENCY_LOG_MERKLE_ALGORITHM

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "profile": self.profile,
            "log_id": self.log_id,
            "hash_algorithm": self.hash_algorithm,
            "merkle_algorithm": self.merkle_algorithm,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> TransparencyLogHeader:
        if not isinstance(payload, Mapping):
            raise TransparencyInvalid(
                "transparency log header must be a mapping",
                reason_code=TRANSPARENCY_LOG_HEADER_INVALID,
            )
        validate_json_depth(payload)
        _exact_fields(
            payload,
            (
                "schema_version",
                "profile",
                "log_id",
                "hash_algorithm",
                "merkle_algorithm",
                "created_at",
            ),
            label="transparency log header",
            reason_code=TRANSPARENCY_LOG_HEADER_INVALID,
        )
        if payload.get("schema_version") != TRANSPARENCY_LOG_SCHEMA_VERSION:
            raise TransparencyInvalid(
                "transparency log schema_version is unsupported",
                reason_code=TRANSPARENCY_LOG_HEADER_INVALID,
            )
        if payload.get("profile") != TRANSPARENCY_LOG_PROFILE:
            raise TransparencyInvalid(
                "transparency log profile is unsupported",
                reason_code=TRANSPARENCY_LOG_HEADER_INVALID,
            )
        if payload.get("hash_algorithm") != TRANSPARENCY_LOG_HASH_ALGORITHM:
            raise TransparencyInvalid(
                "transparency log hash algorithm is unsupported",
                reason_code=TRANSPARENCY_LOG_HEADER_INVALID,
            )
        if payload.get("merkle_algorithm") != TRANSPARENCY_LOG_MERKLE_ALGORITHM:
            raise TransparencyInvalid(
                "transparency log Merkle algorithm is unsupported",
                reason_code=TRANSPARENCY_LOG_HEADER_INVALID,
            )
        return cls(
            log_id=_safe_text(
                payload.get("log_id"),
                field_name="log_id",
                pattern=SAFE_LOG_ID,
                reason_code=TRANSPARENCY_LOG_HEADER_INVALID,
            ),
            created_at=_timestamp(
                payload.get("created_at"),
                field_name="created_at",
                reason_code=TRANSPARENCY_LOG_HEADER_INVALID,
            ),
        )


def derive_log_entry_id(payload: Mapping[str, Any]) -> str:
    """Derive a deterministic entry identifier from every field except itself."""
    body = {key: value for key, value in payload.items() if key != "entry_id"}
    return f"tle-{hashlib.sha256(_canonical_bytes(body)).hexdigest()[:32]}"


@dataclass(frozen=True)
class TransparencyLogEntry:
    """One checkpoint reference stored in the append-only log."""

    entry_index: int
    entry_id: str
    checkpoint_id: str
    checkpoint_sequence: int
    checkpoint_digest: str
    previous_entry_digest: str
    timestamp: str
    entry_type: str = TRANSPARENCY_LOG_ENTRY_TYPE_CHECKPOINT
    schema_version: int = TRANSPARENCY_LOG_SCHEMA_VERSION
    profile: str = TRANSPARENCY_LOG_ENTRY_PROFILE

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "profile": self.profile,
            "entry_index": self.entry_index,
            "entry_id": self.entry_id,
            "entry_type": self.entry_type,
            "checkpoint_id": self.checkpoint_id,
            "checkpoint_sequence": self.checkpoint_sequence,
            "checkpoint_digest": self.checkpoint_digest,
            "previous_entry_digest": self.previous_entry_digest,
            "timestamp": self.timestamp,
        }

    def canonical_bytes(self) -> bytes:
        return _canonical_bytes(self.to_dict())

    def digest(self) -> str:
        return sha256_bytes(self.canonical_bytes())

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> TransparencyLogEntry:
        if not isinstance(payload, Mapping):
            raise TransparencyInvalid(
                "transparency log entry must be a mapping",
                reason_code=TRANSPARENCY_LOG_ENTRY_INVALID,
            )
        validate_json_depth(payload)
        _exact_fields(
            payload,
            (
                "schema_version",
                "profile",
                "entry_index",
                "entry_id",
                "entry_type",
                "checkpoint_id",
                "checkpoint_sequence",
                "checkpoint_digest",
                "previous_entry_digest",
                "timestamp",
            ),
            label="transparency log entry",
            reason_code=TRANSPARENCY_LOG_ENTRY_INVALID,
        )
        if payload.get("schema_version") != TRANSPARENCY_LOG_SCHEMA_VERSION:
            raise TransparencyInvalid(
                "transparency log entry schema_version is unsupported",
                reason_code=TRANSPARENCY_LOG_ENTRY_INVALID,
            )
        if payload.get("profile") != TRANSPARENCY_LOG_ENTRY_PROFILE:
            raise TransparencyInvalid(
                "transparency log entry profile is unsupported",
                reason_code=TRANSPARENCY_LOG_ENTRY_INVALID,
            )
        entry_type = payload.get("entry_type")
        if entry_type not in TRANSPARENCY_LOG_ENTRY_TYPES:
            raise TransparencyInvalid(
                "transparency log entry type is unsupported",
                reason_code=TRANSPARENCY_LOG_ENTRY_INVALID,
            )
        entry_index = _int(
            payload.get("entry_index"),
            field_name="entry_index",
            minimum=0,
            maximum=MAX_LOG_ENTRIES - 1,
            reason_code=TRANSPARENCY_LOG_INDEX_INVALID,
        )
        entry_id = _safe_text(
            payload.get("entry_id"),
            field_name="entry_id",
            pattern=LOG_ENTRY_ID_PATTERN,
            reason_code=TRANSPARENCY_LOG_ENTRY_INVALID,
        )
        checkpoint_id = _safe_text(
            payload.get("checkpoint_id"),
            field_name="checkpoint_id",
            pattern=CHECKPOINT_ID_PATTERN,
            reason_code=TRANSPARENCY_LOG_ENTRY_INVALID,
        )
        sequence = _int(
            payload.get("checkpoint_sequence"),
            field_name="checkpoint_sequence",
            minimum=1,
            reason_code=TRANSPARENCY_LOG_SEQUENCE_INVALID,
        )
        checkpoint_digest = _digest(
            payload.get("checkpoint_digest"),
            field_name="checkpoint_digest",
            reason_code=TRANSPARENCY_LOG_ENTRY_INVALID,
        )
        previous_digest = _digest(
            payload.get("previous_entry_digest"),
            field_name="previous_entry_digest",
            reason_code=TRANSPARENCY_LOG_CHAIN_INVALID,
        )
        timestamp = _timestamp(payload.get("timestamp"), field_name="timestamp")
        if entry_id != derive_log_entry_id(payload):
            raise TransparencyInvalid(
                "transparency log entry identifier does not match its payload",
                reason_code=TRANSPARENCY_LOG_ENTRY_INVALID,
            )
        return cls(
            entry_index=entry_index,
            entry_id=entry_id,
            checkpoint_id=checkpoint_id,
            checkpoint_sequence=sequence,
            checkpoint_digest=checkpoint_digest,
            previous_entry_digest=previous_digest,
            timestamp=timestamp,
            entry_type=entry_type,
        )


@dataclass(frozen=True)
class TransparencyLog:
    """A validated transparency log header and ordered entries."""

    header: TransparencyLogHeader
    entries: tuple[TransparencyLogEntry, ...]

    @property
    def log_id(self) -> str:
        return self.header.log_id

    @property
    def tree_size(self) -> int:
        return len(self.entries)

    @property
    def merkle_root(self) -> str:
        tree = MerkleTree([entry.canonical_bytes() for entry in self.entries], log_id=self.log_id)
        return tree.root

    def tree(self) -> MerkleTree:
        return MerkleTree([entry.canonical_bytes() for entry in self.entries], log_id=self.log_id)


def build_log_entry(
    *,
    entry_index: int,
    checkpoint_id: str,
    checkpoint_sequence: int,
    checkpoint_digest: str,
    previous_entry_digest: str,
    timestamp: str,
    entry_type: str = TRANSPARENCY_LOG_ENTRY_TYPE_CHECKPOINT,
) -> TransparencyLogEntry:
    """Build and validate one deterministic log entry."""
    payload = {
        "schema_version": TRANSPARENCY_LOG_SCHEMA_VERSION,
        "profile": TRANSPARENCY_LOG_ENTRY_PROFILE,
        "entry_index": entry_index,
        "entry_type": entry_type,
        "checkpoint_id": checkpoint_id,
        "checkpoint_sequence": checkpoint_sequence,
        "checkpoint_digest": checkpoint_digest,
        "previous_entry_digest": previous_entry_digest,
        "timestamp": timestamp,
    }
    payload["entry_id"] = derive_log_entry_id(payload)
    return TransparencyLogEntry.from_dict(payload)


def checkpoint_document_digest(checkpoint: Mapping[str, Any]) -> str:
    """Return the SHA-256 of the canonical full signed-checkpoint document."""
    return sha256_bytes(_canonical_bytes(checkpoint))


def _parse_log_line(raw: bytes, *, label: str, reason_code: str) -> dict[str, Any]:
    if not raw:
        raise TransparencyInvalid(f"{label} is empty", reason_code=reason_code)
    if len(raw) > MAX_LOG_LINE_BYTES:
        raise TransparencyInvalid(f"{label} exceeds the maximum line size", reason_code=reason_code)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TransparencyInvalid(f"{label} is not valid UTF-8", reason_code=reason_code) from exc
    try:
        payload = loads_strict(text)
    except MerkleError as exc:
        raise TransparencyInvalid(f"{label} is not valid JSON", reason_code=reason_code) from exc
    if not isinstance(payload, dict):
        raise TransparencyInvalid(f"{label} must be a JSON object", reason_code=reason_code)
    try:
        validate_json_depth(payload)
    except MerkleError as exc:
        raise TransparencyInvalid(
            f"{label} nesting depth exceeds the supported limit", reason_code=reason_code
        ) from exc
    return payload


def read_log(path: Path) -> TransparencyLog:
    """Read and strictly validate a JSONL transparency log."""
    path = Path(path)
    try:
        if not path.is_file():
            raise TransparencyUnavailable(
                "transparency log is missing or unreadable",
                reason_code=TRANSPARENCY_LOG_UNAVAILABLE,
            )
        size = path.stat().st_size
    except OSError as exc:
        raise TransparencyUnavailable(
            "transparency log is missing or unreadable",
            reason_code=TRANSPARENCY_LOG_UNAVAILABLE,
        ) from exc
    if size > MAX_LOG_BYTES:
        raise TransparencyInvalid(
            "transparency log exceeds the maximum supported size",
            reason_code=TRANSPARENCY_LOG_TOO_LARGE,
        )
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise TransparencyUnavailable(
            "transparency log is unreadable",
            reason_code=TRANSPARENCY_LOG_UNAVAILABLE,
        ) from exc
    if not raw:
        raise TransparencyInvalid(
            "transparency log is empty and has no header",
            reason_code=TRANSPARENCY_LOG_HEADER_INVALID,
        )
    if b"\r" in raw:
        raise TransparencyInvalid(
            "transparency log must use LF line endings without carriage returns",
            reason_code=TRANSPARENCY_LOG_SCHEMA_INVALID,
        )
    if not raw.endswith(b"\n"):
        raise TransparencyInvalid(
            "transparency log does not end with a complete line",
            reason_code=TRANSPARENCY_LOG_SCHEMA_INVALID,
        )
    lines = raw.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    if not lines:
        raise TransparencyInvalid(
            "transparency log is empty and has no header",
            reason_code=TRANSPARENCY_LOG_HEADER_INVALID,
        )
    if any(line == b"" for line in lines):
        raise TransparencyInvalid(
            "transparency log contains a blank line",
            reason_code=TRANSPARENCY_LOG_SCHEMA_INVALID,
        )
    if len(lines) - 1 > MAX_LOG_ENTRIES:
        raise TransparencyInvalid(
            "transparency log exceeds the maximum supported entry count",
            reason_code=TRANSPARENCY_LOG_TOO_LARGE,
        )
    header = TransparencyLogHeader.from_dict(
        _parse_log_line(
            lines[0],
            label="transparency log header",
            reason_code=TRANSPARENCY_LOG_HEADER_INVALID,
        )
    )
    entries = tuple(
        TransparencyLogEntry.from_dict(
            _parse_log_line(
                line,
                label=f"transparency log entry {index}",
                reason_code=TRANSPARENCY_LOG_ENTRY_INVALID,
            )
        )
        for index, line in enumerate(lines[1:])
    )
    return TransparencyLog(header=header, entries=entries)


@dataclass(frozen=True)
class TransparencyCheck:
    """One stable transparency verification check."""

    name: str
    outcome: str
    detail: str
    reason_code: str | None = None
    required: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "outcome": self.outcome,
            "detail": redact_text(self.detail)[:500],
            "reason_code": self.reason_code,
            "required": self.required,
        }


@dataclass
class LogVerification:
    """Result of verifying a complete transparency log."""

    outcome: str = NOT_RUN
    log_id: str | None = None
    tree_size: int = 0
    merkle_root: str | None = None
    head_entry_digest: str | None = None
    checks: list[TransparencyCheck] = field(default_factory=list)
    reason_codes: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    entries: list[TransparencyLogEntry] = field(default_factory=list, repr=False)

    def add(self, check: TransparencyCheck) -> TransparencyCheck:
        self.checks.append(check)
        return check

    def finalize(self) -> LogVerification:
        required = [check for check in self.checks if check.required]
        outcomes = {check.outcome for check in required}
        for state in (FAIL, UNAVAILABLE, NOT_RUN):
            if state in outcomes:
                self.outcome = state
                break
        else:
            self.outcome = PASS if required else NOT_RUN
        codes: list[str] = []
        for check in self.checks:
            if check.reason_code is not None and check.outcome != PASS and check.reason_code not in codes:
                codes.append(check.reason_code)
        self.reason_codes = codes
        return self

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "outcome": self.outcome,
            "log_id": self.log_id,
            "tree_size": self.tree_size,
            "merkle_root": self.merkle_root,
            "head_entry_digest": self.head_entry_digest,
            "reason_codes": sorted(set(self.reason_codes)),
            "checks": [check.to_dict() for check in self.checks],
            "limitations": [redact_text(item)[:500] for item in self.limitations],
        }
        cleaned = redact_structure(payload)
        if not isinstance(cleaned, dict):
            raise TransparencyError("log verification result could not be sanitized")
        return cleaned


def verify_log(source: Path | str | TransparencyLog) -> LogVerification:
    """Verify header, entry chain, ordering, uniqueness, and Merkle root."""
    result = LogVerification()
    if isinstance(source, (str, Path)):
        try:
            log = read_log(Path(source))
        except TransparencyUnavailable as exc:
            result.add(
                TransparencyCheck(
                    "transparency-log-read",
                    UNAVAILABLE,
                    str(exc),
                    reason_code=exc.reason_code,
                )
            )
            return result.finalize()
        except TransparencyError as exc:
            result.add(
                TransparencyCheck(
                    "transparency-log-read",
                    FAIL,
                    str(exc),
                    reason_code=exc.reason_code,
                )
            )
            return result.finalize()
    else:
        log = source
    result.log_id = log.log_id
    result.entries = list(log.entries)
    result.add(
        TransparencyCheck(
            "transparency-log-header",
            PASS,
            f"transparency log header is valid for log {log.log_id}",
        )
    )
    previous_digest = TRANSPARENCY_LOG_GENESIS_PREVIOUS
    previous_timestamp: str | None = None
    previous_sequence = 0
    seen_entry_ids: set[str] = set()
    seen_checkpoint_ids: set[str] = set()
    problems = False
    for index, entry in enumerate(log.entries):
        if entry.entry_index != index:
            result.add(
                TransparencyCheck(
                    "transparency-log-index",
                    FAIL,
                    "entry index is missing, duplicated, or reordered",
                    reason_code=TRANSPARENCY_LOG_INDEX_INVALID,
                )
            )
            problems = True
        if entry.entry_id in seen_entry_ids:
            result.add(
                TransparencyCheck(
                    "transparency-log-entry-id",
                    FAIL,
                    "entry identifier is duplicated",
                    reason_code=TRANSPARENCY_LOG_DUPLICATE,
                )
            )
            problems = True
        seen_entry_ids.add(entry.entry_id)
        if entry.checkpoint_id in seen_checkpoint_ids:
            result.add(
                TransparencyCheck(
                    "transparency-log-checkpoint-id",
                    FAIL,
                    "checkpoint identifier is duplicated in the log",
                    reason_code=TRANSPARENCY_LOG_DUPLICATE,
                )
            )
            problems = True
        seen_checkpoint_ids.add(entry.checkpoint_id)
        if entry.previous_entry_digest != previous_digest:
            result.add(
                TransparencyCheck(
                    "transparency-log-chain",
                    FAIL,
                    "entry previous digest does not link to the prior entry",
                    reason_code=TRANSPARENCY_LOG_CHAIN_INVALID,
                )
            )
            problems = True
        if previous_timestamp is not None and entry.timestamp < previous_timestamp:
            result.add(
                TransparencyCheck(
                    "transparency-log-timestamp",
                    FAIL,
                    "entry timestamps are out of order",
                    reason_code=TRANSPARENCY_LOG_TIMESTAMP_INVALID,
                )
            )
            problems = True
        previous_timestamp = entry.timestamp
        if entry.checkpoint_sequence <= previous_sequence:
            result.add(
                TransparencyCheck(
                    "transparency-log-sequence",
                    FAIL,
                    "checkpoint sequences are not strictly increasing",
                    reason_code=TRANSPARENCY_LOG_SEQUENCE_INVALID,
                )
            )
            problems = True
        previous_sequence = entry.checkpoint_sequence
        previous_digest = entry.digest()
    if not problems:
        result.add(
            TransparencyCheck(
                "transparency-log-chain",
                PASS,
                f"all {len(log.entries)} log entr{'y' if len(log.entries) == 1 else 'ies'} "
                "link correctly and are unique",
            )
        )
    result.tree_size = len(log.entries)
    try:
        result.merkle_root = log.merkle_root
    except MerkleError as exc:
        result.add(
            TransparencyCheck(
                "transparency-log-merkle-root",
                FAIL,
                str(exc),
                reason_code=TRANSPARENCY_LOG_SCHEMA_INVALID,
            )
        )
        return result.finalize()
    result.head_entry_digest = log.entries[-1].digest() if log.entries else None
    result.add(
        TransparencyCheck(
            "transparency-log-merkle-root",
            PASS,
            f"Merkle root computed for tree size {result.tree_size}",
        )
    )
    result.limitations.extend(
        [
            "A local transparency log is append-only by convention and hash-linked, but it is not "
            "independently immutable. An attacker with write access to the log can rewrite it.",
            "A Merkle root proves only that the stored checkpoint references hash to that root; it "
            "does not prove that the underlying evidence is truthful or complete.",
        ]
    )
    return result.finalize()


def init_log(
    path: Path,
    *,
    log_id: str = DEFAULT_LOG_ID,
    timestamp: str | None = None,
    overwrite: bool = False,
) -> TransparencyLogHeader:
    """Create a new header-only transparency log."""
    path = Path(path)
    if path.exists() and not overwrite:
        raise TransparencyConflict("refusing to overwrite an existing transparency log")
    header = TransparencyLogHeader(
        log_id=_safe_text(
            log_id,
            field_name="log_id",
            pattern=SAFE_LOG_ID,
            reason_code=TRANSPARENCY_LOG_HEADER_INVALID,
        ),
        created_at=_timestamp(
            timestamp or utc_now_iso(),
            field_name="created_at",
            reason_code=TRANSPARENCY_LOG_HEADER_INVALID,
        ),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    data = _canonical_bytes(header.to_dict()) + b"\n"
    try:
        with path.open("wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise TransparencyUnavailable(
            "transparency log could not be written",
            reason_code=TRANSPARENCY_LOG_UNAVAILABLE,
        ) from exc
    return header


def _read_header_and_last_entry(
    path: Path,
) -> tuple[TransparencyLogHeader, TransparencyLogEntry | None]:
    """Read the header and last entry in O(1) bounded tail space."""
    path = Path(path)
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            header_line = handle.readline(MAX_LOG_LINE_BYTES + 1)
            if len(header_line) > MAX_LOG_LINE_BYTES:
                raise TransparencyInvalid(
                    "transparency log header exceeds the maximum line size",
                    reason_code=TRANSPARENCY_LOG_HEADER_INVALID,
                )
            if not header_line.endswith(b"\n"):
                raise TransparencyInvalid(
                    "transparency log header is incomplete",
                    reason_code=TRANSPARENCY_LOG_HEADER_INVALID,
                )
            header = TransparencyLogHeader.from_dict(
                _parse_log_line(
                    header_line[:-1],
                    label="transparency log header",
                    reason_code=TRANSPARENCY_LOG_HEADER_INVALID,
                )
            )
            if b"\r" in header_line:
                raise TransparencyInvalid(
                    "transparency log must use LF line endings without carriage returns",
                    reason_code=TRANSPARENCY_LOG_SCHEMA_INVALID,
                )
            if size == len(header_line):
                return header, None
            if size < len(header_line):
                raise TransparencyInvalid(
                    "transparency log is truncated",
                    reason_code=TRANSPARENCY_LOG_SCHEMA_INVALID,
                )
            handle.seek(size - 1)
            if handle.read(1) != b"\n":
                raise TransparencyInvalid(
                    "transparency log does not end with a complete line",
                    reason_code=TRANSPARENCY_LOG_SCHEMA_INVALID,
                )
            tail_size = min(size, MAX_LOG_LINE_BYTES + 2)
            handle.seek(size - tail_size)
            tail = handle.read()
    except OSError as exc:
        raise TransparencyUnavailable(
            "transparency log is missing or unreadable",
            reason_code=TRANSPARENCY_LOG_UNAVAILABLE,
        ) from exc
    body = tail[:-1]
    split = body.rfind(b"\n")
    if split >= 0:
        last_line = body[split + 1 :]
    else:
        if size - len(header_line) > MAX_LOG_LINE_BYTES:
            raise TransparencyInvalid(
                "transparency log entry exceeds the maximum line size",
                reason_code=TRANSPARENCY_LOG_SCHEMA_INVALID,
            )
        last_line = body
    entry = TransparencyLogEntry.from_dict(
        _parse_log_line(
            last_line,
            label="transparency log last entry",
            reason_code=TRANSPARENCY_LOG_ENTRY_INVALID,
        )
    )
    return header, entry


def append_checkpoint(
    log_path: Path,
    checkpoint_path: Path,
    *,
    log_id: str | None = None,
    timestamp: str | None = None,
    full_verify: bool = False,
) -> TransparencyLogEntry:
    """Append one V31 signed-checkpoint reference to the log.

    The append validates the checkpoint document and the log tail in ``O(1)``
    bounded space. It does not verify checkpoint signature trust; that is a
    separate V31 operation. Set ``full_verify=True`` to verify the entire log
    before appending at ``O(n)`` cost. Run :func:`verify_log` after appending to
    establish complete chain integrity.
    """
    log_path = Path(log_path)
    checkpoint = load_signed_checkpoint(Path(checkpoint_path))
    digest = checkpoint_document_digest(checkpoint)
    entry_timestamp = _timestamp(
        timestamp or utc_now_iso(),
        field_name="entry timestamp",
        reason_code=TRANSPARENCY_LOG_TIMESTAMP_INVALID,
    )
    if full_verify:
        verification = verify_log(log_path)
        if verification.outcome != PASS:
            raise TransparencyConflict(
                "refusing to append to an invalid transparency log",
                reason_code=TRANSPARENCY_LOG_CHAIN_INVALID,
            )
    if not log_path.exists():
        init_log(
            log_path,
            log_id=log_id or DEFAULT_LOG_ID,
            timestamp=entry_timestamp,
        )
    header, last = _read_header_and_last_entry(log_path)
    if log_id is not None and log_id != header.log_id:
        raise TransparencyConflict(
            "configured log identifier does not match the existing log header",
            reason_code=TRANSPARENCY_LOG_HEADER_INVALID,
        )
    if last is None:
        entry_index = 0
        previous_digest = TRANSPARENCY_LOG_GENESIS_PREVIOUS
    else:
        if entry_timestamp < last.timestamp:
            raise TransparencyConflict(
                "entry timestamp regresses below the prior log entry",
                reason_code=TRANSPARENCY_LOG_TIMESTAMP_INVALID,
            )
        if checkpoint["checkpoint_sequence"] <= last.checkpoint_sequence:
            raise TransparencyConflict(
                "checkpoint sequence is not greater than the prior log entry",
                reason_code=TRANSPARENCY_LOG_SEQUENCE_INVALID,
            )
        entry_index = last.entry_index + 1
        previous_digest = last.digest()
    if entry_index >= MAX_LOG_ENTRIES:
        raise TransparencyConflict(
            "transparency log exceeds the maximum supported entry count",
            reason_code=TRANSPARENCY_LOG_TOO_LARGE,
        )
    entry = build_log_entry(
        entry_index=entry_index,
        checkpoint_id=checkpoint["checkpoint_id"],
        checkpoint_sequence=checkpoint["checkpoint_sequence"],
        checkpoint_digest=digest,
        previous_entry_digest=previous_digest,
        timestamp=entry_timestamp,
    )
    data = _canonical_bytes(entry.to_dict()) + b"\n"
    try:
        with log_path.open("ab") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise TransparencyUnavailable(
            "transparency log entry could not be appended",
            reason_code=TRANSPARENCY_LOG_UNAVAILABLE,
        ) from exc
    return entry


def write_log(
    path: Path,
    header: TransparencyLogHeader,
    entries: Sequence[TransparencyLogEntry],
    *,
    overwrite: bool = False,
) -> None:
    """Write a complete transparency log; used for deterministic fixtures."""
    path = Path(path)
    if path.exists() and not overwrite:
        raise TransparencyConflict("refusing to overwrite an existing transparency log")
    data = _canonical_bytes(header.to_dict()) + b"\n"
    data += b"".join(_canonical_bytes(entry.to_dict()) + b"\n" for entry in entries)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise TransparencyUnavailable(
            "transparency log could not be written",
            reason_code=TRANSPARENCY_LOG_UNAVAILABLE,
        ) from exc


# ---------------------------------------------------------------------------
# Signed transparency tree heads
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TransparencyTreeHead:
    """A validated V32 Ed25519-signed Merkle tree head."""

    tree_head_id: str
    log_id: str
    tree_size: int
    merkle_root: str
    timestamp: str
    key_id: str
    public_key_fingerprint: str
    public_key: str
    payload_digest: str
    signature: str
    schema_version: int = TREE_HEAD_SCHEMA_VERSION
    profile: str = TREE_HEAD_PROFILE
    hash_algorithm: str = TRANSPARENCY_LOG_HASH_ALGORITHM
    signature_algorithm: str = SIGNATURE_ALGORITHM
    signature_encoding: str = TREE_HEAD_SIGNATURE_ENCODING

    def payload(self) -> dict[str, Any]:
        return {field_name: getattr(self, field_name) for field_name in TREE_HEAD_PAYLOAD_FIELDS}

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.payload(),
            "payload_digest": self.payload_digest,
            "signature_encoding": self.signature_encoding,
            "signature": self.signature,
        }

    def document_digest(self) -> str:
        return tree_head_document_digest(self.to_dict())

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> TransparencyTreeHead:
        if not isinstance(payload, Mapping):
            raise TransparencyInvalid("tree head must be a mapping", reason_code=TREE_HEAD_SCHEMA_INVALID)
        validate_json_depth(payload)
        _exact_fields(payload, TREE_HEAD_FIELDS, label="tree head", reason_code=TREE_HEAD_SCHEMA_INVALID)
        normalized = _validate_tree_head_payload(
            {field_name: payload.get(field_name) for field_name in TREE_HEAD_PAYLOAD_FIELDS}
        )
        expected_digest = tree_head_payload_digest(normalized)
        if payload.get("payload_digest") != expected_digest:
            raise TransparencyInvalid(
                "tree-head payload digest does not match the canonical payload",
                reason_code=TREE_HEAD_PAYLOAD_DIGEST_MISMATCH,
            )
        if payload.get("signature_encoding") != TREE_HEAD_SIGNATURE_ENCODING:
            raise TransparencyInvalid(
                "tree-head signature encoding is unsupported",
                reason_code=TREE_HEAD_SIGNATURE_MALFORMED,
            )
        signature = payload.get("signature")
        if not isinstance(signature, str) or SIGNATURE_HEX_PATTERN.fullmatch(signature) is None:
            raise TransparencyInvalid(
                "tree-head signature encoding is malformed",
                reason_code=TREE_HEAD_SIGNATURE_MALFORMED,
            )
        return cls(
            **normalized,
            payload_digest=expected_digest,
            signature=signature,
        )


def tree_head_payload(tree_head: Mapping[str, Any]) -> dict[str, Any]:
    try:
        return {field_name: tree_head[field_name] for field_name in TREE_HEAD_PAYLOAD_FIELDS}
    except KeyError as exc:
        raise TransparencyInvalid("tree head is missing a payload field") from exc


def derive_tree_head_id(payload: Mapping[str, Any]) -> str:
    """Derive a deterministic tree-head identifier from every other payload field."""
    body = {
        field_name: payload[field_name]
        for field_name in TREE_HEAD_PAYLOAD_FIELDS
        if field_name != "tree_head_id"
    }
    return f"sth-{hashlib.sha256(_canonical_bytes(body)).hexdigest()[:32]}"


def signed_tree_head_bytes(payload: Mapping[str, Any]) -> bytes:
    """Return the exact domain-separated bytes covered by the tree-head signature."""
    return TREE_HEAD_DOMAIN + _canonical_bytes(payload)


def tree_head_payload_digest(payload: Mapping[str, Any]) -> str:
    return sha256_bytes(signed_tree_head_bytes(payload))


def tree_head_document_digest(tree_head: Mapping[str, Any]) -> str:
    """Return the SHA-256 of the canonical full signed tree-head document."""
    return sha256_bytes(_canonical_bytes(tree_head))


def _validate_tree_head_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    if payload.get("schema_version") != TREE_HEAD_SCHEMA_VERSION:
        raise TransparencyInvalid(
            "tree-head schema_version is unsupported", reason_code=TREE_HEAD_SCHEMA_INVALID
        )
    if payload.get("profile") != TREE_HEAD_PROFILE:
        raise TransparencyInvalid("tree-head profile is unsupported", reason_code=TREE_HEAD_SCHEMA_INVALID)
    tree_head_id = _safe_text(
        payload.get("tree_head_id"),
        field_name="tree_head_id",
        pattern=TREE_HEAD_ID_PATTERN,
        reason_code=TREE_HEAD_SCHEMA_INVALID,
    )
    if tree_head_id != derive_tree_head_id(payload):
        raise TransparencyInvalid(
            "tree-head identifier does not match the signed payload",
            reason_code=TREE_HEAD_ID_MISMATCH,
        )
    log_id = _safe_text(
        payload.get("log_id"),
        field_name="log_id",
        pattern=SAFE_LOG_ID,
        reason_code=TREE_HEAD_SCHEMA_INVALID,
    )
    tree_size = _int(
        payload.get("tree_size"),
        field_name="tree_size",
        minimum=0,
        maximum=MAX_MERKLE_LEAVES,
        reason_code=TREE_HEAD_SCHEMA_INVALID,
    )
    merkle_root = _digest(
        payload.get("merkle_root"),
        field_name="merkle_root",
        reason_code=TREE_HEAD_SCHEMA_INVALID,
    )
    if tree_size == 0 and merkle_root != EMPTY_ROOT:
        raise TransparencyInvalid(
            "empty tree head must carry the documented empty Merkle root",
            reason_code=TREE_HEAD_SCHEMA_INVALID,
        )
    timestamp = _timestamp(
        payload.get("timestamp"),
        field_name="timestamp",
        reason_code=TREE_HEAD_SCHEMA_INVALID,
    )
    if payload.get("hash_algorithm") != TRANSPARENCY_LOG_HASH_ALGORITHM:
        raise TransparencyInvalid(
            "tree-head hash algorithm is unsupported", reason_code=TREE_HEAD_ALGORITHM_UNKNOWN
        )
    if payload.get("signature_algorithm") not in SUPPORTED_SIGNATURE_ALGORITHMS:
        raise TransparencyInvalid(
            "tree-head signature algorithm is unsupported",
            reason_code=TREE_HEAD_ALGORITHM_UNKNOWN,
        )
    key_id = _safe_text(
        payload.get("key_id"),
        field_name="key_id",
        pattern=SAFE_KEY_ID,
        reason_code=TREE_HEAD_SCHEMA_INVALID,
    )
    raw_public_key = decode_public_key(payload.get("public_key"))
    fingerprint = payload.get("public_key_fingerprint")
    if not isinstance(fingerprint, str) or DIGEST_PATTERN.fullmatch(fingerprint) is None:
        raise TransparencyInvalid(
            "tree-head public-key fingerprint is invalid", reason_code=TREE_HEAD_SCHEMA_INVALID
        )
    if fingerprint != public_key_fingerprint(raw_public_key):
        raise TransparencyInvalid(
            "tree-head public-key fingerprint does not match the key bytes",
            reason_code=TREE_HEAD_KEY_UNTRUSTED,
        )
    return {
        "schema_version": TREE_HEAD_SCHEMA_VERSION,
        "profile": TREE_HEAD_PROFILE,
        "tree_head_id": tree_head_id,
        "log_id": log_id,
        "tree_size": tree_size,
        "merkle_root": merkle_root,
        "timestamp": timestamp,
        "hash_algorithm": TRANSPARENCY_LOG_HASH_ALGORITHM,
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "public_key_fingerprint": fingerprint,
        "public_key": payload["public_key"],
    }


def validate_tree_head(payload: Mapping[str, Any]) -> TransparencyTreeHead:
    """Validate and normalize a signed tree head without verifying its signature."""
    return TransparencyTreeHead.from_dict(payload)


def build_tree_head_payload(
    *,
    log_id: str,
    tree_size: int,
    merkle_root: str,
    timestamp: str,
    key_id: str,
    public_key: str,
    public_key_fingerprint_value: str,
    signature_algorithm: str = SIGNATURE_ALGORITHM,
) -> dict[str, Any]:
    """Build and validate the canonical tree-head payload, deriving its ID."""
    payload = {
        "schema_version": TREE_HEAD_SCHEMA_VERSION,
        "profile": TREE_HEAD_PROFILE,
        "tree_head_id": "sth-" + ("0" * 32),
        "log_id": log_id,
        "tree_size": tree_size,
        "merkle_root": merkle_root,
        "timestamp": timestamp,
        "hash_algorithm": TRANSPARENCY_LOG_HASH_ALGORITHM,
        "signature_algorithm": signature_algorithm,
        "key_id": key_id,
        "public_key_fingerprint": public_key_fingerprint_value,
        "public_key": public_key,
    }
    payload["tree_head_id"] = derive_tree_head_id(payload)
    return _validate_tree_head_payload(payload)


def sign_tree_head_payload(
    payload: Mapping[str, Any],
    private_key: Ed25519PrivateKey,
) -> TransparencyTreeHead:
    """Sign the exact canonical tree-head payload."""
    normalized = _validate_tree_head_payload(tree_head_payload(payload))
    signature = private_key.sign(signed_tree_head_bytes(normalized)).hex()
    return TransparencyTreeHead.from_dict(
        {
            **normalized,
            "payload_digest": tree_head_payload_digest(normalized),
            "signature_encoding": TREE_HEAD_SIGNATURE_ENCODING,
            "signature": signature,
        }
    )


def create_tree_head(
    log: TransparencyLog | Path,
    *,
    private_key_path: Path,
    key_id: str,
    timestamp: str | None = None,
) -> TransparencyTreeHead:
    """Create a signed tree head from a fully verified transparency log."""
    if isinstance(log, (str, Path)):
        verification = verify_log(Path(log))
        if verification.outcome != PASS:
            raise TransparencyConflict(
                "cannot create a tree head from an invalid transparency log",
                reason_code=TRANSPARENCY_LOG_CHAIN_INVALID,
            )
        parsed_log = read_log(Path(log))
    else:
        parsed_log = log
        verification = verify_log(parsed_log)
        if verification.outcome != PASS:
            raise TransparencyConflict(
                "cannot create a tree head from an invalid transparency log",
                reason_code=TRANSPARENCY_LOG_CHAIN_INVALID,
            )
    tree = parsed_log.tree()
    private_key = load_private_key(Path(private_key_path))
    raw_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    payload = build_tree_head_payload(
        log_id=parsed_log.log_id,
        tree_size=parsed_log.tree_size,
        merkle_root=tree.root,
        timestamp=_timestamp(
            timestamp or utc_now_iso(),
            field_name="tree-head timestamp",
            reason_code=TREE_HEAD_SCHEMA_INVALID,
        ),
        key_id=key_id,
        public_key=encode_public_key(raw_public_key),
        public_key_fingerprint_value=public_key_fingerprint(raw_public_key),
    )
    return sign_tree_head_payload(payload, private_key)


def load_tree_head(path: Path) -> TransparencyTreeHead:
    payload = _read_json_strict(
        Path(path),
        label="tree head",
        max_bytes=MAX_TREE_HEAD_BYTES,
        invalid_reason=TREE_HEAD_SCHEMA_INVALID,
        missing_reason=TREE_HEAD_SCHEMA_INVALID,
    )
    return validate_tree_head(payload)


def write_tree_head(
    path: Path,
    tree_head: Mapping[str, Any] | TransparencyTreeHead,
    *,
    overwrite: bool = False,
) -> None:
    normalized = tree_head if isinstance(tree_head, TransparencyTreeHead) else validate_tree_head(tree_head)
    _write_json_atomic(Path(path), normalized.to_dict(), overwrite=overwrite, mode=0o644)


# ---------------------------------------------------------------------------
# Transparency trust state (rollback and split-view detection)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TransparencyStateEntry:
    """One previously trusted tree-head reference."""

    log_id: str
    tree_head_id: str
    tree_size: int
    merkle_root: str
    tree_head_digest: str
    timestamp: str
    key_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "log_id": self.log_id,
            "tree_head_id": self.tree_head_id,
            "tree_size": self.tree_size,
            "merkle_root": self.merkle_root,
            "tree_head_digest": self.tree_head_digest,
            "timestamp": self.timestamp,
            "key_id": self.key_id,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> TransparencyStateEntry:
        if not isinstance(payload, Mapping):
            raise TransparencyInvalid(
                "transparency-state entry must be a mapping",
                reason_code=TRANSPARENCY_STATE_INVALID,
            )
        _exact_fields(
            payload,
            TRANSPARENCY_STATE_ENTRY_FIELDS,
            label="transparency-state entry",
            reason_code=TRANSPARENCY_STATE_INVALID,
        )
        return cls(
            log_id=_safe_text(
                payload.get("log_id"),
                field_name="log_id",
                pattern=SAFE_LOG_ID,
                reason_code=TRANSPARENCY_STATE_INVALID,
            ),
            tree_head_id=_safe_text(
                payload.get("tree_head_id"),
                field_name="tree_head_id",
                pattern=TREE_HEAD_ID_PATTERN,
                reason_code=TRANSPARENCY_STATE_INVALID,
            ),
            tree_size=_int(
                payload.get("tree_size"),
                field_name="tree_size",
                minimum=0,
                maximum=MAX_MERKLE_LEAVES,
                reason_code=TRANSPARENCY_STATE_INVALID,
            ),
            merkle_root=_digest(
                payload.get("merkle_root"),
                field_name="merkle_root",
                reason_code=TRANSPARENCY_STATE_INVALID,
            ),
            tree_head_digest=_digest(
                payload.get("tree_head_digest"),
                field_name="tree_head_digest",
                reason_code=TRANSPARENCY_STATE_INVALID,
            ),
            timestamp=_timestamp(
                payload.get("timestamp"),
                field_name="timestamp",
                reason_code=TRANSPARENCY_STATE_INVALID,
            ),
            key_id=_safe_text(
                payload.get("key_id"),
                field_name="key_id",
                pattern=SAFE_KEY_ID,
                reason_code=TRANSPARENCY_STATE_INVALID,
            ),
        )


@dataclass(frozen=True)
class TransparencyTrustState:
    """A validated local tree-head monotonic reference."""

    entries: tuple[TransparencyStateEntry, ...]
    updated_at: str
    state_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": TRANSPARENCY_STATE_SCHEMA_VERSION,
            "profile": TRANSPARENCY_STATE_PROFILE,
            "updated_at": self.updated_at,
            "tree_heads": [entry.to_dict() for entry in self.entries],
            "state_digest": self.state_digest,
        }


def _transparency_state_digest(
    updated_at: str,
    entries: tuple[TransparencyStateEntry, ...],
) -> str:
    body = {
        "schema_version": TRANSPARENCY_STATE_SCHEMA_VERSION,
        "profile": TRANSPARENCY_STATE_PROFILE,
        "updated_at": updated_at,
        "tree_heads": [entry.to_dict() for entry in entries],
    }
    return sha256_bytes(_canonical_bytes(body))


def validate_transparency_state(payload: Mapping[str, Any]) -> TransparencyTrustState:
    """Validate the local tree-head reference and its self-digest."""
    if not isinstance(payload, Mapping):
        raise TransparencyInvalid(
            "transparency state must be a mapping", reason_code=TRANSPARENCY_STATE_INVALID
        )
    validate_json_depth(payload)
    _exact_fields(
        payload,
        TRANSPARENCY_STATE_FIELDS,
        label="transparency state",
        reason_code=TRANSPARENCY_STATE_INVALID,
    )
    if payload.get("schema_version") != TRANSPARENCY_STATE_SCHEMA_VERSION:
        raise TransparencyInvalid(
            "transparency-state schema_version is unsupported",
            reason_code=TRANSPARENCY_STATE_INVALID,
        )
    if payload.get("profile") != TRANSPARENCY_STATE_PROFILE:
        raise TransparencyInvalid(
            "transparency-state profile is unsupported", reason_code=TRANSPARENCY_STATE_INVALID
        )
    updated_at = _timestamp(
        payload.get("updated_at"),
        field_name="updated_at",
        reason_code=TRANSPARENCY_STATE_INVALID,
    )
    raw_entries = payload.get("tree_heads")
    if not isinstance(raw_entries, list):
        raise TransparencyInvalid(
            "transparency-state tree_heads must be a list",
            reason_code=TRANSPARENCY_STATE_INVALID,
        )
    if len(raw_entries) > MAX_TRANSPARENCY_STATE_ENTRIES:
        raise TransparencyInvalid(
            "transparency state exceeds the maximum supported entry count",
            reason_code=TRANSPARENCY_STATE_INVALID,
        )
    entries: list[TransparencyStateEntry] = []
    seen_ids: set[str] = set()
    seen_roots: dict[tuple[str, int], str] = {}
    for raw_entry in raw_entries:
        entry = TransparencyStateEntry.from_dict(raw_entry)
        if entry.tree_head_id in seen_ids:
            raise TransparencyInvalid(
                "transparency state contains a duplicate tree-head identifier",
                reason_code=TRANSPARENCY_STATE_INVALID,
            )
        root_key = (entry.log_id, entry.tree_size)
        existing = seen_roots.get(root_key)
        if existing is not None and existing != entry.merkle_root:
            raise TransparencyInvalid(
                "transparency state contains conflicting roots for one log and tree size",
                reason_code=TRANSPARENCY_STATE_INVALID,
            )
        seen_ids.add(entry.tree_head_id)
        seen_roots[root_key] = entry.merkle_root
        entries.append(entry)
    normalized = tuple(
        sorted(entries, key=lambda item: (item.log_id, item.tree_size, item.timestamp, item.tree_head_id))
    )
    digest = payload.get("state_digest")
    if not isinstance(digest, str) or DIGEST_PATTERN.fullmatch(digest) is None:
        raise TransparencyInvalid(
            "transparency-state digest is invalid", reason_code=TRANSPARENCY_STATE_INVALID
        )
    if digest != _transparency_state_digest(updated_at, normalized):
        raise TransparencyInvalid(
            "transparency-state digest does not match its contents",
            reason_code=TRANSPARENCY_STATE_INVALID,
        )
    return TransparencyTrustState(entries=normalized, updated_at=updated_at, state_digest=digest)


def load_transparency_state(path: Path | None) -> TransparencyTrustState | None:
    """Load a local transparency trust state; a missing file is not an error."""
    if path is None:
        return None
    path = Path(path)
    if not path.exists():
        return None
    payload = _read_json_strict(
        path,
        label="transparency state",
        max_bytes=MAX_TRANSPARENCY_STATE_BYTES,
        invalid_reason=TRANSPARENCY_STATE_INVALID,
        missing_reason=TRANSPARENCY_STATE_MISSING,
    )
    return validate_transparency_state(payload)


def empty_transparency_state(*, updated_at: str | None = None) -> TransparencyTrustState:
    timestamp = _timestamp(
        updated_at or utc_now_iso(),
        field_name="updated_at",
        reason_code=TRANSPARENCY_STATE_INVALID,
    )
    return TransparencyTrustState(
        entries=(),
        updated_at=timestamp,
        state_digest=_transparency_state_digest(timestamp, ()),
    )


def write_transparency_state(
    path: Path,
    state: TransparencyTrustState | Mapping[str, Any],
    *,
    overwrite: bool = True,
) -> None:
    normalized = state if isinstance(state, TransparencyTrustState) else validate_transparency_state(state)
    _write_json_atomic(Path(path), normalized.to_dict(), overwrite=overwrite, mode=0o600)


def transparency_state_entry(
    tree_head: Mapping[str, Any] | TransparencyTreeHead,
) -> TransparencyStateEntry:
    normalized = tree_head if isinstance(tree_head, TransparencyTreeHead) else validate_tree_head(tree_head)
    return TransparencyStateEntry(
        log_id=normalized.log_id,
        tree_head_id=normalized.tree_head_id,
        tree_size=normalized.tree_size,
        merkle_root=normalized.merkle_root,
        tree_head_digest=normalized.document_digest(),
        timestamp=normalized.timestamp,
        key_id=normalized.key_id,
    )


def evaluate_transparency_state(
    tree_head: Mapping[str, Any],
    state: TransparencyTrustState | None,
    *,
    consistency_proof: Mapping[str, Any] | ConsistencyProof | None = None,
) -> TransparencyCheck:
    """Compare a verified tree head with the locally recorded monotonic reference."""
    normalized = validate_tree_head(tree_head)
    return _evaluate_reference(
        transparency_state_entry(normalized),
        state,
        consistency_proof=consistency_proof,
    )


def _evaluate_reference(
    reference: TransparencyStateEntry,
    state: TransparencyTrustState | None,
    *,
    consistency_proof: Mapping[str, Any] | ConsistencyProof | None = None,
    reject_replay: bool = True,
) -> TransparencyCheck:
    """Compare one tree-head reference with the local monotonic reference."""
    normalized = reference
    if state is None:
        return TransparencyCheck(
            name="tree-head-rollback-protection",
            outcome=NOT_RUN,
            detail=(
                "no transparency trust state was configured; rollback and split-view protection "
                "is limited to this invocation and is not independently established"
            ),
            reason_code=TRANSPARENCY_STATE_MISSING,
            required=False,
        )
    entries = [entry for entry in state.entries if entry.log_id == normalized.log_id]
    if not entries:
        return TransparencyCheck(
            name="tree-head-rollback-protection",
            outcome=PASS,
            detail="no prior tree head is recorded for this transparency log",
            required=True,
        )
    for entry in entries:
        if entry.tree_head_id == normalized.tree_head_id:
            if entry.to_dict() == normalized.to_dict():
                if not reject_replay:
                    return TransparencyCheck(
                        name="tree-head-rollback-protection",
                        outcome=PASS,
                        detail="tree head matches the recorded transparency reference",
                    )
                return TransparencyCheck(
                    name="tree-head-rollback-protection",
                    outcome=FAIL,
                    detail="tree head was already recorded; a replay is not fresh evidence",
                    reason_code=TREE_HEAD_REPLAY,
                )
            return TransparencyCheck(
                name="tree-head-rollback-protection",
                outcome=FAIL,
                detail="tree-head identifier was reused with different contents",
                reason_code=TREE_HEAD_DUPLICATE,
            )
        if entry.tree_size == normalized.tree_size and entry.merkle_root != normalized.merkle_root:
            return TransparencyCheck(
                name="tree-head-rollback-protection",
                outcome=FAIL,
                detail="conflicting Merkle roots were recorded for the same log and tree size",
                reason_code=TREE_ROOT_CONFLICT,
            )
    latest = max(entries, key=lambda item: (item.tree_size, item.timestamp, item.tree_head_id))
    if normalized.tree_size < latest.tree_size:
        return TransparencyCheck(
            name="tree-head-rollback-protection",
            outcome=FAIL,
            detail="tree size is smaller than the recorded trusted tree head",
            reason_code=TREE_SIZE_ROLLBACK,
        )
    if normalized.timestamp < latest.timestamp:
        return TransparencyCheck(
            name="tree-head-rollback-protection",
            outcome=FAIL,
            detail="tree-head timestamp regressed below the recorded trust state",
            reason_code=TREE_HEAD_TIMESTAMP_REGRESSION,
        )
    if normalized.tree_size == latest.tree_size:
        if normalized.merkle_root != latest.merkle_root:
            return TransparencyCheck(
                name="tree-head-rollback-protection",
                outcome=FAIL,
                detail="tree root changed without tree growth",
                reason_code=TREE_ROOT_CONFLICT,
            )
        return TransparencyCheck(
            name="tree-head-rollback-protection",
            outcome=PASS,
            detail="tree head re-attests the recorded size and root with a newer timestamp",
            required=True,
        )
    if consistency_proof is None:
        return TransparencyCheck(
            name="tree-head-rollback-protection",
            outcome=FAIL,
            detail=(
                "tree size grew beyond the recorded trusted tree head without a consistency proof; "
                "a newer timestamp alone is not proof of consistency"
            ),
            reason_code=CONSISTENCY_PROOF_MISSING,
        )
    proof_result = verify_consistency_proof(
        consistency_proof,
        expected_old_root=latest.merkle_root,
        expected_new_root=normalized.merkle_root,
        expected_log_id=normalized.log_id,
        expected_old_tree_size=latest.tree_size,
        expected_new_tree_size=normalized.tree_size,
    )
    if proof_result.outcome != PASS:
        reason = proof_result.reason_codes[0] if proof_result.reason_codes else CONSISTENCY_PROOF_INVALID
        return TransparencyCheck(
            name="tree-head-rollback-protection",
            outcome=FAIL,
            detail="tree growth is not supported by a valid append-only consistency proof",
            reason_code=reason,
        )
    return TransparencyCheck(
        name="tree-head-rollback-protection",
        outcome=PASS,
        detail="tree head advances the recorded tree with a valid append-only consistency proof",
        required=True,
    )


def advance_transparency_state(
    path: Path,
    entry: Mapping[str, Any] | TransparencyStateEntry,
    *,
    consistency_proof: Mapping[str, Any] | ConsistencyProof | None = None,
    updated_at: str | None = None,
) -> dict[str, Any]:
    """Append a verified tree-head reference after a passing state evaluation."""
    normalized_entry = (
        entry if isinstance(entry, TransparencyStateEntry) else TransparencyStateEntry.from_dict(entry)
    )
    state = load_transparency_state(path)
    if state is not None:
        if any(existing == normalized_entry for existing in state.entries):
            return state.to_dict()
        check = _evaluate_reference(
            normalized_entry,
            state,
            consistency_proof=consistency_proof,
        )
        if check.outcome != PASS:
            raise TransparencyConflict(
                check.detail,
                reason_code=check.reason_code or TREE_HEAD_CONFLICT,
            )
    timestamp = _timestamp(
        updated_at or utc_now_iso(),
        field_name="updated_at",
        reason_code=TRANSPARENCY_STATE_INVALID,
    )
    if state is not None and timestamp < state.updated_at:
        raise TransparencyConflict(
            "transparency-state update timestamp regressed",
            reason_code=TRANSPARENCY_STATE_INVALID,
        )
    base_entries = state.entries if state is not None else ()
    entries = tuple(
        sorted(
            (*base_entries, normalized_entry),
            key=lambda item: (item.log_id, item.tree_size, item.timestamp, item.tree_head_id),
        )
    )
    payload = {
        "schema_version": TRANSPARENCY_STATE_SCHEMA_VERSION,
        "profile": TRANSPARENCY_STATE_PROFILE,
        "updated_at": timestamp,
        "tree_heads": [item.to_dict() for item in entries],
        "state_digest": _transparency_state_digest(timestamp, entries),
    }
    normalized = validate_transparency_state(payload)
    write_transparency_state(Path(path), normalized)
    return normalized.to_dict()


# ---------------------------------------------------------------------------
# Signed tree-head verification
# ---------------------------------------------------------------------------


@dataclass
class TreeHeadVerification:
    """Result of verifying one signed transparency tree head."""

    outcome: str = NOT_RUN
    tree_head: TransparencyTreeHead | None = field(default=None, repr=False)
    checks: list[TransparencyCheck] = field(default_factory=list)
    reason_codes: list[str] = field(default_factory=list)
    trust: dict[str, Any] = field(default_factory=dict)
    state_update: str = "not_requested"
    assurance: str = "reduced"
    limitations: list[str] = field(default_factory=list)

    def add(self, check: TransparencyCheck) -> TransparencyCheck:
        self.checks.append(check)
        return check

    def finalize(self) -> TreeHeadVerification:
        required = [check for check in self.checks if check.required]
        outcomes = {check.outcome for check in required}
        for state in (FAIL, UNAVAILABLE, NOT_RUN):
            if state in outcomes:
                self.outcome = state
                break
        else:
            self.outcome = PASS if required else NOT_RUN
        codes: list[str] = []
        for check in self.checks:
            if check.reason_code is not None and check.outcome != PASS and check.reason_code not in codes:
                codes.append(check.reason_code)
        self.reason_codes = codes
        return self

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "outcome": self.outcome,
            "assurance": self.assurance,
            "external_anchor": ANCHOR_NOT_CONFIGURED,
            "external_anchoring": False,
            "state_update": self.state_update,
            "tree_head": self.tree_head.to_dict() if self.tree_head is not None else None,
            "trust": self.trust,
            "reason_codes": sorted(set(self.reason_codes)),
            "checks": [check.to_dict() for check in self.checks],
            "limitations": [redact_text(item)[:500] for item in self.limitations],
        }
        cleaned = redact_structure(payload)
        if not isinstance(cleaned, dict):
            raise TransparencyError("tree-head verification result could not be sanitized")
        return cleaned


def _tree_head_signature_check(
    result: TreeHeadVerification,
    tree_head: TransparencyTreeHead,
    *,
    public_key_bytes: bytes,
) -> None:
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
            bytes.fromhex(tree_head.signature),
            signed_tree_head_bytes(tree_head.payload()),
        )
    except InvalidSignature:
        result.add(
            TransparencyCheck(
                "tree-head-signature",
                FAIL,
                "tree-head signature does not match the exact domain-separated canonical payload",
                reason_code=TREE_HEAD_SIGNATURE_MISMATCH,
            )
        )
    except (ValueError, TypeError):
        result.add(
            TransparencyCheck(
                "tree-head-signature",
                FAIL,
                "tree-head signature or public key is malformed",
                reason_code=TREE_HEAD_SIGNATURE_MALFORMED,
            )
        )
    else:
        result.add(
            TransparencyCheck(
                "tree-head-signature",
                PASS,
                "tree-head signature verifies over the exact domain-separated canonical payload",
            )
        )


def verify_tree_head(
    tree_head: Mapping[str, Any] | TransparencyTreeHead,
    *,
    trust_store_path: Path | None = None,
    trusted_key_fingerprint: str | None = None,
    trust_state_path: Path | None = None,
    consistency_proof: Mapping[str, Any] | ConsistencyProof | None = None,
    require_trust_state: bool = False,
    update_trust_state: bool = False,
    state_updated_at: str | None = None,
) -> TreeHeadVerification:
    """Verify a signed tree head against explicitly configured V31 trust.

    The tree-head document is never trusted on its own. A missing trust store
    or fingerprint pin is ``UNAVAILABLE``; an untrusted key, wrong purpose,
    revoked or expired key, bad signature, rollback, or split view is ``FAIL``.
    A verified local signature without an external provider is ``PASS`` with
    explicitly reduced assurance, never an external-anchoring claim.
    """
    result = TreeHeadVerification()
    try:
        normalized = (
            tree_head
            if isinstance(tree_head, TransparencyTreeHead)
            else TransparencyTreeHead.from_dict(tree_head)
        )
    except (TransparencyError, MerkleError) as exc:
        reason = getattr(exc, "reason_code", TREE_HEAD_SCHEMA_INVALID)
        result.add(TransparencyCheck("tree-head-schema", FAIL, str(exc), reason_code=reason))
        return result.finalize()
    result.tree_head = normalized
    result.add(
        TransparencyCheck(
            "tree-head-schema",
            PASS,
            "tree-head schema, identifier, payload digest, and canonical fields are valid",
        )
    )
    result.add(
        TransparencyCheck(
            "tree-head-algorithm",
            PASS,
            f"tree-head signature algorithm {normalized.signature_algorithm} is allowed",
        )
    )
    result.trust = {
        "source": None,
        "store_path": str(trust_store_path) if trust_store_path is not None else None,
        "key_id": normalized.key_id,
        "fingerprint": normalized.public_key_fingerprint,
        "purpose": None,
        "status": "unresolved",
        "historical": False,
    }

    store: TrustStore | None = None
    key = None
    if trust_store_path is not None:
        try:
            store = load_trust_store(Path(trust_store_path))
        except TrustUnavailable as exc:
            result.add(
                TransparencyCheck(
                    "tree-head-trust-store",
                    UNAVAILABLE,
                    str(exc),
                    reason_code=TREE_HEAD_TRUST_STORE_MISSING,
                )
            )
        except TrustError as exc:
            result.add(
                TransparencyCheck(
                    "tree-head-trust-store",
                    FAIL,
                    str(exc),
                    reason_code=exc.reason_code,
                )
            )
        else:
            result.add(
                TransparencyCheck(
                    "tree-head-trust-store",
                    PASS,
                    "trust store is valid and independently configured",
                )
            )
            key = store.key_by_id(normalized.key_id)
            if key is None:
                result.add(
                    TransparencyCheck(
                        "tree-head-key",
                        FAIL,
                        "tree-head key identifier is not present in the trust store",
                        reason_code=TREE_HEAD_KEY_UNKNOWN,
                    )
                )
            elif trusted_key_fingerprint is not None and key.fingerprint != trusted_key_fingerprint:
                result.add(
                    TransparencyCheck(
                        "tree-head-key",
                        FAIL,
                        "trusted-key fingerprint does not match the separately supplied pin",
                        reason_code=TREE_HEAD_KEY_UNTRUSTED,
                    )
                )
            elif key.public_key != normalized.public_key:
                result.add(
                    TransparencyCheck(
                        "tree-head-key",
                        FAIL,
                        "tree-head-supplied public key does not match the trusted key",
                        reason_code=TREE_HEAD_KEY_UNTRUSTED,
                    )
                )
            else:
                result.add(
                    TransparencyCheck(
                        "tree-head-key",
                        PASS,
                        "tree-head key resolves to an explicitly registered trust-store key",
                    )
                )
                result.trust["source"] = "trust_store"
    elif trusted_key_fingerprint is not None:
        if DIGEST_PATTERN.fullmatch(trusted_key_fingerprint) is None:
            result.add(
                TransparencyCheck(
                    "tree-head-key",
                    FAIL,
                    "trusted key fingerprint is not sha256:<64 lowercase hex>",
                    reason_code=TREE_HEAD_KEY_UNTRUSTED,
                )
            )
        elif normalized.public_key_fingerprint != trusted_key_fingerprint:
            result.add(
                TransparencyCheck(
                    "tree-head-key",
                    FAIL,
                    "tree-head-supplied public key does not match the trusted fingerprint pin",
                    reason_code=TREE_HEAD_KEY_UNTRUSTED,
                )
            )
        else:
            result.trust["source"] = "fingerprint_pin"
            result.add(
                TransparencyCheck(
                    "tree-head-key",
                    PASS,
                    (
                        "tree-head public key matches the separately supplied fingerprint pin; "
                        "no lifecycle metadata was available"
                    ),
                )
            )
    else:
        result.add(
            TransparencyCheck(
                "tree-head-key",
                UNAVAILABLE,
                "no trust store or trusted key fingerprint is configured; a self-signed tree head "
                "is not trusted",
                reason_code=TREE_HEAD_TRUST_STORE_MISSING,
            )
        )

    status = None
    if key is not None:
        if key.purpose != KEY_PURPOSE_TRANSPARENCY_TREE_HEAD:
            result.add(
                TransparencyCheck(
                    "tree-head-key-purpose",
                    FAIL,
                    "trusted key purpose is not transparency tree-head signing",
                    reason_code=TREE_HEAD_KEY_PURPOSE_INVALID,
                )
            )
        else:
            result.add(
                TransparencyCheck(
                    "tree-head-key-purpose",
                    PASS,
                    "trusted key purpose allows transparency tree-head signing",
                )
            )
        if normalized.signature_algorithm not in key.allowed_algorithms:
            result.add(
                TransparencyCheck(
                    "tree-head-key-algorithm",
                    FAIL,
                    "trusted key does not allow the tree-head signature algorithm",
                    reason_code=TREE_HEAD_KEY_ALGORITHM_DISALLOWED,
                )
            )
        else:
            result.add(
                TransparencyCheck(
                    "tree-head-key-algorithm",
                    PASS,
                    "trusted key allows the tree-head signature algorithm",
                )
            )
        assert store is not None
        status = evaluate_key_status(
            key,
            at=normalized.timestamp,
            policy=store.historical_revocation_policy,
        )
        if status.status in ("active", "revoked_historical"):
            result.add(TransparencyCheck("tree-head-key-validity", PASS, status.detail))
        else:
            reason = {
                "not_yet_valid": TREE_HEAD_KEY_NOT_YET_VALID,
                "expired": TREE_HEAD_KEY_EXPIRED,
                "revoked": TREE_HEAD_KEY_REVOKED,
            }.get(status.status, TREE_HEAD_KEY_UNTRUSTED)
            result.add(
                TransparencyCheck(
                    "tree-head-key-validity",
                    FAIL,
                    status.detail,
                    reason_code=reason,
                )
            )
        result.trust.update(
            {
                "purpose": key.purpose,
                "status": status.status,
                "historical": status.historical,
            }
        )
    elif trusted_key_fingerprint is not None:
        status = KeyStatus(
            "pinned_fingerprint",
            "fingerprint pin matched; lifecycle metadata was not available",
        )
        result.add(TransparencyCheck("tree-head-key-validity", PASS, status.detail))
        result.trust.update({"status": status.status, "historical": False})

    public_key_bytes = key.raw_public_key if key is not None else decode_public_key(normalized.public_key)
    _tree_head_signature_check(result, normalized, public_key_bytes=public_key_bytes)

    state = None
    state_configured = trust_state_path is not None
    if state_configured:
        try:
            state = load_transparency_state(Path(trust_state_path))
        except TransparencyUnavailable as exc:
            result.add(
                TransparencyCheck(
                    "tree-head-trust-state",
                    UNAVAILABLE,
                    str(exc),
                    reason_code=TRANSPARENCY_STATE_MISSING,
                )
            )
        except TransparencyError as exc:
            result.add(
                TransparencyCheck(
                    "tree-head-trust-state",
                    FAIL,
                    str(exc),
                    reason_code=TRANSPARENCY_STATE_INVALID,
                )
            )
        else:
            if state is None:
                if require_trust_state:
                    result.add(
                        TransparencyCheck(
                            "tree-head-trust-state",
                            FAIL,
                            "a transparency trust state is required but no state file exists",
                            reason_code=TRANSPARENCY_STATE_MISSING,
                        )
                    )
                else:
                    result.add(
                        TransparencyCheck(
                            "tree-head-trust-state",
                            PASS,
                            "no prior transparency trust state exists; this is the first recorded tree head",
                        )
                    )
            else:
                result.add(
                    TransparencyCheck(
                        "tree-head-trust-state",
                        PASS,
                        "transparency trust state is valid",
                    )
                )
            check = _evaluate_reference(
                transparency_state_entry(normalized),
                state,
                consistency_proof=consistency_proof,
            )
            result.add(check)
    elif require_trust_state:
        result.add(
            TransparencyCheck(
                "tree-head-trust-state",
                FAIL,
                "a transparency trust state is required but no state path is configured",
                reason_code=TRANSPARENCY_STATE_MISSING,
            )
        )
    else:
        result.add(
            TransparencyCheck(
                "tree-head-rollback-protection",
                NOT_RUN,
                (
                    "no transparency trust state is configured; rollback and split-view protection "
                    "is limited to this invocation"
                ),
                reason_code=TRANSPARENCY_STATE_MISSING,
                required=False,
            )
        )

    result.finalize()
    if update_trust_state:
        if trust_state_path is None:
            result.add(
                TransparencyCheck(
                    "tree-head-trust-state-update",
                    FAIL,
                    "trust-state update was requested but no trust-state path is configured",
                    reason_code=TRANSPARENCY_STATE_MISSING,
                )
            )
            result.state_update = "failed"
            result.finalize()
        elif result.outcome != PASS:
            result.state_update = "refused_after_failure"
        else:
            try:
                updated = advance_transparency_state(
                    Path(trust_state_path),
                    transparency_state_entry(normalized),
                    consistency_proof=consistency_proof,
                    updated_at=state_updated_at,
                )
            except TransparencyError as exc:
                result.add(
                    TransparencyCheck(
                        "tree-head-trust-state-update",
                        FAIL,
                        str(exc),
                        reason_code=exc.reason_code,
                    )
                )
                result.state_update = "failed"
                result.finalize()
            else:
                result.add(
                    TransparencyCheck(
                        "tree-head-trust-state-update",
                        PASS,
                        "verified tree head was recorded in the transparency trust state",
                    )
                )
                result.state_update = (
                    "unchanged"
                    if state is not None and updated.get("state_digest") == state.state_digest
                    else "updated"
                )
                result.finalize()
    result.assurance = "reduced"
    result.limitations.extend(
        [
            (
                "A locally verified Ed25519 tree head proves who signed it only when the key is "
                "explicitly trusted; it does not prove the log is independently immutable."
            ),
            (
                "Local transparency trust state is not independent monotonic storage. A writer who "
                "can rewrite the state, the log, and the tree heads can rewrite this history."
            ),
            "No external transparency provider is configured or contacted by V32.",
        ]
    )
    return result


def detect_split_view(
    tree_heads: Sequence[Mapping[str, Any] | TransparencyTreeHead],
    *,
    state: TransparencyTrustState | None = None,
) -> TransparencyCheck:
    """Detect duplicate, conflicting, or rolled-back tree heads in one view."""
    references: list[TransparencyStateEntry] = []
    seen_ids: dict[str, TransparencyStateEntry] = {}
    seen_roots: dict[tuple[str, int], str] = {}
    for item in tree_heads:
        normalized = item if isinstance(item, TransparencyTreeHead) else validate_tree_head(item)
        reference = transparency_state_entry(normalized)
        existing_id = seen_ids.get(reference.tree_head_id)
        if existing_id is not None and existing_id != reference:
            return TransparencyCheck(
                "transparency-split-view",
                FAIL,
                "tree-head identifier was reused with different contents",
                reason_code=TREE_HEAD_DUPLICATE,
            )
        seen_ids[reference.tree_head_id] = reference
        root_key = (reference.log_id, reference.tree_size)
        existing_root = seen_roots.get(root_key)
        if existing_root is not None and existing_root != reference.merkle_root:
            return TransparencyCheck(
                "transparency-split-view",
                FAIL,
                "conflicting Merkle roots were observed for the same log and tree size",
                reason_code=TREE_ROOT_CONFLICT,
            )
        seen_roots[root_key] = reference.merkle_root
        references.append(reference)
    if state is not None:
        for reference in references:
            check = _evaluate_reference(reference, state, reject_replay=False)
            if check.outcome != PASS:
                return check
    return TransparencyCheck(
        "transparency-split-view",
        PASS,
        "no duplicate, conflicting, or rolled-back tree head was observed",
    )


# ---------------------------------------------------------------------------
# Anchor receipts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TransparencyAnchorReceipt:
    """A validated provider-neutral transparency anchor receipt."""

    receipt_id: str
    provider_id: str
    provider_type: str
    anchor_status: str
    log_id: str
    tree_size: int
    merkle_root: str
    tree_head_id: str
    tree_head_digest: str
    receipt_timestamp: str
    key_id: str
    public_key_fingerprint: str
    public_key: str
    payload_digest: str
    signature: str
    schema_version: int = RECEIPT_SCHEMA_VERSION
    profile: str = RECEIPT_PROFILE
    signature_algorithm: str = SIGNATURE_ALGORITHM
    signature_encoding: str = TREE_HEAD_SIGNATURE_ENCODING

    def payload(self) -> dict[str, Any]:
        return {field_name: getattr(self, field_name) for field_name in RECEIPT_PAYLOAD_FIELDS}

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.payload(),
            "payload_digest": self.payload_digest,
            "signature_encoding": self.signature_encoding,
            "signature": self.signature,
        }

    def document_digest(self) -> str:
        return sha256_bytes(_canonical_bytes(self.to_dict()))

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> TransparencyAnchorReceipt:
        if not isinstance(payload, Mapping):
            raise TransparencyInvalid("anchor receipt must be a mapping", reason_code=RECEIPT_SCHEMA_INVALID)
        validate_json_depth(payload)
        _exact_fields(payload, RECEIPT_FIELDS, label="anchor receipt", reason_code=RECEIPT_SCHEMA_INVALID)
        normalized = _validate_receipt_payload(
            {field_name: payload.get(field_name) for field_name in RECEIPT_PAYLOAD_FIELDS}
        )
        expected_digest = receipt_payload_digest(normalized)
        if payload.get("payload_digest") != expected_digest:
            raise TransparencyInvalid(
                "receipt payload digest does not match the canonical payload",
                reason_code=RECEIPT_PAYLOAD_DIGEST_MISMATCH,
            )
        if payload.get("signature_encoding") != TREE_HEAD_SIGNATURE_ENCODING:
            raise TransparencyInvalid(
                "receipt signature encoding is unsupported",
                reason_code=RECEIPT_SIGNATURE_MALFORMED,
            )
        signature = payload.get("signature")
        if not isinstance(signature, str) or SIGNATURE_HEX_PATTERN.fullmatch(signature) is None:
            raise TransparencyInvalid(
                "receipt signature encoding is malformed",
                reason_code=RECEIPT_SIGNATURE_MALFORMED,
            )
        return cls(**normalized, payload_digest=expected_digest, signature=signature)


def derive_receipt_id(payload: Mapping[str, Any]) -> str:
    """Derive a deterministic receipt identifier from every other payload field."""
    body = {
        field_name: payload[field_name] for field_name in RECEIPT_PAYLOAD_FIELDS if field_name != "receipt_id"
    }
    return f"rcpt-{hashlib.sha256(_canonical_bytes(body)).hexdigest()[:32]}"


def signed_receipt_bytes(payload: Mapping[str, Any]) -> bytes:
    """Return the exact domain-separated bytes covered by the receipt signature."""
    return RECEIPT_DOMAIN + _canonical_bytes(payload)


def receipt_payload_digest(payload: Mapping[str, Any]) -> str:
    return sha256_bytes(signed_receipt_bytes(payload))


def receipt_document_digest(receipt: Mapping[str, Any]) -> str:
    return sha256_bytes(_canonical_bytes(receipt))


def _validate_receipt_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    if payload.get("schema_version") != RECEIPT_SCHEMA_VERSION:
        raise TransparencyInvalid("receipt schema_version is unsupported", reason_code=RECEIPT_SCHEMA_INVALID)
    if payload.get("profile") != RECEIPT_PROFILE:
        raise TransparencyInvalid("receipt profile is unsupported", reason_code=RECEIPT_SCHEMA_INVALID)
    receipt_id = _safe_text(
        payload.get("receipt_id"),
        field_name="receipt_id",
        pattern=RECEIPT_ID_PATTERN,
        reason_code=RECEIPT_SCHEMA_INVALID,
    )
    if receipt_id != derive_receipt_id(payload):
        raise TransparencyInvalid(
            "receipt identifier does not match the signed payload",
            reason_code=RECEIPT_ID_MISMATCH,
        )
    provider_id = _safe_text(
        payload.get("provider_id"),
        field_name="provider_id",
        pattern=SAFE_PROVIDER_ID,
        reason_code=RECEIPT_SCHEMA_INVALID,
    )
    provider_type = payload.get("provider_type")
    if provider_type not in (PROVIDER_TYPE_LOCAL_TEST, PROVIDER_TYPE_EXTERNAL):
        raise TransparencyInvalid(
            "receipt provider type is unsupported", reason_code=RECEIPT_PROVIDER_MISMATCH
        )
    anchor_status = payload.get("anchor_status")
    if anchor_status not in ANCHOR_STATUSES:
        raise TransparencyInvalid("receipt anchor status is unsupported", reason_code=RECEIPT_STATUS_INVALID)
    if provider_type == PROVIDER_TYPE_LOCAL_TEST and anchor_status != ANCHOR_SIMULATED:
        raise TransparencyInvalid(
            "a local test provider may only issue SIMULATED receipts",
            reason_code=RECEIPT_STATUS_INVALID,
        )
    if provider_type == PROVIDER_TYPE_EXTERNAL and anchor_status != ANCHOR_EXTERNAL_VERIFIED:
        raise TransparencyInvalid(
            "an external provider receipt must report EXTERNAL_VERIFIED",
            reason_code=RECEIPT_STATUS_INVALID,
        )
    log_id = _safe_text(
        payload.get("log_id"),
        field_name="log_id",
        pattern=SAFE_LOG_ID,
        reason_code=RECEIPT_SCHEMA_INVALID,
    )
    tree_size = _int(
        payload.get("tree_size"),
        field_name="tree_size",
        minimum=0,
        maximum=MAX_MERKLE_LEAVES,
        reason_code=RECEIPT_SCHEMA_INVALID,
    )
    merkle_root = _digest(
        payload.get("merkle_root"),
        field_name="merkle_root",
        reason_code=RECEIPT_SCHEMA_INVALID,
    )
    if tree_size == 0 and merkle_root != EMPTY_ROOT:
        raise TransparencyInvalid(
            "empty-tree receipt must carry the documented empty Merkle root",
            reason_code=RECEIPT_SCHEMA_INVALID,
        )
    tree_head_id = _safe_text(
        payload.get("tree_head_id"),
        field_name="tree_head_id",
        pattern=TREE_HEAD_ID_PATTERN,
        reason_code=RECEIPT_SCHEMA_INVALID,
    )
    tree_head_digest = _digest(
        payload.get("tree_head_digest"),
        field_name="tree_head_digest",
        reason_code=RECEIPT_SCHEMA_INVALID,
    )
    receipt_timestamp = _timestamp(
        payload.get("receipt_timestamp"),
        field_name="receipt_timestamp",
        reason_code=RECEIPT_TIMESTAMP_INVALID,
    )
    if payload.get("signature_algorithm") not in SUPPORTED_SIGNATURE_ALGORITHMS:
        raise TransparencyInvalid(
            "receipt signature algorithm is unsupported",
            reason_code=RECEIPT_SIGNATURE_MALFORMED,
        )
    key_id = _safe_text(
        payload.get("key_id"),
        field_name="key_id",
        pattern=SAFE_KEY_ID,
        reason_code=RECEIPT_SCHEMA_INVALID,
    )
    raw_public_key = decode_public_key(payload.get("public_key"))
    fingerprint = payload.get("public_key_fingerprint")
    if not isinstance(fingerprint, str) or DIGEST_PATTERN.fullmatch(fingerprint) is None:
        raise TransparencyInvalid(
            "receipt public-key fingerprint is invalid", reason_code=RECEIPT_SCHEMA_INVALID
        )
    if fingerprint != public_key_fingerprint(raw_public_key):
        raise TransparencyInvalid(
            "receipt public-key fingerprint does not match the key bytes",
            reason_code=RECEIPT_SCHEMA_INVALID,
        )
    return {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "profile": RECEIPT_PROFILE,
        "receipt_id": receipt_id,
        "provider_id": provider_id,
        "provider_type": provider_type,
        "anchor_status": anchor_status,
        "log_id": log_id,
        "tree_size": tree_size,
        "merkle_root": merkle_root,
        "tree_head_id": tree_head_id,
        "tree_head_digest": tree_head_digest,
        "receipt_timestamp": receipt_timestamp,
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "public_key_fingerprint": fingerprint,
        "public_key": payload["public_key"],
    }


def build_receipt_payload(
    *,
    provider_id: str,
    provider_type: str,
    anchor_status: str,
    log_id: str,
    tree_size: int,
    merkle_root: str,
    tree_head_id: str,
    tree_head_digest: str,
    receipt_timestamp: str,
    key_id: str,
    public_key: str,
    public_key_fingerprint_value: str,
) -> dict[str, Any]:
    """Build and validate a canonical receipt payload, deriving its identifier."""
    payload = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "profile": RECEIPT_PROFILE,
        "receipt_id": "rcpt-" + ("0" * 32),
        "provider_id": provider_id,
        "provider_type": provider_type,
        "anchor_status": anchor_status,
        "log_id": log_id,
        "tree_size": tree_size,
        "merkle_root": merkle_root,
        "tree_head_id": tree_head_id,
        "tree_head_digest": tree_head_digest,
        "receipt_timestamp": receipt_timestamp,
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "public_key_fingerprint": public_key_fingerprint_value,
        "public_key": public_key,
    }
    payload["receipt_id"] = derive_receipt_id(payload)
    return _validate_receipt_payload(payload)


def sign_receipt_payload(
    payload: Mapping[str, Any],
    private_key: Ed25519PrivateKey,
) -> TransparencyAnchorReceipt:
    normalized = _validate_receipt_payload(
        {field_name: payload[field_name] for field_name in RECEIPT_PAYLOAD_FIELDS}
    )
    signature = private_key.sign(signed_receipt_bytes(normalized)).hex()
    return TransparencyAnchorReceipt.from_dict(
        {
            **normalized,
            "payload_digest": receipt_payload_digest(normalized),
            "signature_encoding": TREE_HEAD_SIGNATURE_ENCODING,
            "signature": signature,
        }
    )


def create_anchor_receipt(
    tree_head: Mapping[str, Any] | TransparencyTreeHead,
    *,
    private_key: Ed25519PrivateKey,
    key_id: str,
    provider_id: str,
    provider_type: str = PROVIDER_TYPE_LOCAL_TEST,
    anchor_status: str = ANCHOR_SIMULATED,
    timestamp: str | None = None,
) -> TransparencyAnchorReceipt:
    """Create a signed receipt for one tree head using an explicit test key."""
    normalized = tree_head if isinstance(tree_head, TransparencyTreeHead) else validate_tree_head(tree_head)
    raw_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    payload = build_receipt_payload(
        provider_id=provider_id,
        provider_type=provider_type,
        anchor_status=anchor_status,
        log_id=normalized.log_id,
        tree_size=normalized.tree_size,
        merkle_root=normalized.merkle_root,
        tree_head_id=normalized.tree_head_id,
        tree_head_digest=normalized.document_digest(),
        receipt_timestamp=_timestamp(
            timestamp or utc_now_iso(),
            field_name="receipt_timestamp",
            reason_code=RECEIPT_TIMESTAMP_INVALID,
        ),
        key_id=key_id,
        public_key=encode_public_key(raw_public_key),
        public_key_fingerprint_value=public_key_fingerprint(raw_public_key),
    )
    return sign_receipt_payload(payload, private_key)


def load_receipt(path: Path) -> TransparencyAnchorReceipt:
    payload = _read_json_strict(
        Path(path),
        label="anchor receipt",
        max_bytes=MAX_RECEIPT_BYTES,
        invalid_reason=RECEIPT_SCHEMA_INVALID,
        missing_reason=RECEIPT_SCHEMA_INVALID,
    )
    return TransparencyAnchorReceipt.from_dict(payload)


def write_receipt(
    path: Path,
    receipt: Mapping[str, Any] | TransparencyAnchorReceipt,
    *,
    overwrite: bool = False,
) -> None:
    normalized = receipt if isinstance(receipt, TransparencyAnchorReceipt) else validate_receipt(receipt)
    _write_json_atomic(Path(path), normalized.to_dict(), overwrite=overwrite, mode=0o644)


def validate_receipt(payload: Mapping[str, Any]) -> TransparencyAnchorReceipt:
    """Validate and normalize a receipt without verifying its signature."""
    return TransparencyAnchorReceipt.from_dict(payload)


@dataclass
class ReceiptVerification:
    """Result of verifying one provider receipt."""

    outcome: str = NOT_RUN
    receipt: TransparencyAnchorReceipt | None = field(default=None, repr=False)
    checks: list[TransparencyCheck] = field(default_factory=list)
    reason_codes: list[str] = field(default_factory=list)
    anchor_status: str | None = None
    assurance: str = "none"
    limitations: list[str] = field(default_factory=list)

    def add(self, check: TransparencyCheck) -> TransparencyCheck:
        self.checks.append(check)
        return check

    def finalize(self) -> ReceiptVerification:
        required = [check for check in self.checks if check.required]
        outcomes = {check.outcome for check in required}
        for state in (FAIL, UNAVAILABLE, NOT_RUN):
            if state in outcomes:
                self.outcome = state
                break
        else:
            self.outcome = PASS if required else NOT_RUN
        codes: list[str] = []
        for check in self.checks:
            if check.reason_code is not None and check.outcome != PASS and check.reason_code not in codes:
                codes.append(check.reason_code)
        self.reason_codes = codes
        return self

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "outcome": self.outcome,
            "anchor_status": self.anchor_status,
            "assurance": self.assurance,
            "external_anchoring": False,
            "external_anchor": ANCHOR_NOT_CONFIGURED,
            "receipt": self.receipt.to_dict() if self.receipt is not None else None,
            "reason_codes": sorted(set(self.reason_codes)),
            "checks": [check.to_dict() for check in self.checks],
            "limitations": [redact_text(item)[:500] for item in self.limitations],
        }
        cleaned = redact_structure(payload)
        if not isinstance(cleaned, dict):
            raise TransparencyError("receipt verification result could not be sanitized")
        return cleaned


def verify_receipt(
    receipt: Mapping[str, Any] | TransparencyAnchorReceipt,
    *,
    tree_head: Mapping[str, Any] | TransparencyTreeHead | None = None,
    expected_provider_id: str | None = None,
    trusted_provider_fingerprint: str | None = None,
    now: str | None = None,
    external_provider_configured: bool = False,
) -> ReceiptVerification:
    """Verify a receipt signature, status, binding, and freshness.

    A ``SIMULATED`` local-test receipt verifies structurally and
    cryptographically but never establishes external anchoring. An
    ``EXTERNAL_VERIFIED`` receipt is refused unless an external provider is
    explicitly configured; V32 ships no such provider.
    """
    result = ReceiptVerification()
    try:
        normalized = (
            receipt
            if isinstance(receipt, TransparencyAnchorReceipt)
            else TransparencyAnchorReceipt.from_dict(receipt)
        )
    except (TransparencyError, MerkleError) as exc:
        reason = getattr(exc, "reason_code", RECEIPT_SCHEMA_INVALID)
        result.add(TransparencyCheck("receipt-schema", FAIL, str(exc), reason_code=reason))
        return result.finalize()
    result.receipt = normalized
    result.anchor_status = normalized.anchor_status
    result.add(
        TransparencyCheck(
            "receipt-schema",
            PASS,
            "receipt schema, identifier, payload digest, and canonical fields are valid",
        )
    )
    if expected_provider_id is not None and normalized.provider_id != expected_provider_id:
        result.add(
            TransparencyCheck(
                "receipt-provider",
                FAIL,
                "receipt provider identifier does not match the configured provider",
                reason_code=RECEIPT_PROVIDER_MISMATCH,
            )
        )
    else:
        result.add(TransparencyCheck("receipt-provider", PASS, "receipt provider identifier is consistent"))
    if normalized.anchor_status == ANCHOR_EXTERNAL_VERIFIED:
        if not external_provider_configured:
            result.add(
                TransparencyCheck(
                    "receipt-status",
                    FAIL,
                    (
                        "receipt claims external anchoring but no external provider is configured "
                        "or verified in this offline deployment"
                    ),
                    reason_code=PROVIDER_NOT_CONFIGURED,
                )
            )
        else:
            result.add(
                TransparencyCheck(
                    "receipt-status",
                    PASS,
                    "receipt reports external anchoring from a configured external provider",
                )
            )
    elif normalized.anchor_status == ANCHOR_SIMULATED:
        result.add(
            TransparencyCheck(
                "receipt-status",
                PASS,
                "receipt reports SIMULATED local test anchoring; this is not external trust",
            )
        )
    else:
        result.add(
            TransparencyCheck(
                "receipt-status",
                FAIL,
                "receipt reports a status that cannot be verified by this deployment",
                reason_code=RECEIPT_STATUS_INVALID,
            )
        )
    if trusted_provider_fingerprint is not None:
        if DIGEST_PATTERN.fullmatch(trusted_provider_fingerprint) is None:
            result.add(
                TransparencyCheck(
                    "receipt-key",
                    FAIL,
                    "trusted provider fingerprint is not sha256:<64 lowercase hex>",
                    reason_code=RECEIPT_PROVIDER_MISMATCH,
                )
            )
        elif normalized.public_key_fingerprint != trusted_provider_fingerprint:
            result.add(
                TransparencyCheck(
                    "receipt-key",
                    FAIL,
                    "receipt public key does not match the configured provider fingerprint",
                    reason_code=RECEIPT_PROVIDER_MISMATCH,
                )
            )
        else:
            result.add(
                TransparencyCheck(
                    "receipt-key",
                    PASS,
                    "receipt public key matches the configured provider fingerprint",
                )
            )
    else:
        result.add(
            TransparencyCheck(
                "receipt-key",
                NOT_RUN,
                (
                    "no provider fingerprint is pinned; the receipt signature proves only that the "
                    "embedded key signed this document"
                ),
                required=False,
            )
        )
    try:
        Ed25519PublicKey.from_public_bytes(decode_public_key(normalized.public_key)).verify(
            bytes.fromhex(normalized.signature),
            signed_receipt_bytes(normalized.payload()),
        )
    except InvalidSignature:
        result.add(
            TransparencyCheck(
                "receipt-signature",
                FAIL,
                "receipt signature does not match the exact domain-separated canonical payload",
                reason_code=RECEIPT_SIGNATURE_MISMATCH,
            )
        )
    except (ValueError, TypeError):
        result.add(
            TransparencyCheck(
                "receipt-signature",
                FAIL,
                "receipt signature or public key is malformed",
                reason_code=RECEIPT_SIGNATURE_MALFORMED,
            )
        )
    else:
        result.add(
            TransparencyCheck(
                "receipt-signature",
                PASS,
                "receipt signature verifies over the exact domain-separated canonical payload",
            )
        )
    if tree_head is not None:
        try:
            normalized_head = (
                tree_head if isinstance(tree_head, TransparencyTreeHead) else validate_tree_head(tree_head)
            )
        except (TransparencyError, MerkleError) as exc:
            result.add(
                TransparencyCheck(
                    "receipt-tree-head",
                    FAIL,
                    f"tree head could not be validated: {exc}",
                    reason_code=RECEIPT_TREE_HEAD_MISMATCH,
                )
            )
        else:
            mismatches = []
            if normalized.log_id != normalized_head.log_id:
                mismatches.append("log identifier")
            if normalized.tree_size != normalized_head.tree_size:
                mismatches.append("tree size")
            if normalized.merkle_root != normalized_head.merkle_root:
                mismatches.append("Merkle root")
            if normalized.tree_head_id != normalized_head.tree_head_id:
                mismatches.append("tree-head identifier")
            if normalized.tree_head_digest != normalized_head.document_digest():
                mismatches.append("tree-head document digest")
            if mismatches:
                result.add(
                    TransparencyCheck(
                        "receipt-tree-head",
                        FAIL,
                        "receipt does not bind the supplied tree head: " + ", ".join(mismatches),
                        reason_code=RECEIPT_TREE_HEAD_MISMATCH,
                    )
                )
            else:
                result.add(
                    TransparencyCheck(
                        "receipt-tree-head",
                        PASS,
                        "receipt binds the supplied tree head, tree size, root, and document digest",
                    )
                )
            if normalized.receipt_timestamp < normalized_head.timestamp:
                result.add(
                    TransparencyCheck(
                        "receipt-timestamp-order",
                        FAIL,
                        "receipt timestamp precedes the tree-head timestamp",
                        reason_code=RECEIPT_TIMESTAMP_INVALID,
                    )
                )
            else:
                result.add(
                    TransparencyCheck(
                        "receipt-timestamp-order",
                        PASS,
                        "receipt timestamp does not precede the tree-head timestamp",
                    )
                )
    if now is not None:
        reference = _timestamp(
            now,
            field_name="receipt verification time",
            reason_code=RECEIPT_TIMESTAMP_INVALID,
        )
        age = _seconds_between(normalized.receipt_timestamp, reference)
        if age > MAX_RECEIPT_AGE_SECONDS:
            result.add(
                TransparencyCheck(
                    "receipt-freshness",
                    FAIL,
                    "receipt is older than the supported freshness window",
                    reason_code=RECEIPT_STALE,
                )
            )
        elif age < -MAX_RECEIPT_CLOCK_SKEW_SECONDS:
            result.add(
                TransparencyCheck(
                    "receipt-freshness",
                    FAIL,
                    "receipt timestamp is in the future beyond the supported clock skew",
                    reason_code=RECEIPT_TIMESTAMP_INVALID,
                )
            )
        else:
            result.add(
                TransparencyCheck(
                    "receipt-freshness",
                    PASS,
                    "receipt timestamp is within the supported freshness window",
                )
            )
    else:
        result.add(
            TransparencyCheck(
                "receipt-freshness",
                NOT_RUN,
                "no reference time was supplied; receipt age was not evaluated",
                reason_code=RECEIPT_STALE,
                required=False,
            )
        )
    result.assurance = "simulated" if normalized.anchor_status == ANCHOR_SIMULATED else "external"
    result.limitations.extend(
        [
            (
                "A SIMULATED receipt is produced by a local deterministic test provider. It proves "
                "only that a local test key signed the receipt; it is not independent evidence."
            ),
            (
                "The receipt public key is embedded in the receipt. Without an explicitly pinned "
                "provider fingerprint, the signature is self-asserted."
            ),
            "No external transparency provider is configured or contacted by V32.",
        ]
    )
    return result.finalize()


def _seconds_between(earlier: str, later: str) -> int:
    try:
        start = datetime.fromisoformat(earlier.replace("Z", "+00:00"))
        end = datetime.fromisoformat(later.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TransparencyInvalid(
            "timestamp could not be parsed", reason_code=RECEIPT_TIMESTAMP_INVALID
        ) from exc
    if start.tzinfo is None or end.tzinfo is None:
        raise TransparencyInvalid("timestamp must include a timezone", reason_code=RECEIPT_TIMESTAMP_INVALID)
    return int((end - start).total_seconds())


# ---------------------------------------------------------------------------
# Provider-neutral anchoring interface and local test provider
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProviderCapabilities:
    """Explicit capability metadata for one anchor provider."""

    provider_id: str
    provider_type: str
    anchor_status: str
    external: bool
    independent: bool
    assurance: str
    supports_submit_tree_head: bool
    supports_receipt_retrieval: bool
    supports_anchored_tree_head_retrieval: bool
    supports_consistency_proof_retrieval: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "profile": PROVIDER_PROFILE,
            "provider_id": self.provider_id,
            "provider_type": self.provider_type,
            "anchor_status": self.anchor_status,
            "external": self.external,
            "independent": self.independent,
            "assurance": self.assurance,
            "supports_submit_tree_head": self.supports_submit_tree_head,
            "supports_receipt_retrieval": self.supports_receipt_retrieval,
            "supports_anchored_tree_head_retrieval": self.supports_anchored_tree_head_retrieval,
            "supports_consistency_proof_retrieval": self.supports_consistency_proof_retrieval,
            "external_anchoring": self.external and self.anchor_status == ANCHOR_EXTERNAL_VERIFIED,
            "detail": redact_text(self.detail)[:500],
        }


class AnchorProvider(Protocol):
    """Provider-neutral transparency anchoring interface.

    Implementations may be local test providers or genuinely external
    providers. V32 ships only :class:`LocalTestAnchorProvider`; the protocol is
    defined so a future external implementation cannot silently reuse local
    simulated status.
    """

    @property
    def capabilities(self) -> ProviderCapabilities: ...

    def submit_tree_head(
        self,
        tree_head: Mapping[str, Any] | TransparencyTreeHead,
        *,
        timestamp: str | None = None,
    ) -> TransparencyAnchorReceipt: ...

    def retrieve_receipt(self, receipt_id: str) -> TransparencyAnchorReceipt: ...

    def verify_receipt(
        self,
        receipt: Mapping[str, Any] | TransparencyAnchorReceipt,
        *,
        tree_head: Mapping[str, Any] | TransparencyTreeHead | None = None,
        now: str | None = None,
    ) -> ReceiptVerification: ...

    def retrieve_anchored_tree_head(
        self,
        *,
        log_id: str,
        tree_size: int,
    ) -> TransparencyTreeHead: ...

    def retrieve_consistency_proof(
        self,
        *,
        log_id: str,
        old_tree_size: int,
        new_tree_size: int,
    ) -> ConsistencyProof: ...


class LocalTestAnchorProvider:
    """Offline deterministic test provider that issues SIMULATED receipts.

    This provider stores receipts and tree heads in local directories. It does
    not contact any service, does not provide independent immutability, and
    never reports external anchoring. It is intended for tests and operator
    drills only.
    """

    def __init__(
        self,
        *,
        provider_id: str = "local-test-anchor",
        receipt_dir: Path,
        private_key_path: Path,
        key_id: str,
        tree_head_dir: Path | None = None,
        proof_dir: Path | None = None,
    ) -> None:
        self._provider_id = _safe_text(
            provider_id,
            field_name="provider_id",
            pattern=SAFE_PROVIDER_ID,
            reason_code=RECEIPT_PROVIDER_MISMATCH,
        )
        self._key_id = _safe_text(
            key_id,
            field_name="key_id",
            pattern=SAFE_KEY_ID,
            reason_code=RECEIPT_SCHEMA_INVALID,
        )
        self._private_key = load_private_key(Path(private_key_path))
        raw_public_key = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._fingerprint = public_key_fingerprint(raw_public_key)
        self._receipt_dir = Path(receipt_dir)
        self._tree_head_dir = Path(tree_head_dir) if tree_head_dir is not None else None
        self._proof_dir = Path(proof_dir) if proof_dir is not None else None

    @property
    def provider_id(self) -> str:
        return self._provider_id

    @property
    def fingerprint(self) -> str:
        return self._fingerprint

    @property
    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider_id=self._provider_id,
            provider_type=PROVIDER_TYPE_LOCAL_TEST,
            anchor_status=ANCHOR_SIMULATED,
            external=False,
            independent=False,
            assurance="simulated",
            supports_submit_tree_head=True,
            supports_receipt_retrieval=True,
            supports_anchored_tree_head_retrieval=self._tree_head_dir is not None,
            supports_consistency_proof_retrieval=self._proof_dir is not None,
            detail=(
                "Local deterministic test provider. Receipts are SIMULATED and stored on the "
                "local filesystem; they are not external or independent anchoring."
            ),
        )

    def submit_tree_head(
        self,
        tree_head: Mapping[str, Any] | TransparencyTreeHead,
        *,
        timestamp: str | None = None,
    ) -> TransparencyAnchorReceipt:
        normalized = (
            tree_head if isinstance(tree_head, TransparencyTreeHead) else validate_tree_head(tree_head)
        )
        receipt = create_anchor_receipt(
            normalized,
            private_key=self._private_key,
            key_id=self._key_id,
            provider_id=self._provider_id,
            provider_type=PROVIDER_TYPE_LOCAL_TEST,
            anchor_status=ANCHOR_SIMULATED,
            timestamp=timestamp,
        )
        try:
            self._receipt_dir.mkdir(parents=True, exist_ok=True)
            receipt_path = self._receipt_dir / f"{receipt.receipt_id}.json"
            if receipt_path.exists():
                if load_receipt(receipt_path) != receipt:
                    raise ProviderUnavailable(
                        "local test provider already holds a different receipt with this identifier",
                        reason_code=PROVIDER_UNAVAILABLE,
                    )
            else:
                write_receipt(receipt_path, receipt)
            if self._tree_head_dir is not None:
                target = self._tree_head_dir / normalized.log_id / f"{normalized.tree_size}.json"
                if target.exists():
                    if load_tree_head(target) != normalized:
                        raise ProviderUnavailable(
                            "local test provider already holds a different tree head for this "
                            "log and tree size",
                            reason_code=PROVIDER_UNAVAILABLE,
                        )
                else:
                    write_tree_head(target, normalized)
        except ProviderUnavailable:
            raise
        except (OSError, TransparencyError) as exc:
            raise ProviderUnavailable(
                f"local test provider could not persist the receipt: {exc}",
                reason_code=PROVIDER_UNAVAILABLE,
            ) from exc
        return receipt

    def retrieve_receipt(self, receipt_id: str) -> TransparencyAnchorReceipt:
        _safe_text(
            receipt_id,
            field_name="receipt_id",
            pattern=RECEIPT_ID_PATTERN,
            reason_code=RECEIPT_SCHEMA_INVALID,
        )
        path = self._receipt_dir / f"{receipt_id}.json"
        try:
            return load_receipt(path)
        except TransparencyError as exc:
            raise ProviderUnavailable(
                "local test provider does not have the requested receipt",
                reason_code=PROVIDER_UNAVAILABLE,
            ) from exc

    def verify_receipt(
        self,
        receipt: Mapping[str, Any] | TransparencyAnchorReceipt,
        *,
        tree_head: Mapping[str, Any] | TransparencyTreeHead | None = None,
        now: str | None = None,
    ) -> ReceiptVerification:
        return verify_receipt(
            receipt,
            tree_head=tree_head,
            expected_provider_id=self._provider_id,
            trusted_provider_fingerprint=self._fingerprint,
            now=now,
        )

    def retrieve_anchored_tree_head(
        self,
        *,
        log_id: str,
        tree_size: int,
    ) -> TransparencyTreeHead:
        if self._tree_head_dir is None:
            raise ProviderUnavailable(
                "local test provider was not configured to retain tree heads",
                reason_code=PROVIDER_UNAVAILABLE,
            )
        _safe_text(log_id, field_name="log_id", pattern=SAFE_LOG_ID)
        _int(tree_size, field_name="tree_size", minimum=0, maximum=MAX_MERKLE_LEAVES)
        path = self._tree_head_dir / log_id / f"{tree_size}.json"
        try:
            tree_head = load_tree_head(path)
        except TransparencyError as exc:
            raise ProviderUnavailable(
                "local test provider does not have the requested tree head",
                reason_code=PROVIDER_UNAVAILABLE,
            ) from exc
        if tree_head.log_id != log_id or tree_head.tree_size != tree_size:
            raise ProviderUnavailable(
                "stored tree head does not match the requested log and tree size",
                reason_code=PROVIDER_UNAVAILABLE,
            )
        return tree_head

    def retrieve_consistency_proof(
        self,
        *,
        log_id: str,
        old_tree_size: int,
        new_tree_size: int,
    ) -> ConsistencyProof:
        if self._proof_dir is None:
            raise ProviderUnavailable(
                "local test provider was not configured to retain consistency proofs",
                reason_code=PROVIDER_UNAVAILABLE,
            )
        _safe_text(log_id, field_name="log_id", pattern=SAFE_LOG_ID)
        _int(old_tree_size, field_name="old_tree_size", minimum=0, maximum=MAX_MERKLE_LEAVES)
        _int(new_tree_size, field_name="new_tree_size", minimum=0, maximum=MAX_MERKLE_LEAVES)
        path = self._proof_dir / log_id / f"{old_tree_size}-{new_tree_size}.json"
        try:
            proof = load_consistency_proof(path)
        except TransparencyError as exc:
            raise ProviderUnavailable(
                "local test provider does not have the requested consistency proof",
                reason_code=PROVIDER_UNAVAILABLE,
            ) from exc
        if (
            proof.log_id != log_id
            or proof.old_tree_size != old_tree_size
            or proof.new_tree_size != new_tree_size
        ):
            raise ProviderUnavailable(
                "stored consistency proof does not match the requested log and tree sizes",
                reason_code=PROVIDER_UNAVAILABLE,
            )
        return proof


def provider_status(provider: AnchorProvider | None) -> dict[str, Any]:
    """Return explicit provider status and capability metadata."""
    if provider is None:
        return {
            "schema_version": 1,
            "profile": PROVIDER_PROFILE,
            "provider_id": None,
            "provider_type": None,
            "configured": False,
            "anchor_status": ANCHOR_NOT_CONFIGURED,
            "assurance": "none",
            "external": False,
            "independent": False,
            "external_anchoring": False,
            "detail": "no transparency anchor provider is configured",
        }
    try:
        capabilities = provider.capabilities
    except Exception:
        return {
            "schema_version": 1,
            "profile": PROVIDER_PROFILE,
            "provider_id": getattr(provider, "provider_id", None),
            "provider_type": None,
            "configured": True,
            "anchor_status": ANCHOR_UNAVAILABLE,
            "assurance": "none",
            "external": False,
            "independent": False,
            "external_anchoring": False,
            "detail": "configured provider did not return usable capability metadata",
        }
    payload = capabilities.to_dict()
    payload["configured"] = True
    return payload


# ---------------------------------------------------------------------------
# Proof file I/O and deterministic proof generation
# ---------------------------------------------------------------------------


def load_inclusion_proof(path: Path) -> InclusionProof:
    payload = _read_json_strict(
        Path(path),
        label="inclusion proof",
        max_bytes=MAX_PROOF_BYTES,
        invalid_reason="MERKLE_PROOF_SCHEMA_INVALID",
        missing_reason="MERKLE_PROOF_SCHEMA_INVALID",
    )
    try:
        return InclusionProof.from_dict(payload)
    except MerkleError as exc:
        raise TransparencyInvalid(str(exc), reason_code=exc.reason_code) from exc


def write_inclusion_proof(
    path: Path,
    proof: Mapping[str, Any] | InclusionProof,
    *,
    overwrite: bool = False,
) -> None:
    normalized = proof if isinstance(proof, InclusionProof) else InclusionProof.from_dict(proof)
    _write_json_atomic(Path(path), normalized.to_dict(), overwrite=overwrite, mode=0o644)


def load_consistency_proof(path: Path) -> ConsistencyProof:
    payload = _read_json_strict(
        Path(path),
        label="consistency proof",
        max_bytes=MAX_PROOF_BYTES,
        invalid_reason="MERKLE_PROOF_SCHEMA_INVALID",
        missing_reason="MERKLE_PROOF_SCHEMA_INVALID",
    )
    try:
        return ConsistencyProof.from_dict(payload)
    except MerkleError as exc:
        raise TransparencyInvalid(str(exc), reason_code=exc.reason_code) from exc


def write_consistency_proof(
    path: Path,
    proof: Mapping[str, Any] | ConsistencyProof,
    *,
    overwrite: bool = False,
) -> None:
    normalized = proof if isinstance(proof, ConsistencyProof) else ConsistencyProof.from_dict(proof)
    _write_json_atomic(Path(path), normalized.to_dict(), overwrite=overwrite, mode=0o644)


def inclusion_proof_for_log(log_path: Path, leaf_index: int) -> InclusionProof:
    """Generate an inclusion proof from a fully verified transparency log."""
    verification = verify_log(Path(log_path))
    if verification.outcome != PASS:
        raise TransparencyConflict(
            "cannot generate a proof from an invalid transparency log",
            reason_code=TRANSPARENCY_LOG_CHAIN_INVALID,
        )
    log = read_log(Path(log_path))
    return log.tree().inclusion_proof(leaf_index)


def consistency_proof_for_log(log_path: Path, old_tree_size: int) -> ConsistencyProof:
    """Generate a consistency proof from a fully verified transparency log."""
    verification = verify_log(Path(log_path))
    if verification.outcome != PASS:
        raise TransparencyConflict(
            "cannot generate a proof from an invalid transparency log",
            reason_code=TRANSPARENCY_LOG_CHAIN_INVALID,
        )
    log = read_log(Path(log_path))
    return log.tree().consistency_proof(old_tree_size)


# ---------------------------------------------------------------------------
# Aggregate offline status
# ---------------------------------------------------------------------------


def build_status_report(
    *,
    log_path: Path | None = None,
    tree_head_path: Path | None = None,
    receipt_path: Path | None = None,
    trust_store_path: Path | None = None,
    trust_state_path: Path | None = None,
    consistency_proof_path: Path | None = None,
    provider: AnchorProvider | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    """Build a deterministic, redacted offline transparency status report."""
    components: dict[str, Any] = {}
    outcomes: list[str] = []
    limitations: list[str] = []
    log_result: LogVerification | None = None
    head_result: TreeHeadVerification | None = None
    receipt_result: ReceiptVerification | None = None

    if log_path is not None:
        log_result = verify_log(Path(log_path))
        components["log"] = log_result.to_dict()
        outcomes.append(log_result.outcome)
        limitations.extend(log_result.limitations)
    else:
        components["log"] = {"outcome": NOT_RUN, "detail": "no transparency log was supplied"}
        outcomes.append(NOT_RUN)

    if tree_head_path is not None:
        head_result = verify_tree_head(
            load_tree_head(Path(tree_head_path)).to_dict(),
            trust_store_path=trust_store_path,
            trust_state_path=trust_state_path,
            consistency_proof=(
                load_consistency_proof(Path(consistency_proof_path)).to_dict()
                if consistency_proof_path is not None
                else None
            ),
        )
        components["tree_head"] = head_result.to_dict()
        outcomes.append(head_result.outcome)
        limitations.extend(head_result.limitations)
    else:
        components["tree_head"] = {"outcome": NOT_RUN, "detail": "no tree head was supplied"}
        outcomes.append(NOT_RUN)

    if receipt_path is not None:
        receipt_result = verify_receipt(
            load_receipt(Path(receipt_path)),
            tree_head=head_result.tree_head if head_result is not None else None,
            expected_provider_id=(provider.capabilities.provider_id if provider is not None else None),
            now=now,
        )
        components["receipt"] = receipt_result.to_dict()
        outcomes.append(receipt_result.outcome)
        limitations.extend(receipt_result.limitations)
    else:
        components["receipt"] = {"outcome": NOT_RUN, "detail": "no anchor receipt was supplied"}
        outcomes.append(NOT_RUN)

    components["provider"] = provider_status(provider)

    if FAIL in outcomes:
        outcome = FAIL
    elif UNAVAILABLE in outcomes:
        outcome = UNAVAILABLE
    elif all(item == NOT_RUN for item in outcomes):
        outcome = NOT_RUN
    else:
        outcome = PASS

    if (
        receipt_result is not None
        and receipt_result.outcome == PASS
        and receipt_result.anchor_status == ANCHOR_SIMULATED
    ):
        assurance = "simulated"
    elif head_result is not None and head_result.outcome == PASS:
        assurance = "reduced"
    elif log_result is not None and log_result.outcome == PASS:
        assurance = "local-only"
    else:
        assurance = "none"

    limitations.append(
        "V32 is offline by default. No external transparency service, cloud KMS, or independent "
        "anchor is configured or contacted."
    )
    payload = {
        "schema_version": 1,
        "profile": "transparency_status_report",
        "outcome": outcome,
        "assurance": assurance,
        "external_anchor": ANCHOR_NOT_CONFIGURED,
        "external_anchoring": False,
        "provider": components["provider"],
        "components": components,
        "limitations": limitations,
    }
    cleaned = redact_structure(payload)
    if not isinstance(cleaned, dict):
        raise TransparencyError("status report could not be sanitized")
    return cleaned


__all__ = [
    "ANCHOR_EXTERNAL_VERIFIED",
    "ANCHOR_NOT_CONFIGURED",
    "ANCHOR_SIMULATED",
    "ANCHOR_STATUSES",
    "ANCHOR_UNAVAILABLE",
    "CONSISTENCY_PROOF_INVALID",
    "CONSISTENCY_PROOF_MISSING",
    "DEFAULT_LOG_ID",
    "MAX_LOG_BYTES",
    "MAX_LOG_ENTRIES",
    "MAX_LOG_LINE_BYTES",
    "MAX_RECEIPT_AGE_SECONDS",
    "MAX_RECEIPT_BYTES",
    "MAX_RECEIPT_CLOCK_SKEW_SECONDS",
    "MAX_TRANSPARENCY_STATE_BYTES",
    "MAX_TRANSPARENCY_STATE_ENTRIES",
    "MAX_TREE_HEAD_BYTES",
    "PROVIDER_NOT_CONFIGURED",
    "PROVIDER_PROFILE",
    "PROVIDER_TYPE_EXTERNAL",
    "PROVIDER_TYPE_LOCAL_TEST",
    "PROVIDER_UNAVAILABLE",
    "PROVIDER_UNKNOWN",
    "RECEIPT_FIELDS",
    "RECEIPT_ID_MISMATCH",
    "RECEIPT_LOG_MISMATCH",
    "RECEIPT_PAYLOAD_DIGEST_MISMATCH",
    "RECEIPT_PAYLOAD_FIELDS",
    "RECEIPT_PROFILE",
    "RECEIPT_PROVIDER_MISMATCH",
    "RECEIPT_ROOT_MISMATCH",
    "RECEIPT_SCHEMA_INVALID",
    "RECEIPT_SCHEMA_VERSION",
    "RECEIPT_SIGNATURE_MALFORMED",
    "RECEIPT_SIGNATURE_MISMATCH",
    "RECEIPT_STALE",
    "RECEIPT_STATUS_INVALID",
    "RECEIPT_TIMESTAMP_INVALID",
    "RECEIPT_TREE_HEAD_MISMATCH",
    "RECEIPT_TREE_SIZE_MISMATCH",
    "TREE_HEAD_CONFLICT",
    "TREE_HEAD_DOMAIN",
    "TREE_HEAD_DUPLICATE",
    "TREE_HEAD_FIELDS",
    "TREE_HEAD_ID_MISMATCH",
    "TREE_HEAD_KEY_ALGORITHM_DISALLOWED",
    "TREE_HEAD_KEY_EXPIRED",
    "TREE_HEAD_KEY_NOT_YET_VALID",
    "TREE_HEAD_KEY_PURPOSE_INVALID",
    "TREE_HEAD_KEY_REVOKED",
    "TREE_HEAD_KEY_UNKNOWN",
    "TREE_HEAD_KEY_UNTRUSTED",
    "TREE_HEAD_PAYLOAD_DIGEST_MISMATCH",
    "TREE_HEAD_PAYLOAD_FIELDS",
    "TREE_HEAD_PROFILE",
    "TREE_HEAD_REPLAY",
    "TREE_HEAD_SCHEMA_INVALID",
    "TREE_HEAD_SCHEMA_VERSION",
    "TREE_HEAD_SIGNATURE_MALFORMED",
    "TREE_HEAD_SIGNATURE_MISMATCH",
    "TREE_HEAD_TIMESTAMP_REGRESSION",
    "TREE_HEAD_TRUST_STORE_MISSING",
    "TREE_ROOT_CONFLICT",
    "TREE_SIZE_ROLLBACK",
    "TRANSPARENCY_LOG_CHAIN_INVALID",
    "TRANSPARENCY_LOG_DUPLICATE",
    "TRANSPARENCY_LOG_ENTRY_INVALID",
    "TRANSPARENCY_LOG_ENTRY_PROFILE",
    "TRANSPARENCY_LOG_ENTRY_TYPE_CHECKPOINT",
    "TRANSPARENCY_LOG_GENESIS_PREVIOUS",
    "TRANSPARENCY_LOG_HASH_ALGORITHM",
    "TRANSPARENCY_LOG_HEADER_INVALID",
    "TRANSPARENCY_LOG_INDEX_INVALID",
    "TRANSPARENCY_LOG_MERKLE_ALGORITHM",
    "TRANSPARENCY_LOG_PROFILE",
    "TRANSPARENCY_LOG_SCHEMA_INVALID",
    "TRANSPARENCY_LOG_SCHEMA_VERSION",
    "TRANSPARENCY_LOG_SEQUENCE_INVALID",
    "TRANSPARENCY_LOG_TIMESTAMP_INVALID",
    "TRANSPARENCY_LOG_TOO_LARGE",
    "TRANSPARENCY_LOG_TREE_HEAD_MISMATCH",
    "TRANSPARENCY_LOG_UNAVAILABLE",
    "TRANSPARENCY_STATE_INVALID",
    "TRANSPARENCY_STATE_MISSING",
    "TRANSPARENCY_STATE_PROFILE",
    "TRANSPARENCY_STATE_SCHEMA_VERSION",
    "AnchorProvider",
    "LogVerification",
    "LocalTestAnchorProvider",
    "ProviderCapabilities",
    "ProviderUnavailable",
    "ProviderUnknown",
    "ReceiptVerification",
    "TransparencyAnchorReceipt",
    "TransparencyCheck",
    "TransparencyConflict",
    "TransparencyError",
    "TransparencyInvalid",
    "TransparencyLog",
    "TransparencyLogEntry",
    "TransparencyLogHeader",
    "TransparencyStateEntry",
    "TransparencyTreeHead",
    "TransparencyTrustState",
    "TransparencyUnavailable",
    "TreeHeadVerification",
    "advance_transparency_state",
    "append_checkpoint",
    "build_log_entry",
    "build_receipt_payload",
    "build_status_report",
    "build_tree_head_payload",
    "checkpoint_document_digest",
    "consistency_proof_for_log",
    "create_anchor_receipt",
    "create_tree_head",
    "derive_log_entry_id",
    "derive_receipt_id",
    "derive_tree_head_id",
    "detect_split_view",
    "empty_transparency_state",
    "evaluate_transparency_state",
    "inclusion_proof_for_log",
    "init_log",
    "load_consistency_proof",
    "load_inclusion_proof",
    "load_receipt",
    "load_transparency_state",
    "load_tree_head",
    "provider_status",
    "read_log",
    "receipt_document_digest",
    "receipt_payload_digest",
    "signed_receipt_bytes",
    "signed_tree_head_bytes",
    "sign_receipt_payload",
    "sign_tree_head_payload",
    "transparency_state_entry",
    "tree_head_document_digest",
    "tree_head_payload",
    "tree_head_payload_digest",
    "validate_receipt",
    "validate_transparency_state",
    "validate_tree_head",
    "verify_log",
    "verify_receipt",
    "verify_tree_head",
    "write_consistency_proof",
    "write_inclusion_proof",
    "write_log",
    "write_receipt",
    "write_transparency_state",
    "write_tree_head",
]
