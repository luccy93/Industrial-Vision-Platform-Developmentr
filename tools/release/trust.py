"""V31 signed evidence checkpoints, trust stores, and key lifecycle.

V30 proved that retained evidence still matched its recorded SHA-256 digests
and that the local audit chain was internally consistent. It did not prove who
produced a checkpoint. V31 adds an asymmetric signature over an exact canonical
payload, an independently configured trust store, a monotonic trust-state
record for replay detection, and an optional external-anchor interface.

The trust boundary is deliberately narrow:

* A signature proves possession of the private key that signed the exact
  canonical payload. It does not prove that the evidence is truthful or
  complete.
* A public key copied beside a checkpoint is an untrusted candidate. It is used
  only when its fingerprint matches a separately configured trust store entry
  or a separately supplied trusted fingerprint.
* A local trust-state file is tamper-evident, not independently monotonic. An
  attacker who can rewrite it can also rewrite the sequence it records. V31
  reports that reduced assurance explicitly and never claims external
  anchoring was performed.
* No external service, cloud KMS, registry, or network endpoint is contacted.
  Callers must explicitly supply an :class:`ExternalTrustAnchor`; V31 ships no
  live implementation.

Canonicalization and domain separation
--------------------------------------

The signed bytes are::

    b"industrial-vision-platform:evidence-checkpoint:v1\\x00" + canonical_json

where ``canonical_json`` is UTF-8 JSON with sorted keys, compact separators,
``ensure_ascii=True``, and no trailing newline. The domain prefix is mandatory:
a signature over the payload without the prefix does not verify.

Algorithms
----------

Ed25519 is the only accepted signature algorithm in V31. It is deterministic,
small, and available through the maintained ``cryptography`` dependency.
Unknown algorithms are rejected before any signature operation.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from backend.app.core.redaction import (
    contains_sensitive_material,
    redact_structure,
    redact_text,
)
from tools.release.identity import DIGEST_PATTERN
from tools.release.integrity import (
    AUDIT_CHAIN_INVALID,
    EVIDENCE_REJECTED,
    EVIDENCE_VERIFIED,
    AuditChainError,
    AuditVerification,
    IntegrityError,
    canonical_json_bytes,
    normalize_timestamp,
    read_audit_chain,
    sha256_bytes,
    validate_checkpoint,
    verify_audit_chain,
)
from tools.release.manifest import sha256_file, utc_now_iso
from tools.release.verification import FAIL, NOT_RUN, PASS, UNAVAILABLE

SIGNED_CHECKPOINT_SCHEMA_VERSION = 2
SIGNED_CHECKPOINT_PROFILE = "evidence_checkpoint_signed"
TRUST_STORE_SCHEMA_VERSION = 1
TRUST_STORE_PROFILE = "evidence_trust_store"
TRUST_STATE_SCHEMA_VERSION = 1
TRUST_STATE_PROFILE = "evidence_trust_state"
PUBLIC_KEY_PROFILE = "evidence_public_key"

SIGNATURE_ALGORITHM = "ed25519"
SUPPORTED_SIGNATURE_ALGORITHMS = (SIGNATURE_ALGORITHM,)
PUBLIC_KEY_ENCODING = "base64url"
SIGNATURE_ENCODING = "hex"
KEY_PURPOSE_EVIDENCE_CHECKPOINT = "evidence_checkpoint_signing"
KEY_PURPOSE_TRANSPARENCY_TREE_HEAD = "transparency_tree_head_signing"
SUPPORTED_KEY_PURPOSES = (
    KEY_PURPOSE_EVIDENCE_CHECKPOINT,
    KEY_PURPOSE_TRANSPARENCY_TREE_HEAD,
)
HISTORICAL_REVOCATION_ALLOW = "allow_before_revocation"
HISTORICAL_REVOCATION_DENY = "deny"
HISTORICAL_REVOCATION_POLICIES = (
    HISTORICAL_REVOCATION_ALLOW,
    HISTORICAL_REVOCATION_DENY,
)

SIGNED_CHECKPOINT_DOMAIN = b"industrial-vision-platform:evidence-checkpoint:v1\x00"

SIGNED_CHECKPOINT_PAYLOAD_FIELDS = (
    "schema_version",
    "profile",
    "checkpoint_id",
    "evidence_report_id",
    "audit_chain_terminal_hash",
    "audit_chain_terminal_event_id",
    "audit_chain_terminal_timestamp",
    "audit_record_count",
    "evidence_manifest_digest",
    "checkpoint_sequence",
    "created_at",
    "key_id",
    "public_key_fingerprint",
    "public_key",
    "signature_algorithm",
)

SIGNED_CHECKPOINT_FIELDS = (
    *SIGNED_CHECKPOINT_PAYLOAD_FIELDS,
    "payload_digest",
    "signature_encoding",
    "signature",
)

PUBLIC_KEY_DESCRIPTOR_FIELDS = (
    "schema_version",
    "profile",
    "key_id",
    "algorithm",
    "public_key",
    "public_key_encoding",
    "fingerprint",
    "generated_at",
)

TRUSTED_KEY_FIELDS = (
    "key_id",
    "public_key",
    "fingerprint",
    "purpose",
    "allowed_algorithms",
    "activated_at",
    "expires_at",
    "revoked_at",
    "revocation_reason",
)

TRUST_STORE_FIELDS = (
    "schema_version",
    "profile",
    "policy_version",
    "public_key_encoding",
    "historical_revocation_policy",
    "keys",
)

TRUST_STATE_ENTRY_FIELDS = (
    "evidence_report_id",
    "checkpoint_id",
    "checkpoint_sequence",
    "audit_record_count",
    "audit_chain_terminal_hash",
    "evidence_manifest_digest",
    "created_at",
    "key_id",
)

TRUST_STATE_FIELDS = (
    "schema_version",
    "profile",
    "updated_at",
    "checkpoints",
    "state_digest",
)

EXTERNAL_REFERENCE_FIELDS = (
    "evidence_report_id",
    "checkpoint_id",
    "checkpoint_sequence",
    "audit_record_count",
    "audit_chain_terminal_hash",
    "evidence_manifest_digest",
    "created_at",
)

MAX_CHECKPOINT_BYTES = 1024 * 1024
MAX_TRUST_STORE_BYTES = 4 * 1024 * 1024
MAX_TRUST_STATE_BYTES = 16 * 1024 * 1024
MAX_PRIVATE_KEY_BYTES = 64 * 1024
MAX_TRUST_STATE_ENTRIES = 10_000

SAFE_KEY_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
SAFE_POLICY_VERSION = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
CHECKPOINT_ID_PATTERN = re.compile(r"^chk-[0-9a-f]{32}$")
REPORT_ID_PATTERN = re.compile(r"^report:sha256:[0-9a-f]{64}$")
PUBLIC_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
SIGNATURE_HEX_PATTERN = re.compile(r"^[0-9a-f]{128}$")
SAFE_EVENT_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,512}$")
CONTROL_CHARACTER = re.compile(r"[\x00-\x1f\x7f]")

# Stable reason codes. They are additive to the V30 exit-code contract.
CHECKPOINT_SCHEMA_INVALID = "CHECKPOINT_SCHEMA_INVALID"
CHECKPOINT_UNSIGNED = "CHECKPOINT_UNSIGNED"
CHECKPOINT_ALGORITHM_UNKNOWN = "CHECKPOINT_ALGORITHM_UNKNOWN"
CHECKPOINT_SIGNATURE_MALFORMED = "CHECKPOINT_SIGNATURE_MALFORMED"
CHECKPOINT_SIGNATURE_MISMATCH = "CHECKPOINT_SIGNATURE_MISMATCH"
CHECKPOINT_PAYLOAD_DIGEST_MISMATCH = "CHECKPOINT_PAYLOAD_DIGEST_MISMATCH"
CHECKPOINT_ID_MISMATCH = "CHECKPOINT_ID_MISMATCH"
CHECKPOINT_TIMESTAMP_INVALID = "CHECKPOINT_TIMESTAMP_INVALID"
CHECKPOINT_SEQUENCE_INVALID = "CHECKPOINT_SEQUENCE_INVALID"
CHECKPOINT_REPORT_MISMATCH = "CHECKPOINT_REPORT_MISMATCH"
CHECKPOINT_MANIFEST_MISSING = "CHECKPOINT_MANIFEST_MISSING"
CHECKPOINT_MANIFEST_MISMATCH = "CHECKPOINT_MANIFEST_MISMATCH"
CHECKPOINT_AUDIT_MISMATCH = "CHECKPOINT_AUDIT_MISMATCH"
CHECKPOINT_TIMESTAMP_INCONSISTENT = "CHECKPOINT_TIMESTAMP_INCONSISTENT"
CHECKPOINT_REPLAY = "CHECKPOINT_REPLAY"
CHECKPOINT_SEQUENCE_DUPLICATE = "CHECKPOINT_SEQUENCE_DUPLICATE"
CHECKPOINT_SEQUENCE_DECREASING = "CHECKPOINT_SEQUENCE_DECREASING"
CHECKPOINT_SEQUENCE_GAP = "CHECKPOINT_SEQUENCE_GAP"
CHECKPOINT_ID_REUSED = "CHECKPOINT_ID_REUSED"
CHECKPOINT_CONFLICT = "CHECKPOINT_CONFLICT"
AUDIT_HASH_ROLLBACK = "AUDIT_HASH_ROLLBACK"
MANIFEST_DIGEST_ROLLBACK = "MANIFEST_DIGEST_ROLLBACK"
CHAIN_TRUNCATION = "CHAIN_TRUNCATION"
CHAIN_EXTENSION = "CHAIN_EXTENSION"
TRUST_STORE_MISSING = "TRUST_STORE_MISSING"
TRUST_STORE_INVALID = "TRUST_STORE_INVALID"
TRUST_KEY_UNKNOWN = "TRUST_KEY_UNKNOWN"
TRUST_KEY_UNTRUSTED = "TRUST_KEY_UNTRUSTED"
TRUST_KEY_REVOKED = "TRUST_KEY_REVOKED"
TRUST_KEY_EXPIRED = "TRUST_KEY_EXPIRED"
TRUST_KEY_NOT_YET_VALID = "TRUST_KEY_NOT_YET_VALID"
TRUST_KEY_ALGORITHM_DISALLOWED = "TRUST_KEY_ALGORITHM_DISALLOWED"
TRUST_KEY_PURPOSE_INVALID = "TRUST_KEY_PURPOSE_INVALID"
TRUST_FINGERPRINT_MISMATCH = "TRUST_FINGERPRINT_MISMATCH"
TRUST_STATE_MISSING = "TRUST_STATE_MISSING"
TRUST_STATE_INVALID = "TRUST_STATE_INVALID"
SIGNED_CHECKPOINT_REQUIRES_REPORT = "SIGNED_CHECKPOINT_REQUIRES_REPORT"
INDEPENDENT_FRESHNESS_UNAVAILABLE = "INDEPENDENT_FRESHNESS_UNAVAILABLE"
EXTERNAL_ANCHOR_UNCONFIGURED = "EXTERNAL_ANCHOR_UNCONFIGURED"
EXTERNAL_ANCHOR_REFERENCE_MISSING = "EXTERNAL_ANCHOR_REFERENCE_MISSING"
EXTERNAL_ANCHOR_MISMATCH = "EXTERNAL_ANCHOR_MISMATCH"
PRIVATE_KEY_INVALID = "PRIVATE_KEY_INVALID"


class TrustError(ValueError):
    """A trust-store, checkpoint, or key-lifecycle request is invalid."""

    def __init__(self, message: str, *, reason_code: str = CHECKPOINT_SCHEMA_INVALID) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class TrustUnavailable(TrustError):
    """A required trust input is missing or unreadable."""


class TrustInvalid(TrustError):
    """A trust input exists but is malformed."""


class TrustConflict(TrustError):
    """A trust operation conflicts with recorded or configured state."""


def _canonical_bytes(value: Any) -> bytes:
    try:
        return canonical_json_bytes(value)
    except IntegrityError as exc:
        raise TrustInvalid("metadata cannot be serialized deterministically") from exc


def _safe_text(
    value: Any,
    *,
    field_name: str,
    pattern: re.Pattern[str] | None = None,
    reason_code: str = CHECKPOINT_SCHEMA_INVALID,
) -> str:
    if not isinstance(value, str) or not value:
        raise TrustInvalid(f"{field_name} must be a non-empty string", reason_code=reason_code)
    if CONTROL_CHARACTER.search(value):
        raise TrustInvalid(f"{field_name} contains a control character", reason_code=reason_code)
    if pattern is not None and pattern.fullmatch(value) is None:
        raise TrustInvalid(f"{field_name} contains unsupported characters", reason_code=reason_code)
    if contains_sensitive_material(value):
        raise TrustInvalid(f"{field_name} contains unsupported sensitive material", reason_code=reason_code)
    return value


def _timestamp(value: Any, *, field_name: str) -> str:
    try:
        normalized = normalize_timestamp(value)
    except IntegrityError as exc:
        raise TrustInvalid(
            f"{field_name} is not a valid UTC timestamp", reason_code=CHECKPOINT_TIMESTAMP_INVALID
        ) from exc
    if normalized != value:
        raise TrustInvalid(
            f"{field_name} must be canonical UTC with second precision",
            reason_code=CHECKPOINT_TIMESTAMP_INVALID,
        )
    return normalized


def _positive_int(value: Any, *, field_name: str, reason_code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise TrustInvalid(f"{field_name} must be a positive integer", reason_code=reason_code)
    return value


def _exact_fields(
    payload: Mapping[str, Any], expected: tuple[str, ...], *, label: str, reason_code: str
) -> None:
    if sorted(payload) != sorted(expected):
        raise TrustInvalid(f"{label} has unexpected or missing fields", reason_code=reason_code)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TrustInvalid("JSON document contains a duplicate field")
        result[key] = value
    return result


def load_json_document_strict(
    path: Path,
    *,
    label: str,
    max_bytes: int,
    invalid_reason: str,
    missing_reason: str,
) -> dict[str, Any]:
    """Read a UTF-8 JSON object, rejecting duplicate keys and oversized input."""
    path = Path(path)
    try:
        if not path.is_file():
            raise TrustUnavailable(f"{label} is missing or unreadable", reason_code=missing_reason)
        size = path.stat().st_size
    except OSError as exc:
        raise TrustUnavailable(f"{label} is missing or unreadable", reason_code=missing_reason) from exc
    if size > max_bytes:
        raise TrustInvalid(f"{label} exceeds the maximum supported size", reason_code=invalid_reason)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise TrustUnavailable(f"{label} is unreadable", reason_code=missing_reason) from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TrustInvalid(f"{label} is not valid UTF-8", reason_code=invalid_reason) from exc
    try:
        payload = json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
    except TrustError as exc:
        raise TrustInvalid(f"{label} contains a duplicate field", reason_code=invalid_reason) from exc
    except json.JSONDecodeError as exc:
        raise TrustInvalid(f"{label} is not valid JSON", reason_code=invalid_reason) from exc
    if not isinstance(payload, dict):
        raise TrustInvalid(f"{label} must be a JSON object", reason_code=invalid_reason)
    return payload


def encode_public_key(raw: bytes) -> str:
    """Encode raw Ed25519 public-key bytes as unpadded base64url."""
    if not isinstance(raw, bytes) or len(raw) != 32:
        raise TrustInvalid("public key must contain exactly 32 bytes")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_public_key(value: Any) -> bytes:
    """Decode a canonical unpadded base64url Ed25519 public key."""
    if not isinstance(value, str) or PUBLIC_KEY_PATTERN.fullmatch(value) is None:
        raise TrustInvalid("public key encoding is invalid")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise TrustInvalid("public key encoding is invalid") from exc
    if len(raw) != 32 or encode_public_key(raw) != value:
        raise TrustInvalid("public key encoding is not canonical")
    return raw


def public_key_fingerprint(raw: bytes) -> str:
    """Return the SHA-256 fingerprint of raw Ed25519 public-key bytes."""
    if not isinstance(raw, bytes) or len(raw) != 32:
        raise TrustInvalid("public key must contain exactly 32 bytes")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def public_key_descriptor(
    key_id: str,
    public_key: Ed25519PublicKey,
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build a portable public-key descriptor; no private material is included."""
    key_id = _safe_text(key_id, field_name="key_id", pattern=SAFE_KEY_ID)
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return validate_public_key_descriptor(
        {
            "schema_version": 1,
            "profile": PUBLIC_KEY_PROFILE,
            "key_id": key_id,
            "algorithm": SIGNATURE_ALGORITHM,
            "public_key": encode_public_key(raw),
            "public_key_encoding": PUBLIC_KEY_ENCODING,
            "fingerprint": public_key_fingerprint(raw),
            "generated_at": normalize_timestamp(generated_at or utc_now_iso()),
        }
    )


def validate_public_key_descriptor(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and normalize an offline public-key descriptor."""
    if not isinstance(payload, Mapping):
        raise TrustInvalid("public-key descriptor must be a mapping", reason_code=TRUST_STORE_INVALID)
    _exact_fields(
        payload,
        PUBLIC_KEY_DESCRIPTOR_FIELDS,
        label="public-key descriptor",
        reason_code=TRUST_STORE_INVALID,
    )
    if payload.get("schema_version") != 1 or payload.get("profile") != PUBLIC_KEY_PROFILE:
        raise TrustInvalid(
            "public-key descriptor schema or profile is unsupported", reason_code=TRUST_STORE_INVALID
        )
    key_id = _safe_text(
        payload.get("key_id"),
        field_name="key_id",
        pattern=SAFE_KEY_ID,
        reason_code=TRUST_STORE_INVALID,
    )
    if payload.get("algorithm") != SIGNATURE_ALGORITHM:
        raise TrustInvalid("public-key descriptor algorithm is unsupported", reason_code=TRUST_STORE_INVALID)
    if payload.get("public_key_encoding") != PUBLIC_KEY_ENCODING:
        raise TrustInvalid("public-key descriptor encoding is unsupported", reason_code=TRUST_STORE_INVALID)
    raw = decode_public_key(payload.get("public_key"))
    fingerprint = payload.get("fingerprint")
    if not isinstance(fingerprint, str) or DIGEST_PATTERN.fullmatch(fingerprint) is None:
        raise TrustInvalid(
            "public-key fingerprint must be sha256:<64 lowercase hex>", reason_code=TRUST_STORE_INVALID
        )
    if fingerprint != public_key_fingerprint(raw):
        raise TrustInvalid(
            "public-key fingerprint does not match the key bytes", reason_code=TRUST_FINGERPRINT_MISMATCH
        )
    generated_at = _timestamp(payload.get("generated_at"), field_name="generated_at")
    return {
        "schema_version": 1,
        "profile": PUBLIC_KEY_PROFILE,
        "key_id": key_id,
        "algorithm": SIGNATURE_ALGORITHM,
        "public_key": payload["public_key"],
        "public_key_encoding": PUBLIC_KEY_ENCODING,
        "fingerprint": fingerprint,
        "generated_at": generated_at,
    }


def load_public_key_descriptor(path: Path) -> dict[str, Any]:
    payload = load_json_document_strict(
        path,
        label="public-key descriptor",
        max_bytes=MAX_CHECKPOINT_BYTES,
        invalid_reason=TRUST_STORE_INVALID,
        missing_reason=TRUST_STORE_MISSING,
    )
    return validate_public_key_descriptor(payload)


def write_public_key_descriptor(path: Path, payload: Mapping[str, Any], *, overwrite: bool = False) -> None:
    descriptor = validate_public_key_descriptor(payload)
    _write_json_atomic(Path(path), descriptor, overwrite=overwrite, mode=0o644)


def load_private_key(path: Path) -> Ed25519PrivateKey:
    """Load an unencrypted Ed25519 PKCS#8 PEM private key without echoing it."""
    path = Path(path)
    try:
        if not path.is_file():
            raise TrustUnavailable("private key is missing or unreadable", reason_code=PRIVATE_KEY_INVALID)
        if path.stat().st_size > MAX_PRIVATE_KEY_BYTES:
            raise TrustInvalid("private key file is too large", reason_code=PRIVATE_KEY_INVALID)
        data = path.read_bytes()
    except OSError as exc:
        raise TrustUnavailable(
            "private key is missing or unreadable", reason_code=PRIVATE_KEY_INVALID
        ) from exc
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except Exception:
        raise TrustInvalid(
            "private key is not a supported unencrypted Ed25519 PEM key",
            reason_code=PRIVATE_KEY_INVALID,
        ) from None
    if not isinstance(key, Ed25519PrivateKey):
        raise TrustInvalid("private key is not an Ed25519 key", reason_code=PRIVATE_KEY_INVALID)
    return key


def _permission_label(path: Path) -> str:
    if os.name != "posix":
        return "platform_default"
    try:
        return oct(stat.S_IMODE(Path(path).stat().st_mode))
    except OSError:
        return "unknown"


def write_private_key(path: Path, key: Ed25519PrivateKey, *, overwrite: bool = False) -> None:
    """Write a private key with restrictive permissions and no overwrite by default."""
    path = Path(path)
    if path.exists() and not overwrite:
        raise TrustConflict("refusing to overwrite an existing private key", reason_code=PRIVATE_KEY_INVALID)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags, 0o600)
        view = memoryview(pem)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    except OSError as exc:
        try:
            if descriptor >= 0:
                os.close(descriptor)
                descriptor = -1
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise TrustError("private key could not be written", reason_code=PRIVATE_KEY_INVALID) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        os.chmod(path, 0o600)
        if os.name == "posix" and stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise OSError("permissions are not restrictive")
    except OSError as exc:
        path.unlink(missing_ok=True)
        raise TrustError(
            "private key permissions could not be restricted",
            reason_code=PRIVATE_KEY_INVALID,
        ) from exc


def generate_key_files(
    *,
    key_id: str,
    private_key_path: Path,
    public_key_path: Path | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Generate an offline Ed25519 key pair and optionally export its public key."""
    key_id = _safe_text(key_id, field_name="key_id", pattern=SAFE_KEY_ID, reason_code=PRIVATE_KEY_INVALID)
    private_key = Ed25519PrivateKey.generate()
    write_private_key(Path(private_key_path), private_key, overwrite=False)
    try:
        descriptor = public_key_descriptor(key_id, private_key.public_key(), generated_at=generated_at)
        if public_key_path is not None:
            write_public_key_descriptor(Path(public_key_path), descriptor, overwrite=False)
    except Exception:
        Path(private_key_path).unlink(missing_ok=True)
        raise
    return {
        "key_id": key_id,
        "algorithm": SIGNATURE_ALGORITHM,
        "fingerprint": descriptor["fingerprint"],
        "public_key": descriptor["public_key"],
        "private_key_path": str(private_key_path),
        "public_key_path": str(public_key_path) if public_key_path is not None else None,
        "private_key_permissions": _permission_label(Path(private_key_path)),
        "generated_at": descriptor["generated_at"],
    }


def export_public_key(
    *,
    private_key_path: Path,
    key_id: str,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Derive and return a public-key descriptor from an offline private key."""
    private_key = load_private_key(Path(private_key_path))
    return public_key_descriptor(key_id, private_key.public_key(), generated_at=generated_at)


def fingerprint_private_key(*, private_key_path: Path, key_id: str) -> dict[str, Any]:
    return export_public_key(private_key_path=private_key_path, key_id=key_id)


def _write_json_atomic(
    path: Path,
    payload: Mapping[str, Any],
    *,
    overwrite: bool,
    mode: int,
) -> None:
    path = Path(path)
    if path.exists() and not overwrite:
        raise TrustConflict("refusing to overwrite an existing file")
    try:
        data = json.dumps(payload, allow_nan=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    except (TypeError, ValueError) as exc:
        raise TrustInvalid("metadata cannot be serialized deterministically") from exc
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
        raise TrustError("file could not be written atomically") from exc


def signed_payload_bytes(payload: Mapping[str, Any]) -> bytes:
    """Return the exact domain-separated bytes covered by the signature."""
    return SIGNED_CHECKPOINT_DOMAIN + _canonical_bytes(payload)


def checkpoint_payload(checkpoint: Mapping[str, Any]) -> dict[str, Any]:
    """Extract the signed payload fields from a full signed checkpoint."""
    try:
        return {field_name: checkpoint[field_name] for field_name in SIGNED_CHECKPOINT_PAYLOAD_FIELDS}
    except KeyError as exc:
        raise TrustInvalid("signed checkpoint is missing a payload field") from exc


def derive_checkpoint_id(payload: Mapping[str, Any]) -> str:
    """Derive a deterministic identifier from every payload field except itself."""
    try:
        body = {
            field_name: payload[field_name]
            for field_name in SIGNED_CHECKPOINT_PAYLOAD_FIELDS
            if field_name != "checkpoint_id"
        }
    except KeyError as exc:
        raise TrustInvalid("signed checkpoint is missing a payload field") from exc
    digest = hashlib.sha256(_canonical_bytes(body)).hexdigest()
    return f"chk-{digest[:32]}"


def checkpoint_payload_digest(payload: Mapping[str, Any]) -> str:
    return sha256_bytes(signed_payload_bytes(payload))


def _validate_signed_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    if payload.get("schema_version") != SIGNED_CHECKPOINT_SCHEMA_VERSION:
        raise TrustInvalid("signed checkpoint schema_version must be 2")
    if payload.get("profile") != SIGNED_CHECKPOINT_PROFILE:
        raise TrustInvalid("signed checkpoint profile is unsupported")
    checkpoint_id = _safe_text(
        payload.get("checkpoint_id"),
        field_name="checkpoint_id",
        pattern=CHECKPOINT_ID_PATTERN,
    )
    if checkpoint_id != derive_checkpoint_id(payload):
        raise TrustInvalid(
            "checkpoint identifier does not match the signed payload", reason_code=CHECKPOINT_ID_MISMATCH
        )
    evidence_report_id = _safe_text(
        payload.get("evidence_report_id"),
        field_name="evidence_report_id",
        pattern=REPORT_ID_PATTERN,
    )
    terminal_hash = payload.get("audit_chain_terminal_hash")
    if not isinstance(terminal_hash, str) or DIGEST_PATTERN.fullmatch(terminal_hash) is None:
        raise TrustInvalid("audit_chain_terminal_hash must be sha256:<64 lowercase hex>")
    terminal_event_id = _safe_text(
        payload.get("audit_chain_terminal_event_id"),
        field_name="audit_chain_terminal_event_id",
        pattern=SAFE_EVENT_ID,
    )
    terminal_timestamp = _timestamp(
        payload.get("audit_chain_terminal_timestamp"),
        field_name="audit_chain_terminal_timestamp",
    )
    audit_record_count = _positive_int(
        payload.get("audit_record_count"),
        field_name="audit_record_count",
        reason_code=CHECKPOINT_SCHEMA_INVALID,
    )
    manifest_digest = payload.get("evidence_manifest_digest")
    if not isinstance(manifest_digest, str) or DIGEST_PATTERN.fullmatch(manifest_digest) is None:
        raise TrustInvalid("evidence_manifest_digest must be sha256:<64 lowercase hex>")
    checkpoint_sequence = _positive_int(
        payload.get("checkpoint_sequence"),
        field_name="checkpoint_sequence",
        reason_code=CHECKPOINT_SEQUENCE_INVALID,
    )
    created_at = _timestamp(payload.get("created_at"), field_name="created_at")
    key_id = _safe_text(payload.get("key_id"), field_name="key_id", pattern=SAFE_KEY_ID)
    raw_public_key = decode_public_key(payload.get("public_key"))
    fingerprint = payload.get("public_key_fingerprint")
    if not isinstance(fingerprint, str) or DIGEST_PATTERN.fullmatch(fingerprint) is None:
        raise TrustInvalid("public_key_fingerprint must be sha256:<64 lowercase hex>")
    if fingerprint != public_key_fingerprint(raw_public_key):
        raise TrustInvalid("public-key fingerprint does not match the checkpoint public key")
    algorithm = payload.get("signature_algorithm")
    if algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
        raise TrustInvalid("signature algorithm is not supported", reason_code=CHECKPOINT_ALGORITHM_UNKNOWN)
    return {
        "schema_version": SIGNED_CHECKPOINT_SCHEMA_VERSION,
        "profile": SIGNED_CHECKPOINT_PROFILE,
        "checkpoint_id": checkpoint_id,
        "evidence_report_id": evidence_report_id,
        "audit_chain_terminal_hash": terminal_hash,
        "audit_chain_terminal_event_id": terminal_event_id,
        "audit_chain_terminal_timestamp": terminal_timestamp,
        "audit_record_count": audit_record_count,
        "evidence_manifest_digest": manifest_digest,
        "checkpoint_sequence": checkpoint_sequence,
        "created_at": created_at,
        "key_id": key_id,
        "public_key_fingerprint": fingerprint,
        "public_key": payload["public_key"],
        "signature_algorithm": algorithm,
    }


def validate_signed_checkpoint(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and normalize a V31 signed checkpoint without verifying its signature."""
    if not isinstance(payload, Mapping):
        raise TrustInvalid("signed checkpoint must be a mapping")
    _exact_fields(
        payload,
        SIGNED_CHECKPOINT_FIELDS,
        label="signed checkpoint",
        reason_code=CHECKPOINT_SCHEMA_INVALID,
    )
    normalized_payload = _validate_signed_payload(checkpoint_payload(payload))
    expected_digest = checkpoint_payload_digest(normalized_payload)
    if payload.get("payload_digest") != expected_digest:
        raise TrustInvalid(
            "payload digest does not match the canonical signed payload",
            reason_code=CHECKPOINT_PAYLOAD_DIGEST_MISMATCH,
        )
    if payload.get("signature_encoding") != SIGNATURE_ENCODING:
        raise TrustInvalid("signature encoding is unsupported", reason_code=CHECKPOINT_SIGNATURE_MALFORMED)
    signature = payload.get("signature")
    if not isinstance(signature, str) or SIGNATURE_HEX_PATTERN.fullmatch(signature) is None:
        raise TrustInvalid("signature encoding is malformed", reason_code=CHECKPOINT_SIGNATURE_MALFORMED)
    return {
        **normalized_payload,
        "payload_digest": expected_digest,
        "signature_encoding": SIGNATURE_ENCODING,
        "signature": signature,
    }


def build_signed_checkpoint_payload(
    *,
    evidence_report_id: str,
    audit_chain_terminal_hash: str,
    audit_chain_terminal_event_id: str,
    audit_chain_terminal_timestamp: str,
    audit_record_count: int,
    evidence_manifest_digest: str,
    checkpoint_sequence: int,
    created_at: str,
    key_id: str,
    public_key: str,
    public_key_fingerprint_value: str,
    signature_algorithm: str = SIGNATURE_ALGORITHM,
) -> dict[str, Any]:
    """Build and validate the canonical payload, deriving the checkpoint ID."""
    payload = {
        "schema_version": SIGNED_CHECKPOINT_SCHEMA_VERSION,
        "profile": SIGNED_CHECKPOINT_PROFILE,
        "checkpoint_id": "chk-" + ("0" * 32),
        "evidence_report_id": evidence_report_id,
        "audit_chain_terminal_hash": audit_chain_terminal_hash,
        "audit_chain_terminal_event_id": audit_chain_terminal_event_id,
        "audit_chain_terminal_timestamp": audit_chain_terminal_timestamp,
        "audit_record_count": audit_record_count,
        "evidence_manifest_digest": evidence_manifest_digest,
        "checkpoint_sequence": checkpoint_sequence,
        "created_at": created_at,
        "key_id": key_id,
        "public_key_fingerprint": public_key_fingerprint_value,
        "public_key": public_key,
        "signature_algorithm": signature_algorithm,
    }
    payload["checkpoint_id"] = derive_checkpoint_id(payload)
    return _validate_signed_payload(payload)


def sign_checkpoint_payload(
    payload: Mapping[str, Any],
    private_key: Ed25519PrivateKey,
) -> dict[str, Any]:
    """Sign the exact canonical payload and return a complete checkpoint."""
    normalized = _validate_signed_payload(checkpoint_payload(payload))
    signature = private_key.sign(signed_payload_bytes(normalized)).hex()
    return validate_signed_checkpoint(
        {
            **normalized,
            "payload_digest": checkpoint_payload_digest(normalized),
            "signature_encoding": SIGNATURE_ENCODING,
            "signature": signature,
        }
    )


def create_signed_checkpoint(
    *,
    audit_path: Path,
    report_path: Path,
    integrity_path: Path,
    private_key_path: Path,
    key_id: str,
    sequence: int,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Create a signed checkpoint from a valid audit chain and sealed report."""
    audit_path = Path(audit_path)
    report_path = Path(report_path)
    integrity_path = Path(integrity_path)
    verification = verify_audit_chain(audit_path)
    if verification.outcome != PASS:
        raise TrustConflict(
            "cannot sign an invalid audit chain",
            reason_code=CHECKPOINT_AUDIT_MISMATCH,
        )
    try:
        records = read_audit_chain(audit_path)
    except AuditChainError as exc:
        raise TrustUnavailable(
            "audit chain is missing or unreadable", reason_code=CHECKPOINT_AUDIT_MISMATCH
        ) from exc
    if not records:
        raise TrustConflict("cannot sign an empty audit chain", reason_code=CHECKPOINT_AUDIT_MISMATCH)
    try:
        report_sha256 = sha256_file(report_path)
        manifest_sha256 = sha256_file(integrity_path)
    except OSError as exc:
        raise TrustUnavailable("report or integrity sidecar is missing or unreadable") from exc
    try:
        from tools.release.evidence_verification import load_integrity_manifest

        manifest = load_integrity_manifest(integrity_path)
    except Exception as exc:
        raise TrustInvalid(
            "integrity sidecar is missing or invalid", reason_code=CHECKPOINT_MANIFEST_MISSING
        ) from exc
    if manifest.report["sha256"] != report_sha256:
        raise TrustConflict(
            "integrity sidecar is bound to different report bytes",
            reason_code=CHECKPOINT_REPORT_MISMATCH,
        )
    private_key = load_private_key(Path(private_key_path))
    public_key = private_key.public_key()
    raw_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    terminal = records[-1]
    terminal_timestamp = _timestamp(terminal.get("timestamp"), field_name="audit terminal timestamp")
    creation_timestamp = normalize_timestamp(created_at or utc_now_iso())
    if creation_timestamp < terminal_timestamp:
        raise TrustConflict(
            "checkpoint creation time precedes the terminal audit record",
            reason_code=CHECKPOINT_TIMESTAMP_INCONSISTENT,
        )
    payload = build_signed_checkpoint_payload(
        evidence_report_id=f"report:{report_sha256}",
        audit_chain_terminal_hash=str(terminal["record_hash"]),
        audit_chain_terminal_event_id=str(terminal["event_id"]),
        audit_chain_terminal_timestamp=terminal_timestamp,
        audit_record_count=len(records),
        evidence_manifest_digest=manifest_sha256,
        checkpoint_sequence=sequence,
        created_at=creation_timestamp,
        key_id=key_id,
        public_key=encode_public_key(raw_public_key),
        public_key_fingerprint_value=public_key_fingerprint(raw_public_key),
    )
    return sign_checkpoint_payload(payload, private_key)


def load_signed_checkpoint(path: Path) -> dict[str, Any]:
    payload = load_json_document_strict(
        path,
        label="signed checkpoint",
        max_bytes=MAX_CHECKPOINT_BYTES,
        invalid_reason=CHECKPOINT_SCHEMA_INVALID,
        missing_reason=CHECKPOINT_SCHEMA_INVALID,
    )
    return validate_signed_checkpoint(payload)


def write_signed_checkpoint(path: Path, checkpoint: Mapping[str, Any], *, overwrite: bool = False) -> None:
    normalized = validate_signed_checkpoint(checkpoint)
    _write_json_atomic(Path(path), normalized, overwrite=overwrite, mode=0o644)


def checkpoint_kind(payload: Mapping[str, Any]) -> str:
    """Classify a checkpoint document without trusting its contents."""
    if not isinstance(payload, Mapping):
        raise TrustInvalid("checkpoint must be a JSON object")
    schema_version = payload.get("schema_version")
    if schema_version == 1:
        return "unsigned"
    if schema_version == SIGNED_CHECKPOINT_SCHEMA_VERSION:
        return "signed"
    raise TrustInvalid("checkpoint schema_version is not supported")


def load_checkpoint_document(path: Path) -> dict[str, Any]:
    return load_json_document_strict(
        path,
        label="checkpoint",
        max_bytes=MAX_CHECKPOINT_BYTES,
        invalid_reason=CHECKPOINT_SCHEMA_INVALID,
        missing_reason=CHECKPOINT_SCHEMA_INVALID,
    )


# ---------------------------------------------------------------------------
# Trust store
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrustedKey:
    """One explicitly registered Ed25519 trust key."""

    key_id: str
    public_key: str
    fingerprint: str
    purpose: str
    allowed_algorithms: tuple[str, ...]
    activated_at: str
    expires_at: str | None
    revoked_at: str | None
    revocation_reason: str | None
    raw_public_key: bytes = field(repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "public_key": self.public_key,
            "fingerprint": self.fingerprint,
            "purpose": self.purpose,
            "allowed_algorithms": list(self.allowed_algorithms),
            "activated_at": self.activated_at,
            "expires_at": self.expires_at,
            "revoked_at": self.revoked_at,
            "revocation_reason": self.revocation_reason,
        }


@dataclass(frozen=True)
class TrustStore:
    """A validated, independently configured trust store."""

    policy_version: str
    historical_revocation_policy: str
    keys: tuple[TrustedKey, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": TRUST_STORE_SCHEMA_VERSION,
            "profile": TRUST_STORE_PROFILE,
            "policy_version": self.policy_version,
            "public_key_encoding": PUBLIC_KEY_ENCODING,
            "historical_revocation_policy": self.historical_revocation_policy,
            "keys": [key.to_dict() for key in self.keys],
        }

    def key_by_id(self, key_id: str) -> TrustedKey | None:
        return next((key for key in self.keys if key.key_id == key_id), None)

    def key_by_fingerprint(self, fingerprint: str) -> TrustedKey | None:
        return next((key for key in self.keys if key.fingerprint == fingerprint), None)


def _trust_timestamp(value: Any, *, field_name: str) -> str:
    try:
        return _timestamp(value, field_name=field_name)
    except TrustInvalid as exc:
        raise TrustInvalid(str(exc), reason_code=TRUST_STORE_INVALID) from exc


def validate_trust_store(payload: Mapping[str, Any]) -> TrustStore:
    """Validate a trust store, failing closed on every malformed field."""
    if not isinstance(payload, Mapping):
        raise TrustInvalid("trust store must be a mapping", reason_code=TRUST_STORE_INVALID)
    _exact_fields(payload, TRUST_STORE_FIELDS, label="trust store", reason_code=TRUST_STORE_INVALID)
    if payload.get("schema_version") != TRUST_STORE_SCHEMA_VERSION:
        raise TrustInvalid("trust store schema_version is unsupported", reason_code=TRUST_STORE_INVALID)
    if payload.get("profile") != TRUST_STORE_PROFILE:
        raise TrustInvalid("trust store profile is unsupported", reason_code=TRUST_STORE_INVALID)
    if payload.get("public_key_encoding") != PUBLIC_KEY_ENCODING:
        raise TrustInvalid("trust store public-key encoding is unsupported", reason_code=TRUST_STORE_INVALID)
    policy_version = _safe_text(
        payload.get("policy_version"),
        field_name="policy_version",
        pattern=SAFE_POLICY_VERSION,
        reason_code=TRUST_STORE_INVALID,
    )
    historical_policy = payload.get("historical_revocation_policy")
    if historical_policy not in HISTORICAL_REVOCATION_POLICIES:
        raise TrustInvalid("historical revocation policy is unsupported", reason_code=TRUST_STORE_INVALID)
    keys_payload = payload.get("keys")
    if not isinstance(keys_payload, list):
        raise TrustInvalid("trust store keys must be a list", reason_code=TRUST_STORE_INVALID)
    parsed: list[TrustedKey] = []
    seen_ids: set[str] = set()
    seen_fingerprints: set[str] = set()
    for item in keys_payload:
        if not isinstance(item, Mapping):
            raise TrustInvalid("trusted key must be a mapping", reason_code=TRUST_STORE_INVALID)
        _exact_fields(item, TRUSTED_KEY_FIELDS, label="trusted key", reason_code=TRUST_STORE_INVALID)
        key_id = _safe_text(
            item.get("key_id"),
            field_name="key_id",
            pattern=SAFE_KEY_ID,
            reason_code=TRUST_STORE_INVALID,
        )
        raw_public_key = decode_public_key(item.get("public_key"))
        fingerprint = item.get("fingerprint")
        if not isinstance(fingerprint, str) or DIGEST_PATTERN.fullmatch(fingerprint) is None:
            raise TrustInvalid(
                "trusted-key fingerprint must be sha256:<64 lowercase hex>", reason_code=TRUST_STORE_INVALID
            )
        if fingerprint != public_key_fingerprint(raw_public_key):
            raise TrustInvalid(
                "trusted-key fingerprint does not match its public key",
                reason_code=TRUST_FINGERPRINT_MISMATCH,
            )
        if item.get("purpose") not in SUPPORTED_KEY_PURPOSES:
            raise TrustInvalid("trusted-key purpose is unsupported", reason_code=TRUST_KEY_PURPOSE_INVALID)
        algorithms = item.get("allowed_algorithms")
        if not isinstance(algorithms, list) or not algorithms:
            raise TrustInvalid(
                "trusted-key allowed_algorithms must be a non-empty list", reason_code=TRUST_STORE_INVALID
            )
        normalized_algorithms: list[str] = []
        for algorithm in algorithms:
            if algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
                raise TrustInvalid(
                    "trusted-key allows an unsupported signature algorithm",
                    reason_code=TRUST_KEY_ALGORITHM_DISALLOWED,
                )
            if algorithm in normalized_algorithms:
                raise TrustInvalid(
                    "trusted-key allowed_algorithms contains a duplicate", reason_code=TRUST_STORE_INVALID
                )
            normalized_algorithms.append(algorithm)
        activated_at = _trust_timestamp(item.get("activated_at"), field_name="activated_at")
        expires_at = item.get("expires_at")
        if expires_at is not None:
            expires_at = _trust_timestamp(expires_at, field_name="expires_at")
            if expires_at <= activated_at:
                raise TrustInvalid(
                    "trusted-key expires_at must follow activated_at", reason_code=TRUST_STORE_INVALID
                )
        revoked_at = item.get("revoked_at")
        if revoked_at is not None:
            revoked_at = _trust_timestamp(revoked_at, field_name="revoked_at")
            if revoked_at < activated_at:
                raise TrustInvalid(
                    "trusted-key revoked_at precedes activated_at", reason_code=TRUST_STORE_INVALID
                )
        reason = item.get("revocation_reason")
        if reason is not None:
            if not isinstance(reason, str) or not reason or len(reason) > 500:
                raise TrustInvalid(
                    "revocation_reason must be a non-empty string", reason_code=TRUST_STORE_INVALID
                )
            if CONTROL_CHARACTER.search(reason):
                raise TrustInvalid(
                    "revocation_reason contains a control character", reason_code=TRUST_STORE_INVALID
                )
            if redact_text(reason) != reason or contains_sensitive_material(reason):
                raise TrustInvalid(
                    "revocation_reason contains unsupported sensitive material",
                    reason_code=TRUST_STORE_INVALID,
                )
        if revoked_at is None and reason is not None:
            raise TrustInvalid("revocation_reason requires revoked_at", reason_code=TRUST_STORE_INVALID)
        if key_id in seen_ids:
            raise TrustInvalid("trust store contains a duplicate key_id", reason_code=TRUST_STORE_INVALID)
        if fingerprint in seen_fingerprints:
            raise TrustInvalid(
                "trust store contains a duplicate fingerprint", reason_code=TRUST_STORE_INVALID
            )
        seen_ids.add(key_id)
        seen_fingerprints.add(fingerprint)
        parsed.append(
            TrustedKey(
                key_id=key_id,
                public_key=item["public_key"],
                fingerprint=fingerprint,
                purpose=item["purpose"],
                allowed_algorithms=tuple(normalized_algorithms),
                activated_at=activated_at,
                expires_at=expires_at,
                revoked_at=revoked_at,
                revocation_reason=reason,
                raw_public_key=raw_public_key,
            )
        )
    return TrustStore(
        policy_version=policy_version,
        historical_revocation_policy=historical_policy,
        keys=tuple(parsed),
    )


def new_trust_store(
    *,
    policy_version: str = "v31",
    historical_revocation_policy: str = HISTORICAL_REVOCATION_ALLOW,
) -> TrustStore:
    return validate_trust_store(
        {
            "schema_version": TRUST_STORE_SCHEMA_VERSION,
            "profile": TRUST_STORE_PROFILE,
            "policy_version": policy_version,
            "public_key_encoding": PUBLIC_KEY_ENCODING,
            "historical_revocation_policy": historical_revocation_policy,
            "keys": [],
        }
    )


def load_trust_store(path: Path) -> TrustStore:
    payload = load_json_document_strict(
        path,
        label="trust store",
        max_bytes=MAX_TRUST_STORE_BYTES,
        invalid_reason=TRUST_STORE_INVALID,
        missing_reason=TRUST_STORE_MISSING,
    )
    return validate_trust_store(payload)


def write_trust_store(path: Path, store: TrustStore | Mapping[str, Any], *, overwrite: bool = True) -> None:
    normalized = store if isinstance(store, TrustStore) else validate_trust_store(store)
    _write_json_atomic(Path(path), normalized.to_dict(), overwrite=overwrite, mode=0o644)


def register_public_key(
    store: TrustStore | None,
    descriptor: Mapping[str, Any],
    *,
    activated_at: str | None = None,
    expires_at: str | None = None,
    policy_version: str = "v31",
    historical_revocation_policy: str = HISTORICAL_REVOCATION_ALLOW,
    purpose: str = KEY_PURPOSE_EVIDENCE_CHECKPOINT,
) -> TrustStore:
    """Register a public key explicitly; a replacement key is never auto-trusted."""
    normalized = validate_public_key_descriptor(descriptor)
    if purpose not in SUPPORTED_KEY_PURPOSES:
        raise TrustInvalid("trusted-key purpose is unsupported", reason_code=TRUST_KEY_PURPOSE_INVALID)
    if store is None:
        store = new_trust_store(
            policy_version=policy_version,
            historical_revocation_policy=historical_revocation_policy,
        )
    if store.key_by_id(normalized["key_id"]) is not None:
        raise TrustConflict("key_id is already registered", reason_code=TRUST_STORE_INVALID)
    if store.key_by_fingerprint(normalized["fingerprint"]) is not None:
        raise TrustConflict("public-key fingerprint is already registered", reason_code=TRUST_STORE_INVALID)
    activation = normalize_timestamp(activated_at or utc_now_iso())
    expiration = normalize_timestamp(expires_at) if expires_at is not None else None
    payload = store.to_dict()
    payload["keys"].append(
        {
            "key_id": normalized["key_id"],
            "public_key": normalized["public_key"],
            "fingerprint": normalized["fingerprint"],
            "purpose": purpose,
            "allowed_algorithms": [SIGNATURE_ALGORITHM],
            "activated_at": activation,
            "expires_at": expiration,
            "revoked_at": None,
            "revocation_reason": None,
        }
    )
    return validate_trust_store(payload)


def _replace_key(store: TrustStore, updated: TrustedKey) -> TrustStore:
    payload = store.to_dict()
    payload["keys"] = [
        updated.to_dict() if key.key_id == updated.key_id else key.to_dict() for key in store.keys
    ]
    return validate_trust_store(payload)


def _require_key(store: TrustStore, key_id: str) -> TrustedKey:
    key = store.key_by_id(key_id)
    if key is None:
        raise TrustConflict("trusted key is unknown", reason_code=TRUST_KEY_UNKNOWN)
    return key


def activate_key(store: TrustStore, key_id: str, *, activated_at: str) -> TrustStore:
    key = _require_key(store, key_id)
    activation = normalize_timestamp(activated_at)
    if key.expires_at is not None and activation >= key.expires_at:
        raise TrustConflict("activation time must precede expiration", reason_code=TRUST_STORE_INVALID)
    if key.revoked_at is not None and activation >= key.revoked_at:
        raise TrustConflict("activation time must precede revocation", reason_code=TRUST_STORE_INVALID)
    return _replace_key(
        store,
        TrustedKey(
            key_id=key.key_id,
            public_key=key.public_key,
            fingerprint=key.fingerprint,
            purpose=key.purpose,
            allowed_algorithms=key.allowed_algorithms,
            activated_at=activation,
            expires_at=key.expires_at,
            revoked_at=key.revoked_at,
            revocation_reason=key.revocation_reason,
            raw_public_key=key.raw_public_key,
        ),
    )


def expire_key(store: TrustStore, key_id: str, *, expires_at: str) -> TrustStore:
    key = _require_key(store, key_id)
    expiration = normalize_timestamp(expires_at)
    if expiration <= key.activated_at:
        raise TrustConflict("expiration must follow activation", reason_code=TRUST_STORE_INVALID)
    return _replace_key(
        store,
        TrustedKey(
            key_id=key.key_id,
            public_key=key.public_key,
            fingerprint=key.fingerprint,
            purpose=key.purpose,
            allowed_algorithms=key.allowed_algorithms,
            activated_at=key.activated_at,
            expires_at=expiration,
            revoked_at=key.revoked_at,
            revocation_reason=key.revocation_reason,
            raw_public_key=key.raw_public_key,
        ),
    )


def revoke_key(
    store: TrustStore,
    key_id: str,
    *,
    revoked_at: str,
    reason: str | None = None,
) -> TrustStore:
    key = _require_key(store, key_id)
    revocation = normalize_timestamp(revoked_at)
    if revocation < key.activated_at:
        raise TrustConflict("revocation cannot precede activation", reason_code=TRUST_STORE_INVALID)
    cleaned_reason: str | None = None
    if reason is not None:
        if not isinstance(reason, str) or not reason or len(reason) > 500:
            raise TrustInvalid(
                "revocation reason must be a non-empty string", reason_code=TRUST_STORE_INVALID
            )
        cleaned_reason = redact_text(reason)
        if contains_sensitive_material(cleaned_reason):
            raise TrustInvalid(
                "revocation reason contains unsupported sensitive material", reason_code=TRUST_STORE_INVALID
            )
    return _replace_key(
        store,
        TrustedKey(
            key_id=key.key_id,
            public_key=key.public_key,
            fingerprint=key.fingerprint,
            purpose=key.purpose,
            allowed_algorithms=key.allowed_algorithms,
            activated_at=key.activated_at,
            expires_at=key.expires_at,
            revoked_at=revocation,
            revocation_reason=cleaned_reason,
            raw_public_key=key.raw_public_key,
        ),
    )


def rotate_key(
    store: TrustStore,
    descriptor: Mapping[str, Any],
    *,
    activated_at: str | None = None,
    expires_at: str | None = None,
    revoke_old_key_id: str | None = None,
    revoke_at: str | None = None,
    reason: str | None = None,
    purpose: str = KEY_PURPOSE_EVIDENCE_CHECKPOINT,
) -> TrustStore:
    """Register a replacement key explicitly and optionally revoke the old key."""
    if revoke_old_key_id is not None and revoke_old_key_id == descriptor.get("key_id"):
        raise TrustConflict("replacement key must use a new key_id", reason_code=TRUST_STORE_INVALID)
    rotated = register_public_key(
        store,
        descriptor,
        activated_at=activated_at,
        expires_at=expires_at,
        purpose=purpose,
    )
    if revoke_old_key_id is not None:
        rotated = revoke_key(
            rotated,
            revoke_old_key_id,
            revoked_at=revoke_at or activated_at or utc_now_iso(),
            reason=reason,
        )
    return rotated


@dataclass(frozen=True)
class KeyStatus:
    status: str
    detail: str
    historical: bool = False


def evaluate_key_status(key: TrustedKey, *, at: str, policy: str) -> KeyStatus:
    """Evaluate key validity at the signed checkpoint creation time."""
    timestamp = normalize_timestamp(at)
    if timestamp < key.activated_at:
        return KeyStatus("not_yet_valid", "key was not active when the checkpoint was created")
    if key.revoked_at is not None:
        if timestamp >= key.revoked_at:
            return KeyStatus("revoked", "key was revoked before the checkpoint was created")
        if policy == HISTORICAL_REVOCATION_DENY:
            return KeyStatus("revoked", "key was revoked; policy denies historical verification")
        return KeyStatus(
            "revoked_historical",
            "key was revoked after this historical checkpoint; explicit policy allows verification",
            historical=True,
        )
    if key.expires_at is not None and timestamp >= key.expires_at:
        return KeyStatus("expired", "key had expired when the checkpoint was created")
    return KeyStatus("active", "key was active when the checkpoint was created")


@dataclass(frozen=True)
class TrustState:
    """A validated local monotonic checkpoint reference."""

    entries: tuple[dict[str, Any], ...]
    updated_at: str
    state_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": TRUST_STATE_SCHEMA_VERSION,
            "profile": TRUST_STATE_PROFILE,
            "updated_at": self.updated_at,
            "checkpoints": [dict(entry) for entry in self.entries],
            "state_digest": self.state_digest,
        }


def _state_timestamp(value: Any, *, field_name: str) -> str:
    try:
        return _timestamp(value, field_name=field_name)
    except TrustInvalid as exc:
        raise TrustInvalid(str(exc), reason_code=TRUST_STATE_INVALID) from exc


def _validate_state_entry(entry: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(entry, Mapping):
        raise TrustInvalid("trust-state entry must be a mapping", reason_code=TRUST_STATE_INVALID)
    _exact_fields(entry, TRUST_STATE_ENTRY_FIELDS, label="trust-state entry", reason_code=TRUST_STATE_INVALID)
    evidence_report_id = _safe_text(
        entry.get("evidence_report_id"),
        field_name="evidence_report_id",
        pattern=REPORT_ID_PATTERN,
        reason_code=TRUST_STATE_INVALID,
    )
    checkpoint_id = _safe_text(
        entry.get("checkpoint_id"),
        field_name="checkpoint_id",
        pattern=CHECKPOINT_ID_PATTERN,
        reason_code=TRUST_STATE_INVALID,
    )
    sequence = _positive_int(
        entry.get("checkpoint_sequence"),
        field_name="checkpoint_sequence",
        reason_code=TRUST_STATE_INVALID,
    )
    record_count = _positive_int(
        entry.get("audit_record_count"),
        field_name="audit_record_count",
        reason_code=TRUST_STATE_INVALID,
    )
    terminal_hash = entry.get("audit_chain_terminal_hash")
    if not isinstance(terminal_hash, str) or DIGEST_PATTERN.fullmatch(terminal_hash) is None:
        raise TrustInvalid("trust-state terminal hash is invalid", reason_code=TRUST_STATE_INVALID)
    manifest_digest = entry.get("evidence_manifest_digest")
    if not isinstance(manifest_digest, str) or DIGEST_PATTERN.fullmatch(manifest_digest) is None:
        raise TrustInvalid("trust-state manifest digest is invalid", reason_code=TRUST_STATE_INVALID)
    created_at = _state_timestamp(entry.get("created_at"), field_name="created_at")
    key_id = _safe_text(
        entry.get("key_id"),
        field_name="key_id",
        pattern=SAFE_KEY_ID,
        reason_code=TRUST_STATE_INVALID,
    )
    return {
        "evidence_report_id": evidence_report_id,
        "checkpoint_id": checkpoint_id,
        "checkpoint_sequence": sequence,
        "audit_record_count": record_count,
        "audit_chain_terminal_hash": terminal_hash,
        "evidence_manifest_digest": manifest_digest,
        "created_at": created_at,
        "key_id": key_id,
    }


def _state_digest(updated_at: str, entries: tuple[dict[str, Any], ...]) -> str:
    body = {
        "schema_version": TRUST_STATE_SCHEMA_VERSION,
        "profile": TRUST_STATE_PROFILE,
        "updated_at": updated_at,
        "checkpoints": [dict(entry) for entry in entries],
    }
    return sha256_bytes(_canonical_bytes(body))


def validate_trust_state(payload: Mapping[str, Any]) -> TrustState:
    """Validate the local monotonic reference and its self-digest."""
    if not isinstance(payload, Mapping):
        raise TrustInvalid("trust state must be a mapping", reason_code=TRUST_STATE_INVALID)
    _exact_fields(payload, TRUST_STATE_FIELDS, label="trust state", reason_code=TRUST_STATE_INVALID)
    if payload.get("schema_version") != TRUST_STATE_SCHEMA_VERSION:
        raise TrustInvalid("trust-state schema_version is unsupported", reason_code=TRUST_STATE_INVALID)
    if payload.get("profile") != TRUST_STATE_PROFILE:
        raise TrustInvalid("trust-state profile is unsupported", reason_code=TRUST_STATE_INVALID)
    updated_at = _state_timestamp(payload.get("updated_at"), field_name="updated_at")
    raw_entries = payload.get("checkpoints")
    if not isinstance(raw_entries, list):
        raise TrustInvalid("trust-state checkpoints must be a list", reason_code=TRUST_STATE_INVALID)
    if len(raw_entries) > MAX_TRUST_STATE_ENTRIES:
        raise TrustInvalid(
            "trust state exceeds the maximum supported entry count", reason_code=TRUST_STATE_INVALID
        )
    entries: list[dict[str, Any]] = []
    seen_checkpoints: set[str] = set()
    seen_sequences: set[tuple[str, int]] = set()
    for raw_entry in raw_entries:
        entry = _validate_state_entry(raw_entry)
        if entry["checkpoint_id"] in seen_checkpoints:
            raise TrustInvalid(
                "trust state contains a duplicate checkpoint identifier", reason_code=TRUST_STATE_INVALID
            )
        sequence_key = (entry["evidence_report_id"], entry["checkpoint_sequence"])
        if sequence_key in seen_sequences:
            raise TrustInvalid("trust state contains a duplicate sequence", reason_code=TRUST_STATE_INVALID)
        seen_checkpoints.add(entry["checkpoint_id"])
        seen_sequences.add(sequence_key)
        entries.append(entry)
    normalized_entries = tuple(
        sorted(entries, key=lambda item: (item["evidence_report_id"], item["checkpoint_sequence"]))
    )
    digest = payload.get("state_digest")
    if not isinstance(digest, str) or DIGEST_PATTERN.fullmatch(digest) is None:
        raise TrustInvalid("trust-state digest is invalid", reason_code=TRUST_STATE_INVALID)
    if digest != _state_digest(updated_at, normalized_entries):
        raise TrustInvalid("trust-state digest does not match its contents", reason_code=TRUST_STATE_INVALID)
    return TrustState(entries=normalized_entries, updated_at=updated_at, state_digest=digest)


def load_trust_state(path: Path | None) -> TrustState | None:
    """Load a local trust state; a missing file is not an error."""
    if path is None:
        return None
    path = Path(path)
    if not path.exists():
        return None
    payload = load_json_document_strict(
        path,
        label="trust state",
        max_bytes=MAX_TRUST_STATE_BYTES,
        invalid_reason=TRUST_STATE_INVALID,
        missing_reason=TRUST_STATE_MISSING,
    )
    return validate_trust_state(payload)


def empty_trust_state(*, updated_at: str | None = None) -> TrustState:
    timestamp = normalize_timestamp(updated_at or utc_now_iso())
    return TrustState(entries=(), updated_at=timestamp, state_digest=_state_digest(timestamp, ()))


def write_trust_state(path: Path, state: TrustState | Mapping[str, Any], *, overwrite: bool = True) -> None:
    normalized = state if isinstance(state, TrustState) else validate_trust_state(state)
    _write_json_atomic(Path(path), normalized.to_dict(), overwrite=overwrite, mode=0o600)


def trust_state_entry(checkpoint: Mapping[str, Any]) -> dict[str, Any]:
    try:
        entry = {field_name: checkpoint[field_name] for field_name in TRUST_STATE_ENTRY_FIELDS}
    except KeyError as exc:
        raise TrustInvalid("checkpoint is missing a trust-state field") from exc
    return _validate_state_entry(entry)


def evaluate_trust_state(checkpoint: Mapping[str, Any], state: TrustState | None) -> TrustCheck:
    """Compare a checkpoint with the separately stored monotonic reference."""
    if state is None:
        return TrustCheck(
            name="rollback-protection",
            outcome=NOT_RUN,
            detail=(
                "no trust state was configured; replay and rollback protection is limited to "
                "this invocation and is not independently established"
            ),
            reason_code=TRUST_STATE_MISSING,
            required=False,
        )
    report_id = checkpoint["evidence_report_id"]
    entries = [entry for entry in state.entries if entry["evidence_report_id"] == report_id]
    if not entries:
        return TrustCheck(
            name="rollback-protection",
            outcome=PASS,
            detail="no prior checkpoint is recorded for this evidence report",
            required=True,
        )
    latest = max(entries, key=lambda entry: entry["checkpoint_sequence"])
    for entry in entries:
        if entry["checkpoint_id"] == checkpoint["checkpoint_id"]:
            if entry["checkpoint_sequence"] == checkpoint["checkpoint_sequence"]:
                return TrustCheck(
                    name="rollback-protection",
                    outcome=FAIL,
                    detail="checkpoint was already recorded; a replay is not a fresh checkpoint",
                    reason_code=CHECKPOINT_REPLAY,
                )
            return TrustCheck(
                name="rollback-protection",
                outcome=FAIL,
                detail="checkpoint identifier was reused at a different sequence",
                reason_code=CHECKPOINT_ID_REUSED,
            )
    sequence = checkpoint["checkpoint_sequence"]
    if sequence < latest["checkpoint_sequence"]:
        return TrustCheck(
            name="rollback-protection",
            outcome=FAIL,
            detail="checkpoint sequence is older than the recorded trust state",
            reason_code=CHECKPOINT_SEQUENCE_DECREASING,
        )
    if sequence == latest["checkpoint_sequence"]:
        if checkpoint["checkpoint_id"] != latest["checkpoint_id"]:
            return TrustCheck(
                name="rollback-protection",
                outcome=FAIL,
                detail="checkpoint sequence duplicates a different recorded checkpoint",
                reason_code=CHECKPOINT_SEQUENCE_DUPLICATE,
            )
        return TrustCheck(
            name="rollback-protection",
            outcome=FAIL,
            detail="checkpoint was already recorded; a replay is not a fresh checkpoint",
            reason_code=CHECKPOINT_REPLAY,
        )
    record_count = checkpoint["audit_record_count"]
    if record_count < latest["audit_record_count"]:
        return TrustCheck(
            name="rollback-protection",
            outcome=FAIL,
            detail="checkpoint terminal audit hash would roll back to fewer records",
            reason_code=AUDIT_HASH_ROLLBACK,
        )
    if record_count == latest["audit_record_count"]:
        if checkpoint["audit_chain_terminal_hash"] != latest["audit_chain_terminal_hash"]:
            return TrustCheck(
                name="rollback-protection",
                outcome=FAIL,
                detail="terminal audit hash changed without a new audit record",
                reason_code=AUDIT_HASH_ROLLBACK,
            )
        if checkpoint["evidence_manifest_digest"] != latest["evidence_manifest_digest"]:
            return TrustCheck(
                name="rollback-protection",
                outcome=FAIL,
                detail="conflicting checkpoints claim the same record count with different manifests",
                reason_code=CHECKPOINT_CONFLICT,
            )
    if (
        record_count > latest["audit_record_count"]
        and checkpoint["audit_chain_terminal_hash"] == latest["audit_chain_terminal_hash"]
    ):
        return TrustCheck(
            name="rollback-protection",
            outcome=FAIL,
            detail="terminal audit hash did not advance with the record count",
            reason_code=AUDIT_HASH_ROLLBACK,
        )
    if checkpoint["created_at"] < latest["created_at"]:
        return TrustCheck(
            name="rollback-protection",
            outcome=FAIL,
            detail="checkpoint timestamp regressed below the recorded trust state",
            reason_code=CHECKPOINT_TIMESTAMP_INCONSISTENT,
        )
    for entry in entries:
        if (
            checkpoint["evidence_manifest_digest"] != latest["evidence_manifest_digest"]
            and entry["evidence_manifest_digest"] == checkpoint["evidence_manifest_digest"]
        ):
            return TrustCheck(
                name="rollback-protection",
                outcome=FAIL,
                detail="manifest digest rolls back to an earlier recorded checkpoint",
                reason_code=MANIFEST_DIGEST_ROLLBACK,
            )
        if (
            entry["audit_chain_terminal_hash"] == checkpoint["audit_chain_terminal_hash"]
            and checkpoint["audit_record_count"] > entry["audit_record_count"]
            and entry["checkpoint_sequence"] < sequence
        ):
            return TrustCheck(
                name="rollback-protection",
                outcome=FAIL,
                detail="terminal audit hash was reused from an earlier checkpoint",
                reason_code=AUDIT_HASH_ROLLBACK,
            )
    detail = "checkpoint sequence and terminal state advanced monotonically"
    if sequence > latest["checkpoint_sequence"] + 1:
        detail += "; one or more intermediate sequence values are absent"
    return TrustCheck(
        name="rollback-protection",
        outcome=PASS,
        detail=detail,
        required=True,
    )


def advance_trust_state(
    path: Path,
    entry: Mapping[str, Any],
    *,
    updated_at: str | None = None,
) -> dict[str, Any]:
    """Append a verified checkpoint reference to the local trust state."""
    normalized_entry = _validate_state_entry(entry)
    state = load_trust_state(path)
    if state is not None:
        check = evaluate_trust_state(normalized_entry, state)
        if check.outcome != PASS:
            raise TrustConflict(
                check.detail,
                reason_code=check.reason_code or CHECKPOINT_CONFLICT,
            )
        if any(record == normalized_entry for record in state.entries):
            return state.to_dict()
    timestamp = normalize_timestamp(updated_at or utc_now_iso())
    if state is not None and timestamp < state.updated_at:
        raise TrustConflict(
            "trust-state update timestamp regressed",
            reason_code=CHECKPOINT_TIMESTAMP_INCONSISTENT,
        )
    base_entries = state.entries if state is not None else ()
    entries = tuple(
        sorted(
            (*base_entries, normalized_entry),
            key=lambda item: (item["evidence_report_id"], item["checkpoint_sequence"]),
        )
    )
    payload = {
        "schema_version": TRUST_STATE_SCHEMA_VERSION,
        "profile": TRUST_STATE_PROFILE,
        "updated_at": timestamp,
        "checkpoints": [dict(record) for record in entries],
        "state_digest": _state_digest(timestamp, entries),
    }
    normalized = validate_trust_state(payload)
    write_trust_state(Path(path), normalized)
    return normalized.to_dict()


# ---------------------------------------------------------------------------
# Optional external trust anchor
# ---------------------------------------------------------------------------


class ExternalTrustAnchor(Protocol):
    """Future independently protected checkpoint reference.

    V31 ships no live implementation and never contacts one by default. A
    caller that supplies an implementation is responsible for its transport,
    authentication, and independence from the evidence store.
    """

    def describe(self) -> Mapping[str, Any]:
        """Return non-secret provider metadata."""

    def fetch_reference(self, evidence_report_id: str) -> Mapping[str, Any] | None:
        """Return an independently stored reference, or ``None``."""


def describe_external_anchor(anchor: ExternalTrustAnchor | None) -> dict[str, Any]:
    if anchor is None:
        return {
            "configured": False,
            "used": False,
            "status": "UNCONFIGURED",
            "provider": None,
            "detail": (
                "No external trust anchor is configured; V31 verifies local signatures only "
                "and does not claim external anchoring."
            ),
        }
    try:
        provider = redact_structure(dict(anchor.describe()))
    except Exception:
        provider = {"detail": "external anchor metadata is unavailable"}
    return {
        "configured": True,
        "used": False,
        "status": "CONFIGURED_NOT_USED",
        "provider": provider,
        "detail": "An external anchor implementation was supplied by the caller.",
    }


def _validate_external_reference(reference: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(reference, Mapping):
        raise TrustInvalid("external reference must be a mapping", reason_code=EXTERNAL_ANCHOR_MISMATCH)
    _exact_fields(
        reference,
        EXTERNAL_REFERENCE_FIELDS,
        label="external reference",
        reason_code=EXTERNAL_ANCHOR_MISMATCH,
    )
    report_id = _safe_text(
        reference.get("evidence_report_id"),
        field_name="evidence_report_id",
        pattern=REPORT_ID_PATTERN,
        reason_code=EXTERNAL_ANCHOR_MISMATCH,
    )
    checkpoint_id = _safe_text(
        reference.get("checkpoint_id"),
        field_name="checkpoint_id",
        pattern=CHECKPOINT_ID_PATTERN,
        reason_code=EXTERNAL_ANCHOR_MISMATCH,
    )
    sequence = _positive_int(
        reference.get("checkpoint_sequence"),
        field_name="checkpoint_sequence",
        reason_code=EXTERNAL_ANCHOR_MISMATCH,
    )
    record_count = _positive_int(
        reference.get("audit_record_count"),
        field_name="audit_record_count",
        reason_code=EXTERNAL_ANCHOR_MISMATCH,
    )
    terminal_hash = reference.get("audit_chain_terminal_hash")
    if not isinstance(terminal_hash, str) or DIGEST_PATTERN.fullmatch(terminal_hash) is None:
        raise TrustInvalid("external terminal hash is invalid", reason_code=EXTERNAL_ANCHOR_MISMATCH)
    manifest_digest = reference.get("evidence_manifest_digest")
    if not isinstance(manifest_digest, str) or DIGEST_PATTERN.fullmatch(manifest_digest) is None:
        raise TrustInvalid("external manifest digest is invalid", reason_code=EXTERNAL_ANCHOR_MISMATCH)
    created_at = _state_timestamp(reference.get("created_at"), field_name="created_at")
    return {
        "evidence_report_id": report_id,
        "checkpoint_id": checkpoint_id,
        "checkpoint_sequence": sequence,
        "audit_record_count": record_count,
        "audit_chain_terminal_hash": terminal_hash,
        "evidence_manifest_digest": manifest_digest,
        "created_at": created_at,
    }


def verify_external_reference(
    checkpoint: Mapping[str, Any],
    reference: Mapping[str, Any] | None,
) -> tuple[TrustCheck, dict[str, Any]]:
    """Compare a checkpoint with an independently supplied reference."""
    if reference is None:
        return (
            TrustCheck(
                name="external-anchor-reference",
                outcome=NOT_RUN,
                detail="the external anchor returned no reference for this report",
                reason_code=EXTERNAL_ANCHOR_REFERENCE_MISSING,
                required=False,
            ),
            {"status": "REFERENCE_MISSING"},
        )
    try:
        normalized = _validate_external_reference(reference)
    except TrustError as exc:
        return (
            TrustCheck(
                name="external-anchor-reference",
                outcome=FAIL,
                detail=str(exc),
                reason_code=EXTERNAL_ANCHOR_MISMATCH,
            ),
            {"status": "INVALID_REFERENCE"},
        )
    for field_name in EXTERNAL_REFERENCE_FIELDS:
        if normalized[field_name] != checkpoint[field_name]:
            return (
                TrustCheck(
                    name="external-anchor-reference",
                    outcome=FAIL,
                    detail="checkpoint does not match the independently stored reference",
                    reason_code=EXTERNAL_ANCHOR_MISMATCH,
                ),
                {"status": "MISMATCH"},
            )
    return (
        TrustCheck(
            name="external-anchor-reference",
            outcome=PASS,
            detail="checkpoint matches the independently stored reference",
            required=True,
        ),
        {"status": "REFERENCE_VERIFIED"},
    )


# ---------------------------------------------------------------------------
# Verification result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrustCheck:
    name: str
    outcome: str
    detail: str
    reason_code: str | None = None
    required: bool = True
    event_type: str = EVIDENCE_VERIFIED

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "outcome": self.outcome,
            "detail": redact_text(self.detail)[:500],
            "reason_code": self.reason_code,
            "required": self.required,
            "event_type": self.event_type,
        }


@dataclass(frozen=True)
class TrustIssue:
    event_type: str
    outcome: str
    detail: str
    reason_code: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type,
            "outcome": self.outcome,
            "detail": redact_text(self.detail)[:500],
            "reason_code": self.reason_code,
        }


@dataclass
class SignedCheckpointVerification:
    outcome: str = NOT_RUN
    checks: list[TrustCheck] = field(default_factory=list)
    issues: list[TrustIssue] = field(default_factory=list)
    checkpoint: dict[str, Any] | None = None
    trust: dict[str, Any] | None = None
    freshness: dict[str, Any] = field(default_factory=dict)
    external_anchor: dict[str, Any] = field(default_factory=dict)
    assurance: str = "reduced"
    reason_codes: list[str] = field(default_factory=list)
    v30_checkpoint: dict[str, Any] | None = None
    state_entry: dict[str, Any] | None = None
    limitations: list[str] = field(default_factory=list)
    audit: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "outcome": self.outcome,
            "assurance": self.assurance,
            "checkpoint": self.checkpoint,
            "trust": self.trust,
            "freshness": self.freshness,
            "external_anchor": self.external_anchor,
            "reason_codes": sorted(set(self.reason_codes)),
            "checks": [check.to_dict() for check in self.checks],
            "issues": [issue.to_dict() for issue in self.issues],
            "audit": self.audit,
            "limitations": [redact_text(item)[:500] for item in self.limitations],
        }
        cleaned = redact_structure(payload)
        if not isinstance(cleaned, dict):
            raise TrustError("signed-checkpoint result could not be sanitized")
        return cleaned


def aggregate_trust_outcome(checks: list[TrustCheck]) -> str:
    required = [check for check in checks if check.required]
    if not required:
        return NOT_RUN
    outcomes = {check.outcome for check in required}
    for state in (FAIL, UNAVAILABLE, NOT_RUN):
        if state in outcomes:
            return state
    return PASS


def _record_check(result: SignedCheckpointVerification, check: TrustCheck) -> TrustCheck:
    result.checks.append(check)
    if check.outcome in (FAIL, UNAVAILABLE):
        result.issues.append(
            TrustIssue(
                event_type=check.event_type,
                outcome=check.outcome,
                detail=check.detail,
                reason_code=check.reason_code,
            )
        )
    return check


def _trust_failure_reason(result: SignedCheckpointVerification) -> str | None:
    for check in result.checks:
        if check.outcome in (FAIL, UNAVAILABLE) and check.reason_code is not None:
            return check.reason_code
    return None


def verify_signed_checkpoint(
    checkpoint: Mapping[str, Any],
    *,
    report_path: Path | None = None,
    integrity_path: Path | None = None,
    audit_path: Path | None = None,
    trust_store_path: Path | None = None,
    trusted_key_fingerprint: str | None = None,
    trust_state_path: Path | None = None,
    external_anchor: ExternalTrustAnchor | None = None,
    require_independent_freshness: bool = False,
    generated_at: str | None = None,
) -> SignedCheckpointVerification:
    """Verify a signed checkpoint against independently configured trust.

    The function never generates, repairs, or re-signs a checkpoint. A missing
    trust store is ``UNAVAILABLE``; an invalid store, untrusted key, bad
    signature, binding mismatch, or rollback is ``FAIL``. A locally valid
    signature without independent monotonic storage is ``PASS`` with explicit
    reduced assurance, never an external-anchoring claim.
    """
    del generated_at  # reserved for future timestamp policy; wall-clock time is not a trust input
    result = SignedCheckpointVerification(
        freshness={
            "status": "NOT_CONFIGURED",
            "assurance": "reduced",
            "independent_monotonic": False,
            "state_path": str(trust_state_path) if trust_state_path is not None else None,
            "recorded_sequence": None,
            "recorded_checkpoint_id": None,
            "state_update": "not_requested",
            "detail": (
                "No independent monotonic storage is configured; local signatures do not "
                "establish checkpoint freshness or prevent rollback by a writer who can "
                "rewrite local state."
            ),
        },
        external_anchor=describe_external_anchor(external_anchor),
    )
    try:
        normalized = validate_signed_checkpoint(checkpoint)
    except TrustError as exc:
        _record_check(
            result,
            TrustCheck(
                name="signed-checkpoint-schema",
                outcome=FAIL,
                detail=str(exc),
                reason_code=exc.reason_code,
                event_type=EVIDENCE_REJECTED,
            ),
        )
        result.outcome = FAIL
        result.reason_codes = [exc.reason_code]
        return result
    result.checkpoint = normalized
    _record_check(
        result,
        TrustCheck(
            name="signed-checkpoint-schema",
            outcome=PASS,
            detail="signed checkpoint schema and canonical fields are valid",
        ),
    )
    _record_check(
        result,
        TrustCheck(
            name="signed-checkpoint-id",
            outcome=PASS,
            detail="checkpoint identifier matches the signed payload",
        ),
    )
    _record_check(
        result,
        TrustCheck(
            name="signed-checkpoint-payload-digest",
            outcome=PASS,
            detail="payload digest matches the domain-separated canonical payload",
        ),
    )
    _record_check(
        result,
        TrustCheck(
            name="signed-checkpoint-algorithm",
            outcome=PASS,
            detail=f"signature algorithm {normalized['signature_algorithm']} is allowed",
        ),
    )

    store: TrustStore | None = None
    store_path = Path(trust_store_path) if trust_store_path is not None else None
    if store_path is not None:
        try:
            store = load_trust_store(store_path)
        except TrustUnavailable as exc:
            _record_check(
                result,
                TrustCheck(
                    name="trust-store",
                    outcome=UNAVAILABLE,
                    detail=str(exc),
                    reason_code=exc.reason_code,
                    event_type=EVIDENCE_REJECTED,
                ),
            )
        except TrustError as exc:
            _record_check(
                result,
                TrustCheck(
                    name="trust-store",
                    outcome=FAIL,
                    detail=str(exc),
                    reason_code=exc.reason_code,
                    event_type=EVIDENCE_REJECTED,
                ),
            )
        else:
            _record_check(
                result,
                TrustCheck(
                    name="trust-store",
                    outcome=PASS,
                    detail=(
                        f"trust store loaded with policy version {store.policy_version} "
                        f"and {len(store.keys)} registered key(s)"
                    ),
                ),
            )
    elif trusted_key_fingerprint is None:
        _record_check(
            result,
            TrustCheck(
                name="trust-store",
                outcome=UNAVAILABLE,
                detail="no independent trust store or trusted key fingerprint was supplied",
                reason_code=TRUST_STORE_MISSING,
                event_type=EVIDENCE_REJECTED,
            ),
        )
    else:
        _record_check(
            result,
            TrustCheck(
                name="trust-store",
                outcome=NOT_RUN,
                detail=(
                    "fingerprint pinning was used; activation, expiration, revocation, and "
                    "key-purpose policy are unavailable without a trust store"
                ),
                required=False,
            ),
        )

    trust_info: dict[str, Any] = {
        "source": None,
        "trusted": False,
        "store_path": str(store_path) if store_path is not None else None,
        "policy_version": store.policy_version if store is not None else None,
        "historical_revocation_policy": (store.historical_revocation_policy if store is not None else None),
        "key_id": normalized["key_id"],
        "fingerprint": normalized["public_key_fingerprint"],
        "algorithm": normalized["signature_algorithm"],
        "purpose": None,
        "status": "unresolved",
        "historical": False,
    }
    key: TrustedKey | None = None
    if store is not None:
        candidate = store.key_by_id(normalized["key_id"])
        if candidate is None:
            _record_check(
                result,
                TrustCheck(
                    name="trust-key",
                    outcome=FAIL,
                    detail="checkpoint key identifier is not present in the trust store",
                    reason_code=TRUST_KEY_UNKNOWN,
                    event_type=EVIDENCE_REJECTED,
                ),
            )
        elif trusted_key_fingerprint is not None and candidate.fingerprint != trusted_key_fingerprint:
            _record_check(
                result,
                TrustCheck(
                    name="trust-key",
                    outcome=FAIL,
                    detail="trusted-key fingerprint does not match the separately supplied pin",
                    reason_code=TRUST_KEY_UNTRUSTED,
                    event_type=EVIDENCE_REJECTED,
                ),
            )
        elif normalized["public_key"] != candidate.public_key:
            _record_check(
                result,
                TrustCheck(
                    name="trust-key",
                    outcome=FAIL,
                    detail="checkpoint-supplied public key does not match the trusted key",
                    reason_code=TRUST_KEY_UNTRUSTED,
                    event_type=EVIDENCE_REJECTED,
                ),
            )
        else:
            key = candidate
            trust_info["source"] = "trust_store"
            _record_check(
                result,
                TrustCheck(
                    name="trust-key",
                    outcome=PASS,
                    detail="checkpoint key resolves to an explicitly registered trust-store key",
                ),
            )
    elif trusted_key_fingerprint is not None:
        if DIGEST_PATTERN.fullmatch(trusted_key_fingerprint) is None:
            _record_check(
                result,
                TrustCheck(
                    name="trust-key",
                    outcome=FAIL,
                    detail="trusted key fingerprint is not sha256:<64 lowercase hex>",
                    reason_code=TRUST_FINGERPRINT_MISMATCH,
                    event_type=EVIDENCE_REJECTED,
                ),
            )
        elif normalized["public_key_fingerprint"] != trusted_key_fingerprint:
            _record_check(
                result,
                TrustCheck(
                    name="trust-key",
                    outcome=FAIL,
                    detail="checkpoint-supplied public key does not match the trusted fingerprint",
                    reason_code=TRUST_KEY_UNTRUSTED,
                    event_type=EVIDENCE_REJECTED,
                ),
            )
        else:
            raw_public_key = decode_public_key(normalized["public_key"])
            key = TrustedKey(
                key_id=normalized["key_id"],
                public_key=normalized["public_key"],
                fingerprint=normalized["public_key_fingerprint"],
                purpose=KEY_PURPOSE_EVIDENCE_CHECKPOINT,
                allowed_algorithms=(SIGNATURE_ALGORITHM,),
                activated_at=normalized["created_at"],
                expires_at=None,
                revoked_at=None,
                revocation_reason=None,
                raw_public_key=raw_public_key,
            )
            trust_info["source"] = "fingerprint_pin"
            _record_check(
                result,
                TrustCheck(
                    name="trust-key",
                    outcome=PASS,
                    detail=(
                        "checkpoint-supplied public key matches the separately supplied "
                        "trusted fingerprint; lifecycle policy was not available"
                    ),
                ),
            )

    status: KeyStatus | None = None
    if key is not None:
        if key.purpose != KEY_PURPOSE_EVIDENCE_CHECKPOINT:
            _record_check(
                result,
                TrustCheck(
                    name="trust-key-purpose",
                    outcome=FAIL,
                    detail="trusted key purpose is not evidence checkpoint signing",
                    reason_code=TRUST_KEY_PURPOSE_INVALID,
                    event_type=EVIDENCE_REJECTED,
                ),
            )
        else:
            _record_check(
                result,
                TrustCheck(
                    name="trust-key-purpose",
                    outcome=PASS,
                    detail="trusted key purpose allows evidence checkpoint signing",
                ),
            )
        if normalized["signature_algorithm"] not in key.allowed_algorithms:
            _record_check(
                result,
                TrustCheck(
                    name="trust-key-algorithm",
                    outcome=FAIL,
                    detail="trusted key does not allow the checkpoint signature algorithm",
                    reason_code=TRUST_KEY_ALGORITHM_DISALLOWED,
                    event_type=EVIDENCE_REJECTED,
                ),
            )
        else:
            _record_check(
                result,
                TrustCheck(
                    name="trust-key-algorithm",
                    outcome=PASS,
                    detail="trusted key allows the checkpoint signature algorithm",
                ),
            )
        if store is not None:
            status = evaluate_key_status(
                key,
                at=normalized["created_at"],
                policy=store.historical_revocation_policy,
            )
            if status.status in ("active", "revoked_historical"):
                _record_check(
                    result,
                    TrustCheck(
                        name="trust-key-validity",
                        outcome=PASS,
                        detail=status.detail,
                    ),
                )
            else:
                reason = {
                    "not_yet_valid": TRUST_KEY_NOT_YET_VALID,
                    "expired": TRUST_KEY_EXPIRED,
                    "revoked": TRUST_KEY_REVOKED,
                }.get(status.status, TRUST_KEY_UNTRUSTED)
                _record_check(
                    result,
                    TrustCheck(
                        name="trust-key-validity",
                        outcome=FAIL,
                        detail=status.detail,
                        reason_code=reason,
                        event_type=EVIDENCE_REJECTED,
                    ),
                )
        else:
            status = KeyStatus(
                "pinned_fingerprint",
                "fingerprint pin matched; no activation, expiration, or revocation metadata was available",
            )
            _record_check(
                result,
                TrustCheck(
                    name="trust-key-validity",
                    outcome=PASS,
                    detail=status.detail,
                ),
            )
        trust_info.update(
            {
                "trusted": True,
                "purpose": key.purpose,
                "status": status.status,
                "historical": status.historical,
            }
        )
        try:
            public_key = Ed25519PublicKey.from_public_bytes(key.raw_public_key)
            public_key.verify(
                bytes.fromhex(normalized["signature"]),
                signed_payload_bytes(checkpoint_payload(normalized)),
            )
        except InvalidSignature:
            _record_check(
                result,
                TrustCheck(
                    name="signed-checkpoint-signature",
                    outcome=FAIL,
                    detail="signature does not match the exact canonical payload",
                    reason_code=CHECKPOINT_SIGNATURE_MISMATCH,
                    event_type=EVIDENCE_REJECTED,
                ),
            )
        except (ValueError, TypeError):
            _record_check(
                result,
                TrustCheck(
                    name="signed-checkpoint-signature",
                    outcome=FAIL,
                    detail="signature could not be decoded",
                    reason_code=CHECKPOINT_SIGNATURE_MALFORMED,
                    event_type=EVIDENCE_REJECTED,
                ),
            )
        else:
            _record_check(
                result,
                TrustCheck(
                    name="signed-checkpoint-signature",
                    outcome=PASS,
                    detail="signature verifies over the domain-separated canonical payload",
                ),
            )
    else:
        _record_check(
            result,
            TrustCheck(
                name="signed-checkpoint-signature",
                outcome=NOT_RUN,
                detail="signature was not checked because no trusted key could be resolved",
                reason_code=_trust_failure_reason(result) or TRUST_KEY_UNTRUSTED,
                required=True,
                event_type=EVIDENCE_REJECTED,
            ),
        )

    if report_path is None:
        _record_check(
            result,
            TrustCheck(
                name="signed-checkpoint-report-binding",
                outcome=UNAVAILABLE,
                detail="report path was not supplied for checkpoint binding",
                reason_code=CHECKPOINT_REPORT_MISMATCH,
                event_type=EVIDENCE_REJECTED,
            ),
        )
    else:
        try:
            report_sha256 = sha256_file(Path(report_path))
        except OSError:
            _record_check(
                result,
                TrustCheck(
                    name="signed-checkpoint-report-binding",
                    outcome=UNAVAILABLE,
                    detail="report bytes could not be hashed",
                    reason_code=CHECKPOINT_REPORT_MISMATCH,
                    event_type=EVIDENCE_REJECTED,
                ),
            )
        else:
            if normalized["evidence_report_id"] != f"report:{report_sha256}":
                _record_check(
                    result,
                    TrustCheck(
                        name="signed-checkpoint-report-binding",
                        outcome=FAIL,
                        detail="checkpoint is bound to different report bytes",
                        reason_code=CHECKPOINT_REPORT_MISMATCH,
                        event_type=EVIDENCE_REJECTED,
                    ),
                )
            else:
                _record_check(
                    result,
                    TrustCheck(
                        name="signed-checkpoint-report-binding",
                        outcome=PASS,
                        detail="checkpoint is bound to the exact report bytes",
                    ),
                )

    if integrity_path is None:
        _record_check(
            result,
            TrustCheck(
                name="signed-checkpoint-manifest-binding",
                outcome=FAIL,
                detail="signed checkpoints require an integrity sidecar for manifest binding",
                reason_code=CHECKPOINT_MANIFEST_MISSING,
                event_type=EVIDENCE_REJECTED,
            ),
        )
    else:
        try:
            manifest_sha256 = sha256_file(Path(integrity_path))
        except OSError:
            _record_check(
                result,
                TrustCheck(
                    name="signed-checkpoint-manifest-binding",
                    outcome=UNAVAILABLE,
                    detail="integrity sidecar bytes could not be hashed",
                    reason_code=CHECKPOINT_MANIFEST_MISSING,
                    event_type=EVIDENCE_REJECTED,
                ),
            )
        else:
            if normalized["evidence_manifest_digest"] != manifest_sha256:
                _record_check(
                    result,
                    TrustCheck(
                        name="signed-checkpoint-manifest-binding",
                        outcome=FAIL,
                        detail="checkpoint is bound to different integrity-manifest bytes",
                        reason_code=CHECKPOINT_MANIFEST_MISMATCH,
                        event_type=EVIDENCE_REJECTED,
                    ),
                )
            else:
                _record_check(
                    result,
                    TrustCheck(
                        name="signed-checkpoint-manifest-binding",
                        outcome=PASS,
                        detail="checkpoint is bound to the exact integrity-manifest bytes",
                    ),
                )

    v30_checkpoint: dict[str, Any] | None = None
    try:
        v30_checkpoint = validate_checkpoint(
            {
                "schema_version": 1,
                "record_count": normalized["audit_record_count"],
                "final_record_hash": normalized["audit_chain_terminal_hash"],
                "final_event_id": normalized["audit_chain_terminal_event_id"],
                "final_timestamp": normalized["audit_chain_terminal_timestamp"],
                "source": f"signed-checkpoint:{normalized['checkpoint_id']}",
            }
        )
    except IntegrityError:
        _record_check(
            result,
            TrustCheck(
                name="signed-checkpoint-audit-binding",
                outcome=FAIL,
                detail="signed checkpoint cannot be represented as a V30 audit checkpoint",
                reason_code=CHECKPOINT_AUDIT_MISMATCH,
                event_type=AUDIT_CHAIN_INVALID,
            ),
        )
    else:
        result.v30_checkpoint = v30_checkpoint
        if audit_path is None:
            _record_check(
                result,
                TrustCheck(
                    name="signed-checkpoint-audit-binding",
                    outcome=UNAVAILABLE,
                    detail="audit chain path was not supplied for checkpoint binding",
                    reason_code=CHECKPOINT_AUDIT_MISMATCH,
                    event_type=AUDIT_CHAIN_INVALID,
                ),
            )
        else:
            try:
                audit_verification: AuditVerification = verify_audit_chain(
                    Path(audit_path),
                    checkpoint=v30_checkpoint,
                )
            except (AuditChainError, OSError):
                _record_check(
                    result,
                    TrustCheck(
                        name="signed-checkpoint-audit-binding",
                        outcome=UNAVAILABLE,
                        detail="audit chain is missing or unreadable",
                        reason_code=CHECKPOINT_AUDIT_MISMATCH,
                        event_type=AUDIT_CHAIN_INVALID,
                    ),
                )
            else:
                result.audit = audit_verification.to_dict()
                if audit_verification.outcome != PASS:
                    details = [problem.detail for problem in audit_verification.problems]
                    if any("ended before" in detail for detail in details):
                        reason_code = CHAIN_TRUNCATION
                    elif any("beyond" in detail for detail in details):
                        reason_code = CHAIN_EXTENSION
                    else:
                        reason_code = CHECKPOINT_AUDIT_MISMATCH
                    _record_check(
                        result,
                        TrustCheck(
                            name="signed-checkpoint-audit-binding",
                            outcome=FAIL,
                            detail="audit chain does not match the signed checkpoint",
                            reason_code=reason_code,
                            event_type=AUDIT_CHAIN_INVALID,
                        ),
                    )
                else:
                    _record_check(
                        result,
                        TrustCheck(
                            name="signed-checkpoint-audit-binding",
                            outcome=PASS,
                            detail="audit chain terminal state matches the signed checkpoint",
                        ),
                    )
                    try:
                        audit_records = read_audit_chain(Path(audit_path))
                    except AuditChainError:
                        audit_records = []
                    if audit_records:
                        terminal_timestamp = audit_records[-1].get("timestamp")
                        if (
                            isinstance(terminal_timestamp, str)
                            and normalized["created_at"] < terminal_timestamp
                        ):
                            _record_check(
                                result,
                                TrustCheck(
                                    name="signed-checkpoint-timestamp",
                                    outcome=FAIL,
                                    detail="checkpoint creation time precedes the terminal audit record",
                                    reason_code=CHECKPOINT_TIMESTAMP_INCONSISTENT,
                                    event_type=EVIDENCE_REJECTED,
                                ),
                            )
                        else:
                            _record_check(
                                result,
                                TrustCheck(
                                    name="signed-checkpoint-timestamp",
                                    outcome=PASS,
                                    detail=(
                                        "checkpoint creation time is not earlier than the "
                                        "terminal audit record"
                                    ),
                                ),
                            )

    try:
        state = load_trust_state(trust_state_path)
    except TrustError as exc:
        _record_check(
            result,
            TrustCheck(
                name="rollback-protection",
                outcome=FAIL,
                detail=str(exc),
                reason_code=TRUST_STATE_INVALID,
                event_type=EVIDENCE_REJECTED,
            ),
        )
        result.freshness["status"] = "INVALID"
        result.freshness["detail"] = "The configured local trust state is invalid; it was not rewritten."
    else:
        state_check = evaluate_trust_state(normalized, state)
        _record_check(result, state_check)
        if state is not None and state_check.outcome == PASS:
            entries = [
                entry
                for entry in state.entries
                if entry["evidence_report_id"] == normalized["evidence_report_id"]
            ]
            latest = max(entries, key=lambda entry: entry["checkpoint_sequence"]) if entries else None
            result.freshness.update(
                {
                    "status": "LOCAL_STATE_ONLY",
                    "assurance": "reduced",
                    "independent_monotonic": False,
                    "recorded_sequence": latest["checkpoint_sequence"] if latest is not None else None,
                    "recorded_checkpoint_id": latest["checkpoint_id"] if latest is not None else None,
                    "detail": (
                        "A local trust-state file enforces monotonic sequence and terminal-state "
                        "comparison. It is not independently protected: an attacker who can rewrite "
                        "it can also rewrite the sequence it records."
                    ),
                }
            )
        elif state is not None and state_check.outcome != PASS:
            result.freshness["status"] = "ROLLBACK_DETECTED"
            result.freshness["detail"] = state_check.detail

    if external_anchor is not None:
        try:
            reference = external_anchor.fetch_reference(normalized["evidence_report_id"])
        except Exception:
            _record_check(
                result,
                TrustCheck(
                    name="external-anchor-reference",
                    outcome=FAIL,
                    detail="external anchor reference could not be obtained",
                    reason_code=EXTERNAL_ANCHOR_MISMATCH,
                    event_type=EVIDENCE_REJECTED,
                ),
            )
            result.external_anchor.update({"used": True, "status": "ERROR"})
        else:
            anchor_check, anchor_info = verify_external_reference(normalized, reference)
            _record_check(result, anchor_check)
            result.external_anchor.update(anchor_info)
            result.external_anchor["used"] = reference is not None
            if anchor_check.outcome == PASS:
                result.assurance = "independent"
                result.freshness.update(
                    {
                        "status": "EXTERNAL_REFERENCE",
                        "assurance": "independent",
                        "independent_monotonic": True,
                        "detail": (
                            "An independently supplied external reference matched this checkpoint. "
                            "The reference was supplied by the caller; V31 did not create, publish, "
                            "or contact an external anchor service."
                        ),
                    }
                )
    else:
        _record_check(
            result,
            TrustCheck(
                name="external-anchor",
                outcome=NOT_RUN,
                detail=(
                    "no external trust anchor is configured; local signatures are not described "
                    "as externally anchored"
                ),
                reason_code=EXTERNAL_ANCHOR_UNCONFIGURED,
                required=False,
            ),
        )

    if require_independent_freshness and result.assurance != "independent":
        _record_check(
            result,
            TrustCheck(
                name="independent-freshness",
                outcome=NOT_RUN,
                detail=(
                    "independent freshness was required but no external monotonic reference was configured"
                ),
                reason_code=INDEPENDENT_FRESHNESS_UNAVAILABLE,
                required=True,
                event_type=EVIDENCE_REJECTED,
            ),
        )

    result.limitations.extend(
        [
            "A valid signature proves possession of the signing key over the exact canonical "
            "payload; it does not prove that the evidence is truthful, complete, or correctly "
            "collected.",
            "Trust depends on the independently configured public key or fingerprint. A public "
            "key carried inside the checkpoint is only an untrusted candidate.",
            "A local trust-state file is tamper-evident, not independently monotonic. Reduced "
            "assurance is reported when no external reference is configured.",
            "V31 does not contact an external anchor, cloud KMS, registry, or network service. "
            "External anchoring remains unconfigured and unused.",
        ]
    )
    if trust_info["source"] == "fingerprint_pin":
        result.limitations.append(
            "Fingerprint pinning establishes key identity only; activation, expiration, "
            "revocation, and key-purpose policy require a trust store."
        )

    result.trust = trust_info
    try:
        result.state_entry = trust_state_entry(normalized)
    except TrustError:
        result.state_entry = None
    result.outcome = aggregate_trust_outcome(result.checks)
    ordered_reason_codes: list[str] = []
    for required_only in (True, False):
        for check in result.checks:
            if check.required != required_only:
                continue
            if check.reason_code is None or check.outcome == PASS:
                continue
            if check.reason_code not in ordered_reason_codes:
                ordered_reason_codes.append(check.reason_code)
    result.reason_codes = ordered_reason_codes
    return result


__all__ = [
    "AUDIT_HASH_ROLLBACK",
    "CHAIN_EXTENSION",
    "CHAIN_TRUNCATION",
    "CHECKPOINT_ALGORITHM_UNKNOWN",
    "CHECKPOINT_AUDIT_MISMATCH",
    "CHECKPOINT_CONFLICT",
    "CHECKPOINT_ID_MISMATCH",
    "CHECKPOINT_ID_REUSED",
    "CHECKPOINT_MANIFEST_MISMATCH",
    "CHECKPOINT_MANIFEST_MISSING",
    "CHECKPOINT_PAYLOAD_DIGEST_MISMATCH",
    "CHECKPOINT_REPLAY",
    "CHECKPOINT_REPORT_MISMATCH",
    "CHECKPOINT_SCHEMA_INVALID",
    "CHECKPOINT_SEQUENCE_DECREASING",
    "CHECKPOINT_SEQUENCE_DUPLICATE",
    "CHECKPOINT_SEQUENCE_GAP",
    "CHECKPOINT_SEQUENCE_INVALID",
    "CHECKPOINT_SIGNATURE_MALFORMED",
    "CHECKPOINT_SIGNATURE_MISMATCH",
    "CHECKPOINT_TIMESTAMP_INCONSISTENT",
    "CHECKPOINT_TIMESTAMP_INVALID",
    "CHECKPOINT_UNSIGNED",
    "EXTERNAL_ANCHOR_MISMATCH",
    "EXTERNAL_ANCHOR_REFERENCE_MISSING",
    "EXTERNAL_ANCHOR_UNCONFIGURED",
    "ExternalTrustAnchor",
    "HISTORICAL_REVOCATION_ALLOW",
    "HISTORICAL_REVOCATION_DENY",
    "INDEPENDENT_FRESHNESS_UNAVAILABLE",
    "KEY_PURPOSE_EVIDENCE_CHECKPOINT",
    "KEY_PURPOSE_TRANSPARENCY_TREE_HEAD",
    "SUPPORTED_KEY_PURPOSES",
    "KeyStatus",
    "MANIFEST_DIGEST_ROLLBACK",
    "PRIVATE_KEY_INVALID",
    "PUBLIC_KEY_PROFILE",
    "SIGNATURE_ALGORITHM",
    "SIGNED_CHECKPOINT_FIELDS",
    "SIGNED_CHECKPOINT_PAYLOAD_FIELDS",
    "SIGNED_CHECKPOINT_PROFILE",
    "SIGNED_CHECKPOINT_SCHEMA_VERSION",
    "SIGNED_CHECKPOINT_REQUIRES_REPORT",
    "SUPPORTED_SIGNATURE_ALGORITHMS",
    "SignedCheckpointVerification",
    "TRUST_KEY_ALGORITHM_DISALLOWED",
    "TRUST_KEY_EXPIRED",
    "TRUST_KEY_NOT_YET_VALID",
    "TRUST_KEY_PURPOSE_INVALID",
    "TRUST_KEY_REVOKED",
    "TRUST_KEY_UNKNOWN",
    "TRUST_KEY_UNTRUSTED",
    "TRUST_FINGERPRINT_MISMATCH",
    "TRUST_STATE_INVALID",
    "TRUST_STATE_MISSING",
    "TRUST_STORE_INVALID",
    "TRUST_STORE_MISSING",
    "TrustCheck",
    "TrustConflict",
    "TrustError",
    "TrustInvalid",
    "TrustIssue",
    "TrustState",
    "TrustStore",
    "TrustUnavailable",
    "TrustedKey",
    "activate_key",
    "advance_trust_state",
    "aggregate_trust_outcome",
    "build_signed_checkpoint_payload",
    "checkpoint_kind",
    "checkpoint_payload",
    "checkpoint_payload_digest",
    "create_signed_checkpoint",
    "decode_public_key",
    "derive_checkpoint_id",
    "describe_external_anchor",
    "empty_trust_state",
    "encode_public_key",
    "evaluate_key_status",
    "evaluate_trust_state",
    "expire_key",
    "export_public_key",
    "fingerprint_private_key",
    "generate_key_files",
    "load_checkpoint_document",
    "load_json_document_strict",
    "load_private_key",
    "load_public_key_descriptor",
    "load_signed_checkpoint",
    "load_trust_state",
    "load_trust_store",
    "new_trust_store",
    "public_key_descriptor",
    "public_key_fingerprint",
    "register_public_key",
    "revoke_key",
    "rotate_key",
    "sign_checkpoint_payload",
    "signed_payload_bytes",
    "trust_state_entry",
    "validate_public_key_descriptor",
    "validate_signed_checkpoint",
    "validate_trust_state",
    "validate_trust_store",
    "verify_external_reference",
    "verify_signed_checkpoint",
    "write_private_key",
    "write_public_key_descriptor",
    "write_signed_checkpoint",
    "write_trust_state",
    "write_trust_store",
]
