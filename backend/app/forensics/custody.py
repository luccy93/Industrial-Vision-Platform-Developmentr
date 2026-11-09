"""Append-only hash-chained custody ledger primitives (V34).

The ledger is tamper-evident only relative to its own head and the case's
recorded head/count. It is a local hash chain, not an immutable or externally
anchored log; callers must report that limitation honestly.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from backend.app.core.redaction import contains_sensitive_material, redact_structure
from backend.app.forensics.constants import (
    CUSTODY_ASSURANCE,
    EXTERNAL_ANCHORING_NOTE,
    VALID_ACTOR_ROLES,
    CustodyEventType,
    VerificationOutcome,
)

GENESIS_HASH = "0" * 64


def canonical_json(value: Any) -> str:
    """Canonical JSON used for every custody hash and manifest digest."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def canonical_json_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def sha256_hex(value: bytes | str) -> str:
    data = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


def datetime_to_iso(value: datetime | None) -> str:
    """UTC ISO-8601 with millisecond precision and trailing ``Z``."""
    if value is None:
        return ""
    moment = value
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    moment = moment.astimezone(UTC)
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def event_payload(event: Mapping[str, Any]) -> dict[str, Any]:
    """Return the exact canonical payload hashed for one custody event."""
    return {
        "event_id": str(event.get("event_id") or event.get("id") or ""),
        "case_id": str(event.get("case_id") or ""),
        "sequence": int(event.get("sequence") or 0),
        "event_type": str(event.get("event_type") or ""),
        "timestamp": datetime_to_iso(event.get("timestamp"))
        if isinstance(event.get("timestamp"), datetime)
        else str(event.get("timestamp") or ""),
        "actor_id": str(event.get("actor_id") or ""),
        "actor_role": str(event.get("actor_role") or "").upper(),
        "artifact_id": str(event.get("artifact_id") or ""),
        "previous_hash": str(event.get("previous_hash") or ""),
        "metadata": redact_structure(dict(event.get("metadata") or event.get("meta") or {})),
    }


def compute_event_hash(event: Mapping[str, Any]) -> str:
    return sha256_hex(canonical_json_bytes(event_payload(event)))


def build_event(
    *,
    event_id: str,
    case_id: str,
    sequence: int,
    event_type: CustodyEventType | str,
    timestamp: datetime,
    actor_id: str,
    actor_role: str,
    previous_hash: str,
    artifact_id: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a custody event dict with a deterministic hash."""
    payload = {
        "event_id": str(event_id),
        "case_id": str(case_id),
        "sequence": int(sequence),
        "event_type": event_type.value if isinstance(event_type, CustodyEventType) else str(event_type),
        "timestamp": timestamp,
        "actor_id": str(actor_id or "SYSTEM"),
        "actor_role": str(actor_role or "SYSTEM").upper(),
        "artifact_id": str(artifact_id) if artifact_id else "",
        "previous_hash": str(previous_hash or GENESIS_HASH),
        "metadata": redact_structure(dict(metadata or {})),
    }
    payload["event_hash"] = compute_event_hash(payload)
    return payload


@dataclass
class CustodyVerification:
    outcome: VerificationOutcome
    event_count: int = 0
    head_hash: str | None = None
    expected_head_hash: str | None = None
    checks: list[dict[str, Any]] = field(default_factory=list)
    reason_codes: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    assurance: str = CUSTODY_ASSURANCE

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "event_count": self.event_count,
            "head_hash": self.head_hash,
            "expected_head_hash": self.expected_head_hash,
            "checks": list(self.checks),
            "reason_codes": sorted(set(self.reason_codes)),
            "limitations": list(self.limitations),
            "assurance": self.assurance,
            "external_anchor_claimed": False,
            "external_anchor_note": EXTERNAL_ANCHORING_NOTE,
        }


def _check(
    checks: list[dict[str, Any]],
    reasons: set[str],
    name: str,
    outcome: VerificationOutcome,
    detail: str,
    reason_code: str | None = None,
) -> None:
    entry: dict[str, Any] = {"name": name, "outcome": outcome.value, "detail": detail}
    if reason_code:
        entry["reason_code"] = reason_code
        if outcome is not VerificationOutcome.PASS:
            reasons.add(reason_code)
    checks.append(entry)


def verify_custody_chain(
    *,
    case: Mapping[str, Any],
    events: Sequence[Mapping[str, Any]],
) -> CustodyVerification:
    """Verify sequence, links, hashes, actor metadata, and the recorded head."""
    checks: list[dict[str, Any]] = []
    reasons: set[str] = set()
    materialized = list(events)
    expected_count = int(case.get("custody_event_count") or 0)
    expected_head = str(case.get("custody_head_hash") or "") or None

    if not materialized:
        empty_outcome = VerificationOutcome.FAIL if expected_count else VerificationOutcome.UNAVAILABLE
        _check(
            checks,
            reasons,
            "custody-presence",
            empty_outcome,
            "case has no custody events" if expected_count else "no custody events recorded",
            "CUSTODY_CHAIN_EMPTY",
        )
        return CustodyVerification(
            outcome=empty_outcome,
            checks=checks,
            reason_codes=sorted(reasons),
            expected_head_hash=expected_head,
            limitations=[EXTERNAL_ANCHORING_NOTE],
        )

    sequences = [int(event.get("sequence") or 0) for event in materialized]
    expected_sequences = list(range(1, len(materialized) + 1))
    if len(set(sequences)) != len(sequences):
        _check(
            checks,
            reasons,
            "custody-sequence-unique",
            VerificationOutcome.FAIL,
            "duplicate custody sequence numbers were detected",
            "CUSTODY_SEQUENCE_DUPLICATE",
        )
    if sequences != expected_sequences:
        _check(
            checks,
            reasons,
            "custody-sequence-order",
            VerificationOutcome.FAIL,
            "custody sequence is reordered, duplicated, or has a gap",
            "CUSTODY_SEQUENCE_GAP",
        )
    else:
        _check(
            checks,
            reasons,
            "custody-sequence-order",
            VerificationOutcome.PASS,
            "custody sequence is contiguous and ordered",
        )

    previous = GENESIS_HASH
    for index, event in enumerate(materialized, start=1):
        event_id = str(event.get("event_id") or event.get("id") or f"sequence-{index}")
        if int(event.get("sequence") or 0) != index:
            continue
        if str(event.get("previous_hash") or "") != previous:
            _check(
                checks,
                reasons,
                f"custody-link-{index}",
                VerificationOutcome.FAIL,
                f"event {event_id} previous hash does not match the prior event",
                "CUSTODY_PREVIOUS_HASH_INVALID",
            )
        recomputed = compute_event_hash(event)
        if str(event.get("event_hash") or "") != recomputed:
            _check(
                checks,
                reasons,
                f"custody-hash-{index}",
                VerificationOutcome.FAIL,
                f"event {event_id} payload hash does not match its recorded hash",
                "CUSTODY_EVENT_HASH_INVALID",
            )
        actor_id = str(event.get("actor_id") or "").strip()
        actor_role = str(event.get("actor_role") or "").strip().upper()
        if not actor_id or actor_role not in VALID_ACTOR_ROLES:
            _check(
                checks,
                reasons,
                f"custody-actor-{index}",
                VerificationOutcome.FAIL,
                f"event {event_id} has invalid actor metadata",
                "CUSTODY_ACTOR_INVALID",
            )
        metadata = event.get("metadata") or event.get("meta") or {}
        if contains_sensitive_material(canonical_json(redact_structure(dict(metadata)))):
            _check(
                checks,
                reasons,
                f"custody-metadata-{index}",
                VerificationOutcome.FAIL,
                f"event {event_id} metadata still contains credential-shaped material",
                "CUSTODY_METADATA_UNSAFE",
            )
        previous = str(event.get("event_hash") or "")

    if not any(check["outcome"] == VerificationOutcome.FAIL.value for check in checks):
        _check(
            checks,
            reasons,
            "custody-payloads",
            VerificationOutcome.PASS,
            "all custody payload hashes, links, sequences, and actor snapshots are valid",
        )

    actual_head = str(materialized[-1].get("event_hash") or "") or None
    if expected_count != len(materialized):
        _check(
            checks,
            reasons,
            "custody-count",
            VerificationOutcome.FAIL,
            f"case records {expected_count} events but {len(materialized)} are present",
            "CUSTODY_CHAIN_TRUNCATED",
        )
    else:
        _check(
            checks,
            reasons,
            "custody-count",
            VerificationOutcome.PASS,
            "custody event count matches the case head",
        )

    if expected_head and actual_head != expected_head:
        _check(
            checks,
            reasons,
            "custody-head",
            VerificationOutcome.FAIL,
            "custody head hash does not match the case's recorded head",
            "CUSTODY_HEAD_MISMATCH",
        )
    elif expected_head:
        _check(
            checks,
            reasons,
            "custody-head",
            VerificationOutcome.PASS,
            "custody head hash matches the case head",
        )
    else:
        _check(
            checks,
            reasons,
            "custody-head",
            VerificationOutcome.FAIL,
            "case has no recorded custody head",
            "CUSTODY_HEAD_MISMATCH",
        )

    failed = any(check["outcome"] == VerificationOutcome.FAIL.value for check in checks)
    return CustodyVerification(
        outcome=VerificationOutcome.FAIL if failed else VerificationOutcome.PASS,
        event_count=len(materialized),
        head_hash=actual_head,
        expected_head_hash=expected_head,
        checks=checks,
        reason_codes=sorted(reasons),
        limitations=[
            EXTERNAL_ANCHORING_NOTE,
            "A local hash chain cannot prevent a writer with database access from rewriting the "
            "entire chain; compare the recorded head with an independently retained value.",
        ],
    )


__all__ = [
    "CustodyVerification",
    "GENESIS_HASH",
    "build_event",
    "canonical_json",
    "canonical_json_bytes",
    "compute_event_hash",
    "datetime_to_iso",
    "event_payload",
    "sha256_hex",
    "verify_custody_chain",
]
