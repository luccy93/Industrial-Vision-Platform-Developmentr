"""Read-only forensic case verification (V34).

Verification never repairs, rewrites, re-signs, re-hashes, moves, or deletes a
protected artifact. It hashes current bytes where a path is configured and
compares them with the reference's recorded expected digest, or confirms that
the original V33 finding/audit-run or V10 incident still exists. Cryptographic
signature and transparency verification remain V31/V32/V33 responsibilities and
are not re-implemented here.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from backend.app.core.redaction import redact_text
from backend.app.forensics.constants import (
    CUSTODY_ASSURANCE,
    EXTERNAL_ANCHORING_NOTE,
    EvidenceArtifactType,
    VerificationOutcome,
)
from backend.app.forensics.custody import canonical_json_bytes, sha256_hex
from backend.app.forensics.repository import ForensicRepository
from backend.app.incidents.repository import IncidentRepository
from backend.app.integrity.store import MonitoringStore

_HASH_CHUNK = 1024 * 1024

_FILE_ARTIFACTS = frozenset(
    {
        EvidenceArtifactType.EVIDENCE_FILE.value,
        EvidenceArtifactType.EVIDENCE_SIDECAR.value,
        EvidenceArtifactType.EVIDENCE_AUDIT_CHAIN.value,
        EvidenceArtifactType.SIGNED_CHECKPOINT.value,
        EvidenceArtifactType.TRUST_STATE.value,
        EvidenceArtifactType.TRUST_STORE.value,
        EvidenceArtifactType.TRANSPARENCY_LOG.value,
        EvidenceArtifactType.TREE_HEAD.value,
        EvidenceArtifactType.INCLUSION_PROOF.value,
        EvidenceArtifactType.CONSISTENCY_PROOF.value,
        EvidenceArtifactType.RECEIPT.value,
    }
)


@dataclass
class CaseVerification:
    outcome: VerificationOutcome
    checks: list[dict[str, Any]] = field(default_factory=list)
    observations: list[dict[str, Any]] = field(default_factory=list)
    reason_codes: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    custody: dict[str, Any] = field(default_factory=dict)
    verified_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "checks": list(self.checks),
            "observations": list(self.observations),
            "reason_codes": sorted(set(self.reason_codes)),
            "limitations": list(self.limitations),
            "custody": dict(self.custody),
            "verified_at": self.verified_at,
            "external_anchor_claimed": False,
            "external_anchor_note": EXTERNAL_ANCHORING_NOTE,
            "assurance": CUSTODY_ASSURANCE,
            "counts": {
                "checks": len(self.checks),
                "passed": sum(1 for item in self.checks if item.get("outcome") == "PASS"),
                "failed": sum(1 for item in self.checks if item.get("outcome") == "FAIL"),
                "unavailable": sum(1 for item in self.checks if item.get("outcome") == "UNAVAILABLE"),
                "not_run": sum(1 for item in self.checks if item.get("outcome") == "NOT_RUN"),
            },
        }


def _utc_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(_HASH_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _safe_detail(value: Any, limit: int = 512) -> str:
    return redact_text(str(value or "")).strip()[:limit]


def _resolve_under(root: Path, relative_path: str) -> Path:
    candidate = (root / relative_path).resolve(strict=False)
    resolved_root = root.resolve(strict=False)
    if candidate != resolved_root and resolved_root not in candidate.parents:
        raise ValueError("reference path escapes the configured evidence root")
    return candidate


def _check(
    checks: list[dict[str, Any]],
    reasons: set[str],
    *,
    reference: Mapping[str, Any],
    outcome: VerificationOutcome,
    detail: str,
    reason_code: str | None = None,
    observed_sha256: str = "",
    size_bytes: int = 0,
    metadata: Mapping[str, Any] | None = None,
) -> None:
    entry: dict[str, Any] = {
        "reference_id": reference.get("reference_id"),
        "artifact_type": reference.get("artifact_type"),
        "artifact_id": reference.get("artifact_id"),
        "outcome": outcome.value,
        "detail": _safe_detail(detail),
    }
    if reason_code:
        entry["reason_code"] = reason_code
        if outcome is not VerificationOutcome.PASS:
            reasons.add(reason_code)
    checks.append(entry)


def _observation(
    reference: Mapping[str, Any],
    outcome: VerificationOutcome,
    detail: str,
    *,
    observed_sha256: str = "",
    size_bytes: int = 0,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "reference_id": reference.get("reference_id"),
        "outcome": outcome.value,
        "observed_sha256": observed_sha256,
        "size_bytes": int(size_bytes),
        "detail": _safe_detail(detail),
        "metadata": dict(metadata or {}),
    }


def _verify_file_reference(
    reference: Mapping[str, Any],
    *,
    evidence_base: Path | None,
    checks: list[dict[str, Any]],
    observations: list[dict[str, Any]],
    reasons: set[str],
) -> None:
    relative_path = str(reference.get("original_relative_path") or "").strip()
    expected = str(reference.get("expected_sha256") or "").strip().lower()
    if evidence_base is None:
        _check(
            checks,
            reasons,
            reference=reference,
            outcome=VerificationOutcome.UNAVAILABLE,
            detail="no protected evidence root is configured; the reference was preserved unchanged",
            reason_code="FORENSIC_EVIDENCE_ROOT_UNCONFIGURED",
        )
        observations.append(
            _observation(
                reference,
                VerificationOutcome.UNAVAILABLE,
                "evidence root not configured",
            )
        )
        return
    if not relative_path:
        _check(
            checks,
            reasons,
            reference=reference,
            outcome=VerificationOutcome.UNAVAILABLE,
            detail="reference has no relative path; original evidence was not accessed",
            reason_code="FORENSIC_EVIDENCE_PATH_MISSING",
        )
        observations.append(_observation(reference, VerificationOutcome.UNAVAILABLE, "relative path missing"))
        return
    try:
        path = _resolve_under(evidence_base, relative_path)
    except ValueError as exc:
        _check(
            checks,
            reasons,
            reference=reference,
            outcome=VerificationOutcome.FAIL,
            detail=str(exc),
            reason_code="FORENSIC_EVIDENCE_PATH_UNSAFE",
        )
        observations.append(_observation(reference, VerificationOutcome.FAIL, "unsafe evidence path"))
        return
    if not path.exists() or not path.is_file():
        _check(
            checks,
            reasons,
            reference=reference,
            outcome=VerificationOutcome.UNAVAILABLE,
            detail="referenced artifact is not present at the recorded relative path",
            reason_code="FORENSIC_EVIDENCE_UNAVAILABLE",
        )
        observations.append(_observation(reference, VerificationOutcome.UNAVAILABLE, "artifact unavailable"))
        return
    try:
        observed, size_bytes = _hash_file(path)
    except OSError as exc:
        _check(
            checks,
            reasons,
            reference=reference,
            outcome=VerificationOutcome.UNAVAILABLE,
            detail=f"artifact could not be read ({type(exc).__name__}); no change was made",
            reason_code="FORENSIC_EVIDENCE_UNAVAILABLE",
        )
        observations.append(_observation(reference, VerificationOutcome.UNAVAILABLE, "artifact unreadable"))
        return
    if not expected:
        _check(
            checks,
            reasons,
            reference=reference,
            outcome=VerificationOutcome.UNAVAILABLE,
            detail="reference has no expected digest; observed bytes were hashed but not compared",
            reason_code="FORENSIC_EXPECTED_DIGEST_MISSING",
            observed_sha256=observed,
            size_bytes=size_bytes,
        )
        observations.append(
            _observation(
                reference,
                VerificationOutcome.UNAVAILABLE,
                "expected digest missing",
                observed_sha256=observed,
                size_bytes=size_bytes,
            )
        )
        return
    if observed != expected:
        _check(
            checks,
            reasons,
            reference=reference,
            outcome=VerificationOutcome.FAIL,
            detail="current artifact digest does not match the recorded expected digest",
            reason_code="FORENSIC_EVIDENCE_HASH_MISMATCH",
            observed_sha256=observed,
            size_bytes=size_bytes,
        )
        observations.append(
            _observation(
                reference,
                VerificationOutcome.FAIL,
                "digest mismatch",
                observed_sha256=observed,
                size_bytes=size_bytes,
                metadata={"expected_sha256": expected},
            )
        )
        return
    _check(
        checks,
        reasons,
        reference=reference,
        outcome=VerificationOutcome.PASS,
        detail="current artifact digest matches the recorded expected digest",
        observed_sha256=observed,
        size_bytes=size_bytes,
    )
    observations.append(
        _observation(
            reference,
            VerificationOutcome.PASS,
            "digest matches",
            observed_sha256=observed,
            size_bytes=size_bytes,
        )
    )


def _verify_finding_reference(
    reference: Mapping[str, Any],
    *,
    store: MonitoringStore | None,
    checks: list[dict[str, Any]],
    observations: list[dict[str, Any]],
    reasons: set[str],
) -> None:
    finding_id = str(reference.get("artifact_id") or "").strip()
    if store is None:
        _check(
            checks,
            reasons,
            reference=reference,
            outcome=VerificationOutcome.UNAVAILABLE,
            detail="V33 monitoring store is unavailable; the original finding was not read",
            reason_code="FORENSIC_SOURCE_UNAVAILABLE",
        )
        observations.append(_observation(reference, VerificationOutcome.UNAVAILABLE, "V33 store unavailable"))
        return
    try:
        finding = store.get_finding(finding_id)
    except Exception:
        _check(
            checks,
            reasons,
            reference=reference,
            outcome=VerificationOutcome.UNAVAILABLE,
            detail="V33 monitoring store could not be read",
            reason_code="FORENSIC_SOURCE_UNAVAILABLE",
        )
        observations.append(_observation(reference, VerificationOutcome.UNAVAILABLE, "V33 store read failed"))
        return
    if finding is None:
        _check(
            checks,
            reasons,
            reference=reference,
            outcome=VerificationOutcome.UNAVAILABLE,
            detail="original V33 finding is no longer present in the monitoring store",
            reason_code="FORENSIC_FINDING_NOT_FOUND",
        )
        observations.append(_observation(reference, VerificationOutcome.UNAVAILABLE, "finding not found"))
        return
    payload = canonical_json_bytes(finding.to_dict())
    observed = sha256_hex(payload)
    expected = str(reference.get("expected_sha256") or "").strip().lower()
    if expected and observed != expected:
        _check(
            checks,
            reasons,
            reference=reference,
            outcome=VerificationOutcome.FAIL,
            detail="original V33 finding content no longer matches the referenced digest",
            reason_code="FORENSIC_SOURCE_HASH_MISMATCH",
            observed_sha256=observed,
            size_bytes=len(payload),
        )
        observations.append(
            _observation(
                reference,
                VerificationOutcome.FAIL,
                "finding digest mismatch",
                observed_sha256=observed,
                size_bytes=len(payload),
                metadata={"expected_sha256": expected},
            )
        )
        return
    _check(
        checks,
        reasons,
        reference=reference,
        outcome=VerificationOutcome.PASS,
        detail="original V33 finding exists and matches the referenced digest",
        observed_sha256=observed,
        size_bytes=len(payload),
    )
    observations.append(
        _observation(
            reference,
            VerificationOutcome.PASS,
            "finding reference intact",
            observed_sha256=observed,
            size_bytes=len(payload),
        )
    )


def _verify_audit_run_reference(
    reference: Mapping[str, Any],
    *,
    store: MonitoringStore | None,
    checks: list[dict[str, Any]],
    observations: list[dict[str, Any]],
    reasons: set[str],
) -> None:
    audit_run_id = str(reference.get("artifact_id") or "").strip()
    if store is None:
        _check(
            checks,
            reasons,
            reference=reference,
            outcome=VerificationOutcome.UNAVAILABLE,
            detail="V33 monitoring store is unavailable; the original audit run was not read",
            reason_code="FORENSIC_SOURCE_UNAVAILABLE",
        )
        observations.append(_observation(reference, VerificationOutcome.UNAVAILABLE, "V33 store unavailable"))
        return
    try:
        run = store.get_run(audit_run_id)
    except Exception:
        run = None
    if run is None:
        _check(
            checks,
            reasons,
            reference=reference,
            outcome=VerificationOutcome.UNAVAILABLE,
            detail="original V33 audit run is no longer present in the monitoring store",
            reason_code="FORENSIC_AUDIT_RUN_NOT_FOUND",
        )
        observations.append(_observation(reference, VerificationOutcome.UNAVAILABLE, "audit run not found"))
        return
    payload = canonical_json_bytes(run.to_dict(include_details=True))
    observed = sha256_hex(payload)
    expected = str(reference.get("expected_sha256") or "").strip().lower()
    if expected and observed != expected:
        _check(
            checks,
            reasons,
            reference=reference,
            outcome=VerificationOutcome.FAIL,
            detail="original V33 audit-run content no longer matches the referenced digest",
            reason_code="FORENSIC_SOURCE_HASH_MISMATCH",
            observed_sha256=observed,
            size_bytes=len(payload),
        )
        observations.append(
            _observation(
                reference,
                VerificationOutcome.FAIL,
                "audit-run digest mismatch",
                observed_sha256=observed,
                size_bytes=len(payload),
                metadata={"expected_sha256": expected},
            )
        )
        return
    _check(
        checks,
        reasons,
        reference=reference,
        outcome=VerificationOutcome.PASS,
        detail="original V33 audit run exists and matches the referenced digest",
        observed_sha256=observed,
        size_bytes=len(payload),
    )
    observations.append(
        _observation(
            reference,
            VerificationOutcome.PASS,
            "audit-run reference intact",
            observed_sha256=observed,
            size_bytes=len(payload),
        )
    )


def _verify_incident_reference(
    reference: Mapping[str, Any],
    *,
    incidents: IncidentRepository | None,
    checks: list[dict[str, Any]],
    observations: list[dict[str, Any]],
    reasons: set[str],
) -> None:
    incident_id = str(reference.get("artifact_id") or "").strip()
    if incidents is None:
        _check(
            checks,
            reasons,
            reference=reference,
            outcome=VerificationOutcome.UNAVAILABLE,
            detail="incident repository is unavailable",
            reason_code="FORENSIC_SOURCE_UNAVAILABLE",
        )
        observations.append(
            _observation(reference, VerificationOutcome.UNAVAILABLE, "incident repo unavailable")
        )
        return
    incident = incidents.get_incident(incident_id)
    if incident is None:
        _check(
            checks,
            reasons,
            reference=reference,
            outcome=VerificationOutcome.UNAVAILABLE,
            detail="linked V10 incident no longer exists",
            reason_code="FORENSIC_INCIDENT_NOT_FOUND",
        )
        observations.append(_observation(reference, VerificationOutcome.UNAVAILABLE, "incident not found"))
        return
    _check(
        checks,
        reasons,
        reference=reference,
        outcome=VerificationOutcome.PASS,
        detail="linked V10 incident exists; the incident record was not copied or modified",
    )
    observations.append(_observation(reference, VerificationOutcome.PASS, "incident reference intact"))


def verify_case(
    *,
    case_id: str,
    repository: ForensicRepository,
    store: MonitoringStore | None,
    incidents: IncidentRepository | None,
    evidence_base: str | Path | None,
) -> CaseVerification:
    """Read-only verification of custody plus all referenced artifacts."""
    detail = repository.get_case_detail(case_id)
    if detail is None:
        from backend.app.forensics.errors import ForensicCaseNotFoundError

        raise ForensicCaseNotFoundError(case_id)
    checks: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    reasons: set[str] = set()
    custody = repository.verify_custody(case_id)
    if custody.get("outcome") == VerificationOutcome.FAIL.value:
        reasons.update(str(code) for code in custody.get("reason_codes") or [])
        reasons.add("FORENSIC_CUSTODY_CHAIN_INVALID")
        checks.append(
            {
                "reference_id": None,
                "artifact_type": "CUSTODY_CHAIN",
                "artifact_id": case_id,
                "outcome": VerificationOutcome.FAIL.value,
                "detail": "custody ledger verification failed",
                "reason_code": "FORENSIC_CUSTODY_CHAIN_INVALID",
            }
        )
    elif custody.get("outcome") == VerificationOutcome.PASS.value:
        checks.append(
            {
                "reference_id": None,
                "artifact_type": "CUSTODY_CHAIN",
                "artifact_id": case_id,
                "outcome": VerificationOutcome.PASS.value,
                "detail": "custody ledger sequence, links, hashes, and head are valid",
            }
        )

    base_path = Path(str(evidence_base)).expanduser() if evidence_base else None
    references: Sequence[Mapping[str, Any]] = detail.get("evidence_references") or []
    for reference in references:
        artifact_type = str(reference.get("artifact_type") or "").upper()
        if artifact_type in _FILE_ARTIFACTS:
            _verify_file_reference(
                reference,
                evidence_base=base_path,
                checks=checks,
                observations=observations,
                reasons=reasons,
            )
        elif artifact_type == EvidenceArtifactType.V33_FINDING.value:
            _verify_finding_reference(
                reference,
                store=store,
                checks=checks,
                observations=observations,
                reasons=reasons,
            )
        elif artifact_type == EvidenceArtifactType.V33_AUDIT_RUN.value:
            _verify_audit_run_reference(
                reference,
                store=store,
                checks=checks,
                observations=observations,
                reasons=reasons,
            )
        elif artifact_type == EvidenceArtifactType.INCIDENT.value:
            _verify_incident_reference(
                reference,
                incidents=incidents,
                checks=checks,
                observations=observations,
                reasons=reasons,
            )
        else:
            _check(
                checks,
                reasons,
                reference=reference,
                outcome=VerificationOutcome.NOT_RUN,
                detail="this artifact type has no read-only verifier in V34",
                reason_code="FORENSIC_REFERENCE_NOT_VERIFIABLE",
            )
            observations.append(_observation(reference, VerificationOutcome.NOT_RUN, "no V34 verifier"))

    if not references:
        _check(
            checks,
            reasons,
            reference={},
            outcome=VerificationOutcome.NOT_RUN,
            detail="case has no referenced supporting evidence",
            reason_code="FORENSIC_NO_EVIDENCE_REFERENCES",
        )

    failed = any(item.get("outcome") == VerificationOutcome.FAIL.value for item in checks)
    passed = any(item.get("outcome") == VerificationOutcome.PASS.value for item in checks)
    unavailable = any(item.get("outcome") == VerificationOutcome.UNAVAILABLE.value for item in checks)
    not_run = any(item.get("outcome") == VerificationOutcome.NOT_RUN.value for item in checks)
    if failed:
        outcome = VerificationOutcome.FAIL
    elif unavailable:
        outcome = VerificationOutcome.PARTIAL if passed else VerificationOutcome.UNAVAILABLE
    elif not_run:
        outcome = VerificationOutcome.PARTIAL if passed else VerificationOutcome.NOT_RUN
    elif passed:
        outcome = VerificationOutcome.PASS
    else:
        outcome = VerificationOutcome.NOT_RUN

    return CaseVerification(
        outcome=outcome,
        checks=checks,
        observations=observations,
        reason_codes=sorted(reasons),
        limitations=[
            EXTERNAL_ANCHORING_NOTE,
            "V34 hashes referenced artifacts and checks original source records; it does not "
            "re-implement V31 signature or V32 transparency verification.",
            "A matching digest proves the current bytes match the recorded digest, not that the "
            "artifact was authentic at capture time.",
        ],
        custody=custody,
        verified_at=_utc_iso(),
    )


__all__ = ["CaseVerification", "verify_case"]
