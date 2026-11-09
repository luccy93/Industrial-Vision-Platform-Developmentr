"""Deterministic V33 finding classification and case correlation (V34).

Correlation is intentionally conservative: only concrete integrity failures
can be promoted to a confirmed incident. ``UNAVAILABLE``, ``NOT_RUN``, and
``SIMULATED`` results never become confirmed security incidents without
separate supporting evidence.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from backend.app.core.redaction import redact_text
from backend.app.forensics.constants import (
    CaseSeverity,
    CaseType,
    FindingClassification,
    case_type_for_reason,
    classify_reason,
    priority_for_severity,
)
from backend.app.integrity.constants import severity_for_reason

_SAFE_TOKEN = re.compile(r"[^A-Za-z0-9_.:/@-]+")


def _safe(value: Any, limit: int = 512) -> str:
    text = redact_text(str(value or "")).strip()
    text = _SAFE_TOKEN.sub("_", text)
    return text[:limit]


def _dimension(value: Any) -> str:
    return _safe(value, 512)


@dataclass
class FindingAssessment:
    classification: FindingClassification
    case_type: CaseType
    severity: CaseSeverity
    priority: str
    confirmed: bool
    rationale: str
    dimensions: dict[str, str] = field(default_factory=dict)
    correlation_key: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "classification": self.classification.value,
            "case_type": self.case_type.value,
            "severity": self.severity.value,
            "priority": self.priority,
            "confirmed": self.confirmed,
            "rationale": self.rationale,
            "dimensions": dict(self.dimensions),
            "correlation_key": self.correlation_key,
        }


def finding_dimensions(finding: Any) -> dict[str, str]:
    """Extract stable correlation dimensions from a V33 ``Finding``.

    ``artifact_id`` is the primary grouping key. Audit-run and finding IDs are
    retained for provenance but are not used as the sole case identity, so a
    repeated finding in a later audit run does not create a duplicate case.
    """
    scope = getattr(finding, "scope", None)
    scope_value = scope.value if hasattr(scope, "value") else str(scope or "")
    artifact_id = _dimension(getattr(finding, "artifact_id", "") or "")
    reason_code = str(getattr(finding, "reason_code", "") or "").upper()
    audit_run_id = _dimension(getattr(finding, "audit_run_id", "") or "")
    finding_id = _dimension(getattr(finding, "finding_id", "") or "")
    dimensions: dict[str, str] = {
        "reason_code": reason_code,
        "scope": scope_value,
    }
    if artifact_id:
        dimensions["artifact_id"] = artifact_id
    if audit_run_id:
        dimensions["audit_run_id"] = audit_run_id
    if finding_id:
        dimensions["finding_id"] = finding_id
    return dimensions


def correlation_key(
    *,
    case_type: CaseType | str,
    dimensions: Mapping[str, Any] | None = None,
) -> str:
    """Build a deterministic case identity from stable dimensions.

    Preference order groups repeated observations of the same protected
    artifact while still separating unrelated reason families.
    """
    dims = {str(k): str(v) for k, v in (dimensions or {}).items() if str(v or "").strip()}
    selected_key = ""
    selected_value = ""
    for key in (
        "incident_id",
        "evidence_identifier",
        "checkpoint_id",
        "transparency_log_id",
        "manifest_id",
        "artifact_id",
    ):
        if dims.get(key):
            selected_key, selected_value = key, dims[key]
            break
    if not selected_value and dims.get("finding_id"):
        selected_key, selected_value = "finding_id", dims["finding_id"]
    if not selected_value and dims.get("audit_run_id"):
        selected_key = "audit_run_id"
        selected_value = dims["audit_run_id"]
    if not selected_value:
        selected_key = "reason_code"
        selected_value = dims.get("reason_code", "UNKNOWN")
    case_type_value = case_type.value if isinstance(case_type, CaseType) else str(case_type).upper()
    reason = dims.get("reason_code", "")
    payload = "|".join([case_type_value, selected_key, selected_value, reason])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def assess_finding(finding: Any) -> FindingAssessment:
    """Classify one V33 finding and derive its case identity."""
    reason_code = str(getattr(finding, "reason_code", "") or "").upper()
    source = str(getattr(finding, "verification_source", "") or "")
    classification = classify_reason(reason_code, verification_source=source)
    severity_value = getattr(getattr(finding, "severity", None), "value", None)
    try:
        severity = CaseSeverity(str(severity_value or severity_for_reason(reason_code).value))
    except ValueError:
        severity = CaseSeverity.MEDIUM
    case_type = case_type_for_reason(reason_code)
    if classification in {
        FindingClassification.UNAVAILABLE,
        FindingClassification.NOT_RUN,
        FindingClassification.SIMULATED,
        FindingClassification.OPERATIONAL,
    }:
        case_type = CaseType.FORENSIC_REVIEW
    dimensions = finding_dimensions(finding)
    key = correlation_key(case_type=case_type, dimensions=dimensions)
    confirmed = classification is FindingClassification.CONFIRMED_FAILURE
    rationale = {
        FindingClassification.CONFIRMED_FAILURE: ("concrete integrity failure reported by the verifier"),
        FindingClassification.SUSPICIOUS: (
            "suspicious but unconfirmed condition; requires investigator review"
        ),
        FindingClassification.UNAVAILABLE: (
            "verification was unavailable; not promoted to a confirmed incident"
        ),
        FindingClassification.NOT_RUN: ("verification did not run; not promoted to a confirmed incident"),
        FindingClassification.SIMULATED: ("simulated source; never promoted to an externally anchored claim"),
        FindingClassification.OPERATIONAL: (
            "operational monitoring condition; not a confirmed security incident"
        ),
    }[classification]
    return FindingAssessment(
        classification=classification,
        case_type=case_type,
        severity=severity,
        priority=priority_for_severity(severity),
        confirmed=confirmed,
        rationale=rationale,
        dimensions=dimensions,
        correlation_key=key,
    )


def build_case_title(finding: Any, assessment: FindingAssessment) -> str:
    reason = _safe(getattr(finding, "reason_code", "INTEGRITY_FINDING"), 64)
    artifact = _safe(getattr(finding, "artifact_id", "") or "unscoped artifact", 160)
    return redact_text(f"[{assessment.severity.value}] {reason} on {artifact}")[:256]


def build_case_description(finding: Any, assessment: FindingAssessment) -> str:
    explanation = redact_text(str(getattr(finding, "explanation", "") or ""))[:2000]
    audit_run = _safe(getattr(finding, "audit_run_id", ""), 128)
    finding_id = _safe(getattr(finding, "finding_id", ""), 64)
    source = _safe(getattr(finding, "verification_source", ""), 256)
    return redact_text(
        f"Finding {finding_id} from audit run {audit_run} ({source}). "
        f"Classification: {assessment.classification.value}. {explanation}"
    )[:8192]


__all__ = [
    "FindingAssessment",
    "assess_finding",
    "build_case_description",
    "build_case_title",
    "correlation_key",
    "finding_dimensions",
]
