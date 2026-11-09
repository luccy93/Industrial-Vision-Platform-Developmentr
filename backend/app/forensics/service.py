"""V34 forensic investigation orchestration.

The service reuses V10 incidents, V15 notifications, V33 findings/audit runs,
and the V34 repository/custody/export primitives. It never copies or mutates
protected V29-V33 artifacts. Confirmed failures can create or update a V10
security incident; unavailable, not-run, simulated, and operational findings
are recorded as review context only and are never promoted to confirmed
incidents.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from backend.app.alerting.repository import AlertRepository
from backend.app.core.logging import get_logger
from backend.app.core.redaction import redact_text
from backend.app.domain.common import utcnow
from backend.app.forensics.alerting import ForensicNotifier
from backend.app.forensics.constants import (
    CUSTODY_ASSURANCE,
    EXTERNAL_ANCHORING_NOTE,
    CaseSeverity,
    CaseSource,
    CaseStatus,
    CaseType,
    EvidenceArtifactType,
    FindingClassification,
    NoteVisibility,
    VerificationOutcome,
    priority_for_severity,
)
from backend.app.forensics.correlation import (
    FindingAssessment,
    assess_finding,
    build_case_description,
    build_case_title,
)
from backend.app.forensics.custody import canonical_json_bytes, sha256_hex
from backend.app.forensics.errors import (
    CorrelationError,
    EvidenceReferenceError,
    ForensicCaseNotFoundError,
    ForensicError,
    ForensicExportNotFoundError,
)
from backend.app.forensics.export import (
    ExportPackage,
    build_export_package,
    verify_export_package,
)
from backend.app.forensics.repository import (
    ForensicRepository,
    normalize_sha256,
    validate_relative_path,
)
from backend.app.forensics.verification import verify_case as run_case_verification
from backend.app.incidents.repository import IncidentRepository
from backend.app.incidents.schemas import ActorType, IncidentCategory, TimelineEventType
from backend.app.integrity.models import Finding
from backend.app.integrity.store import MonitoringStore

logger = get_logger("industrial-vision.forensics.service")

_INCIDENT_CATEGORY = IncidentCategory.SECURITY


class ForensicService:
    """Durable forensic case workflow with honest assurance reporting."""

    def __init__(
        self,
        *,
        settings: Any,
        repository: ForensicRepository,
        store: MonitoringStore | None = None,
        incidents: IncidentRepository | None = None,
        alert_repository: AlertRepository | None = None,
        notifier: ForensicNotifier | None = None,
    ) -> None:
        self._settings = settings
        self._repository = repository
        self._store = store
        self._incidents = incidents
        self._alert_repository = alert_repository
        self._notifier = notifier
        self._governance: Any | None = None

    def set_governance(self, governance: Any | None) -> None:
        """Attach the optional V35 governance layer (additive, never required)."""
        self._governance = governance

    def _governance_audit(
        self,
        event_type: str,
        *,
        actor_id: str | None,
        actor_role: str,
        target_type: str,
        target_id: str,
        case_id: str | None = None,
        outcome: str = "SUCCESS",
        reason: str = "",
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        if self._governance is None:
            return
        try:
            self._governance.record_access(
                event_type=event_type,
                actor_id=actor_id,
                actor_role=actor_role,
                target_type=target_type,
                target_id=target_id,
                case_id=case_id,
                outcome=outcome,
                reason=reason,
                metadata=metadata,
            )
        except Exception as exc:  # audit must never break a forensic operation
            logger.warning("governance audit hook failed: %s", type(exc).__name__)

    # ------------------------------------------------------------------
    # Status and reads
    # ------------------------------------------------------------------
    def status(self) -> dict[str, Any]:
        summary = self._repository.summary()
        store_state = "DISABLED"
        if self._store is not None:
            try:
                store_state = "AVAILABLE" if self._store.is_available() else "UNAVAILABLE"
            except Exception:
                store_state = "UNAVAILABLE"
        return {
            "enabled": bool(getattr(self._settings, "forensic_enabled", True)),
            "summary": summary,
            "v33_source": store_state,
            "alerting_enabled": bool(getattr(self._settings, "forensic_alerting_enabled", False)),
            "export_evidence_bytes_enabled": bool(
                getattr(self._settings, "forensic_export_include_evidence_bytes", False)
            ),
            "assurance": CUSTODY_ASSURANCE,
            "external_anchor_claimed": False,
            "external_anchor_note": EXTERNAL_ANCHORING_NOTE,
        }

    def summary(self) -> dict[str, Any]:
        return self._repository.summary()

    def list_cases(self, **filters: Any) -> dict[str, Any]:
        items, total = self._repository.list_cases(**filters)
        page = max(1, int(filters.get("page") or 1))
        page_size = max(1, min(100, int(filters.get("page_size") or 20)))
        return {
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": (total + page_size - 1) // page_size if total else 0,
        }

    def get_case(self, case_id: str) -> dict[str, Any]:
        detail = self._repository.get_case_detail(case_id)
        if detail is None:
            raise ForensicCaseNotFoundError(case_id)
        detail["assurance"] = CUSTODY_ASSURANCE
        detail["external_anchor_claimed"] = False
        detail["external_anchor_note"] = EXTERNAL_ANCHORING_NOTE
        return detail

    def custody(self, case_id: str) -> dict[str, Any]:
        if self._repository.get_case(case_id) is None:
            raise ForensicCaseNotFoundError(case_id)
        return {
            "events": self._repository.list_custody_events(case_id),
            "verification": self._repository.verify_custody(case_id),
        }

    def timeline(self, case_id: str) -> dict[str, Any]:
        if self._repository.get_case(case_id) is None:
            raise ForensicCaseNotFoundError(case_id)
        return {"items": self._repository.timeline(case_id)}

    def list_exports(self, case_id: str) -> dict[str, Any]:
        if self._repository.get_case(case_id) is None:
            raise ForensicCaseNotFoundError(case_id)
        return {"items": self._repository.list_exports(case_id)}

    def list_source_findings(
        self,
        *,
        audit_run_id: str | None = None,
        severity: str | None = None,
        reason_code: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> dict[str, Any]:
        if self._store is None:
            return {
                "items": [],
                "total": 0,
                "available": False,
                "detail": "V33 monitoring store is unavailable",
            }
        items, total = self._store.list_findings(
            audit_run_id=audit_run_id,
            severity=severity,
            reason_code=reason_code,
            page=page,
            page_size=page_size,
        )
        return {
            "items": [item.to_dict() for item in items],
            "total": total,
            "available": True,
        }

    # ------------------------------------------------------------------
    # Case creation and correlation
    # ------------------------------------------------------------------
    def _prepare_reference(
        self,
        reference: Mapping[str, Any],
        *,
        actor_id: str | None,
    ) -> dict[str, Any]:
        payload = dict(reference)
        artifact_type = str(payload.get("artifact_type") or "").upper()
        try:
            parsed_type = EvidenceArtifactType(artifact_type)
        except ValueError:
            raise EvidenceReferenceError(f"unsupported artifact type: {artifact_type}") from None
        artifact_id = str(payload.get("artifact_id") or "").strip()
        if not artifact_id:
            raise EvidenceReferenceError("artifact_id is required")
        expected = normalize_sha256(payload.get("expected_sha256"))
        if parsed_type is EvidenceArtifactType.V33_FINDING:
            if self._store is None:
                raise EvidenceReferenceError("V33 monitoring store is unavailable")
            finding = self._store.get_finding(artifact_id)
            if finding is None:
                raise EvidenceReferenceError("referenced V33 finding does not exist")
            if not expected:
                expected = sha256_hex(canonical_json_bytes(finding.to_dict()))
            payload.setdefault("source_audit_run_id", finding.audit_run_id)
            payload.setdefault("source_finding_id", finding.finding_id)
        elif parsed_type is EvidenceArtifactType.V33_AUDIT_RUN:
            if self._store is None:
                raise EvidenceReferenceError("V33 monitoring store is unavailable")
            run = self._store.get_run(artifact_id)
            if run is None:
                raise EvidenceReferenceError("referenced V33 audit run does not exist")
            if not expected:
                expected = sha256_hex(canonical_json_bytes(run.to_dict(include_details=True)))
        elif parsed_type is EvidenceArtifactType.INCIDENT:
            if self._incidents is None or self._incidents.get_incident(artifact_id) is None:
                raise EvidenceReferenceError("referenced V10 incident does not exist")
        else:
            relative_path = validate_relative_path(payload.get("original_relative_path"))
            if not relative_path:
                raise EvidenceReferenceError("a relative evidence path is required")
            if not expected:
                raise EvidenceReferenceError("an expected SHA-256 digest is required")
        payload["artifact_type"] = parsed_type.value
        payload["artifact_id"] = artifact_id[:512]
        payload["expected_sha256"] = expected
        payload.setdefault("verification_status", VerificationOutcome.NOT_RUN.value)
        payload.setdefault("verification_outcome", VerificationOutcome.NOT_RUN.value)
        payload.setdefault("metadata", {})
        if actor_id:
            payload["metadata"] = {
                **dict(payload.get("metadata") or {}),
                "referenced_by": actor_id,
            }
        return payload

    def create_case(
        self,
        *,
        title: str,
        description: str = "",
        case_type: str = CaseType.FORENSIC_REVIEW.value,
        severity: str = CaseSeverity.MEDIUM.value,
        priority: str | None = None,
        originating_incident_id: str | None = None,
        originating_audit_run_id: str | None = None,
        assigned_to: str | None = None,
        idempotency_key: str | None = None,
        evidence_references: Sequence[Mapping[str, Any]] = (),
        actor_id: str | None = None,
        actor_role: str = "SYSTEM",
    ) -> dict[str, Any]:
        try:
            parsed_type = CaseType(str(case_type).upper())
        except ValueError:
            raise ForensicError(f"unsupported case type: {case_type}") from None
        try:
            parsed_severity = CaseSeverity(str(severity).upper())
        except ValueError:
            raise ForensicError(f"unsupported case severity: {severity}") from None
        if originating_incident_id and (
            self._incidents is None or self._incidents.get_incident(str(originating_incident_id)) is None
        ):
            raise ForensicError("originating incident does not exist")
        if originating_audit_run_id:
            if self._store is None or self._store.get_run(str(originating_audit_run_id)) is None:
                raise ForensicError("originating audit run does not exist")
        prepared = [
            self._prepare_reference(reference, actor_id=actor_id) for reference in evidence_references
        ]
        case, created = self._repository.create_case(
            title=title,
            description=description,
            case_type=parsed_type,
            severity=parsed_severity,
            priority=priority or priority_for_severity(parsed_severity),
            source=CaseSource.MANUAL,
            originating_incident_id=originating_incident_id,
            originating_audit_run_id=originating_audit_run_id,
            created_by=actor_id,
            assigned_to=assigned_to,
            idempotency_key=idempotency_key,
            actor_id=actor_id,
            actor_role=actor_role,
            incident_ids=(str(originating_incident_id),) if originating_incident_id else (),
            evidence_refs=prepared,
        )
        if created and self._notifier is not None:
            self._safe_notify(
                case,
                "FORENSIC_CASE_OPENED",
                detail="A forensic case was opened manually.",
                reason_codes=(),
            )
        return case

    def correlate_findings(
        self,
        *,
        finding_ids: Sequence[str] = (),
        audit_run_id: str | None = None,
        case_id: str | None = None,
        actor_id: str | None = None,
        actor_role: str = "SYSTEM",
    ) -> dict[str, Any]:
        """Deterministically correlate V33 findings into forensic cases."""
        stats = {
            "examined": 0,
            "confirmed": 0,
            "suspicious": 0,
            "skipped_unavailable": 0,
            "skipped_not_run": 0,
            "skipped_simulated": 0,
            "skipped_operational": 0,
            "duplicates": 0,
            "conflicts": 0,
            "cases_created": 0,
            "cases_updated": 0,
            "incidents_created": 0,
            "incidents_linked": 0,
            "failed": 0,
        }
        if self._store is None:
            raise ForensicError("V33 monitoring store is unavailable")
        existing_case = None
        if case_id:
            existing_case = self._repository.get_case(case_id)
            if existing_case is None:
                raise ForensicCaseNotFoundError(case_id)
        findings = self._load_findings(finding_ids=finding_ids, audit_run_id=audit_run_id)
        seen: set[str] = set()
        for finding in findings:
            if finding.finding_id in seen:
                continue
            seen.add(finding.finding_id)
            stats["examined"] += 1
            assessment = assess_finding(finding)
            if assessment.classification is FindingClassification.UNAVAILABLE:
                stats["skipped_unavailable"] += 1
                continue
            if assessment.classification is FindingClassification.NOT_RUN:
                stats["skipped_not_run"] += 1
                continue
            if assessment.classification is FindingClassification.SIMULATED:
                stats["skipped_simulated"] += 1
                continue
            if assessment.classification is FindingClassification.OPERATIONAL:
                stats["skipped_operational"] += 1
                continue
            if assessment.classification is FindingClassification.CONFIRMED_FAILURE:
                stats["confirmed"] += 1
            else:
                stats["suspicious"] += 1
            try:
                self._correlate_one(
                    finding,
                    assessment,
                    stats,
                    existing_case=existing_case,
                    actor_id=actor_id,
                    actor_role=actor_role,
                )
            except Exception as exc:
                logger.warning("forensic correlation failed: %s", type(exc).__name__)
                stats["failed"] += 1
        return {"stats": stats}

    def _load_findings(self, *, finding_ids: Sequence[str], audit_run_id: str | None) -> list[Finding]:
        assert self._store is not None
        findings: list[Finding] = []
        if finding_ids:
            for finding_id in finding_ids:
                finding = self._store.get_finding(str(finding_id))
                if finding is not None:
                    findings.append(finding)
            return findings
        if audit_run_id:
            items, _ = self._store.list_findings(
                audit_run_id=str(audit_run_id),
                page=1,
                page_size=int(getattr(self._settings, "forensic_max_correlation_findings", 500)),
            )
            return list(items)
        items, _ = self._store.list_findings(
            page=1,
            page_size=int(getattr(self._settings, "forensic_max_correlation_findings", 500)),
        )
        return list(items)

    def _correlate_one(
        self,
        finding: Finding,
        assessment: FindingAssessment,
        stats: dict[str, int],
        *,
        existing_case: Mapping[str, Any] | None,
        actor_id: str | None,
        actor_role: str,
    ) -> None:
        existing_link = self._repository.find_correlation_by_finding_id(finding.finding_id)
        if existing_link is not None:
            stats["duplicates"] += 1
            return
        case = existing_case
        created = False
        if case is not None:
            if case.get("correlation_key") and case["correlation_key"] != assessment.correlation_key:
                stats["conflicts"] += 1
                return
        else:
            case = self._repository.find_case_by_correlation_key(assessment.correlation_key)
            if case is None:
                reference = self._prepare_reference(
                    {
                        "artifact_type": EvidenceArtifactType.V33_FINDING.value,
                        "artifact_id": finding.finding_id,
                        "source_audit_run_id": finding.audit_run_id,
                        "source_finding_id": finding.finding_id,
                        "capture_timestamp": utcnow(),
                    },
                    actor_id=actor_id,
                )
                case, created = self._repository.create_case(
                    title=build_case_title(finding, assessment),
                    description=build_case_description(finding, assessment),
                    case_type=assessment.case_type,
                    severity=assessment.severity,
                    priority=assessment.priority,
                    source=CaseSource.CORRELATION,
                    originating_incident_id=None,
                    originating_audit_run_id=finding.audit_run_id,
                    created_by=actor_id,
                    correlation_key=assessment.correlation_key,
                    actor_id=actor_id,
                    actor_role=actor_role,
                    correlation=self._correlation_payload(finding, assessment),
                    evidence_refs=[reference],
                )
                if created:
                    stats["cases_created"] += 1
        if case is None:
            raise CorrelationError("correlation produced no case")
        if not created:
            self._repository.link_correlation(
                str(case["case_id"]),
                self._correlation_payload(finding, assessment),
                actor_id=actor_id or "SYSTEM",
                actor_role=actor_role,
            )
            self._add_finding_reference(
                str(case["case_id"]),
                finding,
                actor_id=actor_id,
                actor_role=actor_role,
            )
            stats["cases_updated"] += 1
        if assessment.confirmed:
            incident_id, incident_created = self._ensure_incident(
                case,
                finding,
                assessment,
                actor_id=actor_id,
                actor_role=actor_role,
            )
            if incident_created:
                stats["incidents_created"] += 1
            elif incident_id:
                stats["incidents_linked"] += 1
            refreshed = self._repository.get_case(str(case["case_id"])) or case
            if self._notifier is not None:
                self._safe_notify(
                    refreshed,
                    "FORENSIC_CASE_OPENED" if created else "FORENSIC_CASE_ESCALATED",
                    detail=f"Confirmed {finding.reason_code} finding was correlated.",
                    finding_id=finding.finding_id,
                    audit_run_id=finding.audit_run_id,
                    reason_codes=(finding.reason_code,),
                )

    def _correlation_payload(self, finding: Finding, assessment: FindingAssessment) -> dict[str, Any]:
        dimensions = dict(assessment.dimensions)
        return {
            "correlation_key": assessment.correlation_key,
            "finding_id": finding.finding_id,
            "audit_run_id": finding.audit_run_id,
            "artifact_id": finding.artifact_id,
            "evidence_identifier": dimensions.get("artifact_id") or finding.artifact_id,
            "reason_code": finding.reason_code,
            "classification": assessment.classification.value,
            "severity": assessment.severity.value,
            "metadata": {
                "rationale": assessment.rationale,
                "dimensions": dimensions,
                "scope": dimensions.get("scope"),
            },
        }

    def _add_finding_reference(
        self,
        case_id: str,
        finding: Finding,
        *,
        actor_id: str | None,
        actor_role: str,
    ) -> None:
        reference = self._prepare_reference(
            {
                "artifact_type": EvidenceArtifactType.V33_FINDING.value,
                "artifact_id": finding.finding_id,
                "source_audit_run_id": finding.audit_run_id,
                "source_finding_id": finding.finding_id,
                "capture_timestamp": utcnow(),
            },
            actor_id=actor_id,
        )
        self._repository.add_evidence_reference(
            case_id, reference, actor_id=actor_id or "SYSTEM", actor_role=actor_role
        )

    def _ensure_incident(
        self,
        case: Mapping[str, Any],
        finding: Finding,
        assessment: FindingAssessment,
        *,
        actor_id: str | None,
        actor_role: str,
    ) -> tuple[str | None, bool]:
        case_id = str(case["case_id"])
        linked = self._repository.case_incident_ids(case_id)
        if linked:
            self._incident_note(
                linked[0],
                f"Additional confirmed forensic finding {finding.finding_id} "
                f"({finding.reason_code}) was correlated to case {case.get('case_number')}.",
                actor_id=actor_id,
            )
            return linked[0], False
        originating = str(case.get("originating_incident_id") or "")
        if originating and self._incidents is not None:
            incident = self._incidents.get_incident(originating)
            if incident is not None:
                self._repository.link_incident(
                    case_id,
                    originating,
                    actor_id=actor_id or "SYSTEM",
                    actor_role=actor_role,
                )
                self._incident_note(
                    originating,
                    f"Confirmed forensic finding {finding.finding_id} ({finding.reason_code}) "
                    f"was linked to case {case.get('case_number')}.",
                    actor_id=actor_id,
                )
                return originating, False
        if self._incidents is None:
            return None, False
        title = redact_text(
            f"[FORENSIC] {finding.reason_code} on "
            f"{finding.artifact_id or case.get('case_number') or 'protected artifact'}"
        )[:256]
        description = build_case_description(finding, assessment)
        try:
            incident = self._incidents.create_manual(
                camera_id=None,
                title=title or "Forensic integrity incident",
                description=description,
                category=_INCIDENT_CATEGORY,
                priority=assessment.priority,
                metadata={
                    "forensic_case_id": case_id,
                    "forensic_case_number": case.get("case_number"),
                    "finding_id": finding.finding_id,
                    "audit_run_id": finding.audit_run_id,
                    "reason_code": finding.reason_code,
                    "classification": assessment.classification.value,
                    "correlation_key": assessment.correlation_key,
                },
                source_event_id=finding.finding_id,
                source="FORENSIC",
            )
        except Exception as exc:
            logger.warning("forensic incident creation failed: %s", type(exc).__name__)
            return None, False
        incident_id = str(incident.id)
        self._repository.link_incident(
            case_id,
            incident_id,
            actor_id=actor_id or "SYSTEM",
            actor_role=actor_role,
        )
        return incident_id, True

    def _incident_note(self, incident_id: str, message: str, *, actor_id: str | None) -> None:
        if self._incidents is None:
            return
        try:
            self._incidents.add_timeline_entry(
                incident_id,
                TimelineEventType.NOTE_ADDED,
                message=redact_text(message)[:2000],
                actor_id=actor_id,
                actor_type=ActorType.OPERATOR if actor_id else ActorType.SYSTEM,
                metadata={"source": "FORENSIC_V34"},
            )
        except Exception as exc:
            logger.warning("forensic incident timeline update failed: %s", type(exc).__name__)

    def _safe_notify(
        self,
        case: Mapping[str, Any],
        event_type: str,
        *,
        detail: str = "",
        finding_id: str | None = None,
        audit_run_id: str | None = None,
        reason_codes: Sequence[str] = (),
    ) -> None:
        if self._notifier is None:
            return
        try:
            self._notifier.notify_case_event(
                case,
                event_type,
                detail=detail,
                finding_id=finding_id,
                audit_run_id=audit_run_id,
                reason_codes=reason_codes,
            )
        except Exception as exc:
            logger.warning("forensic notification failed: %s", type(exc).__name__)

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------
    def transition_case(
        self,
        case_id: str,
        *,
        target_status: str,
        reason: str,
        actor_id: str | None,
        actor_role: str,
        expected_version: int | None = None,
        resolution_summary: str | None = None,
        reopening: bool = False,
        acknowledge_critical_findings: bool = False,
        acknowledge_evidence_failures: bool = False,
        allow_unverified_evidence: bool = False,
    ) -> dict[str, Any]:
        case = self._repository.transition_case(
            case_id,
            target_status=target_status,
            actor_id=actor_id or "SYSTEM",
            actor_role=actor_role,
            reason=reason,
            expected_version=expected_version,
            resolution_summary=resolution_summary,
            reopening=reopening,
            acknowledge_critical_findings=acknowledge_critical_findings,
            acknowledge_evidence_failures=acknowledge_evidence_failures,
            allow_unverified_evidence=allow_unverified_evidence,
        )
        status = str(case.get("status") or "")
        event_type = {
            CaseStatus.CONTAINMENT_RECOMMENDED.value: "FORENSIC_CASE_ESCALATED",
            CaseStatus.RESOLVED.value: "FORENSIC_CASE_RESOLVED",
            CaseStatus.CLOSED.value: "FORENSIC_CASE_CLOSED",
        }.get(status)
        if event_type:
            self._safe_notify(
                case,
                event_type,
                detail=f"Case status changed to {status}.",
                reason_codes=(),
            )
        for incident_id in self._repository.case_incident_ids(case_id):
            self._incident_note(
                incident_id,
                f"Forensic case {case.get('case_number')} moved to {status}: {redact_text(reason)[:500]}",
                actor_id=actor_id,
            )
        return case

    def assign_case(
        self,
        case_id: str,
        *,
        assignee: str | None,
        reason: str,
        actor_id: str | None,
        actor_role: str,
        expected_version: int | None = None,
    ) -> dict[str, Any]:
        return self._repository.assign_case(
            case_id,
            assignee=assignee,
            actor_id=actor_id or "SYSTEM",
            actor_role=actor_role,
            reason=reason,
            expected_version=expected_version,
        )

    def note_revisions(self, case_id: str, note_id: str) -> dict[str, Any]:
        if self._repository.get_case(case_id) is None:
            raise ForensicCaseNotFoundError(case_id)
        notes = self._repository.list_notes(case_id)
        if not any(item.get("note_id") == note_id for item in notes):
            from backend.app.forensics.errors import ForensicNoteNotFoundError

            raise ForensicNoteNotFoundError(note_id)
        return {"items": self._repository.list_note_revisions(note_id)}

    def add_note(
        self,
        case_id: str,
        *,
        note_type: str,
        content: str,
        visibility: str = NoteVisibility.INTERNAL.value,
        related_evidence_ids: Sequence[str] = (),
        author_id: str | None,
        actor_role: str,
    ) -> dict[str, Any]:
        return self._repository.add_note(
            case_id,
            author_id=author_id or "SYSTEM",
            actor_role=actor_role,
            note_type=note_type,
            content=content,
            visibility=visibility,
            related_evidence_ids=related_evidence_ids,
        )

    def update_note(
        self,
        case_id: str,
        note_id: str,
        *,
        content: str,
        editor_id: str | None,
        actor_role: str,
        expected_version: int | None = None,
        related_evidence_ids: Sequence[str] | None = None,
    ) -> dict[str, Any]:
        return self._repository.update_note(
            case_id,
            note_id,
            editor_id=editor_id or "SYSTEM",
            actor_role=actor_role,
            content=content,
            expected_version=expected_version,
            related_evidence_ids=related_evidence_ids,
        )

    def add_action(
        self,
        case_id: str,
        *,
        action_type: str,
        description: str,
        related_finding_ids: Sequence[str] = (),
        result: str = "RECORDED",
        approval_reference: str | None = None,
        actor_id: str | None,
        actor_role: str,
    ) -> dict[str, Any]:
        return self._repository.add_action(
            case_id,
            actor_id=actor_id or "SYSTEM",
            actor_role=actor_role,
            action_type=action_type,
            description=description,
            related_finding_ids=related_finding_ids,
            result=result,
            approval_reference=approval_reference,
        )

    def add_evidence_reference(
        self,
        case_id: str,
        *,
        reference: Mapping[str, Any],
        actor_id: str | None,
        actor_role: str,
    ) -> dict[str, Any]:
        if self._repository.get_case(case_id) is None:
            raise ForensicCaseNotFoundError(case_id)
        prepared = self._prepare_reference(reference, actor_id=actor_id)
        return self._repository.add_evidence_reference(
            case_id, prepared, actor_id=actor_id or "SYSTEM", actor_role=actor_role
        )

    def link_incident(
        self,
        case_id: str,
        *,
        incident_id: str,
        actor_id: str | None,
        actor_role: str,
    ) -> dict[str, Any]:
        if self._incidents is None or self._incidents.get_incident(incident_id) is None:
            raise ForensicError("incident does not exist")
        return self._repository.link_incident(
            case_id,
            incident_id,
            actor_id=actor_id or "SYSTEM",
            actor_role=actor_role,
        )

    # ------------------------------------------------------------------
    # Verification and exports
    # ------------------------------------------------------------------
    def verify_case(
        self,
        case_id: str,
        *,
        actor_id: str | None,
        actor_role: str,
    ) -> dict[str, Any]:
        report = run_case_verification(
            case_id=case_id,
            repository=self._repository,
            store=self._store,
            incidents=self._incidents,
            evidence_base=getattr(self._settings, "forensic_evidence_base", ""),
        ).to_dict()
        self._repository.record_reference_observations(
            case_id,
            report.get("observations") or [],
            actor_id=actor_id or "SYSTEM",
            actor_role=actor_role,
            verification_report=report,
        )
        if report.get("custody", {}).get("outcome") == VerificationOutcome.FAIL.value:
            case = self._repository.get_case(case_id)
            if case is not None:
                self._safe_notify(
                    case,
                    "FORENSIC_CUSTODY_FAILURE",
                    detail="Custody ledger verification failed.",
                    reason_codes=tuple(report.get("custody", {}).get("reason_codes") or []),
                )
        self._governance_audit(
            "EVIDENCE_VERIFICATION_REQUESTED",
            actor_id=actor_id,
            actor_role=actor_role,
            target_type="FORENSIC_CASE",
            target_id=case_id,
            case_id=case_id,
            outcome=(
                "SUCCESS"
                if report.get("custody", {}).get("outcome") == VerificationOutcome.PASS.value
                else "FAILURE"
            ),
            metadata={
                "custody_outcome": report.get("custody", {}).get("outcome"),
                "reason_codes": list(report.get("custody", {}).get("reason_codes") or []),
                "approval_id": None,
            },
        )
        return report

    def _export_root(self) -> Path:
        root = Path(str(self._settings.forensic_export_path)).expanduser().resolve(strict=False)
        evidence_base = str(getattr(self._settings, "forensic_evidence_base", "") or "").strip()
        if evidence_base:
            protected = Path(evidence_base).expanduser().resolve(strict=False)
            if root == protected or protected in root.parents:
                raise ForensicError(
                    "forensic export directory must not be inside the protected evidence root"
                )
        return root

    def create_export(
        self,
        case_id: str,
        *,
        include_evidence_bytes: bool = False,
        actor_id: str | None,
        actor_role: str,
        export_id: str | None = None,
    ) -> dict[str, Any]:
        detail = self.get_case(case_id)
        allowed_bytes = bool(getattr(self._settings, "forensic_export_include_evidence_bytes", False))
        if include_evidence_bytes and not allowed_bytes:
            raise ForensicError(
                "evidence-byte export is disabled by policy; only references and hashes are exported"
            )
        if self._governance is not None:
            try:
                self._governance.guard_direct_export(
                    case_id,
                    include_evidence_bytes=include_evidence_bytes,
                    actor_id=actor_id,
                    actor_role=actor_role,
                )
            except Exception as exc:
                self._governance_audit(
                    "EXPORT_GENERATION_FAILED",
                    actor_id=actor_id,
                    actor_role=actor_role,
                    target_type="FORENSIC_EXPORT",
                    target_id=case_id,
                    case_id=case_id,
                    outcome="FAILURE",
                    reason=str(exc)[:512],
                    metadata={"approval_id": None, "direct_export": True},
                )
                raise
        evidence_base = str(getattr(self._settings, "forensic_evidence_base", "") or "").strip()
        package: ExportPackage = build_export_package(
            case_detail=detail,
            export_root=self._export_root(),
            include_evidence_bytes=include_evidence_bytes,
            evidence_base=Path(evidence_base).expanduser() if evidence_base else None,
            max_files=int(getattr(self._settings, "forensic_export_max_files", 64)),
            max_bytes=int(getattr(self._settings, "forensic_export_max_bytes", 50 * 1024 * 1024)),
            export_id=export_id,
        )
        try:
            record = self._repository.create_export_record(
                case_id,
                export_id=package.export_id,
                filename=package.filename,
                storage_relative_path=package.storage_relative_path,
                sha256=package.sha256,
                size_bytes=package.size_bytes,
                file_count=package.file_count,
                schema_version=package.schema_version,
                policy_version=package.policy_version,
                created_by=actor_id or "SYSTEM",
                actor_role=actor_role,
                manifest_digest=package.manifest_digest,
                root_digest=package.root_digest,
                evidence_bytes_included=package.evidence_bytes_included,
            )
        except Exception:
            target = self._export_root() / package.storage_relative_path
            target.unlink(missing_ok=True)
            raise
        self._governance_audit(
            "EXPORT_GENERATED",
            actor_id=actor_id,
            actor_role=actor_role,
            target_type="FORENSIC_EXPORT",
            target_id=str(record.get("export_id") or package.export_id),
            case_id=case_id,
            metadata={
                "approval_id": None,
                "direct_export": True,
                "export_sha256": record.get("sha256"),
                "manifest_digest": record.get("manifest_digest"),
                "root_digest": record.get("root_digest"),
                "include_evidence_bytes": include_evidence_bytes,
                "delivery_claimed": False,
            },
        )
        return record

    def get_export(self, export_id: str) -> dict[str, Any]:
        record = self._repository.get_export(export_id)
        if record is None:
            raise ForensicExportNotFoundError(export_id)
        return record

    def export_path(self, export_id: str) -> tuple[Path, str]:
        record = self.get_export(export_id)
        root = self._export_root()
        relative = str(record.get("storage_relative_path") or "")
        candidate = (root / relative).resolve(strict=False)
        if candidate != root and root not in candidate.parents:
            raise ForensicError("export path escapes the configured export directory")
        if not candidate.is_file():
            raise ForensicExportNotFoundError(export_id)
        return candidate, str(record.get("filename") or candidate.name)

    def verify_export(
        self,
        export_id: str,
        *,
        actor_id: str | None,
        actor_role: str,
    ) -> dict[str, Any]:
        record = self.get_export(export_id)
        path, _ = self.export_path(export_id)
        result = verify_export_package(
            path,
            expected_sha256=str(record.get("sha256") or ""),
            expected_manifest_digest=str(record.get("manifest_digest") or ""),
            max_files=int(getattr(self._settings, "forensic_export_max_files", 64)),
            max_bytes=int(getattr(self._settings, "forensic_export_max_bytes", 50 * 1024 * 1024)),
        )
        updated = self._repository.record_export_verification(
            export_id,
            actor_id=actor_id or "SYSTEM",
            actor_role=actor_role,
            outcome=result.outcome,
            detail=result.detail,
            metadata={"reason_codes": result.reason_codes},
        )
        if result.outcome == VerificationOutcome.FAIL.value:
            case = self._repository.get_case(str(record.get("case_id") or ""))
            if case is not None:
                self._safe_notify(
                    case,
                    "FORENSIC_EXPORT_FAILURE",
                    detail="Forensic export verification failed.",
                    reason_codes=tuple(result.reason_codes),
                )
        self._governance_audit(
            (
                "EXPORT_VERIFIED"
                if result.outcome == VerificationOutcome.PASS.value
                else "EXPORT_VERIFICATION_FAILED"
            ),
            actor_id=actor_id,
            actor_role=actor_role,
            target_type="FORENSIC_EXPORT",
            target_id=export_id,
            case_id=str(record.get("case_id") or ""),
            outcome="SUCCESS" if result.outcome == VerificationOutcome.PASS.value else "FAILURE",
            reason=str(result.detail or "")[:512],
            metadata={"approval_id": None, "outcome": result.outcome},
        )
        return {"export": updated, "verification": result.to_dict()}


__all__ = ["ForensicService"]
