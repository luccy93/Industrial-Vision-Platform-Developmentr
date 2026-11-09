"""Focused V34 forensic unit tests.

All fixtures are synthetic and local. No protected evidence is modified: the
tests build their own temporary artifacts, tamper only with copies, and assert
that classification, correlation, custody verification, exports, workflow, and
notifications fail closed and report limitations honestly.
"""

from __future__ import annotations

import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from backend.app.alerting.repository import AlertRepository
from backend.app.core.config import AppEnv, Settings
from backend.app.forensics.alerting import ForensicNotifier
from backend.app.forensics.constants import (
    CUSTODY_ASSURANCE,
    EXTERNAL_ANCHORING_NOTE,
    CaseSeverity,
    CaseStatus,
    CaseType,
    CustodyEventType,
    EvidenceArtifactType,
    FindingClassification,
    VerificationOutcome,
    classify_reason,
)
from backend.app.forensics.correlation import (
    assess_finding,
    correlation_key,
    finding_dimensions,
)
from backend.app.forensics.custody import (
    GENESIS_HASH,
    build_event,
    sha256_hex,
    verify_custody_chain,
)
from backend.app.forensics.errors import (
    ExportPolicyError,
    InvalidCaseTransitionError,
)
from backend.app.forensics.export import build_export_package, verify_export_package
from backend.app.forensics.state import requires_close_capability, validate_case_transition
from backend.app.infrastructure.db import get_session_factory, init_db
from backend.app.integrity.constants import (
    IntegrityScope,
    Severity,
)
from backend.app.integrity.models import Finding


def _settings(tmp_path: Path, **overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "app_name": "industrial-vision-platform",
        "app_env": AppEnv.testing,
        "log_level": "WARNING",
        "database_url": f"sqlite:///{tmp_path}/test.db",
        "_env_file": None,
    }
    values.update(overrides)
    return Settings(**values)


def _finding(
    *,
    reason_code: str,
    artifact_id: str = "evidence/synthetic.bin",
    audit_run_id: str = "run-1",
    verification_source: str | None = None,
    severity: Severity | None = None,
) -> Finding:
    return Finding.create(
        audit_run_id=audit_run_id,
        scope=IntegrityScope.EVIDENCE,
        reason_code=reason_code,
        artifact_id=artifact_id,
        explanation="synthetic test finding",
        verification_source=verification_source,
        severity=severity,
    )


# ---------------------------------------------------------------------------
# Classification and correlation
# ---------------------------------------------------------------------------
def test_only_confirmed_failure_reasons_are_promotable() -> None:
    assert classify_reason("EVIDENCE_MODIFIED") is FindingClassification.CONFIRMED_FAILURE
    assert classify_reason("TREE_HEAD_REPLAY") is FindingClassification.CONFIRMED_FAILURE
    assert classify_reason("EVIDENCE_UNAVAILABLE") is FindingClassification.UNAVAILABLE
    assert classify_reason("AUDIT_TIMEOUT") is FindingClassification.NOT_RUN
    assert classify_reason("EXTERNAL_ANCHOR_UNCONFIGURED") is FindingClassification.OPERATIONAL
    assert classify_reason("EVIDENCE_MISSING") is FindingClassification.SUSPICIOUS
    assert classify_reason("UNRECOGNIZED_CODE") is FindingClassification.SUSPICIOUS

    # A simulated source always wins, even when the reason code is concrete.
    simulated = _finding(
        reason_code="EVIDENCE_MODIFIED",
        verification_source="SIMULATED_LOCAL_TEST",
    )
    assessment = assess_finding(simulated)
    assert assessment.classification is FindingClassification.SIMULATED
    assert assessment.confirmed is False
    assert assessment.case_type is CaseType.FORENSIC_REVIEW

    unavailable = assess_finding(_finding(reason_code="EVIDENCE_UNAVAILABLE"))
    assert unavailable.confirmed is False
    assert unavailable.case_type is CaseType.FORENSIC_REVIEW
    assert "not promoted" in unavailable.rationale

    confirmed = assess_finding(_finding(reason_code="EVIDENCE_MODIFIED", severity=Severity.CRITICAL))
    assert confirmed.confirmed is True
    assert confirmed.case_type is CaseType.EVIDENCE_TAMPERING
    assert confirmed.severity is CaseSeverity.CRITICAL
    assert confirmed.priority == "P1"


def test_correlation_key_is_deterministic_and_groups_repeats() -> None:
    dimensions = {"artifact_id": "evidence/a.bin", "reason_code": "EVIDENCE_MODIFIED"}
    first = correlation_key(case_type=CaseType.EVIDENCE_TAMPERING, dimensions=dimensions)
    second = correlation_key(case_type=CaseType.EVIDENCE_TAMPERING, dimensions=dimensions)
    assert first == second

    different_reason = correlation_key(
        case_type=CaseType.EVIDENCE_TAMPERING,
        dimensions={"artifact_id": "evidence/a.bin", "reason_code": "EVIDENCE_REPLACED"},
    )
    different_artifact = correlation_key(
        case_type=CaseType.EVIDENCE_TAMPERING,
        dimensions={"artifact_id": "evidence/b.bin", "reason_code": "EVIDENCE_MODIFIED"},
    )
    assert len({first, different_reason, different_artifact}) == 3

    # A repeated finding in a later audit run keeps the same artifact identity.
    early = _finding(reason_code="EVIDENCE_MODIFIED", audit_run_id="run-1")
    later = _finding(reason_code="EVIDENCE_MODIFIED", audit_run_id="run-2")
    early_dims = finding_dimensions(early)
    later_dims = finding_dimensions(later)
    assert early_dims["audit_run_id"] != later_dims["audit_run_id"]
    assert correlation_key(case_type=CaseType.EVIDENCE_TAMPERING, dimensions=early_dims) == correlation_key(
        case_type=CaseType.EVIDENCE_TAMPERING, dimensions=later_dims
    )


# ---------------------------------------------------------------------------
# Custody chain
# ---------------------------------------------------------------------------
def _custody_events(case_id: str = "case-1") -> list[dict[str, Any]]:
    first = build_event(
        event_id="event-1",
        case_id=case_id,
        sequence=1,
        event_type=CustodyEventType.CASE_CREATED,
        timestamp=datetime(2026, 1, 1, 12, 0, tzinfo=UTC),
        actor_id="admin@example.com",
        actor_role="ADMIN",
        previous_hash=GENESIS_HASH,
        metadata={"case_number": "CASE-2026-000001"},
    )
    second = build_event(
        event_id="event-2",
        case_id=case_id,
        sequence=2,
        event_type=CustodyEventType.EVIDENCE_REFERENCED,
        timestamp=datetime(2026, 1, 1, 12, 1, tzinfo=UTC),
        actor_id="operator@example.com",
        actor_role="OPERATOR",
        previous_hash=first["event_hash"],
        artifact_id="evidence/a.bin",
        metadata={"expected_sha256": "a" * 64},
    )
    return [first, second]


def _case_head(events: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "custody_event_count": len(events),
        "custody_head_hash": events[-1]["event_hash"] if events else None,
    }


def test_custody_chain_verifies_and_reports_limitations() -> None:
    events = _custody_events()
    result = verify_custody_chain(case=_case_head(events), events=events)
    assert result.outcome is VerificationOutcome.PASS
    assert result.event_count == 2
    assert result.reason_codes == []
    assert result.assurance == CUSTODY_ASSURANCE
    assert result.to_dict()["external_anchor_claimed"] is False
    assert EXTERNAL_ANCHORING_NOTE in result.limitations


@pytest.mark.parametrize(
    ("mutation", "expected_reason"),
    [
        ("event_hash", "CUSTODY_EVENT_HASH_INVALID"),
        ("previous_hash", "CUSTODY_PREVIOUS_HASH_INVALID"),
        ("sequence", "CUSTODY_SEQUENCE_GAP"),
        ("head", "CUSTODY_HEAD_MISMATCH"),
        ("count", "CUSTODY_CHAIN_TRUNCATED"),
    ],
)
def test_custody_chain_detects_tampering(mutation: str, expected_reason: str) -> None:
    events = _custody_events()
    case = _case_head(events)
    if mutation == "event_hash":
        events[1]["event_hash"] = "0" * 64
    elif mutation == "previous_hash":
        events[1]["previous_hash"] = "0" * 64
    elif mutation == "sequence":
        events[1]["sequence"] = 3
    elif mutation == "head":
        case["custody_head_hash"] = "f" * 64
    elif mutation == "count":
        case["custody_event_count"] = 3
    result = verify_custody_chain(case=case, events=events)
    assert result.outcome is VerificationOutcome.FAIL
    assert expected_reason in result.reason_codes, result.reason_codes


def test_empty_custody_chain_is_not_reported_as_pass() -> None:
    result = verify_custody_chain(case={"custody_event_count": 0}, events=[])
    assert result.outcome is VerificationOutcome.UNAVAILABLE
    assert "CUSTODY_CHAIN_EMPTY" in result.reason_codes

    inconsistent = verify_custody_chain(case={"custody_event_count": 2}, events=[])
    assert inconsistent.outcome is VerificationOutcome.FAIL


# ---------------------------------------------------------------------------
# Export package
# ---------------------------------------------------------------------------
def _case_detail(**overrides: Any) -> dict[str, Any]:
    detail: dict[str, Any] = {
        "case": {
            "case_id": "case-1",
            "case_number": "CASE-2026-000001",
            "title": "Synthetic forensic case",
            "case_type": "EVIDENCE_TAMPERING",
            "severity": "HIGH",
            "status": "OPEN",
            "priority": "P2",
            "version": 2,
            "updated_at": "2026-01-01T00:00:00.000Z",
            "originating_incident_id": None,
            "originating_audit_run_id": "run-1",
        },
        "correlations": [],
        "incident_links": [],
        "evidence_references": [],
        "custody": {"events": [], "verification": {"outcome": "PASS"}},
        "notes": [],
        "actions": [],
        "assignments": [],
        "latest_verification": None,
    }
    detail.update(overrides)
    return detail


def test_export_is_deterministic_and_verifiable(tmp_path: Path) -> None:
    first = build_export_package(
        case_detail=_case_detail(),
        export_id="11111111-1111-1111-1111-111111111111",
        export_root=tmp_path / "exports-a",
    )
    second = build_export_package(
        case_detail=_case_detail(),
        export_id="22222222-2222-2222-2222-222222222222",
        export_root=tmp_path / "exports-b",
    )
    assert first.sha256 == second.sha256
    assert first.manifest_digest == second.manifest_digest
    assert first.root_digest == second.root_digest
    assert first.file_count == 12
    assert first.evidence_bytes_included is False

    for package in (first, second):
        path = Path(package.storage_relative_path)
        root = tmp_path / ("exports-a" if package is first else "exports-b")
        verification = verify_export_package(
            root / path,
            expected_sha256=package.sha256,
            expected_manifest_digest=package.manifest_digest,
        )
        assert verification.outcome == "PASS", verification.to_dict()
        assert verification.manifest_digest == package.manifest_digest
        assert verification.root_digest == package.root_digest


def _rewrite_zip(source: Path, target: Path, replacement: dict[str, bytes]) -> None:
    with zipfile.ZipFile(source, "r") as original:
        entries = {info.filename: original.read(info.filename) for info in original.infolist()}
    entries.update(replacement)
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(entries):
            archive.writestr(name, entries[name])


def test_export_verification_detects_member_tampering(tmp_path: Path) -> None:
    package = build_export_package(
        case_detail=_case_detail(),
        export_id="33333333-3333-3333-3333-333333333333",
        export_root=tmp_path / "exports",
    )
    original = tmp_path / "exports" / package.storage_relative_path
    tampered = tmp_path / "tampered.zip"
    _rewrite_zip(original, tampered, {"case.json": b'{"tampered": true}\n'})

    result = verify_export_package(
        tampered,
        expected_manifest_digest=package.manifest_digest,
    )
    assert result.outcome == "FAIL"
    assert "FORENSIC_EXPORT_MEMBER_DIGEST_MISMATCH" in result.reason_codes
    assert "FORENSIC_EXPORT_MEMBER_SIZE_MISMATCH" in result.reason_codes

    # Archive digest verification is independent of member checks.
    archive_check = verify_export_package(tampered, expected_sha256=package.sha256)
    assert "FORENSIC_EXPORT_ARCHIVE_DIGEST_MISMATCH" in archive_check.reason_codes


def test_export_rejects_unsafe_archive_members(tmp_path: Path) -> None:
    unsafe = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(unsafe, "w") as archive:
        archive.writestr("../escape.json", b"{}")
    result = verify_export_package(unsafe)
    assert result.outcome == "FAIL"
    assert "FORENSIC_EXPORT_ARCHIVE_INVALID" in result.reason_codes


def test_export_includes_evidence_bytes_only_when_policy_and_digest_allow(
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    payload = b"synthetic-evidence-bytes"
    (evidence_root / "artifact.bin").write_bytes(payload)
    digest = sha256_hex(payload)
    reference = {
        "reference_id": "ref-1",
        "artifact_type": EvidenceArtifactType.EVIDENCE_FILE.value,
        "artifact_id": "artifact.bin",
        "original_relative_path": "artifact.bin",
        "expected_sha256": digest,
    }
    detail = _case_detail(evidence_references=[reference])

    references_only = build_export_package(
        case_detail=detail,
        export_id="44444444-4444-4444-4444-444444444444",
        export_root=tmp_path / "exports-refs",
    )
    assert references_only.evidence_bytes_included is False

    with_bytes = build_export_package(
        case_detail=detail,
        export_id="55555555-5555-5555-5555-555555555555",
        export_root=tmp_path / "exports-bytes",
        include_evidence_bytes=True,
        evidence_base=evidence_root,
    )
    assert with_bytes.evidence_bytes_included is True
    assert with_bytes.file_count == 13
    verified = verify_export_package(
        tmp_path / "exports-bytes" / with_bytes.storage_relative_path,
        expected_sha256=with_bytes.sha256,
        expected_manifest_digest=with_bytes.manifest_digest,
    )
    assert verified.outcome == "PASS", verified.to_dict()

    # A later byte change is refused rather than exported as if intact.
    (evidence_root / "artifact.bin").write_bytes(b"changed")
    with pytest.raises(ExportPolicyError):
        build_export_package(
            case_detail=detail,
            export_id="66666666-6666-6666-6666-666666666666",
            export_root=tmp_path / "exports-tampered",
            include_evidence_bytes=True,
            evidence_base=evidence_root,
        )


# ---------------------------------------------------------------------------
# Workflow
# ---------------------------------------------------------------------------
def test_case_transitions_are_explicit_and_reopen_is_separate() -> None:
    validate_case_transition(CaseStatus.OPEN, CaseStatus.TRIAGED)
    validate_case_transition(CaseStatus.TRIAGED, CaseStatus.INVESTIGATING)
    validate_case_transition(CaseStatus.INVESTIGATING, CaseStatus.CONTAINMENT_RECOMMENDED)
    validate_case_transition(CaseStatus.CONTAINMENT_RECOMMENDED, CaseStatus.AWAITING_REVIEW)
    validate_case_transition(CaseStatus.AWAITING_REVIEW, CaseStatus.RESOLVED)
    validate_case_transition(CaseStatus.RESOLVED, CaseStatus.CLOSED)
    validate_case_transition(CaseStatus.CLOSED, CaseStatus.OPEN, reopening=True)

    with pytest.raises(InvalidCaseTransitionError):
        validate_case_transition(CaseStatus.OPEN, CaseStatus.CLOSED)
    with pytest.raises(InvalidCaseTransitionError):
        validate_case_transition(CaseStatus.CLOSED, CaseStatus.OPEN)

    assert requires_close_capability(CaseStatus.RESOLVED) is True
    assert requires_close_capability(CaseStatus.CLOSED) is True
    assert requires_close_capability(CaseStatus.OPEN, reopening=True) is True
    assert requires_close_capability(CaseStatus.TRIAGED) is False


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------
def _notifier_case(**overrides: Any) -> dict[str, Any]:
    case: dict[str, Any] = {
        "case_id": "case-1",
        "case_number": "CASE-2026-000001",
        "case_type": "EVIDENCE_TAMPERING",
        "status": "OPEN",
        "severity": "CRITICAL",
        "priority": "P1",
        "version": 1,
        "originating_incident_id": "incident-1",
        "originating_audit_run_id": "run-1",
        "incident_ids": ["incident-1"],
    }
    case.update(overrides)
    return case


def test_forensic_notifications_dedup_cooldown_and_pending_delivery(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    init_db(settings.database_url)
    factory = get_session_factory(settings.database_url)
    repository = AlertRepository(factory)
    repository.create_rule(
        name="Forensic critical events",
        enabled=True,
        domains=["FORENSIC"],
        event_types=["FORENSIC_CASE_OPENED"],
        min_severity="HIGH",
        channels=["in_app"],
        cooldown_seconds=3600,
    )
    notifier = ForensicNotifier(
        session_factory=factory,
        alert_repository=repository,
        enabled=True,
        min_severity="HIGH",
        cooldown_seconds=3600,
    )

    first = notifier.notify_case_event(
        _notifier_case(),
        "FORENSIC_CASE_OPENED",
        detail="confirmed evidence tampering; password=SuperSecret123",
        reason_codes=["EVIDENCE_MODIFIED"],
    )
    assert first["queued"] == 1
    second = notifier.notify_case_event(_notifier_case(), "FORENSIC_CASE_OPENED")
    assert second["duplicate"] == 1
    cooldown = notifier.notify_case_event(_notifier_case(version=2), "FORENSIC_CASE_OPENED")
    assert cooldown["suppressed"] == 1

    # A zero-cooldown notifier queues the next case version.
    immediate = ForensicNotifier(
        session_factory=factory,
        alert_repository=repository,
        enabled=True,
        min_severity="HIGH",
        cooldown_seconds=0,
    )
    queued = immediate.notify_case_event(_notifier_case(version=3), "FORENSIC_CASE_OPENED")
    assert queued["queued"] == 1

    notifications, total = repository.list_notifications(page=1, page_size=10)
    assert total == 2
    assert all(item.source_domain == "FORENSIC" for item in notifications)
    assert all(item.incident_id == "incident-1" for item in notifications)
    assert all(item.context["delivery_status"] == "pending" for item in notifications)
    assert all(item.context["external_anchor_claimed"] is False for item in notifications)
    assert all(item.context["case_version"] in {1, 3} for item in notifications)
    assert all("SuperSecret123" not in item.message for item in notifications)

    deliveries = repository.list_deliveries(page=1, page_size=10)
    items = deliveries[0]
    assert len(items) == 2
    assert all(item.status.value == "pending" for item in items)

    # Low-severity cases never reach a HIGH-minimum rule.
    low = notifier.notify_case_event(_notifier_case(severity="LOW", version=9), "FORENSIC_CASE_OPENED")
    assert low == {
        "considered": 0,
        "queued": 0,
        "duplicate": 0,
        "suppressed": 0,
        "no_rule": 0,
        "failed": 0,
    }
