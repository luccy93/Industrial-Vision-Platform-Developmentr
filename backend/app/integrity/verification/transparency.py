"""V33 transparency scopes: log, signed tree heads, inclusion, consistency.

All cryptography is delegated to the V32 modules. The auditor never appends to
the log, never advances a transparency trust state, never writes a tree head,
and never creates or re-signs a receipt.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from backend.app.integrity.constants import (
    CONSISTENCY_PROOF_INVALID,
    CONSISTENCY_PROOFS_NOT_CONFIGURED,
    INCLUSION_PROOF_INVALID,
    INCLUSION_PROOFS_NOT_CONFIGURED,
    MERKLE_ROOT_CONFLICT,
    RECEIPT_INVALID,
    TRANSPARENCY_LOG_INVALID,
    TRANSPARENCY_LOG_NOT_CONFIGURED,
    TREE_HEAD_INVALID,
    TREE_HEAD_NOT_CONFIGURED,
    TREE_HEAD_TRUST_UNAVAILABLE,
    IntegrityScope,
    ScopeStatus,
    map_reason_code,
)
from backend.app.integrity.errors import AuditCancelledError, AuditTimeoutError
from backend.app.integrity.models import Finding, safe_artifact_id, severity_for_reason
from backend.app.integrity.verification.base import (
    AuditContext,
    ScopeExecution,
    combine_statuses,
    evaluate_checks,
    missing_input,
    unavailable,
)
from tools.release import transparency as T
from tools.release.merkle import MerkleError, verify_consistency_proof, verify_inclusion_proof
from tools.release.transparency import TransparencyError


def _json_files(directory: Path | None) -> list[Path]:
    if directory is None or not directory.is_dir():
        return []
    try:
        return sorted(
            path for path in directory.iterdir() if path.is_file() and path.suffix.lower() == ".json"
        )
    except OSError:
        return []


def _label(path: Path, ctx: AuditContext) -> str:
    return safe_artifact_id(path, roots=ctx.targets.safe_roots) or path.name


def _load_tree_head_index(ctx: AuditContext) -> dict[tuple[str, int], Any]:
    files, _ = ctx.bounded(_json_files(ctx.targets.tree_heads_dir))
    index: dict[tuple[str, int], Any] = {}
    for path in files:
        try:
            head = T.load_tree_head(path)
        except (TransparencyError, MerkleError, OSError, ValueError):
            continue
        index[(str(head.log_id), int(head.tree_size))] = head
    return index


def _log_entries(ctx: AuditContext) -> tuple[dict[tuple[str, int], bytes] | None, bool]:
    """Return ``(entries, configured)``; entries is None when unreadable."""
    path = ctx.targets.transparency_log
    if path is None:
        return None, False
    try:
        log = T.read_log(path)
    except (TransparencyError, MerkleError, OSError, ValueError):
        return None, True
    entries = {(str(log.log_id), int(entry.entry_index)): entry.canonical_bytes() for entry in log.entries}
    return entries, True


def verify_transparency_log(ctx: AuditContext) -> ScopeExecution:
    targets = ctx.targets
    if targets.transparency_log is None:
        return unavailable(
            ctx,
            IntegrityScope.TRANSPARENCY_LOG,
            TRANSPARENCY_LOG_NOT_CONFIGURED,
            "no transparency log is configured; log integrity was not verified",
            details={"configured": False},
        )
    ctx.check_budget()
    try:
        result = T.verify_log(targets.transparency_log)
    except (AuditCancelledError, AuditTimeoutError):
        raise
    except (TransparencyError, MerkleError, OSError, ValueError) as exc:
        return missing_input(
            ctx,
            IntegrityScope.TRANSPARENCY_LOG,
            TRANSPARENCY_LOG_INVALID,
            f"transparency log verification could not run ({type(exc).__name__})",
            artifact_id=_label(targets.transparency_log, ctx),
        )
    evaluation = evaluate_checks(
        ctx,
        IntegrityScope.TRANSPARENCY_LOG,
        result.checks,
        outcome=result.outcome,
        reason_codes=result.reason_codes,
        default_reason=TRANSPARENCY_LOG_INVALID,
        artifact_id=_label(targets.transparency_log, ctx),
    )
    details = {
        "log_id": result.log_id,
        "tree_size": result.tree_size,
        "merkle_root": result.merkle_root,
        "head_entry_digest": result.head_entry_digest,
        "limitations": [str(item)[:300] for item in result.limitations[:20]],
    }
    findings = list(evaluation.findings)
    if len(findings) > ctx.max_findings:
        findings = findings[: ctx.max_findings]
        details["findings_truncated"] = True
    return ScopeExecution(
        status=evaluation.status,
        checks_total=evaluation.checks_total,
        checks_failed=evaluation.checks_failed,
        artifacts_checked=len(result.entries),
        findings=findings,
        reason_codes=evaluation.reason_codes,
        details=details,
    ).finalize()


def verify_tree_heads(ctx: AuditContext) -> ScopeExecution:
    targets = ctx.targets
    directory = targets.tree_heads_dir
    if directory is None:
        return unavailable(
            ctx,
            IntegrityScope.TREE_HEADS,
            TREE_HEAD_NOT_CONFIGURED,
            "no signed tree-head directory is configured; tree heads were not verified",
            details={"configured": False},
        )
    if not directory.is_dir():
        return missing_input(
            ctx,
            IntegrityScope.TREE_HEADS,
            TREE_HEAD_NOT_CONFIGURED,
            "the configured tree-head directory is missing or unreadable",
            artifact_id="tree-heads",
        )
    files, truncated = ctx.bounded(_json_files(directory))
    if not files:
        return unavailable(
            ctx,
            IntegrityScope.TREE_HEADS,
            TREE_HEAD_NOT_CONFIGURED,
            "the configured tree-head directory contains no tree heads",
            details={"configured": True, "count": 0},
        )

    statuses: list[ScopeStatus] = []
    findings: list[Finding] = []
    codes: set[str] = set()
    checks_total = 0
    checks_failed = 0
    heads: list[Any] = []
    head_details: list[dict[str, Any]] = []

    for path in files:
        ctx.check_budget()
        label = _label(path, ctx)
        try:
            head = T.load_tree_head(path)
        except (TransparencyError, MerkleError, OSError, ValueError) as exc:
            statuses.append(ScopeStatus.FAIL)
            checks_total += 1
            checks_failed += 1
            codes.add(TREE_HEAD_INVALID)
            findings.append(
                Finding.create(
                    audit_run_id=ctx.run_id,
                    scope=IntegrityScope.TREE_HEADS,
                    reason_code=TREE_HEAD_INVALID,
                    artifact_id=label,
                    explanation=f"tree head could not be loaded ({type(exc).__name__})",
                    severity=severity_for_reason(TREE_HEAD_INVALID),
                    detected_at=ctx.now(),
                )
            )
            head_details.append({"artifact_id": label, "outcome": "INVALID"})
            continue
        heads.append(head)
        try:
            result = T.verify_tree_head(
                head,
                trust_store_path=targets.transparency_trust_store,
                trusted_key_fingerprint=targets.tree_head_trusted_fingerprint,
                trust_state_path=targets.transparency_trust_state,
                update_trust_state=False,
            )
        except (AuditCancelledError, AuditTimeoutError):
            raise
        except (TransparencyError, MerkleError, OSError, ValueError) as exc:
            statuses.append(ScopeStatus.FAIL)
            checks_total += 1
            checks_failed += 1
            codes.add(TREE_HEAD_INVALID)
            findings.append(
                Finding.create(
                    audit_run_id=ctx.run_id,
                    scope=IntegrityScope.TREE_HEADS,
                    reason_code=TREE_HEAD_INVALID,
                    artifact_id=label,
                    explanation=f"tree-head verification failed ({type(exc).__name__})",
                    severity=severity_for_reason(TREE_HEAD_INVALID),
                    detected_at=ctx.now(),
                )
            )
            head_details.append({"artifact_id": label, "outcome": "INVALID"})
            continue
        evaluation = evaluate_checks(
            ctx,
            IntegrityScope.TREE_HEADS,
            result.checks,
            outcome=result.outcome,
            reason_codes=result.reason_codes,
            default_reason=TREE_HEAD_INVALID,
            artifact_id=label,
        )
        statuses.append(evaluation.status)
        findings.extend(evaluation.findings)
        codes.update(evaluation.reason_codes)
        checks_total += evaluation.checks_total
        checks_failed += evaluation.checks_failed
        head_details.append(
            {
                "artifact_id": label,
                "tree_head_id": head.tree_head_id,
                "log_id": head.log_id,
                "tree_size": head.tree_size,
                "merkle_root": head.merkle_root,
                "timestamp": head.timestamp,
                "outcome": str(result.outcome).upper(),
                "assurance": result.assurance,
            }
        )

    split_view = "NOT_EVALUATED"
    if heads:
        try:
            split = T.detect_split_view(heads)
        except (TransparencyError, MerkleError, ValueError) as exc:
            split_view = "UNAVAILABLE"
            codes.add(TREE_HEAD_TRUST_UNAVAILABLE)
            findings.append(
                Finding.create(
                    audit_run_id=ctx.run_id,
                    scope=IntegrityScope.TREE_HEADS,
                    reason_code=TREE_HEAD_TRUST_UNAVAILABLE,
                    explanation=f"split-view comparison could not run ({type(exc).__name__})",
                    severity=severity_for_reason(TREE_HEAD_TRUST_UNAVAILABLE),
                    detected_at=ctx.now(),
                )
            )
            statuses.append(ScopeStatus.UNAVAILABLE)
        else:
            split_view = str(split.outcome).upper()
            if split_view == "FAIL":
                reason = map_reason_code(
                    split.reason_code or "TREE_HEAD_INVALID", scope=IntegrityScope.TREE_HEADS
                )
                if reason not in {MERKLE_ROOT_CONFLICT, TREE_HEAD_INVALID}:
                    reason = TREE_HEAD_INVALID
                codes.add(reason)
                statuses.append(ScopeStatus.FAIL)
                findings.append(
                    Finding.create(
                        audit_run_id=ctx.run_id,
                        scope=IntegrityScope.TREE_HEADS,
                        reason_code=reason,
                        explanation=str(split.detail or "conflicting tree heads were observed"),
                        severity=severity_for_reason(reason),
                        detected_at=ctx.now(),
                    )
                )

    external_anchor: dict[str, Any] = {
        "configured": False,
        "status": "NOT_CONFIGURED",
        "detail": "no external transparency provider is configured; V33 never claims external anchoring",
    }
    if targets.receipt is not None:
        receipt_label = _label(targets.receipt, ctx)
        if not targets.receipt.exists():
            statuses.append(ScopeStatus.UNAVAILABLE)
            codes.add(RECEIPT_INVALID)
            findings.append(
                Finding.create(
                    audit_run_id=ctx.run_id,
                    scope=IntegrityScope.TREE_HEADS,
                    reason_code=RECEIPT_INVALID,
                    artifact_id=receipt_label,
                    explanation="the configured anchor receipt is missing",
                    severity=severity_for_reason(RECEIPT_INVALID),
                    detected_at=ctx.now(),
                )
            )
        else:
            try:
                receipt = T.load_receipt(targets.receipt)
                matched_head = next(
                    (head for head in heads if head.tree_head_id == receipt.tree_head_id),
                    None,
                )
                if matched_head is None:
                    matched_head = next(
                        (
                            head
                            for head in heads
                            if head.log_id == receipt.log_id and head.tree_size == receipt.tree_size
                        ),
                        None,
                    )
                receipt_result = T.verify_receipt(
                    receipt,
                    tree_head=matched_head,
                    now=ctx.now(),
                    external_provider_configured=False,
                )
            except (AuditCancelledError, AuditTimeoutError):
                raise
            except (TransparencyError, MerkleError, OSError, ValueError) as exc:
                statuses.append(ScopeStatus.FAIL)
                codes.add(RECEIPT_INVALID)
                findings.append(
                    Finding.create(
                        audit_run_id=ctx.run_id,
                        scope=IntegrityScope.TREE_HEADS,
                        reason_code=RECEIPT_INVALID,
                        artifact_id=receipt_label,
                        explanation=f"anchor receipt could not be verified ({type(exc).__name__})",
                        severity=severity_for_reason(RECEIPT_INVALID),
                        detected_at=ctx.now(),
                    )
                )
            else:
                evaluation = evaluate_checks(
                    ctx,
                    IntegrityScope.TREE_HEADS,
                    receipt_result.checks,
                    outcome=receipt_result.outcome,
                    reason_codes=receipt_result.reason_codes,
                    default_reason=RECEIPT_INVALID,
                    artifact_id=receipt_label,
                )
                statuses.append(evaluation.status)
                findings.extend(evaluation.findings)
                codes.update(evaluation.reason_codes)
                checks_total += evaluation.checks_total
                checks_failed += evaluation.checks_failed
                anchor_status = str(receipt_result.anchor_status or "UNAVAILABLE").upper()
                external_anchor = {
                    "configured": False,
                    "status": anchor_status,
                    "provider_id": receipt.provider_id,
                    "assurance": receipt_result.assurance,
                    "detail": (
                        "a SIMULATED local-test receipt is not external anchoring"
                        if anchor_status == "SIMULATED"
                        else "no external transparency provider is configured"
                    ),
                }

    latest = max(heads, key=lambda head: int(head.tree_size), default=None)
    details = {
        "count": len(files),
        "truncated": truncated,
        "heads": head_details[:50],
        "split_view": split_view,
        "external_anchor": external_anchor,
        "latest_tree_size": int(latest.tree_size) if latest is not None else None,
        "latest_tree_head_id": latest.tree_head_id if latest is not None else None,
        "latest_merkle_root": latest.merkle_root if latest is not None else None,
    }
    unique: dict[str, Finding] = {}
    for finding in findings:
        unique.setdefault(finding.finding_id, finding)
    bounded_findings = list(unique.values())
    if len(bounded_findings) > ctx.max_findings:
        bounded_findings = bounded_findings[: ctx.max_findings]
        details["findings_truncated"] = True
    return ScopeExecution(
        status=combine_statuses(statuses),
        checks_total=checks_total,
        checks_failed=checks_failed,
        artifacts_checked=len(files),
        findings=bounded_findings,
        reason_codes=sorted(codes),
        details=details,
        truncated=truncated,
    ).finalize()


def verify_inclusion_proofs(ctx: AuditContext) -> ScopeExecution:
    targets = ctx.targets
    directory = targets.inclusion_proofs_dir
    if directory is None:
        return unavailable(
            ctx,
            IntegrityScope.INCLUSION_PROOFS,
            INCLUSION_PROOFS_NOT_CONFIGURED,
            "no inclusion-proof directory is configured; inclusion was not verified",
            details={"configured": False},
        )
    if not directory.is_dir():
        return missing_input(
            ctx,
            IntegrityScope.INCLUSION_PROOFS,
            INCLUSION_PROOFS_NOT_CONFIGURED,
            "the configured inclusion-proof directory is missing or unreadable",
            artifact_id="inclusion-proofs",
        )
    files, truncated = ctx.bounded(_json_files(directory))
    if not files:
        return unavailable(
            ctx,
            IntegrityScope.INCLUSION_PROOFS,
            INCLUSION_PROOFS_NOT_CONFIGURED,
            "the configured inclusion-proof directory contains no proofs",
            details={"configured": True, "count": 0},
        )

    head_index = _load_tree_head_index(ctx)
    entries, log_configured = _log_entries(ctx)
    statuses: list[ScopeStatus] = []
    findings: list[Finding] = []
    codes: set[str] = set()
    checks_total = 0
    checks_failed = 0
    proof_details: list[dict[str, Any]] = []

    for path in files:
        ctx.check_budget()
        label = _label(path, ctx)
        try:
            proof = T.load_inclusion_proof(path)
        except (TransparencyError, MerkleError, OSError, ValueError) as exc:
            statuses.append(ScopeStatus.FAIL)
            checks_total += 1
            checks_failed += 1
            codes.add(INCLUSION_PROOF_INVALID)
            findings.append(
                Finding.create(
                    audit_run_id=ctx.run_id,
                    scope=IntegrityScope.INCLUSION_PROOFS,
                    reason_code=INCLUSION_PROOF_INVALID,
                    artifact_id=label,
                    explanation=f"inclusion proof could not be loaded ({type(exc).__name__})",
                    severity=severity_for_reason(INCLUSION_PROOF_INVALID),
                    detected_at=ctx.now(),
                )
            )
            proof_details.append({"artifact_id": label, "outcome": "INVALID"})
            continue

        head = head_index.get((str(proof.log_id), int(proof.tree_size)))
        expected_root = head.merkle_root if head is not None else proof.root
        leaf_bytes = None
        if entries is not None:
            leaf_bytes = entries.get((str(proof.log_id), int(proof.leaf_index)))
        try:
            result = verify_inclusion_proof(
                proof,
                expected_root=expected_root,
                expected_log_id=proof.log_id,
                expected_tree_size=proof.tree_size,
                leaf_bytes=leaf_bytes,
            )
        except (AuditCancelledError, AuditTimeoutError):
            raise
        except (MerkleError, ValueError) as exc:
            statuses.append(ScopeStatus.FAIL)
            checks_total += 1
            checks_failed += 1
            codes.add(INCLUSION_PROOF_INVALID)
            findings.append(
                Finding.create(
                    audit_run_id=ctx.run_id,
                    scope=IntegrityScope.INCLUSION_PROOFS,
                    reason_code=INCLUSION_PROOF_INVALID,
                    artifact_id=label,
                    explanation=f"inclusion proof verification failed ({type(exc).__name__})",
                    severity=severity_for_reason(INCLUSION_PROOF_INVALID),
                    detected_at=ctx.now(),
                )
            )
            proof_details.append({"artifact_id": label, "outcome": "INVALID"})
            continue

        evaluation = evaluate_checks(
            ctx,
            IntegrityScope.INCLUSION_PROOFS,
            result.checks,
            outcome=result.outcome,
            reason_codes=result.reason_codes,
            default_reason=INCLUSION_PROOF_INVALID,
            artifact_id=label,
        )
        status = evaluation.status
        checks_total += evaluation.checks_total
        checks_failed += evaluation.checks_failed
        codes.update(evaluation.reason_codes)
        findings.extend(evaluation.findings)

        if status is ScopeStatus.PASS and head is None:
            status = ScopeStatus.PARTIAL
            codes.add(TREE_HEAD_TRUST_UNAVAILABLE)
        if entries is None and log_configured:
            status = ScopeStatus.PARTIAL if status is ScopeStatus.PASS else status
            codes.add(TREE_HEAD_TRUST_UNAVAILABLE)
        statuses.append(status)
        proof_details.append(
            {
                "artifact_id": label,
                "log_id": proof.log_id,
                "tree_size": proof.tree_size,
                "leaf_index": proof.leaf_index,
                "outcome": str(result.outcome).upper(),
                "bound_to_tree_head": head is not None,
                "leaf_bytes_checked": leaf_bytes is not None,
            }
        )

    details = {
        "count": len(files),
        "truncated": truncated,
        "proofs": proof_details[:50],
        "log_configured": log_configured,
        "tree_heads_configured": bool(head_index),
    }
    unique: dict[str, Finding] = {}
    for finding in findings:
        unique.setdefault(finding.finding_id, finding)
    bounded_findings = list(unique.values())
    if len(bounded_findings) > ctx.max_findings:
        bounded_findings = bounded_findings[: ctx.max_findings]
        details["findings_truncated"] = True
    return ScopeExecution(
        status=combine_statuses(statuses),
        checks_total=checks_total,
        checks_failed=checks_failed,
        artifacts_checked=len(files),
        findings=bounded_findings,
        reason_codes=sorted(codes),
        details=details,
        truncated=truncated,
    ).finalize()


def verify_consistency_proofs(ctx: AuditContext) -> ScopeExecution:
    targets = ctx.targets
    directory = targets.consistency_proofs_dir
    if directory is None:
        return unavailable(
            ctx,
            IntegrityScope.CONSISTENCY_PROOFS,
            CONSISTENCY_PROOFS_NOT_CONFIGURED,
            "no consistency-proof directory is configured; consistency was not verified",
            details={"configured": False},
        )
    if not directory.is_dir():
        return missing_input(
            ctx,
            IntegrityScope.CONSISTENCY_PROOFS,
            CONSISTENCY_PROOFS_NOT_CONFIGURED,
            "the configured consistency-proof directory is missing or unreadable",
            artifact_id="consistency-proofs",
        )
    files, truncated = ctx.bounded(_json_files(directory))
    if not files:
        return unavailable(
            ctx,
            IntegrityScope.CONSISTENCY_PROOFS,
            CONSISTENCY_PROOFS_NOT_CONFIGURED,
            "the configured consistency-proof directory contains no proofs",
            details={"configured": True, "count": 0},
        )

    head_index = _load_tree_head_index(ctx)
    statuses: list[ScopeStatus] = []
    findings: list[Finding] = []
    codes: set[str] = set()
    checks_total = 0
    checks_failed = 0
    proof_details: list[dict[str, Any]] = []

    for path in files:
        ctx.check_budget()
        label = _label(path, ctx)
        try:
            proof = T.load_consistency_proof(path)
        except (TransparencyError, MerkleError, OSError, ValueError) as exc:
            statuses.append(ScopeStatus.FAIL)
            checks_total += 1
            checks_failed += 1
            codes.add(CONSISTENCY_PROOF_INVALID)
            findings.append(
                Finding.create(
                    audit_run_id=ctx.run_id,
                    scope=IntegrityScope.CONSISTENCY_PROOFS,
                    reason_code=CONSISTENCY_PROOF_INVALID,
                    artifact_id=label,
                    explanation=f"consistency proof could not be loaded ({type(exc).__name__})",
                    severity=severity_for_reason(CONSISTENCY_PROOF_INVALID),
                    detected_at=ctx.now(),
                )
            )
            proof_details.append({"artifact_id": label, "outcome": "INVALID"})
            continue

        old_head = head_index.get((str(proof.log_id), int(proof.old_tree_size)))
        new_head = head_index.get((str(proof.log_id), int(proof.new_tree_size)))
        expected_old_root = old_head.merkle_root if old_head is not None else proof.old_root
        expected_new_root = new_head.merkle_root if new_head is not None else proof.new_root
        try:
            result = verify_consistency_proof(
                proof,
                expected_old_root=expected_old_root,
                expected_new_root=expected_new_root,
                expected_log_id=proof.log_id,
                expected_old_tree_size=proof.old_tree_size,
                expected_new_tree_size=proof.new_tree_size,
            )
        except (AuditCancelledError, AuditTimeoutError):
            raise
        except (MerkleError, ValueError) as exc:
            statuses.append(ScopeStatus.FAIL)
            checks_total += 1
            checks_failed += 1
            codes.add(CONSISTENCY_PROOF_INVALID)
            findings.append(
                Finding.create(
                    audit_run_id=ctx.run_id,
                    scope=IntegrityScope.CONSISTENCY_PROOFS,
                    reason_code=CONSISTENCY_PROOF_INVALID,
                    artifact_id=label,
                    explanation=f"consistency proof verification failed ({type(exc).__name__})",
                    severity=severity_for_reason(CONSISTENCY_PROOF_INVALID),
                    detected_at=ctx.now(),
                )
            )
            proof_details.append({"artifact_id": label, "outcome": "INVALID"})
            continue

        evaluation = evaluate_checks(
            ctx,
            IntegrityScope.CONSISTENCY_PROOFS,
            result.checks,
            outcome=result.outcome,
            reason_codes=result.reason_codes,
            default_reason=CONSISTENCY_PROOF_INVALID,
            artifact_id=label,
        )
        status = evaluation.status
        checks_total += evaluation.checks_total
        checks_failed += evaluation.checks_failed
        codes.update(evaluation.reason_codes)
        findings.extend(evaluation.findings)
        if status is ScopeStatus.PASS and (old_head is None or new_head is None):
            status = ScopeStatus.PARTIAL
            codes.add(TREE_HEAD_TRUST_UNAVAILABLE)
        statuses.append(status)
        proof_details.append(
            {
                "artifact_id": label,
                "log_id": proof.log_id,
                "old_tree_size": proof.old_tree_size,
                "new_tree_size": proof.new_tree_size,
                "outcome": str(result.outcome).upper(),
                "bound_to_tree_heads": old_head is not None and new_head is not None,
            }
        )

    details = {
        "count": len(files),
        "truncated": truncated,
        "proofs": proof_details[:50],
        "tree_heads_configured": bool(head_index),
    }
    unique: dict[str, Finding] = {}
    for finding in findings:
        unique.setdefault(finding.finding_id, finding)
    bounded_findings = list(unique.values())
    if len(bounded_findings) > ctx.max_findings:
        bounded_findings = bounded_findings[: ctx.max_findings]
        details["findings_truncated"] = True
    return ScopeExecution(
        status=combine_statuses(statuses),
        checks_total=checks_total,
        checks_failed=checks_failed,
        artifacts_checked=len(files),
        findings=bounded_findings,
        reason_codes=sorted(codes),
        details=details,
        truncated=truncated,
    ).finalize()


__all__ = [
    "verify_consistency_proofs",
    "verify_inclusion_proofs",
    "verify_transparency_log",
    "verify_tree_heads",
]
