"""V33 TRUST_STATE scope and honest trust-material overview."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from backend.app.integrity.constants import (
    TRUST_STATE_INVALID,
    TRUST_STATE_NOT_CONFIGURED,
    TRUST_STATE_UNAVAILABLE,
    TRUST_STORE_INVALID,
    TRUST_STORE_UNAVAILABLE,
    AnchorStatus,
    AssuranceLevel,
    IntegrityScope,
    ScopeStatus,
)
from backend.app.integrity.models import (
    Finding,
    TrustOverview,
    safe_artifact_id,
    severity_for_reason,
    utc_now_iso,
)
from backend.app.integrity.verification.base import (
    AuditContext,
    ScopeExecution,
    combine_statuses,
    unavailable,
)
from tools.release import transparency as T
from tools.release.merkle import MerkleError
from tools.release.transparency import TransparencyError
from tools.release.trust import (
    TrustError,
    evaluate_key_status,
    load_trust_state,
    load_trust_store,
)


def _label(path: Path, ctx: AuditContext) -> str:
    return safe_artifact_id(path, roots=ctx.targets.safe_roots) or path.name


def _key_counts(store: Any, now: str) -> dict[str, int]:
    counts = {
        "trusted": 0,
        "active": 0,
        "expired": 0,
        "revoked": 0,
        "unknown": 0,
    }
    for key in getattr(store, "keys", []) or []:
        counts["trusted"] += 1
        try:
            status = evaluate_key_status(key, at=now, policy=str(store.historical_revocation_policy)).status
        except (TrustError, ValueError):
            counts["unknown"] += 1
            continue
        if status == "active":
            counts["active"] += 1
        elif status == "expired":
            counts["expired"] += 1
        elif status.startswith("revoked"):
            counts["revoked"] += 1
        elif status == "not_yet_valid":
            counts["unknown"] += 1
        else:
            counts["unknown"] += 1
    return counts


def verify_trust_state(ctx: AuditContext) -> ScopeExecution:
    """Verify configured trust stores and prior trust states (read-only)."""
    targets = ctx.targets
    configured_states = [
        ("evidence-trust-state", targets.evidence_trust_state),
        ("transparency-trust-state", targets.transparency_trust_state),
    ]
    configured_stores = [
        ("evidence-trust-store", targets.evidence_trust_store),
        ("transparency-trust-store", targets.transparency_trust_store),
    ]
    active_states = [(label, path) for label, path in configured_states if path is not None]
    active_stores = [(label, path) for label, path in configured_stores if path is not None]
    if not active_states and not active_stores:
        return unavailable(
            ctx,
            IntegrityScope.TRUST_STATE,
            TRUST_STATE_NOT_CONFIGURED,
            "no trust store or trust state is configured; replay and rollback protection is unavailable",
            details={"configured": False},
        )

    statuses: list[ScopeStatus] = []
    findings: list[Finding] = []
    codes: set[str] = set()
    checks_total = 0
    checks_failed = 0
    state_details: list[dict[str, Any]] = []
    store_details: list[dict[str, Any]] = []
    now = ctx.now()

    for label, path in active_states:
        ctx.check_budget()
        checks_total += 1
        artifact = _label(path, ctx)
        if not path.exists():
            checks_failed += 1
            statuses.append(ScopeStatus.UNAVAILABLE)
            codes.add(TRUST_STATE_UNAVAILABLE)
            findings.append(
                Finding.create(
                    audit_run_id=ctx.run_id,
                    scope=IntegrityScope.TRUST_STATE,
                    reason_code=TRUST_STATE_UNAVAILABLE,
                    artifact_id=artifact,
                    explanation=f"{label} is configured but missing",
                    severity=severity_for_reason(TRUST_STATE_UNAVAILABLE),
                    detected_at=now,
                )
            )
            state_details.append({"name": label, "artifact_id": artifact, "status": "MISSING"})
            continue
        try:
            if label.startswith("evidence"):
                state = load_trust_state(path)
                entry_count = len(getattr(state, "entries", {}) or {}) if state else 0
                updated_at = getattr(state, "updated_at", None) if state else None
                digest = getattr(state, "state_digest", None) if state else None
            else:
                state = T.load_transparency_state(path)
                entry_count = len(getattr(state, "entries", {}) or {}) if state else 0
                updated_at = getattr(state, "updated_at", None) if state else None
                digest = getattr(state, "state_digest", None) if state else None
        except (TrustError, TransparencyError, MerkleError, OSError, ValueError) as exc:
            checks_failed += 1
            statuses.append(ScopeStatus.FAIL)
            codes.add(TRUST_STATE_INVALID)
            findings.append(
                Finding.create(
                    audit_run_id=ctx.run_id,
                    scope=IntegrityScope.TRUST_STATE,
                    reason_code=TRUST_STATE_INVALID,
                    artifact_id=artifact,
                    explanation=f"{label} is invalid ({type(exc).__name__})",
                    severity=severity_for_reason(TRUST_STATE_INVALID),
                    detected_at=now,
                )
            )
            state_details.append({"name": label, "artifact_id": artifact, "status": "INVALID"})
            continue
        statuses.append(ScopeStatus.PASS)
        state_details.append(
            {
                "name": label,
                "artifact_id": artifact,
                "status": "AVAILABLE",
                "entry_count": entry_count,
                "updated_at": updated_at,
                "state_digest": digest,
            }
        )

    for label, path in active_stores:
        ctx.check_budget()
        checks_total += 1
        artifact = _label(path, ctx)
        if not path.exists():
            checks_failed += 1
            statuses.append(ScopeStatus.UNAVAILABLE)
            codes.add(TRUST_STORE_UNAVAILABLE)
            findings.append(
                Finding.create(
                    audit_run_id=ctx.run_id,
                    scope=IntegrityScope.TRUST_STATE,
                    reason_code=TRUST_STORE_UNAVAILABLE,
                    artifact_id=artifact,
                    explanation=f"{label} is configured but missing",
                    severity=severity_for_reason(TRUST_STORE_UNAVAILABLE),
                    detected_at=now,
                )
            )
            store_details.append({"name": label, "artifact_id": artifact, "status": "MISSING"})
            continue
        try:
            store = load_trust_store(path)
            counts = _key_counts(store, now)
        except (TrustError, OSError, ValueError) as exc:
            checks_failed += 1
            statuses.append(ScopeStatus.FAIL)
            codes.add(TRUST_STORE_INVALID)
            findings.append(
                Finding.create(
                    audit_run_id=ctx.run_id,
                    scope=IntegrityScope.TRUST_STATE,
                    reason_code=TRUST_STORE_INVALID,
                    artifact_id=artifact,
                    explanation=f"{label} is invalid ({type(exc).__name__})",
                    severity=severity_for_reason(TRUST_STORE_INVALID),
                    detected_at=now,
                )
            )
            store_details.append({"name": label, "artifact_id": artifact, "status": "INVALID"})
            continue
        statuses.append(ScopeStatus.PASS)
        store_details.append(
            {
                "name": label,
                "artifact_id": artifact,
                "status": "AVAILABLE",
                "policy_version": getattr(store, "policy_version", None),
                "keys": counts,
            }
        )

    details = {
        "states": state_details,
        "stores": store_details,
        "external_anchor_configured": False,
        "assurance": "local_only",
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
        artifacts_checked=len(active_states) + len(active_stores),
        findings=bounded_findings,
        reason_codes=sorted(codes),
        details=details,
    ).finalize()


def build_trust_overview(
    targets: Any,
    *,
    now: str | None = None,
) -> TrustOverview:
    """Read-only trust summary for the dashboard; never claims external trust."""
    moment = now or utc_now_iso()
    overview = TrustOverview()
    limitations: list[str] = []
    store_counts = {"trusted": 0, "active": 0, "expired": 0, "revoked": 0, "unknown": 0}
    stores_available = 0
    states_available = 0

    for path in (targets.evidence_trust_store, targets.transparency_trust_store):
        if path is None:
            continue
        try:
            store = load_trust_store(path)
            counts = _key_counts(store, moment)
        except (TrustError, OSError, ValueError):
            limitations.append("a configured trust store is missing or invalid")
            continue
        stores_available += 1
        for key, value in counts.items():
            store_counts[key] += int(value)
    overview.trusted_key_count = store_counts["trusted"]
    overview.active_key_count = store_counts["active"]
    overview.expired_key_count = store_counts["expired"]
    overview.revoked_key_count = store_counts["revoked"]
    overview.unknown_key_count = store_counts["unknown"]

    evidence_state = targets.evidence_trust_state
    if evidence_state is None:
        overview.evidence_trust_state = "NOT_CONFIGURED"
        limitations.append("evidence trust state is not configured; replay protection is limited")
    elif not evidence_state.exists():
        overview.evidence_trust_state = "MISSING"
        limitations.append("the configured evidence trust state is missing")
    else:
        try:
            load_trust_state(evidence_state)
        except (TrustError, OSError, ValueError):
            overview.evidence_trust_state = "INVALID"
            limitations.append("the configured evidence trust state is invalid")
        else:
            overview.evidence_trust_state = "AVAILABLE"
            states_available += 1

    transparency_state = targets.transparency_trust_state
    if transparency_state is None:
        overview.transparency_trust_state = "NOT_CONFIGURED"
        limitations.append("transparency trust state is not configured; split-view protection is limited")
    elif not transparency_state.exists():
        overview.transparency_trust_state = "MISSING"
        limitations.append("the configured transparency trust state is missing")
    else:
        try:
            T.load_transparency_state(transparency_state)
        except (TransparencyError, MerkleError, OSError, ValueError):
            overview.transparency_trust_state = "INVALID"
            limitations.append("the configured transparency trust state is invalid")
        else:
            overview.transparency_trust_state = "AVAILABLE"
            states_available += 1

    latest_head = _latest_tree_head(targets)
    if latest_head is not None:
        overview.latest_tree_head_size = int(latest_head.tree_size)
        overview.latest_tree_head_digest = latest_head.merkle_root
        overview.latest_tree_head_id = latest_head.tree_head_id

    receipt_path = targets.receipt
    if receipt_path is None:
        overview.external_anchor_status = AnchorStatus.NOT_CONFIGURED
        overview.external_anchor_detail = (
            "no external transparency provider is configured; all assurance is local"
        )
    elif not receipt_path.exists():
        overview.external_anchor_status = AnchorStatus.UNAVAILABLE
        overview.external_anchor_detail = "the configured anchor receipt is missing"
        limitations.append("the configured anchor receipt is missing")
    else:
        try:
            receipt = T.load_receipt(receipt_path)
        except (TransparencyError, MerkleError, OSError, ValueError):
            overview.external_anchor_status = AnchorStatus.UNAVAILABLE
            overview.external_anchor_detail = "the configured anchor receipt is invalid"
            limitations.append("the configured anchor receipt is invalid")
        else:
            status = str(receipt.anchor_status or "").upper()
            if status == "SIMULATED":
                overview.external_anchor_status = AnchorStatus.SIMULATED
                overview.external_anchor_detail = (
                    "a SIMULATED local-test receipt is present; this is not external anchoring"
                )
            elif status == "EXTERNAL_VERIFIED":
                overview.external_anchor_status = AnchorStatus.UNAVAILABLE
                overview.external_anchor_detail = (
                    "the receipt claims external anchoring but no external provider is configured"
                )
                limitations.append("external anchoring claims cannot be verified offline")
            else:
                overview.external_anchor_status = AnchorStatus.UNAVAILABLE
                overview.external_anchor_detail = "the configured anchor receipt has an unsupported status"

    material_configured = bool(
        targets.evidence_trust_store
        or targets.transparency_trust_store
        or targets.evidence_trust_state
        or targets.transparency_trust_state
        or latest_head is not None
    )
    if material_configured and stores_available and (states_available or latest_head is not None):
        overview.assurance = AssuranceLevel.LOCAL_VERIFIED
    elif material_configured:
        overview.assurance = AssuranceLevel.LOCAL_ONLY
    else:
        overview.assurance = AssuranceLevel.NONE
    limitations.append("V33 runs offline; external anchoring is never claimed")
    overview.limitations = limitations[:20]
    return overview


def _latest_tree_head(targets: Any) -> Any:
    directory = targets.tree_heads_dir
    if directory is None or not directory.is_dir():
        return None
    try:
        files = sorted(
            path for path in directory.iterdir() if path.is_file() and path.suffix.lower() == ".json"
        )[:50]
    except OSError:
        return None
    latest = None
    for path in files:
        try:
            head = T.load_tree_head(path)
        except (TransparencyError, MerkleError, OSError, ValueError):
            continue
        if latest is None or int(head.tree_size) > int(latest.tree_size):
            latest = head
    return latest


__all__ = ["build_trust_overview", "verify_trust_state"]
