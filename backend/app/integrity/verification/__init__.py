"""Read-only scope adapters over the V30-V32 verification tools."""

from __future__ import annotations

from backend.app.integrity.verification.base import (
    AuditContext,
    ScopeExecution,
    combine_statuses,
    evaluate_checks,
)
from backend.app.integrity.verification.checkpoints import verify_signed_checkpoints
from backend.app.integrity.verification.evidence import verify_evidence
from backend.app.integrity.verification.snapshot import capture_inputs
from backend.app.integrity.verification.transparency import (
    verify_consistency_proofs,
    verify_inclusion_proofs,
    verify_transparency_log,
    verify_tree_heads,
)
from backend.app.integrity.verification.trust_state import build_trust_overview, verify_trust_state

__all__ = [
    "AuditContext",
    "ScopeExecution",
    "build_trust_overview",
    "capture_inputs",
    "combine_statuses",
    "evaluate_checks",
    "verify_consistency_proofs",
    "verify_evidence",
    "verify_inclusion_proofs",
    "verify_signed_checkpoints",
    "verify_transparency_log",
    "verify_tree_heads",
    "verify_trust_state",
]
