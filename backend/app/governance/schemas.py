"""Validated request schemas for the V35 governance API."""

from __future__ import annotations

from datetime import date
from typing import Any

from pydantic import BaseModel, Field


class PolicyCreateRequest(BaseModel):
    policy_id: str | None = Field(default=None, max_length=64)
    name: str = Field(min_length=1, max_length=128)
    state: str = Field(default="DRAFT", max_length=16)
    case_type: str | None = Field(default=None, max_length=32)
    evidence_category: str | None = Field(default=None, max_length=32)
    retention_days: int | None = Field(default=None, ge=1, le=36500)
    review_interval_days: int | None = Field(default=None, ge=1, le=36500)
    required_approval_level: str = Field(default="SINGLE_REVIEWER", max_length=24)
    export_allowed: bool = True
    export_requires_approval: bool = True
    allow_evidence_bytes: bool = False
    export_expiry_days: int | None = Field(default=None, ge=1, le=36500)
    export_review_days: int | None = Field(default=None, ge=1, le=36500)
    legal_hold_eligible: bool = True
    disposition_review_required: bool = True
    reason: str = Field(min_length=1, max_length=2048)
    idempotency_key: str | None = Field(default=None, max_length=128)


class PolicyUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    state: str | None = Field(default=None, max_length=16)
    case_type: str | None = Field(default=None, max_length=32)
    evidence_category: str | None = Field(default=None, max_length=32)
    retention_days: int | None = Field(default=None, ge=1, le=36500)
    review_interval_days: int | None = Field(default=None, ge=1, le=36500)
    required_approval_level: str | None = Field(default=None, max_length=24)
    export_allowed: bool | None = None
    export_requires_approval: bool | None = None
    allow_evidence_bytes: bool | None = None
    export_expiry_days: int | None = Field(default=None, ge=1, le=36500)
    export_review_days: int | None = Field(default=None, ge=1, le=36500)
    legal_hold_eligible: bool | None = None
    disposition_review_required: bool | None = None
    reason: str = Field(min_length=1, max_length=2048)
    expected_version: int | None = Field(default=None, ge=1)
    idempotency_key: str | None = Field(default=None, max_length=128)


class PolicyStateRequest(BaseModel):
    state: str = Field(min_length=1, max_length=16)
    reason: str = Field(min_length=1, max_length=2048)
    expected_version: int | None = Field(default=None, ge=1)
    idempotency_key: str | None = Field(default=None, max_length=128)


class RetentionEvaluateRequest(BaseModel):
    case_id: str | None = Field(default=None, max_length=36)
    case_ids: list[str] = Field(default_factory=list, max_length=500)
    as_of: date | None = None


class RetentionReviewRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=2048)
    as_of: date | None = None


class LegalHoldCreateRequest(BaseModel):
    case_id: str = Field(min_length=1, max_length=36)
    evidence_reference_id: str | None = Field(default=None, max_length=36)
    scope: str = Field(default="", max_length=2048)
    reason: str = Field(min_length=1, max_length=2048)
    idempotency_key: str | None = Field(default=None, max_length=128)


class LegalHoldActionRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=2048)
    expected_version: int | None = Field(default=None, ge=1)
    idempotency_key: str | None = Field(default=None, max_length=128)


class DispositionCreateRequest(BaseModel):
    case_id: str = Field(min_length=1, max_length=36)
    justification: str = Field(min_length=1, max_length=4096)
    idempotency_key: str | None = Field(default=None, max_length=128)


class DispositionDecisionRequest(BaseModel):
    decision: str = Field(min_length=1, max_length=16)
    reason: str = Field(min_length=1, max_length=2048)
    expected_version: int | None = Field(default=None, ge=1)
    idempotency_key: str | None = Field(default=None, max_length=128)


class DispositionWithdrawRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=2048)
    expected_version: int | None = Field(default=None, ge=1)
    idempotency_key: str | None = Field(default=None, max_length=128)


class ExportApprovalCreateRequest(BaseModel):
    case_id: str = Field(min_length=1, max_length=36)
    include_evidence_bytes: bool = False
    reason: str = Field(min_length=1, max_length=2048)
    idempotency_key: str | None = Field(default=None, max_length=128)


class ExportApprovalActionRequest(BaseModel):
    reason: str = Field(default="", max_length=2048)
    expected_version: int | None = Field(default=None, ge=1)
    idempotency_key: str | None = Field(default=None, max_length=128)


# ---------------------------------------------------------------------------
# V36 governance automation
# ---------------------------------------------------------------------------
class AutomationScheduleUpdateRequest(BaseModel):
    enabled: bool = False
    interval_minutes: int = Field(default=1440, ge=5, le=10080)
    config: dict[str, Any] = Field(default_factory=dict)
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=3, max_length=2048)


class AutomationRunRequest(BaseModel):
    job_type: str = Field(min_length=1, max_length=64)
    idempotency_key: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=3, max_length=2048)


class AutomationActionRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=2048)


class AutomationSnapshotGenerateRequest(BaseModel):
    idempotency_key: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=3, max_length=2048)


__all__ = [
    "AutomationActionRequest",
    "AutomationRunRequest",
    "AutomationScheduleUpdateRequest",
    "AutomationSnapshotGenerateRequest",
    "DispositionCreateRequest",
    "DispositionDecisionRequest",
    "DispositionWithdrawRequest",
    "ExportApprovalActionRequest",
    "ExportApprovalCreateRequest",
    "LegalHoldActionRequest",
    "LegalHoldCreateRequest",
    "PolicyCreateRequest",
    "PolicyStateRequest",
    "PolicyUpdateRequest",
    "RetentionEvaluateRequest",
    "RetentionReviewRequest",
]
