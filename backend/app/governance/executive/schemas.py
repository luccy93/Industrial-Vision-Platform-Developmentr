"""Validated request schemas for the V38 executive governance API."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from backend.app.governance.executive.constants import (
    MAX_ACTION_DESCRIPTION_LENGTH,
    MAX_ACTION_OWNER_LENGTH,
    MAX_ACTION_REASON_LENGTH,
    MAX_ACTION_TITLE_LENGTH,
    MAX_REPORT_IDEMPOTENCY_KEY_LENGTH,
    MAX_REPORT_REASON_LENGTH,
    MIN_ACTION_REASON_LENGTH,
    MIN_REPORT_REASON_LENGTH,
)


class ExecutiveActionCreateRequest(BaseModel):
    recommendation_id: str = Field(min_length=1, max_length=36)
    title: str = Field(min_length=3, max_length=MAX_ACTION_TITLE_LENGTH)
    description: str = Field(default="", max_length=MAX_ACTION_DESCRIPTION_LENGTH)
    owner_id: str = Field(min_length=1, max_length=MAX_ACTION_OWNER_LENGTH)
    due_at: datetime
    priority: str = Field(default="MEDIUM", pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    idempotency_key: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=MIN_ACTION_REASON_LENGTH, max_length=MAX_ACTION_REASON_LENGTH)


class ExecutiveActionTransitionRequest(BaseModel):
    target_status: str = Field(pattern="^(IN_PROGRESS|BLOCKED|COMPLETED|CANCELLED)$")
    expected_version: int = Field(ge=1)
    reason: str = Field(default="", max_length=MAX_ACTION_REASON_LENGTH)
    outcome_summary: str = Field(default="", max_length=4000)
    block_reason: str = Field(default="", max_length=2048)
    cancel_reason: str = Field(default="", max_length=2048)


class ExecutiveActionAssignRequest(BaseModel):
    owner_id: str = Field(min_length=1, max_length=MAX_ACTION_OWNER_LENGTH)
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=MIN_ACTION_REASON_LENGTH, max_length=MAX_ACTION_REASON_LENGTH)


class ExecutiveReportGenerateRequest(BaseModel):
    report_type: str = Field(
        pattern="^(EXECUTIVE_SUMMARY|EXECUTIVE_RISK|EXECUTIVE_SLA|EXECUTIVE_OPERATIONS)$"
    )
    format: str = Field(default="json", pattern="^(json|csv)$")
    window_days: int | None = Field(default=None, ge=1, le=90)
    idempotency_key: str = Field(min_length=1, max_length=MAX_REPORT_IDEMPOTENCY_KEY_LENGTH)
    reason: str = Field(min_length=MIN_REPORT_REASON_LENGTH, max_length=MAX_REPORT_REASON_LENGTH)


class ExecutiveConfigUpdateRequest(BaseModel):
    config: dict[str, Any]
    reason: str = Field(min_length=MIN_REPORT_REASON_LENGTH, max_length=MAX_REPORT_REASON_LENGTH)


__all__ = [
    "ExecutiveActionAssignRequest",
    "ExecutiveActionCreateRequest",
    "ExecutiveActionTransitionRequest",
    "ExecutiveConfigUpdateRequest",
    "ExecutiveReportGenerateRequest",
]
