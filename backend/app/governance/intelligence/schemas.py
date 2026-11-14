"""Validated request schemas for the V37 governance intelligence API."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class RiskModelUpdateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    thresholds: dict[str, dict[str, int]] = Field(default_factory=dict)
    factor_points: dict[str, int] | None = None
    effective_from: datetime | None = None
    reason: str = Field(min_length=3, max_length=2048)
    expected_version: int | None = Field(default=None, ge=1)
    idempotency_key: str | None = Field(default=None, max_length=128)


class SlaTargetUpdateRequest(BaseModel):
    target_hours: int = Field(ge=1, le=87600)
    warning_hours: int = Field(ge=1, le=87600)
    effective_from: datetime | None = None
    reason: str = Field(min_length=3, max_length=2048)
    expected_version: int | None = Field(default=None, ge=1)
    idempotency_key: str | None = Field(default=None, max_length=128)


__all__ = ["RiskModelUpdateRequest", "SlaTargetUpdateRequest"]
