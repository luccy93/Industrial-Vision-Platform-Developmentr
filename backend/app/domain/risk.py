"""Risk assessment contract."""

from __future__ import annotations

from enum import Enum

from pydantic import Field

from backend.app.domain.common import EntityBase


class RiskLevel(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class RiskAssessment(EntityBase):
    camera_id: str | None = Field(default=None, max_length=128)
    class_name: str | None = Field(default=None, max_length=128)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    risk_score: float = Field(ge=0.0, le=1.0)
    risk_level: RiskLevel = RiskLevel.low
    rationale: str | None = Field(default=None, max_length=2048)
