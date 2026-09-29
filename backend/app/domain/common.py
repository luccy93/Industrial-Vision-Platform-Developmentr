"""Shared domain primitives."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(UTC)


class EntityBase(BaseModel):
    """Base class for domain entities with identity + audit metadata."""

    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"populate_by_name": True, "use_enum_values": False}
