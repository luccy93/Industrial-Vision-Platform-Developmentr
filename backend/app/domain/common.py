"""Shared domain primitives."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class EntityBase(BaseModel):
    """Base class for domain entities with identity + audit metadata."""

    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"populate_by_name": True, "use_enum_values": False}
