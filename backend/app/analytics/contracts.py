"""Analytics contracts — shared time ranges, validation, availability (V14).

All analytics endpoints reuse these models. Time windows are UTC-normalized;
naive timestamps are interpreted as UTC (matching existing API conventions)
and documented as such. Every aggregate section reports its own
availability: missing sources are unavailable, never zero.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

from pydantic import BaseModel, field_validator, model_validator

MAX_WINDOW_DAYS = 90
MAX_EXPORT_ROWS = 5000
MAX_WINDOW_ROWS = 5000
MAX_BUCKETS = 744

VALID_BUCKETS = ("hour", "day", "week")


class SectionAvailability(str, Enum):
    OK = "ok"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


class TimeRange(BaseModel):
    """Validated reporting window with UTC-normalized bounds."""

    start_at: datetime | None = None
    end_at: datetime | None = None

    _coerce_start = field_validator("start_at", mode="before")(lambda value: _coerce_utc(value))
    _coerce_end = field_validator("end_at", mode="before")(lambda value: _coerce_utc(value))

    @model_validator(mode="after")
    def _default_and_validate(self) -> TimeRange:
        end = self.end_at or datetime.now(UTC)
        start = self.start_at or (end - timedelta(days=7))
        if start >= end:
            raise ValueError("start_at must be before end_at")
        if (end - start).total_seconds() > MAX_WINDOW_DAYS * 86400:
            raise ValueError(f"time window must not exceed {MAX_WINDOW_DAYS} days")
        # Rejects absurd historical/future bounds that indicate client error.
        if end.year < 2000 or start.year > 2100:
            raise ValueError("time window outside supported range")
        self.start_at = start
        self.end_at = end
        return self


def _coerce_utc(value: Any) -> datetime | None:
    """Parse ISO-8601; naive timestamps are interpreted as UTC (documented)."""
    if value is None or isinstance(value, datetime):
        moment = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"invalid timestamp: {value!r}") from exc
    else:
        raise ValueError(f"invalid timestamp: {value!r}")
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC)


def as_utc(moment: datetime | None) -> datetime | None:
    """Normalize a stored timestamp for comparison (naive assumed UTC)."""
    if moment is None:
        return None
    if moment.tzinfo is None:
        return moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC)


def validate_bucket(bucket: str, start: datetime, end: datetime) -> str:
    """Validate bucket granularity and bound total bucket counts."""
    normalized = str(bucket or "day").strip().lower()
    if normalized not in VALID_BUCKETS:
        raise ValueError(f"bucket must be one of {list(VALID_BUCKETS)}")
    seconds = (end - start).total_seconds()
    hours = seconds / 3600.0
    count = hours if normalized == "hour" else hours / 24.0 if normalized == "day" else hours / 168.0
    if normalized == "hour" and seconds > 31 * 86400:
        raise ValueError("hour buckets support at most a 31-day window (use day)")
    if count > MAX_BUCKETS:
        raise ValueError(f"bucket count {int(count)} exceeds limit {MAX_BUCKETS}")
    return normalized


def bucket_start(moment: datetime, bucket: str) -> datetime:
    """Floor a UTC moment to its bucket boundary (inclusive-start convention)."""
    moment = as_utc(moment) or datetime.now(UTC)
    if bucket == "hour":
        return moment.replace(minute=0, second=0, microsecond=0)
    if bucket == "week":
        start = moment.replace(hour=0, minute=0, second=0, microsecond=0)
        return start - timedelta(days=start.weekday())
    return moment.replace(hour=0, minute=0, second=0, microsecond=0)
