"""Analytics contract tests — time ranges, buckets, validation (V14)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from backend.app.analytics.contracts import (
    MAX_WINDOW_DAYS,
    TimeRange,
    as_utc,
    bucket_start,
    validate_bucket,
)


def test_defaults_cover_last_7_days() -> None:
    window = TimeRange()
    assert window.start_at is not None and window.end_at is not None
    assert (window.end_at - window.start_at).total_seconds() == pytest.approx(7 * 86400, abs=5)


def test_naive_interpreted_as_utc() -> None:
    window = TimeRange(start_at="2026-01-01T00:00:00", end_at="2026-01-08T00:00:00")  # type: ignore[arg-type]
    assert window.start_at is not None and window.start_at.tzinfo is not None
    assert window.start_at.isoformat() == "2026-01-01T00:00:00+00:00"


def test_z_suffix_and_offsets_normalize() -> None:
    window = TimeRange(start_at="2026-01-01T00:00:00Z", end_at="2026-01-01T04:00:00+02:00")  # type: ignore[arg-type]
    assert window.start_at is not None and window.end_at is not None
    assert window.start_at.isoformat() == "2026-01-01T00:00:00+00:00"
    assert window.end_at.isoformat() == "2026-01-01T02:00:00+00:00"


def test_start_must_precede_end() -> None:
    with pytest.raises(ValidationError):
        TimeRange(start_at="2026-02-01T00:00:00Z", end_at="2026-01-01T00:00:00Z")  # type: ignore[arg-type]


def test_window_capped_at_retention() -> None:
    far = (datetime(2026, 1, 1, tzinfo=UTC) + timedelta(days=MAX_WINDOW_DAYS + 1)).isoformat()
    with pytest.raises(ValidationError):
        TimeRange(start_at="2026-01-01T00:00:00Z", end_at=far)  # type: ignore[arg-type]
    ok_end = (datetime(2026, 1, 1, tzinfo=UTC) + timedelta(days=MAX_WINDOW_DAYS)).isoformat()
    window = TimeRange(start_at="2026-01-01T00:00:00Z", end_at=ok_end)  # type: ignore[arg-type]
    assert window.end_at is not None


def test_malformed_timestamps_rejected() -> None:
    with pytest.raises(ValidationError):
        TimeRange(start_at="not-a-date", end_at="2026-01-02T00:00:00Z")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        TimeRange(start_at=12345, end_at="2026-01-02T00:00:00Z")  # type: ignore[arg-type]


def test_empty_string_means_absent() -> None:
    window = TimeRange(start_at="", end_at="2026-01-08T00:00:00Z")  # type: ignore[arg-type]
    assert window.start_at == datetime(2026, 1, 1, tzinfo=UTC)


def test_bucket_validation_and_caps() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    assert validate_bucket("day", start, start + timedelta(days=7)) == "day"
    assert validate_bucket("HOUR", start, start + timedelta(hours=2)) == "hour"
    with pytest.raises(ValueError):
        validate_bucket("minute", start, start + timedelta(days=1))
    with pytest.raises(ValueError):
        validate_bucket("hour", start, start + timedelta(days=32))


def test_bucket_boundaries_utc_aligned() -> None:
    moment = datetime(2026, 1, 7, 15, 34, 12, tzinfo=UTC)  # a Wednesday
    assert bucket_start(moment, "hour") == datetime(2026, 1, 7, 15, 0, tzinfo=UTC)
    assert bucket_start(moment, "day") == datetime(2026, 1, 7, 0, 0, tzinfo=UTC)
    assert bucket_start(moment, "week") == datetime(2026, 1, 5, 0, 0, tzinfo=UTC)


def test_as_utc_normalizes_naive() -> None:
    assert as_utc(None) is None
    naive = datetime(2026, 1, 1, 12, 0)
    assert as_utc(naive) == datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
