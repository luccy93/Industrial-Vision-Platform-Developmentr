"""V23 publication outcome and partial-failure recovery tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from tools.release.identity import REQUIRED_IMAGES
from tools.release.publication import (
    build_publication_report,
    render_publication_summary,
)

TAG = "v1.2.3"
REPOSITORY = "octo/repo"


def _digest(name: str) -> str:
    return "sha256:" + hashlib.sha256(name.encode()).hexdigest()


def _event(name: str, status: str, **overrides: Any) -> dict[str, Any]:
    event: dict[str, Any] = {
        "image": name,
        "status": status,
        "tag": TAG,
        "repository": f"ghcr.io/{REPOSITORY}/{name}",
        "timestamp": "2026-10-23T00:00:00Z",
    }
    if status == "pushed":
        event["digest"] = _digest(name)
        event["image_id"] = _digest(f"{name}-id")
    event.update(overrides)
    return event


def _write_events(tmp_path: Path, events: list[dict[str, Any]]) -> Path:
    path = tmp_path / "published-images.jsonl"
    path.write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )
    return path


def test_complete_publication_is_reported(tmp_path: Path) -> None:
    path = _write_events(
        tmp_path,
        [_event(name, "push_started") for name in REQUIRED_IMAGES]
        + [_event(name, "pushed") for name in REQUIRED_IMAGES],
    )
    report = build_publication_report(path, tag=TAG, source_repository=REPOSITORY)
    assert report["status"] == "complete"
    assert report["complete"] is True
    assert report["published_images"] == sorted(REQUIRED_IMAGES)
    assert report["unknown_images"] == []
    assert report["missing_images"] == []
    assert report["errors"] == []
    assert "Publication is complete" in " ".join(report["recovery"])


def test_partial_publication_reports_unknown_and_missing(tmp_path: Path) -> None:
    path = _write_events(
        tmp_path,
        [
            _event("api", "push_started"),
            _event("api", "pushed"),
            _event("web", "push_started"),
        ],
    )
    report = build_publication_report(path, tag=TAG, source_repository=REPOSITORY)
    assert report["status"] == "partial"
    assert report["complete"] is False
    assert report["published_images"] == ["api"]
    assert report["unknown_images"] == ["web"]
    assert report["missing_images"] == ["api-gpu"]
    recovery = " ".join(report["recovery"])
    assert "unknown state" in recovery
    assert "next PATCH" in recovery
    assert "previous verified manifest" in recovery
    assert "down -v" in recovery


def test_failed_publication_is_not_success(tmp_path: Path) -> None:
    path = _write_events(tmp_path, [_event("api", "push_started")])
    report = build_publication_report(path, tag=TAG, source_repository=REPOSITORY)
    assert report["status"] == "failed"
    assert report["complete"] is False
    assert report["published_images"] == []
    assert "No image push was proven" in " ".join(report["recovery"])


def test_missing_events_file_is_a_failed_report(tmp_path: Path) -> None:
    report = build_publication_report(
        tmp_path / "missing.jsonl",
        tag=TAG,
        source_repository=REPOSITORY,
    )
    assert report["status"] == "failed"
    assert report["complete"] is False
    assert any("could not read publication events" in error for error in report["errors"])


def test_placeholder_or_malformed_digest_is_rejected(tmp_path: Path) -> None:
    path = _write_events(
        tmp_path,
        [_event(name, "pushed", digest="sha256:" + "0" * 64) for name in REQUIRED_IMAGES],
    )
    report = build_publication_report(path, tag=TAG, source_repository=REPOSITORY)
    assert report["complete"] is False
    assert any("placeholder" in error for error in report["errors"])


def test_conflicting_digests_are_rejected(tmp_path: Path) -> None:
    path = _write_events(
        tmp_path,
        [
            _event("api", "pushed"),
            _event(
                "api",
                "pushed",
                digest="sha256:" + hashlib.sha256(b"other-digest").hexdigest(),
            ),
        ],
    )
    report = build_publication_report(path, tag=TAG, source_repository=REPOSITORY)
    assert report["complete"] is False
    assert any("two different digests" in error for error in report["errors"])


def test_failed_event_after_a_proven_push_is_contradictory(tmp_path: Path) -> None:
    path = _write_events(
        tmp_path,
        [_event(name, "pushed") for name in REQUIRED_IMAGES] + [_event("api", "failed")],
    )
    report = build_publication_report(path, tag=TAG, source_repository=REPOSITORY)
    assert report["complete"] is False
    assert any("failed after a proven push" in error for error in report["errors"])


def test_started_then_failed_is_failed_not_unknown(tmp_path: Path) -> None:
    path = _write_events(
        tmp_path,
        [
            _event("api", "push_started"),
            _event("api", "failed"),
            _event("web", "push_started"),
        ],
    )
    report = build_publication_report(path, tag=TAG, source_repository=REPOSITORY)
    assert report["status"] == "failed"
    assert report["unknown_images"] == ["web"]
    assert report["failed_images"] == ["api"]
    assert report["missing_images"] == ["api-gpu"]
    assert report["complete"] is False


def test_wrong_repository_and_tag_are_rejected(tmp_path: Path) -> None:
    path = _write_events(
        tmp_path,
        [
            _event("api", "pushed", repository="ghcr.io/other/repo/api"),
            _event("web", "pushed", tag="v9.9.9"),
        ],
    )
    report = build_publication_report(path, tag=TAG, source_repository=REPOSITORY)
    assert report["complete"] is False
    assert any("ghcr.io/octo/repo/api" in error for error in report["errors"])
    assert any("does not match the requested tag" in error for error in report["errors"])


def test_invalid_json_line_is_reported(tmp_path: Path) -> None:
    path = tmp_path / "published-images.jsonl"
    path.write_text("{not json}\n", encoding="utf-8")
    report = build_publication_report(path, tag=TAG, source_repository=REPOSITORY)
    assert report["complete"] is False
    assert any("not valid JSON" in error for error in report["errors"])


def test_publication_summary_mentions_status_and_recovery(tmp_path: Path) -> None:
    path = _write_events(tmp_path, [_event("api", "pushed")])
    report = build_publication_report(path, tag=TAG, source_repository=REPOSITORY)
    summary = render_publication_summary(report)
    assert "Publication outcome: partial" in summary
    assert "Published: api" in summary
    assert "Recovery:" in summary
