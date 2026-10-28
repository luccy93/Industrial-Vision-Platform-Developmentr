"""Partial-publication reporting and recovery guidance (V23).

A release can fail after one or more images have already been pushed. The
publication report records exactly which images were proven published, which
were only started, and which are missing, then states the safe recovery path.
It never treats an unproven push as success and never suggests moving or
reusing a release tag.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from tools.release.identity import DIGEST_PATTERN, REQUIRED_IMAGES
from tools.release.manifest import utc_now_iso
from tools.release.verification import is_placeholder_digest

PUBLICATION_SCHEMA_VERSION = 1
EVENT_STATUSES = ("push_started", "pushed", "failed")


class PublicationError(RuntimeError):
    """The publication evidence is malformed or contradictory."""


def _plain_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _event_errors(
    event: Any,
    *,
    expected_images: Sequence[str],
    tag: str | None,
    source_repository: str | None,
) -> list[str]:
    if not isinstance(event, Mapping):
        return ["event must be a JSON object"]
    errors: list[str] = []
    image = event.get("image")
    if image not in expected_images:
        errors.append(f"unknown image {image!r}")
    status = event.get("status")
    if status not in EVENT_STATUSES:
        errors.append(f"status {status!r} is not one of {EVENT_STATUSES}")
    if not _plain_string(event.get("tag")):
        errors.append("tag is missing")
    elif tag is not None and event.get("tag") != tag:
        errors.append(f"tag {event.get('tag')!r} does not match the requested tag {tag!r}")
    repository = event.get("repository")
    if not _plain_string(repository):
        errors.append("repository is missing")
    elif isinstance(image, str) and image in expected_images:
        if source_repository is not None:
            expected_repository = f"ghcr.io/{source_repository.lower()}/{image}"
            if repository != expected_repository:
                errors.append(f"repository {repository!r} is not the expected {expected_repository!r}")
        elif not repository.startswith("ghcr.io/") or not repository.endswith(f"/{image}"):
            errors.append(f"repository {repository!r} is not a GHCR repository for {image}")
    if status == "pushed":
        digest = event.get("digest")
        if not isinstance(digest, str) or DIGEST_PATTERN.fullmatch(digest) is None:
            errors.append("pushed event is missing a valid digest")
        elif is_placeholder_digest(digest):
            errors.append("pushed event digest is a placeholder, not a real artifact")
        image_id = event.get("image_id")
        if image_id is not None and (
            not isinstance(image_id, str) or DIGEST_PATTERN.fullmatch(image_id) is None
        ):
            errors.append("image_id is not a valid digest")
    return errors


def _load_events(
    path: Path,
) -> tuple[list[dict[str, Any]], list[str]]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [], [f"could not read publication events {path}: {exc}"]
    events: list[dict[str, Any]] = []
    errors: list[str] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"line {line_number} is not valid JSON: {exc}")
            continue
        if not isinstance(payload, dict):
            errors.append(f"line {line_number} is not a JSON object")
            continue
        events.append(payload)
    return events, errors


def build_publication_report(
    events_path: Path,
    *,
    tag: str | None = None,
    source_repository: str | None = None,
    expected_images: Sequence[str] = REQUIRED_IMAGES,
    now: Any = utc_now_iso,
) -> dict[str, Any]:
    events, errors = _load_events(events_path)
    expected = list(expected_images)
    published: set[str] = set()
    started: set[str] = set()
    failed: set[str] = set()
    digests: dict[str, str] = {}
    for index, event in enumerate(events, start=1):
        event_errors = _event_errors(
            event,
            expected_images=expected,
            tag=tag,
            source_repository=source_repository,
        )
        if event_errors:
            errors.extend(f"event {index}: {item}" for item in event_errors)
            continue
        image = str(event["image"])
        status = str(event["status"])
        if status == "pushed":
            digest = str(event["digest"])
            if image in digests and digests[image] != digest:
                errors.append(f"event {index}: image {image} was published with two different digests")
                continue
            digests[image] = digest
            published.add(image)
        elif status == "push_started":
            started.add(image)
        elif status == "failed":
            if image in published:
                errors.append(
                    f"event {index}: image {image} failed after a proven push; "
                    "publication state is contradictory"
                )
                continue
            failed.add(image)

    # A started or failed event followed by a proven push is a retry; the push
    # wins. A proven push followed by a later failure is contradictory. An
    # image with a failure event is failed, not unknown; unknown means only a
    # push_started event was recorded.
    unknown = sorted(started - published - failed)
    failed_only = sorted(failed - published)
    missing = sorted(set(expected) - published - started - failed)
    complete = not errors and not missing and not unknown and not failed_only
    if complete:
        status = "complete"
    elif published:
        status = "partial"
    else:
        status = "failed"

    recovery: list[str] = [
        "Never move, delete, or reuse the release tag; the version is consumed.",
        "Do not overwrite tags or digests that were already pushed.",
    ]
    if complete:
        recovery.append(
            "Publication is complete; continue with production verification and the GitHub Release."
        )
    else:
        if unknown:
            recovery.append(
                "Images with only a push_started event are in an unknown state: inspect the GHCR "
                "tag before assuming it is absent, and never overwrite it."
            )
        if published:
            recovery.append(
                "Publish the fix as the next PATCH version; the already-pushed images remain immutable."
            )
        else:
            recovery.append("No image push was proven. Fix the cause and publish the next PATCH version.")
        recovery.append(
            "Keep deployments on the previous verified manifest digests until a complete release exists."
        )
        recovery.append("Never run `docker compose down -v`; it deletes the PostgreSQL volume.")

    return {
        "schema_version": PUBLICATION_SCHEMA_VERSION,
        "generated_at": now(),
        "tag": tag,
        "source_repository": source_repository,
        "expected_images": expected,
        "published_images": sorted(published),
        "unknown_images": unknown,
        "failed_images": failed_only,
        "missing_images": missing,
        "status": status,
        "complete": complete,
        "digests": dict(sorted(digests.items())),
        "events": events,
        "errors": errors,
        "recovery": recovery,
    }


def write_publication_report(report: Mapping[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def render_publication_summary(report: Mapping[str, Any]) -> str:
    lines = [
        f"Publication outcome: {report.get('status')} (complete={report.get('complete')})",
        f"Tag: {report.get('tag')} from {report.get('source_repository')}",
        f"Published: {', '.join(report.get('published_images') or []) or 'none'}",
    ]
    if report.get("unknown_images"):
        lines.append(f"Unknown (push started, no proven digest): {', '.join(report['unknown_images'])}")
    if report.get("failed_images"):
        lines.append(f"Failed: {', '.join(report['failed_images'])}")
    if report.get("missing_images"):
        lines.append(f"Missing: {', '.join(report['missing_images'])}")
    errors = report.get("errors") or []
    if errors:
        lines.append("Evidence errors:")
        lines.extend(f"- {item}" for item in errors)
    lines.append("Recovery:")
    lines.extend(f"- {item}" for item in report.get("recovery") or [])
    return "\n".join(lines) + "\n"
