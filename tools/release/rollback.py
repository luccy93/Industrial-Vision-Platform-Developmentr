"""Rollback prerequisite validation for V28 readiness.

These helpers only read local evidence. They never execute a rollback, touch a
database, delete a volume, or restore a backup.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from tools.release.identity import REQUIRED_IMAGES

MAX_BACKUP_DOCUMENT_BYTES = 1024 * 1024
MIN_BACKUP_DOCUMENT_CHARACTERS = 400
BACKUP_TOPICS = {
    "backup": ("backup", "back up", "snapshot"),
    "restore": ("restore", "recovery", "recover"),
    "postgresql": ("postgres", "postgresql"),
    "redis": ("redis",),
    "volumes": ("volume",),
}


def _digests(manifest: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for image in manifest.get("images") or []:
        if isinstance(image, Mapping) and isinstance(image.get("name"), str):
            result[str(image["name"])] = image.get("digest")
    return result


def previous_digest_errors(
    manifest: Mapping[str, Any],
    previous: Mapping[str, Any],
) -> list[str]:
    """Return every reason the previous release is not a distinct rollback target."""
    problems: list[str] = []
    current = _digests(manifest)
    prior = _digests(previous)
    for name in REQUIRED_IMAGES:
        current_digest = current.get(name)
        previous_digest = prior.get(name)
        if not isinstance(previous_digest, str) or not previous_digest:
            problems.append(f"the previous manifest has no {name} digest")
        elif previous_digest == current_digest:
            problems.append(f"{name} resolves to the same digest in both releases")
    return problems


def backup_documentation_errors(path: Path) -> list[str]:
    """Validate backup and restore documentation without executing anything."""
    if not path.is_file():
        return [f"backup documentation does not exist: {path}"]
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return [f"backup documentation could not be read: {exc}"]
    if len(raw) > MAX_BACKUP_DOCUMENT_BYTES:
        return [f"backup documentation exceeds {MAX_BACKUP_DOCUMENT_BYTES} bytes"]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return ["backup documentation must be UTF-8 text or Markdown"]
    if len(text.strip()) < MIN_BACKUP_DOCUMENT_CHARACTERS:
        return ["backup documentation is too short to describe a real backup and restore procedure"]
    lowered = text.lower()
    missing = [
        topic for topic, markers in BACKUP_TOPICS.items() if not any(marker in lowered for marker in markers)
    ]
    if missing:
        return ["backup documentation does not cover: " + ", ".join(sorted(missing))]
    if "```" not in text and not any(line.lstrip().startswith("#") for line in text.splitlines()):
        return ["backup documentation must include headings or command examples"]
    return []
