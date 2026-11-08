"""Read-only before/after snapshots of protected V30-V32 inputs.

The snapshot exists only to detect concurrent modification while an audit is
running. It never writes to the protected trees, never repairs bytes, and
never follows links outside a configured root. Cryptographic verification
itself is delegated to the V30-V32 verifiers.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from backend.app.integrity.models import safe_artifact_id, utc_now_iso
from backend.app.integrity.targets import IntegrityTargets

_HASH_LIMIT_BYTES = 8 * 1024 * 1024
_CHUNK = 1024 * 1024


@dataclass(frozen=True)
class InputSnapshot:
    files: dict[str, tuple[int, str]] = field(default_factory=dict)
    directories: dict[str, tuple[int, int]] = field(default_factory=dict)
    missing: tuple[str, ...] = ()
    unreadable: tuple[str, ...] = ()
    truncated: bool = False
    captured_at: str = ""

    def changes_since(self, other: InputSnapshot) -> list[str]:
        keys = set(self.files) | set(other.files) | set(self.directories) | set(other.directories)
        changed = [
            key
            for key in keys
            if self.files.get(key) != other.files.get(key)
            or self.directories.get(key) != other.directories.get(key)
        ]
        if set(self.missing) != set(other.missing) or set(self.unreadable) != set(other.unreadable):
            changed.append("input-availability")
        if self.truncated != other.truncated:
            changed.append("snapshot-bounds")
        return sorted(set(changed))


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > _HASH_LIMIT_BYTES:
                return f"mtime:{path.stat().st_mtime_ns}"
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _file_key(path: Path, roots: tuple[Path, ...], fallback: str) -> str:
    relative = safe_artifact_id(path, roots=roots)
    if relative and relative not in {".", ""}:
        return relative
    return f"{fallback}/{path.name}"


def _record_file(
    snapshot_files: dict[str, tuple[int, str]],
    missing: list[str],
    unreadable: list[str],
    *,
    path: Path | None,
    roots: tuple[Path, ...],
    fallback: str,
) -> None:
    if path is None:
        return
    key = _file_key(path, roots, fallback)
    try:
        stat = path.lstat()
        if path.is_symlink():
            unreadable.append(key)
            return
        if not path.is_file():
            missing.append(key)
            return
        snapshot_files[key] = (int(stat.st_size), _digest_file(path))
    except FileNotFoundError:
        missing.append(key)
    except OSError:
        unreadable.append(key)


def _walk_directory(
    directory: Path,
    *,
    label: str,
    budget: int,
    snapshot_dirs: dict[str, tuple[int, int]],
    truncated: list[bool],
) -> None:
    if not directory.exists() or not directory.is_dir():
        return
    count = 0
    stack = [directory]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(os.scandir(current), key=lambda entry: entry.name)
        except OSError:
            continue
        for entry in entries:
            if count >= budget:
                truncated[0] = True
                return
            try:
                if entry.is_symlink():
                    count += 1
                    snapshot_dirs[f"{label}/{entry.name}"] = (-1, -1)
                    continue
                if entry.is_dir(follow_symlinks=False):
                    stack.append(Path(entry.path))
                    continue
                stat = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            relative = Path(entry.path).relative_to(directory).as_posix()
            snapshot_dirs[f"{label}/{relative}"] = (int(stat.st_size), int(stat.st_mtime_ns))
            count += 1


def capture_inputs(
    targets: IntegrityTargets,
    *,
    batch_artifacts: int = 500,
    clock: Callable[[], str] = utc_now_iso,
) -> InputSnapshot:
    """Capture bounded metadata for every configured protected input."""
    roots = targets.safe_roots
    budget = max(1, int(batch_artifacts))
    files: dict[str, tuple[int, str]] = {}
    directories: dict[str, tuple[int, int]] = {}
    missing: list[str] = []
    unreadable: list[str] = []
    truncated = [False]

    configured = [
        ("manifest", targets.evidence_manifest),
        ("report", targets.evidence_report),
        ("integrity", targets.evidence_integrity),
        ("audit", targets.evidence_audit),
        ("checkpoint", targets.evidence_checkpoint),
        ("evidence-trust-store", targets.evidence_trust_store),
        ("evidence-trust-state", targets.evidence_trust_state),
        ("transparency-log", targets.transparency_log),
        ("transparency-trust-store", targets.transparency_trust_store),
        ("transparency-trust-state", targets.transparency_trust_state),
        ("receipt", targets.receipt),
    ]
    for label, path in configured:
        _record_file(files, missing, unreadable, path=path, roots=roots, fallback=label)

    directory_inputs = [
        ("evidence", targets.evidence_root),
        ("tree-heads", targets.tree_heads_dir),
        ("inclusion-proofs", targets.inclusion_proofs_dir),
        ("consistency-proofs", targets.consistency_proofs_dir),
    ]
    for label, directory in directory_inputs:
        if directory is None:
            continue
        if not directory.exists() or not directory.is_dir():
            missing.append(f"{label}/")
            continue
        _walk_directory(
            directory,
            label=label,
            budget=budget,
            snapshot_dirs=directories,
            truncated=truncated,
        )

    return InputSnapshot(
        files=files,
        directories=directories,
        missing=tuple(sorted(set(missing))),
        unreadable=tuple(sorted(set(unreadable))),
        truncated=bool(truncated[0]),
        captured_at=clock(),
    )


def snapshot_details(snapshot: InputSnapshot) -> dict[str, Any]:
    """Safe summary for scope details (no absolute paths)."""
    return {
        "files": len(snapshot.files),
        "directories": len(snapshot.directories),
        "missing": list(snapshot.missing[:20]),
        "unreadable": list(snapshot.unreadable[:20]),
        "truncated": snapshot.truncated,
    }


__all__ = ["InputSnapshot", "capture_inputs", "snapshot_details"]
