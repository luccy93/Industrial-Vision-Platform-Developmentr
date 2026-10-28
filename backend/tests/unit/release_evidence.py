"""Shared offline builders for V24 deployment, rehearsal, and GPU evidence tests."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from tools.release.identity import release_image_tags
from tools.release.manifest import sha256_file, write_manifest
from tools.release.verification import PASS

PREVIOUS_TAG = "v1.2.2"
PREVIOUS_COMMIT = "b" * 40


def previous_release_manifest(
    tmp_path: Path,
    manifest: dict[str, Any],
) -> tuple[Path, dict[str, Any]]:
    """Build a valid previous manifest with a different commit and image digests."""
    previous = copy.deepcopy(manifest)
    previous["release"]["tag"] = PREVIOUS_TAG
    previous["release"]["commit"] = PREVIOUS_COMMIT
    previous["release"]["workflow_run_url"] = "https://github.com/octo/repo/actions/runs/122"
    previous["release"]["workflow_run_id"] = 122
    previous["build"]["ref"] = f"refs/tags/{PREVIOUS_TAG}"
    for image in previous["images"]:
        digest = "sha256:" + hashlib.sha256(f"previous-{image['name']}".encode()).hexdigest()
        image["digest"] = digest
        image["tags"] = list(release_image_tags(PREVIOUS_TAG, PREVIOUS_COMMIT))
        for field in ("provenance", "sbom_attestation"):
            attestation = image[field]
            attestation["attestation_url"] = (
                f"https://api.github.com/repos/{previous['release']['source_repository']}"
                f"/attestations/{digest}"
            )
            command = (
                f"gh attestation verify oci://{image['repository']}@{digest} "
                f"--repo {previous['release']['source_repository']}"
            )
            if field == "sbom_attestation":
                command += f" --predicate-type {attestation['predicate_type']}"
            attestation["verification_command"] = command
    path = tmp_path / "previous-manifest.json"
    write_manifest(previous, path)
    return path, previous


def write_production_verification_report(
    path: Path,
    manifest_path: Path,
    manifest: dict[str, Any],
    *,
    profile: str = "production",
) -> dict[str, Any]:
    """Write a minimal production verification report bound to *manifest_path*."""
    release = manifest["release"]
    report: dict[str, Any] = {
        "schema_version": 2,
        "profile": profile,
        "generated_at": "2026-10-23T00:00:00Z",
        "manifest_sha256": sha256_file(manifest_path),
        "subject": {
            "tag": release["tag"],
            "commit": release["commit"],
            "source_repository": release["source_repository"],
        },
        "overall_state": PASS,
        "verified": True,
        "production_verified": True,
        "artifact_status": {
            "cpu": {"state": PASS},
            "gpu": {"state": PASS},
        },
        "checks": [],
    }
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    return report
