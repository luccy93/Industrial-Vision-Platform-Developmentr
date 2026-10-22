"""Release manifest construction and validation (V22).

The manifest is the immutable record attached to a GitHub Release: which tag,
commit, images, digests, scans, SBOMs, and attestations were actually
produced. Validation is deliberately strict and fail-closed: an absent or
malformed field blocks publication instead of degrading the record.

The authoritative validation lives here. ``release/release-manifest.schema.json``
documents the same shape for external consumers; tests assert the two do not
drift.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from tools.release.identity import (
    DIGEST_PATTERN,
    REQUIRED_IMAGES,
    IdentityError,
    image_repository,
    release_image_tags,
    validate_commit,
    validate_digest,
    validate_source_repository,
    validate_tag,
)

SCHEMA_VERSION = 1

TOP_LEVEL_FIELDS = ("schema_version", "release", "build", "images", "variants")
RELEASE_FIELDS = (
    "tag",
    "commit",
    "source_repository",
    "workflow_run_url",
    "workflow_run_id",
    "workflow_run_attempt",
    "created_at",
)
BUILD_FIELDS = ("workflow", "event", "ref", "builder")
IMAGE_FIELDS = (
    "name",
    "repository",
    "digest",
    "tags",
    "image_id",
    "pulled_image_id",
    "platform",
    "size_bytes",
    "sbom",
    "scan",
    "provenance",
    "sbom_attestation",
)
SBOM_FIELDS = ("format", "path", "sha256")
SCAN_FIELDS = ("tool", "version", "severity", "ignore_unfixed", "result", "target", "log")
EVIDENCE_FIELDS = ("path", "sha256")
ATTESTATION_FIELDS = (
    "mechanism",
    "predicate_type",
    "attestation_url",
    "verification_command",
    "evidence",
)
VARIANT_FIELDS = ("image", "published", "runtime_smoke", "runtime_smoke_reason")

ALLOWED_PLATFORMS = ("linux/amd64", "linux/arm64")
SCAN_SEVERITY = "CRITICAL,HIGH"
SCAN_TOOL = "trivy"
SBOM_FORMAT = "spdx-json"
PROVENANCE_MECHANISM = "github-artifact-attestation"
PROVENANCE_PREDICATE = "https://slsa.dev/provenance/v1"
SBOM_PREDICATE = "https://spdx.dev/Document"
WORKFLOW_PATTERN = r"^\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml$"


class ManifestError(ValueError):
    """The release manifest is incomplete, inconsistent, or unverifiable."""


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def canonical_json(manifest: Mapping[str, Any]) -> str:
    """Serialize deterministically so the manifest hash is reproducible."""
    return json.dumps(manifest, indent=2, sort_keys=True) + "\n"


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ManifestError(f"could not read manifest {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ManifestError(f"manifest {path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ManifestError("release manifest must be a JSON object")
    return payload


def write_manifest(manifest: Mapping[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_json(manifest), encoding="utf-8", newline="\n")


def _check_keys(value: Any, expected: Sequence[str], label: str, errors: list[str]) -> bool:
    if not isinstance(value, dict):
        errors.append(f"{label} must be an object")
        return False
    missing = sorted(set(expected) - set(value))
    unknown = sorted(set(value) - set(expected))
    if missing:
        errors.append(f"{label} is missing required fields: {', '.join(missing)}")
    if unknown:
        errors.append(f"{label} has unknown fields: {', '.join(unknown)}")
    return True


def _positive_int(value: Any, label: str, errors: list[str]) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        errors.append(f"{label} must be a positive integer")
        return None
    return value


def _validate_timestamp(value: Any, label: str, errors: list[str]) -> None:
    if not isinstance(value, str):
        errors.append(f"{label} must be an ISO-8601 UTC timestamp")
        return
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        errors.append(f"{label} must use YYYY-MM-DDTHH:MM:SSZ")


def _plain_file_name(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and "/" not in value
        and "\\" not in value
        and value not in {".", ".."}
    )


def _validate_evidence(
    value: Any,
    label: str,
    errors: list[str],
    artifacts_dir: Path | None,
    *,
    allowed_extra: Sequence[str] = (),
) -> None:
    if not _check_keys(value, (*EVIDENCE_FIELDS, *allowed_extra), label, errors):
        return
    path = value.get("path")
    digest = value.get("sha256")
    if not _plain_file_name(path):
        errors.append(f"{label}.path must be a plain file name inside the artifacts directory")
        return
    if not isinstance(digest, str) or DIGEST_PATTERN.fullmatch(digest) is None:
        errors.append(f"{label}.sha256 must be a sha256 digest")
        return
    if artifacts_dir is None:
        return
    candidate = artifacts_dir / path
    if not candidate.is_file():
        errors.append(f"{label}.path does not exist under the artifacts directory: {path}")
    elif sha256_file(candidate) != digest:
        errors.append(f"{label}.sha256 does not match the artifact: {path}")


def manifest_errors(
    manifest: Any,
    *,
    artifacts_dir: Path | None = None,
    expected_tag: str | None = None,
    expected_commit: str | None = None,
) -> list[str]:
    """Return every validation problem; an empty list means publishable."""
    errors: list[str] = []
    if not isinstance(manifest, dict):
        return ["release manifest must be a JSON object"]

    _check_keys(manifest, TOP_LEVEL_FIELDS, "manifest", errors)
    if manifest.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION}")

    tag: str | None = None
    commit: str | None = None
    source_repository: str | None = None

    release = manifest.get("release")
    if _check_keys(release, RELEASE_FIELDS, "release", errors):
        raw_tag = release.get("tag")
        if isinstance(raw_tag, str):
            try:
                tag = validate_tag(raw_tag)
            except IdentityError as exc:
                errors.append(f"release.tag: {exc}")
        else:
            errors.append("release.tag must be a string")

        raw_commit = release.get("commit")
        if isinstance(raw_commit, str):
            try:
                commit = validate_commit(raw_commit)
            except IdentityError as exc:
                errors.append(f"release.commit: {exc}")
        else:
            errors.append("release.commit must be a string")

        raw_source = release.get("source_repository")
        if isinstance(raw_source, str):
            try:
                source_repository = validate_source_repository(raw_source)
            except IdentityError as exc:
                errors.append(f"release.source_repository: {exc}")
        else:
            errors.append("release.source_repository must be a string")

        run_id = _positive_int(release.get("workflow_run_id"), "release.workflow_run_id", errors)
        _positive_int(release.get("workflow_run_attempt"), "release.workflow_run_attempt", errors)
        run_url = release.get("workflow_run_url")
        if not isinstance(run_url, str) or not run_url.startswith(
            f"https://github.com/{source_repository or ''}/actions/runs/"
        ):
            errors.append("release.workflow_run_url must reference this repository's Actions run")
        elif run_id is not None and not run_url.endswith(f"/{run_id}"):
            errors.append("release.workflow_run_url must end with workflow_run_id")
        _validate_timestamp(release.get("created_at"), "release.created_at", errors)

    build = manifest.get("build")
    if _check_keys(build, BUILD_FIELDS, "build", errors):
        workflow = build.get("workflow")
        if not isinstance(workflow, str) or re.fullmatch(WORKFLOW_PATTERN, workflow) is None:
            errors.append("build.workflow must be a workflow file under .github/workflows")
        if build.get("event") != "push":
            errors.append("build.event must be 'push'")
        if tag is not None and build.get("ref") != f"refs/tags/{tag}":
            errors.append("build.ref must be refs/tags/<release tag>")
        if build.get("builder") != "docker build":
            errors.append("build.builder must be 'docker build'")

    images = manifest.get("images")
    seen: list[str] = []
    if not isinstance(images, list):
        errors.append("images must be an array")
    else:
        if len(images) != len(REQUIRED_IMAGES):
            errors.append(f"images must contain exactly {len(REQUIRED_IMAGES)} entries")
        for index, image in enumerate(images):
            label = f"images[{index}]"
            if not _check_keys(image, IMAGE_FIELDS, label, errors):
                continue
            name = image.get("name")
            if name not in REQUIRED_IMAGES:
                errors.append(f"{label}.name must be one of {', '.join(REQUIRED_IMAGES)}")
            else:
                seen.append(name)

            digest: str | None = None
            try:
                digest = validate_digest(image.get("digest"))
            except IdentityError as exc:
                errors.append(f"{label}.digest: {exc}")

            expected_repository = None
            if source_repository is not None and name in REQUIRED_IMAGES:
                expected_repository = image_repository(source_repository, str(name))
                if image.get("repository") != expected_repository:
                    errors.append(f"{label}.repository must be {expected_repository}")

            if tag is not None and commit is not None:
                expected_tags = set(release_image_tags(tag, commit))
                received_tags = image.get("tags")
                if not isinstance(received_tags, list) or not all(
                    isinstance(item, str) for item in received_tags
                ):
                    errors.append(f"{label}.tags must be an array of strings")
                elif set(received_tags) != expected_tags or len(received_tags) != len(expected_tags):
                    errors.append(
                        f"{label}.tags must be exactly {sorted(expected_tags)} (no mutable aliases)"
                    )

            image_id: str | None = None
            try:
                image_id = validate_digest(image.get("image_id"))
            except IdentityError as exc:
                errors.append(f"{label}.image_id: {exc}")
            pulled_image_id: str | None = None
            try:
                pulled_image_id = validate_digest(image.get("pulled_image_id"))
            except IdentityError as exc:
                errors.append(f"{label}.pulled_image_id: {exc}")
            if image_id is not None and pulled_image_id is not None and image_id != pulled_image_id:
                errors.append(f"{label} digest pull proof failed: locally built and pulled image IDs differ")

            if image.get("platform") not in ALLOWED_PLATFORMS:
                errors.append(f"{label}.platform must be one of {', '.join(ALLOWED_PLATFORMS)}")
            if isinstance(image.get("size_bytes"), bool) or not isinstance(image.get("size_bytes"), int):
                errors.append(f"{label}.size_bytes must be a positive integer")
            elif image["size_bytes"] < 1:
                errors.append(f"{label}.size_bytes must be a positive integer")

            sbom = image.get("sbom")
            if _check_keys(sbom, SBOM_FIELDS, f"{label}.sbom", errors):
                if sbom.get("format") != SBOM_FORMAT:
                    errors.append(f"{label}.sbom.format must be {SBOM_FORMAT}")
                _validate_evidence(
                    sbom,
                    f"{label}.sbom",
                    errors,
                    artifacts_dir,
                    allowed_extra=("format",),
                )

            scan = image.get("scan")
            if _check_keys(scan, SCAN_FIELDS, f"{label}.scan", errors):
                if scan.get("tool") != SCAN_TOOL:
                    errors.append(f"{label}.scan.tool must be {SCAN_TOOL}")
                if not isinstance(scan.get("version"), str) or not scan["version"].strip():
                    errors.append(f"{label}.scan.version must record the scanner version")
                if scan.get("severity") != SCAN_SEVERITY:
                    errors.append(f"{label}.scan.severity must be {SCAN_SEVERITY}")
                if scan.get("ignore_unfixed") is not True:
                    errors.append(f"{label}.scan.ignore_unfixed must be true")
                if scan.get("result") != "clean":
                    errors.append(f"{label}.scan.result must be 'clean' (publication is fail-closed)")
                if scan.get("target") != "image":
                    errors.append(f"{label}.scan.target must be 'image'")
                _validate_evidence(scan.get("log"), f"{label}.scan.log", errors, artifacts_dir)

            for field, predicate, predicate_flag in (
                ("provenance", PROVENANCE_PREDICATE, False),
                ("sbom_attestation", SBOM_PREDICATE, True),
            ):
                attestation = image.get(field)
                attestation_label = f"{label}.{field}"
                if not _check_keys(attestation, ATTESTATION_FIELDS, attestation_label, errors):
                    continue
                if attestation.get("mechanism") != PROVENANCE_MECHANISM:
                    errors.append(f"{attestation_label}.mechanism must be {PROVENANCE_MECHANISM}")
                if attestation.get("predicate_type") != predicate:
                    errors.append(f"{attestation_label}.predicate_type must be {predicate}")
                if expected_repository is not None and digest is not None:
                    expected_url = f"https://api.github.com/repos/{source_repository}/attestations/{digest}"
                    if attestation.get("attestation_url") != expected_url:
                        errors.append(f"{attestation_label}.attestation_url must be {expected_url}")
                    expected_command = (
                        f"gh attestation verify oci://{expected_repository}@{digest} "
                        f"--repo {source_repository}"
                    )
                    if predicate_flag:
                        expected_command += f" --predicate-type {predicate}"
                    if attestation.get("verification_command") != expected_command:
                        errors.append(f"{attestation_label}.verification_command must be {expected_command}")
                _validate_evidence(
                    attestation.get("evidence"), f"{attestation_label}.evidence", errors, artifacts_dir
                )

    if len(seen) != len(set(seen)) or set(seen) != set(REQUIRED_IMAGES):
        missing = sorted(set(REQUIRED_IMAGES) - set(seen))
        if missing:
            errors.append(f"images is missing required artifacts: {', '.join(missing)}")
        if len(seen) != len(set(seen)):
            errors.append("images contains duplicate image names")

    variants = manifest.get("variants")
    if _check_keys(variants, ("gpu",), "variants", errors):
        gpu = variants.get("gpu")
        if _check_keys(gpu, VARIANT_FIELDS, "variants.gpu", errors):
            if gpu.get("image") != "api-gpu":
                errors.append("variants.gpu.image must be api-gpu")
            if gpu.get("published") is not True:
                errors.append("variants.gpu.published must be true for a stable release")
            runtime_smoke = gpu.get("runtime_smoke")
            reason = gpu.get("runtime_smoke_reason")
            if runtime_smoke not in {"passed", "not_run"}:
                errors.append("variants.gpu.runtime_smoke must be 'passed' or 'not_run'")
            if not isinstance(reason, str):
                errors.append("variants.gpu.runtime_smoke_reason must be a string")
            elif runtime_smoke == "not_run" and not reason.strip():
                errors.append("variants.gpu.runtime_smoke_reason is required when runtime smoke is not_run")
            if "api-gpu" not in seen:
                errors.append("variants.gpu.published=true requires the api-gpu image entry")

    if expected_tag is not None and tag != expected_tag:
        errors.append(f"manifest tag {tag!r} does not match expected tag {expected_tag!r}")
    if expected_commit is not None and commit != expected_commit:
        errors.append(f"manifest commit {commit!r} does not match expected commit {expected_commit!r}")

    return errors


def validate_manifest(
    manifest: Any,
    *,
    artifacts_dir: Path | None = None,
    expected_tag: str | None = None,
    expected_commit: str | None = None,
) -> None:
    errors = manifest_errors(
        manifest,
        artifacts_dir=artifacts_dir,
        expected_tag=expected_tag,
        expected_commit=expected_commit,
    )
    if errors:
        raise ManifestError("release manifest is invalid:\n- " + "\n- ".join(errors))


def _input_string(inputs: Mapping[str, Any], field: str) -> str:
    value = inputs.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ManifestError(f"release inputs are missing a non-empty string field: {field}")
    return value


def _input_int(inputs: Mapping[str, Any], field: str) -> int:
    value = inputs.get(field)
    if isinstance(value, str) and value.isdigit():
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ManifestError(f"release inputs field {field} must be a positive integer")
    return value


def _input_artifact(inputs: Mapping[str, Any], field: str, artifacts_dir: Path) -> tuple[str, str]:
    name = _input_string(inputs, field)
    if not _plain_file_name(name):
        raise ManifestError(f"release inputs field {field} must be a plain file name")
    path = artifacts_dir / name
    if not path.is_file():
        raise ManifestError(f"release artifact not found for {field}: {name}")
    return name, sha256_file(path)


def build_manifest(inputs: Mapping[str, Any], artifacts_dir: Path) -> dict[str, Any]:
    """Build and validate the canonical manifest from workflow-collected facts.

    ``inputs`` is produced by the release workflow from observed build, scan,
    and push results. Nothing is inferred from wishful defaults: any missing
    fact raises instead of producing an incomplete provenance record.
    """
    if not isinstance(inputs, Mapping):
        raise ManifestError("release inputs must be a JSON object")

    tag = validate_tag(_input_string(inputs, "tag"))
    commit = validate_commit(_input_string(inputs, "commit"))
    source_repository = validate_source_repository(_input_string(inputs, "source_repository"))
    workflow = _input_string(inputs, "workflow")
    created_at = inputs.get("created_at") or utc_now_iso()
    if not isinstance(created_at, str):
        raise ManifestError("release inputs field created_at must be a string")

    raw_images = inputs.get("images")
    if not isinstance(raw_images, list):
        raise ManifestError("release inputs must include an images array")
    by_name: dict[str, Mapping[str, Any]] = {}
    for entry in raw_images:
        if not isinstance(entry, Mapping):
            raise ManifestError("each release input image must be an object")
        name = entry.get("name")
        if name not in REQUIRED_IMAGES:
            raise ManifestError(f"release input image name is invalid: {name!r}")
        if name in by_name:
            raise ManifestError(f"release input contains a duplicate image: {name}")
        by_name[name] = entry
    missing = sorted(set(REQUIRED_IMAGES) - set(by_name))
    if missing:
        raise ManifestError(f"release inputs are missing images: {', '.join(missing)}")

    images: list[dict[str, Any]] = []
    for name in REQUIRED_IMAGES:
        entry = by_name[name]
        repository = image_repository(source_repository, name)
        digest = validate_digest(_input_string(entry, "digest"))
        image_id = validate_digest(_input_string(entry, "image_id"))
        pulled_image_id = validate_digest(_input_string(entry, "pulled_image_id"))
        platform = _input_string(entry, "platform")
        if platform not in ALLOWED_PLATFORMS:
            raise ManifestError(f"release input image {name} has unsupported platform {platform!r}")
        size_bytes = _input_int(entry, "size_bytes")
        sbom_path, sbom_sha = _input_artifact(entry, "sbom_file", artifacts_dir)
        scan_log_path, scan_log_sha = _input_artifact(entry, "scan_log_file", artifacts_dir)
        provenance_path, provenance_sha = _input_artifact(entry, "provenance_bundle_file", artifacts_dir)
        sbom_attestation_path, sbom_attestation_sha = _input_artifact(
            entry, "sbom_attestation_bundle_file", artifacts_dir
        )

        attestation_url = f"https://api.github.com/repos/{source_repository}/attestations/{digest}"
        verification_command = f"gh attestation verify oci://{repository}@{digest} --repo {source_repository}"
        sbom_verification_command = f"{verification_command} --predicate-type {SBOM_PREDICATE}"

        images.append(
            {
                "name": name,
                "repository": repository,
                "digest": digest,
                "tags": list(release_image_tags(tag, commit)),
                "image_id": image_id,
                "pulled_image_id": pulled_image_id,
                "platform": platform,
                "size_bytes": size_bytes,
                "sbom": {"format": SBOM_FORMAT, "path": sbom_path, "sha256": sbom_sha},
                "scan": {
                    "tool": SCAN_TOOL,
                    "version": _input_string(entry, "scan_version"),
                    "severity": SCAN_SEVERITY,
                    "ignore_unfixed": True,
                    "result": "clean",
                    "target": "image",
                    "log": {"path": scan_log_path, "sha256": scan_log_sha},
                },
                "provenance": {
                    "mechanism": PROVENANCE_MECHANISM,
                    "predicate_type": PROVENANCE_PREDICATE,
                    "attestation_url": attestation_url,
                    "verification_command": verification_command,
                    "evidence": {"path": provenance_path, "sha256": provenance_sha},
                },
                "sbom_attestation": {
                    "mechanism": PROVENANCE_MECHANISM,
                    "predicate_type": SBOM_PREDICATE,
                    "attestation_url": attestation_url,
                    "verification_command": sbom_verification_command,
                    "evidence": {
                        "path": sbom_attestation_path,
                        "sha256": sbom_attestation_sha,
                    },
                },
            }
        )

    gpu_runtime_smoke = _input_string(inputs, "gpu_runtime_smoke")
    gpu_runtime_reason = inputs.get("gpu_runtime_smoke_reason", "")
    if not isinstance(gpu_runtime_reason, str):
        raise ManifestError("release inputs field gpu_runtime_smoke_reason must be a string")

    manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "release": {
            "tag": tag,
            "commit": commit,
            "source_repository": source_repository,
            "workflow_run_url": _input_string(inputs, "workflow_run_url"),
            "workflow_run_id": _input_int(inputs, "workflow_run_id"),
            "workflow_run_attempt": _input_int(inputs, "workflow_run_attempt"),
            "created_at": created_at,
        },
        "build": {
            "workflow": workflow,
            "event": "push",
            "ref": f"refs/tags/{tag}",
            "builder": "docker build",
        },
        "images": images,
        "variants": {
            "gpu": {
                "image": "api-gpu",
                "published": True,
                "runtime_smoke": gpu_runtime_smoke,
                "runtime_smoke_reason": gpu_runtime_reason,
            }
        },
    }

    validate_manifest(manifest, artifacts_dir=artifacts_dir, expected_tag=tag, expected_commit=commit)
    return manifest
