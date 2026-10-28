"""Live release qualification and production-readiness evidence (V24).

Qualification is the final, independent gate between "the release pipeline
finished" and "this exact release may be deployed". It consumes the immutable
manifest, the V23 verification report, the publication report, and, for
deployment scopes, deployment, rollback-rehearsal, and GPU-runtime evidence.
Every input is bound by SHA-256 so a report cannot be reused for different
manifest bytes, a different tag, commit, or repository.

Nothing here upgrades unavailable evidence to success. ``qualified`` is true
only when every required check is ``PASS``; ``production_qualified`` additionally
requires the ``production_qualification`` profile, ``full`` scope, a V23
production verification, a GPU deployment, an executed rollback rehearsal with
hash-verifiable evidence, and verified container-level GPU runtime.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from tools.release.deployment import DEPLOYMENT_SCHEMA_VERSION
from tools.release.gpu import GPU_SCHEMA_VERSION
from tools.release.identity import (
    DIGEST_PATTERN,
    REQUIRED_IMAGES,
    IdentityError,
    validate_commit,
    validate_source_repository,
    validate_tag,
    verify_tag_commit,
)
from tools.release.manifest import (
    ManifestError,
    load_manifest,
    manifest_errors,
    sha256_file,
    utc_now_iso,
)
from tools.release.rehearsal import REHEARSAL_SCHEMA_VERSION, STEP_NAMES
from tools.release.verification import (
    FAIL,
    NOT_RUN,
    PASS,
    SIMULATED,
    UNAVAILABLE,
    VERIFICATION_SCHEMA_VERSION,
)

QUALIFICATION_SCHEMA_VERSION = 1
QUALIFICATION_PROFILES = ("local_validation", "staging_qualification", "production_qualification")
SCOPES = ("artifact", "deployment", "full")
DEPLOYMENT_REQUIRED_CHECKS = (
    "manifest-digests",
    "compose-config",
    "verification-report",
    "preflight",
    "running-service:api",
    "running-service:web",
    "running-image:api",
    "running-image:web",
)
REHEARSAL_REQUIRED_CHECKS = (
    "target-manifest",
    "previous-manifest",
    "distinct-release",
    "execution",
    *STEP_NAMES,
)
GPU_REQUIRED_CHECKS = (
    "gpu-image",
    "execution",
    "nvidia-smi",
    "docker-cli",
    "docker-runtime",
    "gpu-container",
)

QUALIFICATION_CHECK_FIELDS = ("name", "state", "required", "detail", "command")
EVIDENCE_STATES = (PASS, FAIL, NOT_RUN, UNAVAILABLE, SIMULATED)
DEPLOYMENT_SCOPES = ("deployment", "full")
REQUIRED_PUBLICATION_IMAGES = frozenset(REQUIRED_IMAGES)

SUBJECT_FIELDS = ("tag", "commit", "source_repository")
CHECK_FIELDS = QUALIFICATION_CHECK_FIELDS
EVIDENCE_FIELDS = ("kind", "path", "sha256")
ARTIFACT_FIELDS = ("name", "digest", "sbom", "scan", "provenance", "sbom_attestation", "state")
QUALIFICATION_FIELDS = (
    "schema_version",
    "profile",
    "scope",
    "generated_at",
    "manifest_sha256",
    "subject",
    "overall_state",
    "qualified",
    "production_qualified",
    "verification",
    "publication",
    "deployment",
    "rehearsal",
    "gpu_runtime",
    "artifacts",
    "checks",
    "evidence",
    "blockers",
    "limitations",
)


class QualificationError(RuntimeError):
    """The requested qualification could not be performed."""


CommandRunner = Callable[..., subprocess.CompletedProcess[str]]
IdentityVerifier = Callable[..., None]


def _check(
    name: str,
    state: str,
    required: bool,
    detail: str,
    command: str | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "state": state,
        "required": required,
        "detail": detail,
        "command": command,
    }


def _plain_file_name(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and "/" not in value
        and "\\" not in value
        and value not in {".", ".."}
    )


def _load_json_object(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        return None, f"could not read {path}: {exc}"
    except json.JSONDecodeError as exc:
        return None, f"{path} is not valid JSON: {exc}"
    if not isinstance(payload, dict):
        return None, f"{path} must contain a JSON object"
    return payload, None


def _required_checks_errors(
    payload: Mapping[str, Any],
    label: str,
    required_names: Sequence[str],
) -> list[str]:
    checks = payload.get("checks")
    if not isinstance(checks, list):
        return [f"{label} checks are missing"]
    expected = set(required_names)
    errors: list[str] = []
    by_name: dict[str, Mapping[str, Any]] = {}
    for item in checks:
        if not isinstance(item, Mapping) or not isinstance(item.get("name"), str):
            errors.append(f"{label} contains a malformed check")
            continue
        by_name[item["name"]] = item
        if item.get("required") is True and item.get("state") != PASS and item["name"] not in expected:
            errors.append(f"{label} required check {item['name']} is {item.get('state')!r}, not PASS")
    for name in required_names:
        item = by_name.get(name)
        if item is None:
            errors.append(f"{label} has no {name} check")
        elif item.get("state") != PASS:
            errors.append(f"{label} check {name} is {item.get('state')!r}, not PASS")
    return errors


def _evidence_errors(
    payload: Mapping[str, Any],
    report_path: Path,
    label: str,
) -> list[str]:
    evidence = payload.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        return [f"{label} evidence is missing"]
    errors: list[str] = []
    for item in evidence:
        if not isinstance(item, Mapping):
            errors.append(f"{label} evidence contains a malformed entry")
            continue
        name = item.get("path")
        digest = item.get("sha256")
        if not _plain_file_name(name):
            errors.append(f"{label} evidence path is invalid")
            continue
        if not isinstance(digest, str) or DIGEST_PATTERN.fullmatch(digest) is None:
            errors.append(f"{label} evidence hash is invalid")
            continue
        evidence_path = report_path.parent / str(name)
        if not evidence_path.is_file():
            errors.append(f"{label} evidence file is missing: {name}")
            continue
        try:
            actual = sha256_file(evidence_path)
        except OSError as exc:
            errors.append(f"{label} evidence file could not be hashed: {exc}")
            continue
        if actual != digest:
            errors.append(f"{label} evidence hash does not match {name}")
    return errors


def _binding_evidence_errors(
    report: Mapping[str, Any],
    kind: str,
    binding: Mapping[str, Any],
) -> list[str]:
    evidence = report.get("evidence")
    if not isinstance(evidence, list):
        return [f"qualification report has no {kind} evidence"]
    matching = [item for item in evidence if isinstance(item, Mapping) and item.get("kind") == kind]
    if not matching:
        return [f"qualification report has no {kind} evidence"]
    if not any(
        item.get("sha256") == binding.get("sha256") and item.get("path") == binding.get("path")
        for item in matching
    ):
        return [f"qualification {kind} evidence does not match its binding"]
    return []


def _aggregate(checks: Sequence[Mapping[str, Any]]) -> str:
    states = {str(check.get("state")) for check in checks}
    required_states = {str(check.get("state")) for check in checks if check.get("required") is True}
    if FAIL in states:
        return FAIL
    if SIMULATED in states:
        return SIMULATED
    if UNAVAILABLE in required_states:
        return UNAVAILABLE
    if NOT_RUN in required_states:
        return NOT_RUN
    return PASS


def _combine(states: Sequence[str], errors: Sequence[str] = ()) -> str:
    if errors or FAIL in states:
        return FAIL
    if SIMULATED in states:
        return SIMULATED
    if UNAVAILABLE in states:
        return UNAVAILABLE
    if NOT_RUN in states:
        return NOT_RUN
    if any(state != PASS for state in states):
        return FAIL
    return PASS


def _subject(manifest: Mapping[str, Any]) -> dict[str, Any]:
    release = manifest.get("release")
    if not isinstance(release, Mapping):
        return {"tag": None, "commit": None, "source_repository": None}
    return {
        "tag": release.get("tag"),
        "commit": release.get("commit"),
        "source_repository": release.get("source_repository"),
    }


def _subject_errors(
    subject: Any,
    manifest: Mapping[str, Any],
) -> list[str]:
    release = manifest.get("release") if isinstance(manifest.get("release"), Mapping) else {}
    if not isinstance(subject, Mapping):
        return ["subject is missing"]
    return [
        f"subject.{field} does not match the manifest release"
        for field in ("tag", "commit", "source_repository")
        if subject.get(field) != release.get(field)
    ]


def _evidence_binding(
    artifacts_dir: Path,
    record: Any,
    kind: str,
) -> tuple[dict[str, Any] | None, list[str]]:
    if not isinstance(record, Mapping):
        return None, [f"{kind} evidence record is missing"]
    path = record.get("path")
    expected = record.get("sha256")
    if not _plain_file_name(path):
        return None, [f"{kind} evidence path is not a plain file name"]
    candidate = artifacts_dir / path
    if not candidate.is_file():
        return None, [f"{kind} evidence file does not exist: {path}"]
    try:
        actual = sha256_file(candidate)
    except OSError as exc:
        return None, [f"could not hash {kind} evidence {path}: {exc}"]
    binding = {"kind": kind, "path": path, "sha256": actual}
    if expected != actual:
        return binding, [f"{kind} evidence hash mismatch for {path}: expected {expected}, got {actual}"]
    return binding, []


def _verification_binding(
    path: Path | None,
    manifest: Mapping[str, Any],
    manifest_sha: str,
    *,
    require_production: bool,
) -> tuple[dict[str, Any] | None, list[str]]:
    if path is None:
        return None, ["a verification report is required for qualification"]
    payload, error = _load_json_object(path)
    if payload is None:
        return None, [error or "verification report is unreadable"]
    errors: list[str] = []
    if payload.get("schema_version") != VERIFICATION_SCHEMA_VERSION:
        errors.append(f"verification report schema_version must be {VERIFICATION_SCHEMA_VERSION}")
    if payload.get("manifest_sha256") != manifest_sha:
        errors.append("verification report is not bound to the supplied manifest (manifest_sha256 mismatch)")
    errors.extend(_subject_errors(payload.get("subject"), manifest))
    if payload.get("overall_state") != PASS:
        errors.append(f"verification report overall_state is {payload.get('overall_state')!r}, not PASS")
    if payload.get("verified") is not True:
        errors.append("verification report verified is not true")
    artifact_status = payload.get("artifact_status")
    if not isinstance(artifact_status, Mapping):
        errors.append("verification report artifact_status is missing")
    else:
        for variant in ("cpu", "gpu"):
            status = artifact_status.get(variant)
            if not isinstance(status, Mapping):
                errors.append(f"verification report artifact_status.{variant} is missing")
            elif status.get("state") != PASS:
                errors.append(
                    f"verification report artifact_status.{variant}.state is "
                    f"{status.get('state')!r}, not PASS"
                )
    if require_production:
        if payload.get("profile") != "production":
            errors.append("verification report profile must be 'production'")
        if payload.get("production_verified") is not True:
            errors.append("verification report production_verified is not true")
    elif payload.get("profile") == "production" and payload.get("production_verified") is not True:
        errors.append("production verification report is internally inconsistent")
    try:
        report_sha = sha256_file(path)
    except OSError as exc:
        errors.append(f"could not hash verification report {path}: {exc}")
        report_sha = None
    binding = {
        "path": path.name,
        "sha256": report_sha,
        "manifest_sha256": payload.get("manifest_sha256"),
        "schema_version": payload.get("schema_version"),
        "profile": payload.get("profile"),
        "overall_state": payload.get("overall_state"),
        "verified": payload.get("verified"),
        "production_verified": payload.get("production_verified"),
    }
    return binding, errors


def _publication_binding(
    path: Path | None,
    manifest: Mapping[str, Any],
) -> tuple[dict[str, Any] | None, list[str]]:
    if path is None:
        return None, ["a publication report is required for live evidence"]
    payload, error = _load_json_object(path)
    if payload is None:
        return None, [error or "publication report is unreadable"]
    errors: list[str] = []
    if payload.get("schema_version") != 1:
        errors.append("publication report schema_version must be 1")
    if payload.get("complete") is not True or payload.get("status") != "complete":
        errors.append("publication report does not prove a complete publication")
    release = manifest.get("release") if isinstance(manifest.get("release"), Mapping) else {}
    if payload.get("tag") != release.get("tag"):
        errors.append("publication report tag does not match the manifest release")
    if payload.get("source_repository") != release.get("source_repository"):
        errors.append("publication report source_repository does not match the manifest release")
    expected_images = payload.get("expected_images")
    if not isinstance(expected_images, list) or set(expected_images) != REQUIRED_PUBLICATION_IMAGES:
        errors.append("publication report expected_images does not match the required images")
    published_images = payload.get("published_images")
    if not isinstance(published_images, list) or set(published_images) != REQUIRED_PUBLICATION_IMAGES:
        errors.append("publication report does not prove every required image was published")
    digests = payload.get("digests")
    images = {
        image.get("name"): image.get("digest")
        for image in manifest.get("images") or []
        if isinstance(image, Mapping)
    }
    if not isinstance(digests, Mapping):
        errors.append("publication report digests are missing")
    else:
        for name in REQUIRED_IMAGES:
            if digests.get(name) != images.get(name):
                errors.append(f"publication report digest for {name} does not match the manifest")
    if payload.get("errors"):
        errors.append("publication report records evidence errors")
    try:
        report_sha = sha256_file(path)
    except OSError as exc:
        errors.append(f"could not hash publication report {path}: {exc}")
        report_sha = None
    binding = {
        "path": path.name,
        "sha256": report_sha,
        "status": payload.get("status"),
        "complete": payload.get("complete"),
        "tag": payload.get("tag"),
        "source_repository": payload.get("source_repository"),
        "digests": dict(digests) if isinstance(digests, Mapping) else None,
    }
    return binding, errors


def _deployment_binding(
    path: Path | None,
    manifest: Mapping[str, Any],
    manifest_sha: str,
    *,
    require_gpu: bool = False,
) -> tuple[dict[str, Any] | None, list[str]]:
    if path is None:
        return None, ["a deployment verification report is required for this scope"]
    payload, error = _load_json_object(path)
    if payload is None:
        return None, [error or "deployment report is unreadable"]
    errors: list[str] = []
    if payload.get("schema_version") != DEPLOYMENT_SCHEMA_VERSION:
        errors.append(f"deployment report schema_version must be {DEPLOYMENT_SCHEMA_VERSION}")
    if payload.get("manifest_sha256") != manifest_sha:
        errors.append("deployment report is not bound to the supplied manifest (manifest_sha256 mismatch)")
    errors.extend(_subject_errors(payload.get("subject"), manifest))
    if payload.get("state") != PASS:
        errors.append(f"deployment report state is {payload.get('state')!r}, not PASS")
    gpu = payload.get("gpu")
    if not isinstance(gpu, bool):
        errors.append("deployment report gpu flag is missing")
    elif require_gpu and gpu is not True:
        errors.append("deployment report does not prove a GPU deployment")
    errors.extend(_required_checks_errors(payload, "deployment report", DEPLOYMENT_REQUIRED_CHECKS))
    try:
        report_sha = sha256_file(path)
    except OSError as exc:
        errors.append(f"could not hash deployment report {path}: {exc}")
        report_sha = None
    binding = {
        "path": path.name,
        "sha256": report_sha,
        "manifest_sha256": payload.get("manifest_sha256"),
        "state": payload.get("state"),
        "gpu": gpu,
    }
    return binding, errors


def _rehearsal_binding(
    path: Path | None,
    manifest: Mapping[str, Any],
    manifest_sha: str,
) -> tuple[dict[str, Any] | None, list[str]]:
    if path is None:
        return None, ["a rollback rehearsal report is required for full scope"]
    payload, error = _load_json_object(path)
    if payload is None:
        return None, [error or "rollback rehearsal report is unreadable"]
    errors: list[str] = []
    if payload.get("schema_version") != REHEARSAL_SCHEMA_VERSION:
        errors.append(f"rollback rehearsal schema_version must be {REHEARSAL_SCHEMA_VERSION}")
    if payload.get("executed") is not True:
        errors.append("rollback rehearsal was not executed")
    if payload.get("state") != PASS or payload.get("verified") is not True:
        errors.append("rollback rehearsal did not pass")
    if payload.get("manifest_sha256") != manifest_sha:
        errors.append("rollback rehearsal is not bound to the supplied manifest")
    errors.extend(_subject_errors(payload.get("subject"), manifest))
    previous_sha = payload.get("previous_manifest_sha256")
    if not isinstance(previous_sha, str) or DIGEST_PATTERN.fullmatch(previous_sha) is None:
        errors.append("rollback rehearsal previous_manifest_sha256 is invalid")
    elif previous_sha == manifest_sha:
        errors.append("rollback rehearsal target and previous manifest are identical")
    previous_subject = payload.get("previous_subject")
    if not isinstance(previous_subject, Mapping):
        errors.append("rollback rehearsal previous_subject is missing")
    else:
        for field in ("tag", "commit", "source_repository"):
            if not isinstance(previous_subject.get(field), str):
                errors.append(f"rollback rehearsal previous_subject.{field} is missing")
    errors.extend(_required_checks_errors(payload, "rollback rehearsal", REHEARSAL_REQUIRED_CHECKS))

    steps = payload.get("steps")
    if not isinstance(steps, list):
        errors.append("rollback rehearsal steps are missing")
    else:
        by_name = {
            item.get("name"): item
            for item in steps
            if isinstance(item, Mapping) and isinstance(item.get("name"), str)
        }
        for name in STEP_NAMES:
            item = by_name.get(name)
            if item is None:
                errors.append(f"rollback rehearsal has no {name} step")
            elif item.get("state") != PASS:
                errors.append(f"rollback rehearsal step {name} is {item.get('state')!r}, not PASS")

    target_digests: dict[str, Any] = {}
    target = payload.get("target")
    if not isinstance(target, Mapping):
        errors.append("rollback rehearsal target binding is missing")
    else:
        if target.get("manifest_sha256") != manifest_sha:
            errors.append("rollback rehearsal target binding is not bound to the supplied manifest")
        errors.extend(_subject_errors(target.get("subject"), manifest))
        digests = target.get("digests")
        if not isinstance(digests, Mapping):
            errors.append("rollback rehearsal target digests are missing")
        else:
            target_digests = dict(digests)
            for name, image in _image_map(manifest).items():
                if target_digests.get(name) != image.get("digest"):
                    errors.append(f"rollback rehearsal target digest for {name} does not match the manifest")

    previous_digests: dict[str, Any] = {}
    previous = payload.get("previous")
    if not isinstance(previous, Mapping):
        errors.append("rollback rehearsal previous binding is missing")
    else:
        if previous.get("manifest_sha256") != previous_sha:
            errors.append("rollback rehearsal previous binding is not bound to previous_manifest_sha256")
        digests = previous.get("digests")
        if not isinstance(digests, Mapping):
            errors.append("rollback rehearsal previous digests are missing")
        else:
            previous_digests = dict(digests)
            for name, digest in previous_digests.items():
                if (
                    not isinstance(name, str)
                    or not isinstance(digest, str)
                    or DIGEST_PATTERN.fullmatch(digest) is None
                ):
                    errors.append("rollback rehearsal previous digests are invalid")
                    break
    if target_digests and previous_digests:
        if set(previous_digests) != set(target_digests):
            errors.append("rollback rehearsal previous digests do not cover the target images")
        shared = set(target_digests) & set(previous_digests)
        if not shared or all(target_digests[name] == previous_digests[name] for name in shared):
            errors.append("rollback rehearsal target and previous digests are not different")

    errors.extend(_evidence_errors(payload, path, "rollback rehearsal"))
    try:
        report_sha = sha256_file(path)
    except OSError as exc:
        errors.append(f"could not hash rollback rehearsal report {path}: {exc}")
        report_sha = None
    binding = {
        "path": path.name,
        "sha256": report_sha,
        "executed": payload.get("executed"),
        "state": payload.get("state"),
        "verified": payload.get("verified"),
        "previous_manifest_sha256": previous_sha,
    }
    return binding, errors


def _gpu_binding(
    path: Path | None,
    manifest: Mapping[str, Any],
    manifest_sha: str,
) -> tuple[dict[str, Any] | None, list[str]]:
    if path is None:
        return None, ["a GPU runtime report is required for production qualification"]
    payload, error = _load_json_object(path)
    if payload is None:
        return None, [error or "GPU runtime report is unreadable"]
    errors: list[str] = []
    if payload.get("schema_version") != GPU_SCHEMA_VERSION:
        errors.append(f"GPU runtime report schema_version must be {GPU_SCHEMA_VERSION}")
    if payload.get("executed") is not True:
        errors.append("GPU runtime qualification was not executed")
    if payload.get("state") != PASS or payload.get("verified") is not True:
        errors.append("GPU runtime report did not pass")
    if payload.get("manifest_sha256") != manifest_sha:
        errors.append("GPU runtime report is not bound to the supplied manifest")
    errors.extend(_subject_errors(payload.get("subject"), manifest))
    errors.extend(_required_checks_errors(payload, "GPU runtime report", GPU_REQUIRED_CHECKS))
    gpu = payload.get("gpu")
    api_gpu = _image_map(manifest).get("api-gpu")
    expected_digest = api_gpu.get("digest") if isinstance(api_gpu, Mapping) else None
    if not isinstance(gpu, Mapping):
        errors.append("GPU runtime report gpu details are missing")
    else:
        for field in ("name", "runtime"):
            if not isinstance(gpu.get(field), str) or not gpu.get(field).strip():
                errors.append(f"GPU runtime report gpu.{field} is missing")
        runtime = gpu.get("runtime")
        if isinstance(runtime, str) and runtime.lower() != "nvidia":
            errors.append(f"GPU runtime report gpu.runtime is {runtime!r}, not 'nvidia'")
        if gpu.get("container_cuda") is not True:
            errors.append("GPU runtime report does not prove container CUDA access")
        if expected_digest is None:
            errors.append("manifest has no digest-pinned api-gpu image")
        else:
            if gpu.get("image_digest") != expected_digest:
                errors.append("GPU runtime report image digest does not match the manifest")
            image = gpu.get("image")
            if not isinstance(image, str) or not image.endswith(f"@{expected_digest}"):
                errors.append("GPU runtime report image is not digest-pinned to the manifest")
    try:
        report_sha = sha256_file(path)
    except OSError as exc:
        errors.append(f"could not hash GPU runtime report {path}: {exc}")
        report_sha = None
    binding = {
        "path": path.name,
        "sha256": report_sha,
        "executed": payload.get("executed"),
        "state": payload.get("state"),
        "verified": payload.get("verified"),
        "gpu": dict(gpu) if isinstance(gpu, Mapping) else None,
    }
    return binding, errors


def _verification_checks(payload: Mapping[str, Any] | None) -> dict[str, Mapping[str, Any]]:
    if payload is None:
        return {}
    checks = payload.get("checks")
    if not isinstance(checks, list):
        return {}
    result: dict[str, Mapping[str, Any]] = {}
    for item in checks:
        if isinstance(item, Mapping) and isinstance(item.get("name"), str):
            result.setdefault(item["name"], item)
    return result


def _state_from_verification(
    verification_checks: Mapping[str, Mapping[str, Any]],
    name: str,
) -> tuple[str, str]:
    item = verification_checks.get(name)
    if item is None:
        return FAIL, f"verification report has no {name} check"
    state = str(item.get("state"))
    if state not in EVIDENCE_STATES:
        return FAIL, f"verification check {name} has an invalid state {state!r}"
    detail = str(item.get("detail") or "")
    return state, f"{name} is {state}: {detail}"


def _image_map(manifest: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    images = manifest.get("images")
    if not isinstance(images, list):
        return {}
    result: dict[str, Mapping[str, Any]] = {}
    for image in images:
        if isinstance(image, Mapping) and isinstance(image.get("name"), str):
            result.setdefault(image["name"], image)
    return result


def _nested_evidence(image: Mapping[str, Any], field: str, subfield: str) -> Any:
    value = image.get(field)
    return value.get(subfield) if isinstance(value, Mapping) else None


def _identity_check(
    manifest: Mapping[str, Any],
    *,
    expected_tag: str | None,
    expected_commit: str | None,
    expected_repository: str | None,
) -> dict[str, Any]:
    if expected_tag is None or expected_commit is None:
        return _check(
            "identity",
            FAIL,
            True,
            "qualification requires the expected tag and commit",
        )
    try:
        validate_tag(expected_tag)
        validate_commit(expected_commit)
        if expected_repository is not None:
            validate_source_repository(expected_repository)
    except IdentityError as exc:
        return _check("identity", FAIL, True, str(exc))
    release = manifest.get("release") if isinstance(manifest.get("release"), Mapping) else {}
    if release.get("tag") != expected_tag:
        return _check(
            "identity",
            FAIL,
            True,
            f"manifest tag {release.get('tag')!r} does not match {expected_tag!r}",
        )
    if release.get("commit") != expected_commit:
        return _check(
            "identity",
            FAIL,
            True,
            f"manifest commit {release.get('commit')!r} does not match {expected_commit!r}",
        )
    if expected_repository is not None and release.get("source_repository") != expected_repository:
        return _check(
            "identity",
            FAIL,
            True,
            "manifest repository "
            f"{release.get('source_repository')!r} does not match {expected_repository!r}",
        )
    return _check("identity", PASS, True, f"manifest is bound to {expected_tag} at {expected_commit}")


def _source_identity_check(
    *,
    profile: str,
    expected_tag: str | None,
    expected_commit: str | None,
    repo_root: Path | None,
    main_ref: str,
    identity_verifier: IdentityVerifier,
) -> dict[str, Any]:
    required = profile != "local_validation"
    label = "source-identity"
    if expected_tag is None or expected_commit is None:
        return _check(
            label,
            FAIL if required else NOT_RUN,
            required,
            "source identity requires the expected tag and commit",
        )
    if repo_root is None:
        return _check(
            label,
            FAIL if required else NOT_RUN,
            required,
            "no repository checkout supplied; tag-to-commit and main-branch reachability were not verified",
        )
    try:
        identity_verifier(expected_tag, expected_commit, repo_root, main_ref=main_ref)
    except IdentityError as exc:
        return _check(label, FAIL, True, str(exc))
    except (OSError, subprocess.SubprocessError) as exc:
        return _check(label, UNAVAILABLE, required, f"git verification could not run: {exc}")
    return _check(
        label,
        PASS,
        required,
        f"tag {expected_tag} resolves to {expected_commit} and is reachable from {main_ref}",
    )


def qualify_release(
    manifest_path: Path,
    *,
    artifacts_dir: Path,
    profile: str,
    scope: str,
    verification_report_path: Path | None = None,
    publication_report_path: Path | None = None,
    deployment_report_path: Path | None = None,
    rehearsal_report_path: Path | None = None,
    gpu_report_path: Path | None = None,
    expected_tag: str | None = None,
    expected_commit: str | None = None,
    expected_repository: str | None = None,
    repo_root: Path | None = None,
    main_ref: str = "origin/main",
    require_live_evidence: bool = False,
    require_gpu_runtime: bool = False,
    identity_verifier: IdentityVerifier = verify_tag_commit,
    now: Callable[[], str] = utc_now_iso,
) -> dict[str, Any]:
    if profile not in QUALIFICATION_PROFILES:
        raise QualificationError(
            f"unknown qualification profile {profile!r}; expected one of {QUALIFICATION_PROFILES}"
        )
    if scope not in SCOPES:
        raise QualificationError(f"unknown qualification scope {scope!r}; expected one of {SCOPES}")
    if expected_tag is not None:
        try:
            validate_tag(expected_tag)
        except IdentityError as exc:
            raise QualificationError(str(exc)) from exc
    if expected_commit is not None:
        try:
            validate_commit(expected_commit)
        except IdentityError as exc:
            raise QualificationError(str(exc)) from exc
    if not manifest_path.is_file():
        raise QualificationError(f"manifest does not exist: {manifest_path}")
    if not artifacts_dir.is_dir():
        raise QualificationError(f"artifacts directory does not exist: {artifacts_dir}")
    try:
        manifest = load_manifest(manifest_path)
        manifest_sha = sha256_file(manifest_path)
    except (ManifestError, OSError) as exc:
        raise QualificationError(str(exc)) from exc

    checks: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = [
        {"kind": "manifest", "path": manifest_path.name, "sha256": manifest_sha}
    ]

    checks.append(
        _identity_check(
            manifest,
            expected_tag=expected_tag,
            expected_commit=expected_commit,
            expected_repository=expected_repository,
        )
    )
    checks.append(
        _source_identity_check(
            profile=profile,
            expected_tag=expected_tag,
            expected_commit=expected_commit,
            repo_root=repo_root,
            main_ref=main_ref,
            identity_verifier=identity_verifier,
        )
    )

    manifest_problems = manifest_errors(
        manifest,
        artifacts_dir=artifacts_dir,
        expected_tag=expected_tag,
        expected_commit=expected_commit,
    )
    checks.append(
        _check(
            "manifest",
            FAIL if manifest_problems else PASS,
            True,
            "; ".join(manifest_problems[:12])
            if manifest_problems
            else "manifest and local evidence hashes are valid",
        )
    )

    require_production = profile in ("staging_qualification", "production_qualification")
    verification, verification_errors = _verification_binding(
        verification_report_path,
        manifest,
        manifest_sha,
        require_production=require_production,
    )
    checks.append(
        _check(
            "verification-report",
            FAIL if verification_errors else PASS,
            True,
            "; ".join(verification_errors[:12])
            if verification_errors
            else "verification report matches the manifest, subject, and artifact status",
        )
    )
    verification_payload: Mapping[str, Any] | None = None
    if verification_report_path is not None:
        verification_payload, _ = _load_json_object(verification_report_path)
    verification_checks = _verification_checks(verification_payload)

    publication_required = require_live_evidence or profile != "local_validation" or scope != "artifact"
    if publication_required:
        publication, publication_errors = _publication_binding(publication_report_path, manifest)
        checks.append(
            _check(
                "publication-report",
                FAIL if publication_errors else PASS,
                True,
                "; ".join(publication_errors[:12])
                if publication_errors
                else "publication report proves every required digest was published",
            )
        )
        if publication is not None and publication.get("sha256") is not None:
            evidence.append(
                {
                    "kind": "publication-report",
                    "path": publication["path"],
                    "sha256": publication["sha256"],
                }
            )
    else:
        publication = None
        checks.append(
            _check(
                "publication-report",
                NOT_RUN,
                False,
                "artifact-scoped local validation: publication evidence was not required",
            )
        )

    if verification is not None and verification.get("sha256") is not None:
        evidence.append(
            {
                "kind": "verification-report",
                "path": verification["path"],
                "sha256": verification["sha256"],
            }
        )

    images = _image_map(manifest)
    artifacts: list[dict[str, Any]] = []
    for name in REQUIRED_IMAGES:
        image = images.get(name)
        if image is None:
            for label in (
                f"artifact-digest:{name}",
                f"artifact-sbom:{name}",
                f"artifact-scan:{name}",
                f"attestation-bundle:{name}",
            ):
                checks.append(_check(label, FAIL, True, "image entry is missing"))
            if profile != "local_validation":
                checks.append(_check(f"attestation-trust:{name}", FAIL, True, "image entry is missing"))
            artifacts.append(
                {
                    "name": name,
                    "digest": None,
                    "sbom": None,
                    "scan": None,
                    "provenance": None,
                    "sbom_attestation": None,
                    "state": FAIL,
                }
            )
            continue

        digest_state, digest_detail = _state_from_verification(verification_checks, f"digest:{name}")
        checks.append(_check(f"artifact-digest:{name}", digest_state, True, digest_detail))

        sbom_binding, sbom_errors = _evidence_binding(artifacts_dir, image.get("sbom"), f"sbom:{name}")
        scan_binding, scan_errors = _evidence_binding(
            artifacts_dir, _nested_evidence(image, "scan", "log"), f"scan:{name}"
        )
        provenance_binding, provenance_errors = _evidence_binding(
            artifacts_dir, _nested_evidence(image, "provenance", "evidence"), f"provenance:{name}"
        )
        sbom_attestation_binding, sbom_attestation_errors = _evidence_binding(
            artifacts_dir,
            _nested_evidence(image, "sbom_attestation", "evidence"),
            f"sbom-attestation:{name}",
        )
        for binding in (sbom_binding, scan_binding, provenance_binding, sbom_attestation_binding):
            if binding is not None:
                evidence.append(binding)

        sbom_state, sbom_detail = _state_from_verification(verification_checks, f"sbom:{name}")
        checks.append(
            _check(
                f"artifact-sbom:{name}",
                _combine([sbom_state], sbom_errors),
                True,
                "; ".join(sbom_errors) if sbom_errors else sbom_detail,
            )
        )
        scan_state, scan_detail = _state_from_verification(verification_checks, f"scan:{name}")
        checks.append(
            _check(
                f"artifact-scan:{name}",
                _combine([scan_state], scan_errors),
                True,
                "; ".join(scan_errors) if scan_errors else scan_detail,
            )
        )

        provenance_state, provenance_detail = _state_from_verification(
            verification_checks, f"provenance-bundle:{name}"
        )
        sbom_attestation_state, sbom_attestation_detail = _state_from_verification(
            verification_checks, f"sbom-attestation-bundle:{name}"
        )
        bundle_errors = provenance_errors + sbom_attestation_errors
        checks.append(
            _check(
                f"attestation-bundle:{name}",
                _combine([provenance_state, sbom_attestation_state], bundle_errors),
                True,
                "; ".join(bundle_errors)
                if bundle_errors
                else f"{provenance_detail}; {sbom_attestation_detail}",
            )
        )

        if profile == "local_validation":
            checks.append(
                _check(
                    f"attestation-trust:{name}",
                    NOT_RUN,
                    False,
                    "local_validation: GitHub attestation trust was not required",
                )
            )
        else:
            trust_states: list[str] = []
            trust_details: list[str] = []
            for label in (
                f"provenance-attestation:{name}",
                f"sbom-attestation:{name}",
                f"provenance-bundle-signature:{name}",
                f"sbom-bundle-signature:{name}",
            ):
                state, detail = _state_from_verification(verification_checks, label)
                trust_states.append(state)
                trust_details.append(detail)
            checks.append(
                _check(
                    f"attestation-trust:{name}",
                    _combine(trust_states),
                    True,
                    "; ".join(trust_details),
                )
            )

        artifact_state = _aggregate(
            [
                check
                for check in checks
                if check["name"].endswith(f":{name}")
                and check["name"].startswith(
                    (
                        "artifact-digest:",
                        "artifact-sbom:",
                        "artifact-scan:",
                        "attestation-bundle:",
                        "attestation-trust:",
                    )
                )
                and check["required"] is True
            ]
        )
        artifacts.append(
            {
                "name": name,
                "digest": image.get("digest"),
                "sbom": sbom_binding,
                "scan": scan_binding,
                "provenance": provenance_binding,
                "sbom_attestation": sbom_attestation_binding,
                "state": artifact_state,
            }
        )

    gpu_artifact_state, gpu_artifact_detail = _state_from_verification(verification_checks, "gpu-artifact")
    checks.append(_check("gpu-artifact", gpu_artifact_state, True, gpu_artifact_detail))

    if scope in DEPLOYMENT_SCOPES:
        deployment, deployment_errors = _deployment_binding(
            deployment_report_path,
            manifest,
            manifest_sha,
            require_gpu=profile == "production_qualification",
        )
        checks.append(
            _check(
                "deployment-report",
                FAIL if deployment_errors else PASS,
                True,
                "; ".join(deployment_errors[:12])
                if deployment_errors
                else "deployment report is digest-pinned and bound to the manifest",
            )
        )
        if deployment is not None and deployment.get("sha256") is not None:
            evidence.append(
                {
                    "kind": "deployment-report",
                    "path": deployment["path"],
                    "sha256": deployment["sha256"],
                }
            )
    else:
        deployment = None
        checks.append(
            _check(
                "deployment-report",
                NOT_RUN,
                False,
                "artifact scope: deployment evidence was not required",
            )
        )

    if scope == "full":
        rehearsal, rehearsal_errors = _rehearsal_binding(rehearsal_report_path, manifest, manifest_sha)
        checks.append(
            _check(
                "rollback-rehearsal",
                FAIL if rehearsal_errors else PASS,
                True,
                "; ".join(rehearsal_errors[:12])
                if rehearsal_errors
                else "rollback rehearsal passed and is bound to the manifest",
            )
        )
        if rehearsal is not None and rehearsal.get("sha256") is not None:
            evidence.append(
                {
                    "kind": "rollback-rehearsal",
                    "path": rehearsal["path"],
                    "sha256": rehearsal["sha256"],
                }
            )
    else:
        rehearsal = None
        checks.append(
            _check(
                "rollback-rehearsal",
                NOT_RUN,
                False,
                "full scope is required for a rollback rehearsal",
            )
        )

    gpu_required = require_gpu_runtime or profile == "production_qualification"
    if gpu_required:
        gpu_runtime, gpu_errors = _gpu_binding(gpu_report_path, manifest, manifest_sha)
        checks.append(
            _check(
                "gpu-runtime",
                FAIL if gpu_errors else PASS,
                True,
                "; ".join(gpu_errors[:12]) if gpu_errors else "GPU runtime is verified on the target host",
            )
        )
        if gpu_runtime is not None and gpu_runtime.get("sha256") is not None:
            evidence.append(
                {
                    "kind": "gpu-runtime",
                    "path": gpu_runtime["path"],
                    "sha256": gpu_runtime["sha256"],
                }
            )
    else:
        gpu_runtime = None
        checks.append(
            _check(
                "gpu-runtime",
                NOT_RUN,
                False,
                "GPU runtime is not required for this profile",
            )
        )

    overall = _aggregate(checks)
    qualified = overall == PASS and all(
        check.get("state") == PASS for check in checks if check.get("required") is True
    )
    production_qualified = (
        qualified
        and profile == "production_qualification"
        and scope == "full"
        and isinstance(verification, Mapping)
        and verification.get("production_verified") is True
        and isinstance(deployment, Mapping)
        and deployment.get("gpu") is True
        and isinstance(rehearsal, Mapping)
        and rehearsal.get("executed") is True
        and rehearsal.get("verified") is True
        and isinstance(gpu_runtime, Mapping)
        and gpu_runtime.get("verified") is True
        and isinstance(gpu_runtime.get("gpu"), Mapping)
        and gpu_runtime["gpu"].get("container_cuda") is True
    )
    blockers = [
        f"{check['name']}: {check['state']} - {check['detail']}"
        for check in checks
        if check.get("required") is True and check.get("state") != PASS
    ]
    limitations = [
        f"{check['name']}: {check['state']} - {check['detail']}"
        for check in checks
        if check.get("required") is not True and check.get("state") != PASS
    ]
    return {
        "schema_version": QUALIFICATION_SCHEMA_VERSION,
        "profile": profile,
        "scope": scope,
        "generated_at": now(),
        "manifest_sha256": manifest_sha,
        "subject": _subject(manifest),
        "overall_state": overall,
        "qualified": qualified,
        "production_qualified": production_qualified,
        "verification": verification,
        "publication": publication,
        "deployment": deployment,
        "rehearsal": rehearsal,
        "gpu_runtime": gpu_runtime,
        "artifacts": artifacts,
        "checks": checks,
        "evidence": evidence,
        "blockers": blockers,
        "limitations": limitations,
    }


def write_qualification_report(report: Mapping[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def qualification_report_errors(
    report: Any,
    manifest: Mapping[str, Any],
    *,
    manifest_path: Path,
    require_production: bool = False,
    verification_report_path: Path | None = None,
    publication_report_path: Path | None = None,
    deployment_report_path: Path | None = None,
    rehearsal_report_path: Path | None = None,
    gpu_report_path: Path | None = None,
) -> list[str]:
    """Return every reason a qualification report cannot authorize this release."""
    if not isinstance(report, Mapping):
        return ["qualification report must be a JSON object"]
    errors: list[str] = []
    if report.get("schema_version") != QUALIFICATION_SCHEMA_VERSION:
        errors.append(f"qualification report schema_version must be {QUALIFICATION_SCHEMA_VERSION}")
    try:
        expected_sha = sha256_file(manifest_path)
    except OSError as exc:
        return [f"could not hash manifest {manifest_path}: {exc}"]
    if report.get("manifest_sha256") != expected_sha:
        errors.append("qualification report is not bound to the supplied manifest (manifest_sha256 mismatch)")
    errors.extend(_subject_errors(report.get("subject"), manifest))
    profile = report.get("profile")
    scope = report.get("scope")
    if profile not in QUALIFICATION_PROFILES:
        errors.append(f"qualification report profile {profile!r} is not recognized")
    if scope not in SCOPES:
        errors.append(f"qualification report scope {scope!r} is not recognized")
    if report.get("overall_state") != PASS:
        errors.append(f"qualification report overall_state is {report.get('overall_state')!r}, not PASS")
    if report.get("qualified") is not True:
        errors.append("qualification report qualified is not true")
    if require_production:
        if profile != "production_qualification":
            errors.append("qualification report profile must be 'production_qualification'")
        if scope != "full":
            errors.append("qualification report scope must be 'full'")
        if report.get("production_qualified") is not True:
            errors.append("qualification report production_qualified is not true")

    verification = report.get("verification")
    if not isinstance(verification, Mapping):
        errors.append("qualification report verification binding is missing")
    else:
        if not isinstance(verification.get("sha256"), str):
            errors.append("qualification verification binding has no evidence hash")
        if verification.get("manifest_sha256") != expected_sha:
            errors.append("qualification verification binding is not bound to the manifest")
        if verification.get("overall_state") != PASS or verification.get("verified") is not True:
            errors.append("qualification verification binding does not prove verification")
        if require_production:
            if verification.get("profile") != "production":
                errors.append("qualification verification binding profile must be 'production'")
            if verification.get("production_verified") is not True:
                errors.append("qualification verification binding production_verified is not true")

    publication = report.get("publication")
    if require_production:
        if not isinstance(publication, Mapping):
            errors.append("qualification publication binding is missing")
        elif publication.get("complete") is not True:
            errors.append("qualification publication binding does not prove complete publication")
        elif not isinstance(publication.get("sha256"), str):
            errors.append("qualification publication binding has no evidence hash")

    deployment = report.get("deployment")
    rehearsal = report.get("rehearsal")
    gpu_runtime = report.get("gpu_runtime")
    if require_production:
        for kind, binding in (
            ("deployment-report", deployment),
            ("rollback-rehearsal", rehearsal),
            ("gpu-runtime", gpu_runtime),
        ):
            if not isinstance(binding, Mapping):
                errors.append(f"qualification {kind} binding is missing")
                continue
            if not isinstance(binding.get("sha256"), str):
                errors.append(f"qualification {kind} binding has no evidence hash")
            if binding.get("state") != PASS:
                errors.append(f"qualification {kind} binding state is {binding.get('state')!r}, not PASS")
            errors.extend(_binding_evidence_errors(report, kind, binding))
        if isinstance(deployment, Mapping):
            if deployment.get("manifest_sha256") != expected_sha:
                errors.append("qualification deployment binding is not bound to the manifest")
            if deployment.get("gpu") is not True:
                errors.append("qualification deployment binding does not prove a GPU deployment")
        if isinstance(rehearsal, Mapping):
            if rehearsal.get("executed") is not True:
                errors.append("qualification rehearsal binding was not executed")
            if rehearsal.get("verified") is not True:
                errors.append("qualification rehearsal binding is not verified")
            previous_sha = rehearsal.get("previous_manifest_sha256")
            if not isinstance(previous_sha, str) or previous_sha == expected_sha:
                errors.append(
                    "qualification rehearsal binding does not identify a different previous manifest"
                )
        if isinstance(gpu_runtime, Mapping):
            if gpu_runtime.get("verified") is not True:
                errors.append("qualification GPU binding is not verified")
            gpu = gpu_runtime.get("gpu")
            if not isinstance(gpu, Mapping) or gpu.get("container_cuda") is not True:
                errors.append("qualification GPU binding does not prove container CUDA access")

    bindings_by_kind = {
        "deployment-report": deployment,
        "rollback-rehearsal": rehearsal,
        "gpu-runtime": gpu_runtime,
    }
    for kind, supplied in (
        ("deployment-report", deployment_report_path),
        ("rollback-rehearsal", rehearsal_report_path),
        ("gpu-runtime", gpu_report_path),
    ):
        if supplied is None:
            continue
        binding = bindings_by_kind[kind]
        if not isinstance(binding, Mapping):
            errors.append(f"qualification {kind} binding is missing; cannot compare the report")
            continue
        try:
            actual = sha256_file(supplied)
        except OSError as exc:
            errors.append(f"could not hash {kind} report {supplied}: {exc}")
            continue
        if binding.get("sha256") != actual:
            errors.append(f"qualification {kind} binding does not match the supplied report")

    if verification_report_path is not None:
        if not isinstance(verification, Mapping):
            errors.append("qualification verification binding is missing; cannot compare the report")
        else:
            try:
                actual_verification_sha = sha256_file(verification_report_path)
            except OSError as exc:
                errors.append(f"could not hash verification report {verification_report_path}: {exc}")
            else:
                if verification.get("sha256") != actual_verification_sha:
                    errors.append(
                        "qualification verification binding does not match the supplied verification report"
                    )
    if publication_report_path is not None:
        if not isinstance(publication, Mapping):
            errors.append("qualification publication binding is missing; cannot compare the report")
        else:
            try:
                actual_publication_sha = sha256_file(publication_report_path)
            except OSError as exc:
                errors.append(f"could not hash publication report {publication_report_path}: {exc}")
            else:
                if publication.get("sha256") != actual_publication_sha:
                    errors.append(
                        "qualification publication binding does not match the supplied publication report"
                    )

    artifacts = report.get("artifacts")
    if not isinstance(artifacts, list):
        errors.append("qualification report artifacts are missing")
    else:
        images = _image_map(manifest)
        by_name = {item.get("name"): item for item in artifacts if isinstance(item, Mapping)}
        for name in REQUIRED_IMAGES:
            item = by_name.get(name)
            if not isinstance(item, Mapping):
                errors.append(f"qualification report has no artifact evidence for {name}")
                continue
            image = images.get(name)
            if image is not None and item.get("digest") != image.get("digest"):
                errors.append(f"qualification artifact digest for {name} does not match the manifest")
            if item.get("state") != PASS:
                errors.append(f"qualification artifact state for {name} is {item.get('state')!r}, not PASS")

    evidence = report.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        errors.append("qualification report evidence is missing")
    else:
        manifest_evidence = [
            item for item in evidence if isinstance(item, Mapping) and item.get("kind") == "manifest"
        ]
        if not manifest_evidence:
            errors.append("qualification report does not include manifest evidence")
        elif manifest_evidence[0].get("sha256") != expected_sha:
            errors.append("qualification manifest evidence does not match the supplied manifest")
    return errors


def render_qualification_summary(report: Mapping[str, Any]) -> str:
    subject = report.get("subject") or {}
    lines = [
        f"Release qualification: {report.get('overall_state')} "
        f"(profile={report.get('profile')}, scope={report.get('scope')}, "
        f"qualified={report.get('qualified')}, production_qualified={report.get('production_qualified')})",
        f"Subject: {subject.get('tag')} at {subject.get('commit')} from {subject.get('source_repository')}",
        f"Manifest: {report.get('manifest_sha256')}",
    ]
    verification = report.get("verification") or {}
    if verification:
        lines.append(
            f"Verification: {verification.get('overall_state')} "
            f"(profile={verification.get('profile')}, "
            f"production_verified={verification.get('production_verified')})"
        )
    publication = report.get("publication") or {}
    if publication:
        lines.append(f"Publication: {publication.get('status')} (complete={publication.get('complete')})")
    for check in report.get("checks") or []:
        required = "required" if check.get("required") else "informational"
        lines.append(f"- {check.get('name')}: {check.get('state')} ({required}) - {check.get('detail')}")
    blockers = report.get("blockers") or []
    if blockers:
        lines.append("Blockers:")
        lines.extend(f"- {item}" for item in blockers)
    limitations = report.get("limitations") or []
    if limitations:
        lines.append("Limitations:")
        lines.extend(f"- {item}" for item in limitations)
    return "\n".join(lines) + "\n"
