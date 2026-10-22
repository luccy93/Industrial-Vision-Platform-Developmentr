"""V22 release manifest construction and fail-closed validation tests."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from tools.release import manifest as manifest_module
from tools.release.identity import REQUIRED_IMAGES
from tools.release.manifest import (
    ManifestError,
    build_manifest,
    canonical_json,
    load_manifest,
    sha256_file,
    validate_manifest,
    write_manifest,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
TAG = "v1.2.3"
COMMIT = "a" * 40
SOURCE_REPOSITORY = "octo/repo"


def _digest(label: str) -> str:
    return f"sha256:{hashlib.sha256(label.encode()).hexdigest()}"


def _image_artifacts(artifacts: Path, name: str) -> dict[str, str]:
    files = {
        "sbom_file": (f"{name}.spdx.json", '{"spdxVersion": "SPDX-2.3"}\n'),
        "scan_log_file": (f"{name}.scan.txt", "trivy: image scan clean\n"),
        "provenance_bundle_file": (f"{name}.provenance.jsonl", '{"bundle": "provenance"}\n'),
        "sbom_attestation_bundle_file": (
            f"{name}.sbom-attestation.jsonl",
            '{"bundle": "sbom"}\n',
        ),
    }
    resolved: dict[str, str] = {}
    for field, (filename, content) in files.items():
        (artifacts / filename).write_text(content, encoding="utf-8")
        resolved[field] = filename
    return resolved


def make_inputs(tmp_path: Path) -> tuple[dict[str, Any], Path]:
    artifacts = tmp_path / "release-artifacts"
    artifacts.mkdir()
    images: list[dict[str, Any]] = []
    for name in REQUIRED_IMAGES:
        image_id = _digest(f"{name}-image-id")
        entry: dict[str, Any] = {
            "name": name,
            "digest": _digest(f"{name}-digest"),
            "image_id": image_id,
            "pulled_image_id": image_id,
            "platform": "linux/amd64",
            "size_bytes": 1_000_000,
            "scan_version": "0.76.0",
        }
        entry.update(_image_artifacts(artifacts, name))
        images.append(entry)
    inputs: dict[str, Any] = {
        "tag": TAG,
        "commit": COMMIT,
        "source_repository": SOURCE_REPOSITORY,
        "workflow": ".github/workflows/release.yml",
        "workflow_run_url": "https://github.com/octo/repo/actions/runs/123",
        "workflow_run_id": 123,
        "workflow_run_attempt": 1,
        "created_at": "2026-10-22T12:00:00Z",
        "gpu_runtime_smoke": "not_run",
        "gpu_runtime_smoke_reason": "GPU infrastructure unavailable on the release runner",
        "images": images,
    }
    return inputs, artifacts


@pytest.fixture()
def release(tmp_path: Path) -> tuple[dict[str, Any], Path, dict[str, Any]]:
    inputs, artifacts = make_inputs(tmp_path)
    manifest = build_manifest(inputs, artifacts)
    return manifest, artifacts, inputs


def test_generated_manifest_is_valid_and_complete(
    release: tuple[dict[str, Any], Path, dict[str, Any]],
) -> None:
    manifest, artifacts, _ = release
    validate_manifest(
        manifest,
        artifacts_dir=artifacts,
        expected_tag=TAG,
        expected_commit=COMMIT,
    )
    images = {image["name"]: image for image in manifest["images"]}
    assert list(images) == list(REQUIRED_IMAGES)
    api = images["api"]
    assert api["repository"] == "ghcr.io/octo/repo/api"
    assert api["tags"] == ["v1.2.3", "sha-aaaaaaa"]
    assert api["sbom"]["sha256"] == sha256_file(artifacts / "api.spdx.json")
    assert api["scan"] == {
        "tool": "trivy",
        "version": "0.76.0",
        "severity": "CRITICAL,HIGH",
        "ignore_unfixed": True,
        "result": "clean",
        "target": "image",
        "log": {
            "path": "api.scan.txt",
            "sha256": sha256_file(artifacts / "api.scan.txt"),
        },
    }
    assert images["api-gpu"]["repository"] == "ghcr.io/octo/repo/api-gpu"
    assert images["api-gpu"]["provenance"]["verification_command"] == (
        "gh attestation verify oci://ghcr.io/octo/repo/api-gpu@"
        f"{images['api-gpu']['digest']} --repo octo/repo"
    )
    assert manifest["variants"]["gpu"] == {
        "image": "api-gpu",
        "published": True,
        "runtime_smoke": "not_run",
        "runtime_smoke_reason": "GPU infrastructure unavailable on the release runner",
    }


def test_manifest_serialization_is_canonical_and_round_trips(
    release: tuple[dict[str, Any], Path, dict[str, Any]], tmp_path: Path
) -> None:
    manifest, _, _ = release
    text = canonical_json(manifest)
    assert text.endswith("\n")
    assert text == canonical_json(json.loads(text))
    output = tmp_path / "release-manifest.json"
    write_manifest(manifest, output)
    assert load_manifest(output) == manifest


def _wrong_tag(manifest: dict[str, Any]) -> None:
    manifest["release"]["tag"] = "v1.2.3-rc.1"


def _bad_commit(manifest: dict[str, Any]) -> None:
    manifest["release"]["commit"] = "A" * 40


def _wrong_repository(manifest: dict[str, Any]) -> None:
    manifest["images"][0]["repository"] = "ghcr.io/other/repo/api"


def _mutable_alias(manifest: dict[str, Any]) -> None:
    manifest["images"][0]["tags"] = [TAG, "latest"]


def _duplicate_image(manifest: dict[str, Any]) -> None:
    manifest["images"][1]["name"] = "api"


def _missing_image(manifest: dict[str, Any]) -> None:
    manifest["images"].pop()


def _extra_image(manifest: dict[str, Any]) -> None:
    manifest["images"].append(copy.deepcopy(manifest["images"][0]))


def _bad_digest(manifest: dict[str, Any]) -> None:
    manifest["images"][0]["digest"] = "sha256:xyz"


def _id_mismatch(manifest: dict[str, Any]) -> None:
    manifest["images"][0]["pulled_image_id"] = _digest("different-image-id")


def _bad_sbom_hash(manifest: dict[str, Any]) -> None:
    manifest["images"][0]["sbom"]["sha256"] = "sha256:" + "0" * 64


def _traversal_sbom(manifest: dict[str, Any]) -> None:
    manifest["images"][0]["sbom"]["path"] = "../escape.spdx.json"


def _scan_failed(manifest: dict[str, Any]) -> None:
    manifest["images"][0]["scan"]["result"] = "failed"


def _unfixed(manifest: dict[str, Any]) -> None:
    manifest["images"][0]["scan"]["ignore_unfixed"] = False


def _missing_provenance(manifest: dict[str, Any]) -> None:
    del manifest["images"][0]["provenance"]


def _bad_attestation_url(manifest: dict[str, Any]) -> None:
    manifest["images"][0]["provenance"]["attestation_url"] = "https://example.test"


def _gpu_reason_missing(manifest: dict[str, Any]) -> None:
    manifest["variants"]["gpu"]["runtime_smoke_reason"] = ""


def _gpu_not_published(manifest: dict[str, Any]) -> None:
    manifest["variants"]["gpu"]["published"] = False


def _unknown_field(manifest: dict[str, Any]) -> None:
    manifest["unexpected"] = True


def _wrong_schema_version(manifest: dict[str, Any]) -> None:
    manifest["schema_version"] = 2


def _bad_platform(manifest: dict[str, Any]) -> None:
    manifest["images"][0]["platform"] = "windows/amd64"


def _bad_size(manifest: dict[str, Any]) -> None:
    manifest["images"][0]["size_bytes"] = 0


def _bad_scan_version(manifest: dict[str, Any]) -> None:
    manifest["images"][0]["scan"]["version"] = ""


def _wrong_builder(manifest: dict[str, Any]) -> None:
    manifest["build"]["builder"] = "kaniko"


def _wrong_event(manifest: dict[str, Any]) -> None:
    manifest["build"]["event"] = "pull_request"


TAMPERS = [
    pytest.param(_wrong_tag, "release.tag", id="invalid-tag"),
    pytest.param(_bad_commit, "release.commit", id="bad-commit"),
    pytest.param(_wrong_repository, "repository must be ghcr.io/octo/repo/api", id="wrong-registry"),
    pytest.param(_mutable_alias, "no mutable aliases", id="mutable-alias"),
    pytest.param(_duplicate_image, "duplicate image names", id="duplicate-image"),
    pytest.param(_missing_image, "images must contain exactly", id="missing-image"),
    pytest.param(_extra_image, "images must contain exactly", id="extra-image"),
    pytest.param(_bad_digest, "invalid image digest", id="bad-digest"),
    pytest.param(_id_mismatch, "digest pull proof failed", id="digest-pull-mismatch"),
    pytest.param(_bad_sbom_hash, "does not match the artifact", id="sbom-hash-mismatch"),
    pytest.param(_traversal_sbom, "plain file name", id="artifact-path-traversal"),
    pytest.param(_scan_failed, "scan.result must be 'clean'", id="scan-not-clean"),
    pytest.param(_unfixed, "ignore_unfixed must be true", id="ignore-unfixed-disabled"),
    pytest.param(_missing_provenance, "missing required fields: provenance", id="provenance-missing"),
    pytest.param(_bad_attestation_url, "attestation_url must be", id="attestation-url"),
    pytest.param(_gpu_reason_missing, "runtime_smoke_reason is required", id="gpu-reason-missing"),
    pytest.param(_gpu_not_published, "published must be true", id="gpu-unpublished"),
    pytest.param(_unknown_field, "unknown fields: unexpected", id="unknown-field"),
    pytest.param(_wrong_schema_version, "schema_version must be 1", id="schema-version"),
    pytest.param(_bad_platform, "platform must be one of", id="bad-platform"),
    pytest.param(_bad_size, "size_bytes must be a positive integer", id="bad-size"),
    pytest.param(_bad_scan_version, "scan.version must record", id="scan-version-missing"),
    pytest.param(_wrong_builder, "build.builder", id="wrong-builder"),
    pytest.param(_wrong_event, "build.event", id="wrong-event"),
]


@pytest.mark.parametrize(("mutator", "match"), TAMPERS)
def test_manifest_rejects_tampering(
    release: tuple[dict[str, Any], Path, dict[str, Any]],
    mutator: Any,
    match: str,
) -> None:
    manifest, artifacts, _ = release
    tampered = copy.deepcopy(manifest)
    mutator(tampered)
    with pytest.raises(ManifestError, match=match):
        validate_manifest(
            tampered,
            artifacts_dir=artifacts,
            expected_tag=TAG,
            expected_commit=COMMIT,
        )


def test_expected_tag_and_commit_are_enforced(release: tuple[dict[str, Any], Path, dict[str, Any]]) -> None:
    manifest, artifacts, _ = release
    with pytest.raises(ManifestError, match="does not match expected tag"):
        validate_manifest(manifest, artifacts_dir=artifacts, expected_tag="v9.9.9")
    with pytest.raises(ManifestError, match="does not match expected commit"):
        validate_manifest(manifest, artifacts_dir=artifacts, expected_commit="b" * 40)


def test_missing_artifact_file_is_rejected(release: tuple[dict[str, Any], Path, dict[str, Any]]) -> None:
    manifest, artifacts, _ = release
    (artifacts / "web.spdx.json").unlink()
    with pytest.raises(ManifestError, match="does not exist"):
        validate_manifest(manifest, artifacts_dir=artifacts)


def _drop_sbom(inputs: dict[str, Any]) -> None:
    del inputs["images"][0]["sbom_file"]


def _bad_image_name(inputs: dict[str, Any]) -> None:
    inputs["images"][0]["name"] = "debug"


def _duplicate_input_image(inputs: dict[str, Any]) -> None:
    inputs["images"][1]["name"] = "api"


def _unsupported_platform(inputs: dict[str, Any]) -> None:
    inputs["images"][0]["platform"] = "windows/amd64"


def _missing_smoke(inputs: dict[str, Any]) -> None:
    inputs["gpu_runtime_smoke"] = ""


def _missing_artifact(inputs: dict[str, Any]) -> None:
    inputs["images"][0]["sbom_file"] = "absent.spdx.json"


def _unsafe_artifact(inputs: dict[str, Any]) -> None:
    inputs["images"][0]["sbom_file"] = "sub/escape.spdx.json"


def _drop_image(inputs: dict[str, Any]) -> None:
    inputs["images"] = [entry for entry in inputs["images"] if entry["name"] != "api-gpu"]


INPUT_TAMPERS = [
    pytest.param(_drop_sbom, "sbom_file", id="missing-sbom-field"),
    pytest.param(_bad_image_name, "image name is invalid", id="bad-image-name"),
    pytest.param(_duplicate_input_image, "duplicate image", id="duplicate-input-image"),
    pytest.param(_unsupported_platform, "unsupported platform", id="unsupported-platform"),
    pytest.param(_missing_smoke, "gpu_runtime_smoke", id="missing-gpu-smoke"),
    pytest.param(_missing_artifact, "release artifact not found", id="missing-artifact"),
    pytest.param(_unsafe_artifact, "plain file name", id="unsafe-artifact-name"),
    pytest.param(_drop_image, "missing images: api-gpu", id="missing-image-input"),
]


@pytest.mark.parametrize(("mutator", "match"), INPUT_TAMPERS)
def test_build_manifest_fails_closed(tmp_path: Path, mutator: Any, match: str) -> None:
    inputs, artifacts = make_inputs(tmp_path)
    mutator(inputs)
    with pytest.raises(ManifestError, match=match):
        build_manifest(inputs, artifacts)


def test_schema_matches_validator_contract() -> None:
    schema = json.loads((REPO_ROOT / "release" / "release-manifest.schema.json").read_text(encoding="utf-8"))
    assert set(schema["required"]) == set(manifest_module.TOP_LEVEL_FIELDS)
    assert set(schema["properties"]["release"]["required"]) == set(manifest_module.RELEASE_FIELDS)
    assert set(schema["properties"]["build"]["required"]) == set(manifest_module.BUILD_FIELDS)
    assert set(schema["$defs"]["image"]["required"]) == set(manifest_module.IMAGE_FIELDS)
    assert set(schema["$defs"]["sbom"]["required"]) == set(manifest_module.SBOM_FIELDS)
    assert set(schema["$defs"]["scan"]["required"]) == set(manifest_module.SCAN_FIELDS)
    assert set(schema["$defs"]["evidence"]["required"]) == set(manifest_module.EVIDENCE_FIELDS)
    assert set(schema["$defs"]["attestation"]["required"]) == set(manifest_module.ATTESTATION_FIELDS)
    gpu = schema["properties"]["variants"]["properties"]["gpu"]
    assert set(gpu["required"]) == set(manifest_module.VARIANT_FIELDS)
    assert schema["properties"]["images"]["minItems"] == len(REQUIRED_IMAGES)
    assert schema["properties"]["images"]["maxItems"] == len(REQUIRED_IMAGES)
    assert schema["properties"]["schema_version"]["const"] == manifest_module.SCHEMA_VERSION
