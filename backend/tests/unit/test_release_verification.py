"""V23 independent release verification and evidence-state tests."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

from tools.release import manifest as manifest_module
from tools.release import verification as verification_module
from tools.release.identity import REQUIRED_IMAGES, verify_tag_commit
from tools.release.manifest import PROVENANCE_PREDICATE, SBOM_PREDICATE, build_manifest, write_manifest
from tools.release.verification import (
    FAIL,
    NOT_RUN,
    PASS,
    SIMULATED,
    UNAVAILABLE,
    verify_release,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
TAG = "v1.2.3"
COMMIT = "a" * 40
SOURCE_REPOSITORY = "octo/repo"
DIGESTS = {
    name: "sha256:" + hashlib.sha256(f"{name}-digest".encode()).hexdigest() for name in REQUIRED_IMAGES
}
IMAGE_IDS = {
    name: "sha256:" + hashlib.sha256(f"{name}-image-id".encode()).hexdigest() for name in REQUIRED_IMAGES
}
CLEAN_SCAN = """Report Summary

| Target | Type | Vulnerabilities |
| --- | --- | --- |
| image | debian 12.15 | 0 |
"""
CLEAN_SBOM_PAYLOAD = {
    "spdxVersion": "SPDX-2.3",
    "name": "release-image",
    "packages": [{"name": "fastapi", "SPDXID": "SPDXRef-Package-fastapi"}],
}
CLEAN_SBOM = json.dumps(CLEAN_SBOM_PAYLOAD)
SIMULATED_BUNDLE = json.dumps({"_simulation": True, "_note": "local placeholder"}) + "\n"


def _accept_identity(*args: Any, **kwargs: Any) -> None:
    del args, kwargs


def _bundle(digest: str, predicate: str, predicate_payload: Any) -> str:
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "release-image", "digest": {"sha256": digest.split(":", 1)[1]}}],
        "predicateType": predicate,
        "predicate": predicate_payload,
    }
    payload = base64.b64encode(json.dumps(statement).encode()).decode()
    bundle = {
        "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
        "verificationMaterial": {"tlogEntries": [{"logIndex": "1"}]},
        "dsseEnvelope": {
            "payloadType": "application/vnd.in-toto+json",
            "payload": payload,
            "signatures": [{"sig": "test-signature"}],
        },
    }
    return json.dumps(bundle) + "\n"


def _write_bundle(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def make_release(
    tmp_path: Path,
    *,
    bundle_content: str | None = None,
    scan_content: str = CLEAN_SCAN,
    sbom_content: str = CLEAN_SBOM,
) -> tuple[Path, Path, dict[str, Any]]:
    artifacts = tmp_path / "release-artifacts"
    artifacts.mkdir()
    images: list[dict[str, Any]] = []
    for name in REQUIRED_IMAGES:
        sbom_name = f"{name}.spdx.json"
        scan_name = f"{name}.scan.txt"
        provenance_name = f"{name}.provenance.jsonl"
        sbom_attestation_name = f"{name}.sbom-attestation.jsonl"
        (artifacts / sbom_name).write_text(sbom_content, encoding="utf-8")
        (artifacts / scan_name).write_text(scan_content, encoding="utf-8")
        if bundle_content is None:
            provenance = _bundle(DIGESTS[name], PROVENANCE_PREDICATE, {"buildDefinition": {}})
            sbom_attestation = _bundle(DIGESTS[name], SBOM_PREDICATE, json.loads(sbom_content))
        else:
            provenance = bundle_content
            sbom_attestation = bundle_content
        _write_bundle(artifacts / provenance_name, provenance)
        _write_bundle(artifacts / sbom_attestation_name, sbom_attestation)
        images.append(
            {
                "name": name,
                "digest": DIGESTS[name],
                "image_id": IMAGE_IDS[name],
                "pulled_image_id": IMAGE_IDS[name],
                "platform": "linux/amd64",
                "size_bytes": 1_000_000,
                "scan_version": "0.76.0",
                "sbom_file": sbom_name,
                "scan_log_file": scan_name,
                "provenance_bundle_file": provenance_name,
                "sbom_attestation_bundle_file": sbom_attestation_name,
            }
        )
    inputs = {
        "tag": TAG,
        "commit": COMMIT,
        "source_repository": SOURCE_REPOSITORY,
        "workflow": ".github/workflows/release.yml",
        "workflow_run_url": "https://github.com/octo/repo/actions/runs/123",
        "workflow_run_id": 123,
        "workflow_run_attempt": 1,
        "created_at": "2026-10-22T12:00:00Z",
        "gpu_runtime_smoke": "not_run",
        "gpu_runtime_smoke_reason": "no GPU hardware on this host",
        "images": images,
    }
    manifest = build_manifest(inputs, artifacts)
    manifest_path = artifacts / "release-manifest.json"
    write_manifest(manifest, manifest_path)
    return manifest_path, artifacts, manifest


def _attestation_payload(
    digest: str,
    predicate: str,
    predicate_payload: Any,
    *,
    certificate: bool = True,
) -> str:
    verification_result: dict[str, Any] = {
        "statement": {
            "predicateType": predicate,
            "subject": [{"digest": {"sha256": digest.split(":", 1)[1]}}],
            "predicate": predicate_payload,
        },
    }
    if certificate:
        verification_result["signature"] = {
            "certificate": {"subjectAlternativeName": "release.yml"},
        }
    return json.dumps([{"verificationResult": verification_result}])


def make_runner(
    *,
    registry_digest: str | None = None,
    attestation_failure: bool = False,
    bundle_signature_failure: bool = False,
    sbom_predicate_mismatch: bool = False,
    pull_failure: str | None = None,
    pulled_image_id: str | None = None,
    certificate: bool = True,
) -> Any:
    def runner(args: Any, *, timeout: int = 180, env: Any = None) -> subprocess.CompletedProcess[str]:
        del timeout, env
        if args[:3] == ["docker", "buildx", "imagetools"]:
            reference = args[-1]
            digest = reference.split("@", 1)[1] if "@" in reference else None
            base = f"ghcr.io/{SOURCE_REPOSITORY.lower()}"
            for name, expected in DIGESTS.items():
                if digest is None and (
                    reference.startswith(f"{base}/{name}:") or reference.startswith(f"{base}/{name}@")
                ):
                    digest = registry_digest or expected
                    break
            return subprocess.CompletedProcess(args, 0, (digest or "") + "\n", "")
        if args[:2] == ["docker", "pull"]:
            if pull_failure is not None:
                return subprocess.CompletedProcess(args, 1, "", pull_failure)
            return subprocess.CompletedProcess(args, 0, "pulled\n", "")
        if args[:3] == ["docker", "image", "inspect"]:
            reference = args[-1]
            name = next((name for name in REQUIRED_IMAGES if f"/{name}@" in reference), None)
            observed = pulled_image_id or IMAGE_IDS.get(name or "", "")
            return subprocess.CompletedProcess(args, 0, observed + "\n", "")
        if args[:3] == ["docker", "image", "rm"]:
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[:3] == ["gh", "attestation", "verify"]:
            if attestation_failure:
                return subprocess.CompletedProcess(args, 1, "", "not signed by trusted workflow")
            if bundle_signature_failure and "--bundle" in args:
                return subprocess.CompletedProcess(args, 1, "", "bundle signature is invalid")
            reference = args[3]
            digest = reference.rsplit("@", 1)[1]
            predicate = args[args.index("--predicate-type") + 1]
            if predicate == SBOM_PREDICATE:
                payload = (
                    {"spdxVersion": "SPDX-2.3", "packages": [{"name": "substituted"}]}
                    if sbom_predicate_mismatch
                    else CLEAN_SBOM_PAYLOAD
                )
            else:
                payload = {"buildDefinition": {}}
            return subprocess.CompletedProcess(
                args,
                0,
                _attestation_payload(digest, predicate, payload, certificate=certificate),
                "",
            )
        return subprocess.CompletedProcess(args, 1, "", "unexpected command")

    return runner


def _verify(
    manifest_path: Path,
    artifacts: Path,
    *,
    profile: str = "production",
    expected_tag: str = TAG,
    expected_commit: str = COMMIT,
    runner: Any | None = None,
    which: Any | None = None,
    repo_root: Path | None = REPO_ROOT,
    identity_verifier: Any = _accept_identity,
    main_ref: str = "origin/main",
) -> dict[str, Any]:
    return verify_release(
        manifest_path,
        artifacts_dir=artifacts,
        profile=profile,
        expected_tag=expected_tag,
        expected_commit=expected_commit,
        repo_root=repo_root,
        main_ref=main_ref,
        runner=runner or make_runner(),
        which=which or (lambda name: f"/usr/bin/{name}"),
        identity_verifier=identity_verifier,
        now=lambda: "2026-10-23T00:00:00Z",
    )


def test_production_verification_passes_with_trusted_evidence(tmp_path: Path) -> None:
    manifest_path, artifacts, _ = make_release(tmp_path)
    report = _verify(manifest_path, artifacts)
    assert report["overall_state"] == PASS
    assert report["verified"] is True
    assert report["production_verified"] is True
    assert report["generated_at"] == "2026-10-23T00:00:00Z"
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["identity"]["state"] == PASS
    assert checks["manifest"]["state"] == PASS
    assert checks["workflow-identity"]["state"] == PASS
    assert checks["digest:api"]["state"] == PASS
    assert checks["registry:api"]["state"] == PASS
    assert checks["provenance-attestation:api"]["state"] == PASS
    assert checks["sbom-attestation:api"]["state"] == PASS
    assert checks["provenance-bundle-signature:api"]["state"] == PASS
    assert checks["sbom-bundle-signature:api"]["state"] == PASS
    assert checks["gpu-artifact"]["state"] == PASS
    assert checks["gpu-runtime"]["state"] == NOT_RUN
    assert report["artifact_status"]["cpu"]["state"] == PASS
    assert report["artifact_status"]["gpu"]["state"] == PASS
    assert report["artifact_status"]["gpu"]["runtime_state"] == NOT_RUN
    assert report["artifact_status"]["gpu"]["runtime_verified"] is False
    assert report["limitations"] == [
        "gpu-runtime: NOT_RUN - GPU runtime smoke was not run: no GPU hardware on this host"
    ]


def test_local_simulated_attestations_are_not_success(tmp_path: Path) -> None:
    manifest_path, artifacts, _ = make_release(tmp_path, bundle_content=SIMULATED_BUNDLE)
    report = _verify(manifest_path, artifacts, profile="local")
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["provenance-bundle:api"]["state"] == SIMULATED
    assert checks["sbom-attestation-bundle:api"]["state"] == SIMULATED
    assert report["overall_state"] == SIMULATED
    assert report["verified"] is False
    assert report["production_verified"] is False


def test_production_rejects_simulated_attestations(tmp_path: Path) -> None:
    manifest_path, artifacts, _ = make_release(tmp_path, bundle_content=SIMULATED_BUNDLE)
    report = _verify(manifest_path, artifacts)
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["provenance-bundle:api"]["state"] == SIMULATED
    assert checks["provenance-bundle:api"]["required"] is True
    assert report["overall_state"] == SIMULATED
    assert report["verified"] is False
    assert report["production_verified"] is False


def test_sbom_hash_mismatch_fails(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest = make_release(tmp_path)
    tampered = copy.deepcopy(manifest)
    tampered["images"][0]["sbom"]["sha256"] = "sha256:" + "0" * 64
    write_manifest(tampered, manifest_path)
    report = _verify(manifest_path, artifacts, profile="local")
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["manifest"]["state"] == FAIL
    assert checks["sbom:api"]["state"] == FAIL
    assert report["verified"] is False


def test_missing_scan_evidence_fails(tmp_path: Path) -> None:
    manifest_path, artifacts, _ = make_release(tmp_path)
    (artifacts / "api.scan.txt").unlink()
    report = _verify(manifest_path, artifacts, profile="local")
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["manifest"]["state"] == FAIL
    assert checks["scan:api"]["state"] == FAIL
    assert "scan log" in checks["scan:api"]["detail"] or "does not exist" in checks["scan:api"]["detail"]


def test_missing_provenance_evidence_fails(tmp_path: Path) -> None:
    manifest_path, artifacts, _ = make_release(tmp_path)
    (artifacts / "api.provenance.jsonl").unlink()
    report = _verify(manifest_path, artifacts, profile="local")
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["manifest"]["state"] == FAIL
    assert checks["provenance-bundle:api"]["state"] == FAIL
    assert "does not exist" in checks["provenance-bundle:api"]["detail"]


def test_scan_with_high_finding_fails(tmp_path: Path) -> None:
    manifest_path, artifacts, _ = make_release(
        tmp_path,
        scan_content=(
            "Report Summary\n"
            "| Target | Type | Vulnerabilities |\n"
            "| image | debian | 1 |\n"
            "| openssl | HIGH |\n"
        ),
    )
    report = _verify(manifest_path, artifacts, profile="local")
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["scan:api"]["state"] == FAIL


def test_simulated_scan_is_not_success(tmp_path: Path) -> None:
    manifest_path, artifacts, _ = make_release(
        tmp_path, scan_content="SIMULATED EVIDENCE - no scanner was run\n"
    )
    report = _verify(manifest_path, artifacts, profile="local")
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["scan:api"]["state"] == SIMULATED
    assert report["overall_state"] == SIMULATED
    assert report["verified"] is False


def test_registry_digest_mismatch_fails(tmp_path: Path) -> None:
    manifest_path, artifacts, _ = make_release(tmp_path)
    wrong = "sha256:" + "1" * 64
    report = _verify(manifest_path, artifacts, runner=make_runner(registry_digest=wrong))
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["registry:api"]["state"] == FAIL
    assert report["overall_state"] == FAIL
    assert report["production_verified"] is False


def test_registry_pull_image_id_mismatch_fails(tmp_path: Path) -> None:
    manifest_path, artifacts, _ = make_release(tmp_path)
    wrong = "sha256:" + "f" * 64
    report = _verify(manifest_path, artifacts, runner=make_runner(pulled_image_id=wrong))
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["registry:api"]["state"] == FAIL
    assert "image ID" in checks["registry:api"]["detail"]


def test_registry_missing_artifact_fails(tmp_path: Path) -> None:
    manifest_path, artifacts, _ = make_release(tmp_path)
    report = _verify(manifest_path, artifacts, runner=make_runner(pull_failure="manifest unknown"))
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["registry:api"]["state"] == FAIL
    assert report["overall_state"] == FAIL


def test_registry_credentials_unavailable_is_not_success(tmp_path: Path) -> None:
    manifest_path, artifacts, _ = make_release(tmp_path)
    report = _verify(
        manifest_path, artifacts, runner=make_runner(pull_failure="unauthorized: authentication required")
    )
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["registry:api"]["state"] == UNAVAILABLE
    assert report["overall_state"] == UNAVAILABLE
    assert report["verified"] is False


def test_untrusted_attestation_fails(tmp_path: Path) -> None:
    manifest_path, artifacts, _ = make_release(tmp_path)
    report = _verify(manifest_path, artifacts, runner=make_runner(attestation_failure=True))
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["provenance-attestation:api"]["state"] == FAIL
    assert "rejected" in checks["provenance-attestation:api"]["detail"]
    assert report["overall_state"] == FAIL
    assert report["production_verified"] is False


def test_bundle_signature_failure_fails(tmp_path: Path) -> None:
    manifest_path, artifacts, _ = make_release(tmp_path)
    report = _verify(manifest_path, artifacts, runner=make_runner(bundle_signature_failure=True))
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["provenance-bundle-signature:api"]["state"] == FAIL
    assert report["overall_state"] == FAIL


def test_attestation_without_certificate_fails(tmp_path: Path) -> None:
    manifest_path, artifacts, _ = make_release(tmp_path)
    report = _verify(manifest_path, artifacts, runner=make_runner(certificate=False))
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["provenance-attestation:api"]["state"] == FAIL


def test_sbom_attestation_predicate_mismatch_fails(tmp_path: Path) -> None:
    manifest_path, artifacts, _ = make_release(tmp_path)
    report = _verify(manifest_path, artifacts, runner=make_runner(sbom_predicate_mismatch=True))
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["sbom-attestation:api"]["state"] == FAIL
    assert "does not match" in checks["sbom-attestation:api"]["detail"]


def test_bundle_statement_digest_mismatch_fails(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest = make_release(tmp_path)
    wrong = "sha256:" + "9" * 64
    tampered_bundle = _bundle(wrong, PROVENANCE_PREDICATE, {"buildDefinition": {}})
    (artifacts / "api.provenance.jsonl").write_text(tampered_bundle, encoding="utf-8")
    tampered = copy.deepcopy(manifest)
    tampered["images"][0]["provenance"]["evidence"]["sha256"] = manifest_module.sha256_file(
        artifacts / "api.provenance.jsonl"
    )
    write_manifest(tampered, manifest_path)
    report = _verify(manifest_path, artifacts, profile="local")
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["provenance-bundle:api"]["state"] == FAIL
    assert "does not bind" in checks["provenance-bundle:api"]["detail"]


def test_identity_mismatch_fails(tmp_path: Path) -> None:
    manifest_path, artifacts, _ = make_release(tmp_path)
    report = _verify(manifest_path, artifacts, profile="local", expected_tag="v9.9.9")
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["identity"]["state"] == FAIL
    assert checks["manifest"]["state"] == FAIL
    assert report["verified"] is False


def test_production_requires_expected_identity(tmp_path: Path) -> None:
    manifest_path, artifacts, _ = make_release(tmp_path)
    report = verify_release(
        manifest_path,
        artifacts_dir=artifacts,
        profile="production",
        runner=make_runner(),
        which=lambda name: f"/usr/bin/{name}",
        identity_verifier=_accept_identity,
    )
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["identity"]["state"] == FAIL
    assert checks["source-identity"]["state"] == FAIL
    assert report["production_verified"] is False


def test_production_requires_repository_identity(tmp_path: Path) -> None:
    manifest_path, artifacts, _ = make_release(tmp_path)
    report = _verify(manifest_path, artifacts, repo_root=None)
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["source-identity"]["state"] == FAIL
    assert report["production_verified"] is False


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _repo(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "release-tests@example.test")
    _git(repo, "config", "user.name", "Release Tests")
    (repo / "file.txt").write_text("one\n", encoding="utf-8")
    _git(repo, "add", "file.txt")
    _git(repo, "commit", "-m", "one")
    _git(repo, "branch", "-M", "main")
    return repo, _git(repo, "rev-parse", "HEAD")


def test_source_identity_tag_mismatch_fails(tmp_path: Path) -> None:
    manifest_path, artifacts, _ = make_release(tmp_path)
    repo, _ = _repo(tmp_path)
    _git(repo, "tag", TAG)
    report = _verify(
        manifest_path,
        artifacts,
        repo_root=repo,
        identity_verifier=verify_tag_commit,
    )
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["source-identity"]["state"] == FAIL
    assert "points at" in checks["source-identity"]["detail"]


def test_source_identity_branch_policy_fails(tmp_path: Path) -> None:
    manifest_path, artifacts, _ = make_release(tmp_path)
    repo, commit = _repo(tmp_path)
    _git(repo, "checkout", "-b", "feature")
    (repo / "file.txt").write_text("feature\n", encoding="utf-8")
    _git(repo, "commit", "-am", "feature")
    feature = _git(repo, "rev-parse", "HEAD")
    _git(repo, "tag", TAG)
    _git(repo, "checkout", "main")
    report = verify_release(
        manifest_path,
        artifacts_dir=artifacts,
        profile="local",
        expected_tag=TAG,
        expected_commit=feature,
        repo_root=repo,
        runner=make_runner(),
        which=lambda name: f"/usr/bin/{name}",
        identity_verifier=verify_tag_commit,
        main_ref="main",
    )
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["source-identity"]["state"] == FAIL
    assert "not reachable from main" in checks["source-identity"]["detail"]
    assert commit != feature


def test_workflow_identity_mismatch_fails(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest = make_release(tmp_path)
    tampered = copy.deepcopy(manifest)
    tampered["build"]["workflow"] = ".github/workflows/other.yml"
    write_manifest(tampered, manifest_path)
    report = _verify(manifest_path, artifacts, profile="local")
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["workflow-identity"]["state"] == FAIL
    assert report["verified"] is False


def test_missing_image_is_rejected(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest = make_release(tmp_path)
    tampered = copy.deepcopy(manifest)
    tampered["images"] = [image for image in tampered["images"] if image["name"] != "api"]
    write_manifest(tampered, manifest_path)
    report = _verify(manifest_path, artifacts, profile="local")
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["manifest"]["state"] == FAIL
    assert checks["sbom:api"]["state"] == FAIL
    assert checks["gpu-artifact"]["state"] == PASS
    assert report["artifact_status"]["cpu"]["state"] == FAIL
    assert report["verified"] is False


def test_missing_gpu_image_is_rejected(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest = make_release(tmp_path)
    tampered = copy.deepcopy(manifest)
    tampered["images"] = [image for image in tampered["images"] if image["name"] != "api-gpu"]
    write_manifest(tampered, manifest_path)
    report = _verify(manifest_path, artifacts, profile="local")
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["gpu-artifact"]["state"] == FAIL
    assert report["artifact_status"]["gpu"]["state"] == FAIL
    assert report["artifact_status"]["gpu"]["runtime_verified"] is False
    assert report["verified"] is False


def test_placeholder_digest_is_rejected(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest = make_release(tmp_path)
    tampered = copy.deepcopy(manifest)
    tampered["images"][0]["digest"] = "sha256:" + "0" * 64
    write_manifest(tampered, manifest_path)
    report = _verify(manifest_path, artifacts, profile="local")
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["digest:api"]["state"] == FAIL
    assert "placeholder" in checks["digest:api"]["detail"]
    assert report["verified"] is False


def test_incomplete_manifest_is_rejected(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest = make_release(tmp_path)
    tampered = copy.deepcopy(manifest)
    del tampered["variants"]
    write_manifest(tampered, manifest_path)
    report = _verify(manifest_path, artifacts, profile="local")
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["manifest"]["state"] == FAIL
    assert checks["gpu-artifact"]["state"] == FAIL
    assert report["verified"] is False


def test_missing_tools_are_unavailable_not_pass(tmp_path: Path) -> None:
    manifest_path, artifacts, _ = make_release(tmp_path)
    report = _verify(manifest_path, artifacts, which=lambda name: None)
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["registry:api"]["state"] == UNAVAILABLE
    assert checks["provenance-attestation:api"]["state"] == UNAVAILABLE
    assert report["verified"] is False


def test_v22_manifest_remains_supported(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest = make_release(tmp_path)
    assert manifest["schema_version"] == 1
    report = _verify(manifest_path, artifacts, profile="local")
    assert report["overall_state"] == PASS
    assert report["artifact_status"]["cpu"]["state"] == PASS


def test_verification_schema_matches_contract() -> None:
    schema = json.loads(
        (REPO_ROOT / "release" / "release-verification.schema.json").read_text(encoding="utf-8")
    )
    assert set(schema["required"]) == set(verification_module.REPORT_FIELDS)
    assert schema["properties"]["schema_version"]["const"] == (
        verification_module.VERIFICATION_SCHEMA_VERSION
    )
    assert set(schema["properties"]["subject"]["required"]) == set(verification_module.SUBJECT_FIELDS)
    assert set(schema["properties"]["checks"]["items"]["required"]) == set(verification_module.CHECK_FIELDS)
    assert set(schema["properties"]["artifact_status"]["required"]) == set(
        verification_module.ARTIFACT_FIELDS
    )
    artifact = schema["$defs"]["artifact"]
    assert set(artifact["required"]) == set(verification_module.ARTIFACT_STATUS_FIELDS)
    assert schema["properties"]["overall_state"]["enum"] == list(verification_module.EVIDENCE_STATES)
    assert set(schema["properties"]["profile"]["enum"]) == set(verification_module.PROFILES)
    assert set(manifest_module.TOP_LEVEL_FIELDS) == {
        "schema_version",
        "release",
        "build",
        "images",
        "variants",
    }


def test_attestation_predicates_are_bound(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest = make_release(tmp_path)
    report = _verify(manifest_path, artifacts)
    commands = " ".join(
        str(check.get("command"))
        for check in report["checks"]
        if check["name"].endswith("-attestation:api") or check["name"].endswith("-signature:api")
    )
    assert "--signer-workflow octo/repo/.github/workflows/release.yml" in commands
    assert "--source-digest " + COMMIT in commands
    assert f"--source-ref refs/tags/{TAG}" in commands
    assert "--deny-self-hosted-runners" in commands
    assert PROVENANCE_PREDICATE in commands
    assert SBOM_PREDICATE in commands
    assert manifest["release"]["tag"] == TAG
