"""V24 live release qualification and evidence-binding tests."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from backend.tests.unit.test_release_verification import (
    COMMIT,
    DIGESTS,
    REPO_ROOT,
    SIMULATED_BUNDLE,
    SOURCE_REPOSITORY,
    TAG,
    make_release,
    make_runner,
)
from tools.release.manifest import load_manifest, sha256_file, write_manifest
from tools.release.publication import build_publication_report, write_publication_report
from tools.release.qualification import (
    ARTIFACT_FIELDS,
    CHECK_FIELDS,
    DEPLOYMENT_REQUIRED_CHECKS,
    EVIDENCE_FIELDS,
    FAIL,
    GPU_REQUIRED_CHECKS,
    NOT_RUN,
    PASS,
    QUALIFICATION_FIELDS,
    QUALIFICATION_PROFILES,
    REHEARSAL_REQUIRED_CHECKS,
    SCOPES,
    SUBJECT_FIELDS,
    qualification_report_errors,
    qualify_release,
    render_qualification_summary,
    write_qualification_report,
)
from tools.release.rehearsal import STEP_NAMES
from tools.release.verification import verify_release, write_verification_report

GENERATED_AT = "2026-10-24T00:00:00Z"


def _accept_identity(*args: Any, **kwargs: Any) -> None:
    del args, kwargs


def _subject(manifest: dict[str, Any]) -> dict[str, Any]:
    release = manifest["release"]
    return {
        "tag": release["tag"],
        "commit": release["commit"],
        "source_repository": release["source_repository"],
    }


def _verification(
    manifest_path: Path,
    artifacts: Path,
    *,
    profile: str = "production",
) -> tuple[Path, dict[str, Any]]:
    report = verify_release(
        manifest_path,
        artifacts_dir=artifacts,
        profile=profile,
        expected_tag=TAG,
        expected_commit=COMMIT,
        repo_root=REPO_ROOT,
        identity_verifier=_accept_identity,
        runner=make_runner(),
        which=lambda name: f"/usr/bin/{name}",
        now=lambda: "2026-10-23T00:00:00Z",
    )
    path = artifacts / "release-verification.json"
    write_verification_report(report, path)
    return path, report


def _publication(
    artifacts: Path,
    manifest: dict[str, Any],
) -> tuple[Path, dict[str, Any]]:
    events = []
    for image in manifest["images"]:
        events.append(
            {
                "image": image["name"],
                "status": "pushed",
                "tag": TAG,
                "repository": image["repository"],
                "digest": image["digest"],
                "image_id": image["image_id"],
                "timestamp": "2026-10-23T00:00:00Z",
            }
        )
    events_path = artifacts / "published-images.jsonl"
    events_path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")
    report = build_publication_report(
        events_path,
        tag=TAG,
        source_repository=SOURCE_REPOSITORY,
        now=lambda: "2026-10-23T00:00:00Z",
    )
    path = artifacts / "publication-report.json"
    write_publication_report(report, path)
    return path, report


def _passing_checks(names: tuple[str, ...]) -> list[dict[str, Any]]:
    return [
        {
            "name": name,
            "state": PASS,
            "required": True,
            "detail": "test evidence",
            "command": None,
        }
        for name in names
    ]


def _deployment(
    artifacts: Path,
    manifest_path: Path,
    manifest: dict[str, Any],
    **overrides: Any,
) -> Path:
    payload: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": GENERATED_AT,
        "manifest_sha256": sha256_file(manifest_path),
        "subject": _subject(manifest),
        "state": PASS,
        "gpu": True,
        "checks": _passing_checks(DEPLOYMENT_REQUIRED_CHECKS),
    }
    payload.update(overrides)
    path = artifacts / "deployment-report.json"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def _rehearsal(
    artifacts: Path,
    manifest_path: Path,
    manifest: dict[str, Any],
    **overrides: Any,
) -> Path:
    previous_sha = "sha256:" + "b" * 64
    previous_subject = {
        "tag": "v1.2.2",
        "commit": "b" * 40,
        "source_repository": SOURCE_REPOSITORY,
    }
    target_digests = {image["name"]: image["digest"] for image in manifest["images"]}
    previous_digests = {
        name: "sha256:" + hashlib.sha256(f"previous-{name}".encode()).hexdigest() for name in target_digests
    }
    evidence_path = artifacts / "previous-rollback-deployment.json"
    evidence_path.write_text(
        json.dumps({"kind": "previous-deployment", "state": PASS}) + "\n",
        encoding="utf-8",
    )
    payload: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": GENERATED_AT,
        "executed": True,
        "state": PASS,
        "verified": True,
        "manifest_sha256": sha256_file(manifest_path),
        "subject": _subject(manifest),
        "previous_manifest_sha256": previous_sha,
        "previous_subject": previous_subject,
        "target": {
            "manifest_sha256": sha256_file(manifest_path),
            "subject": _subject(manifest),
            "digests": target_digests,
        },
        "previous": {
            "manifest_sha256": previous_sha,
            "subject": previous_subject,
            "digests": previous_digests,
        },
        "checks": _passing_checks(REHEARSAL_REQUIRED_CHECKS),
        "steps": [
            {
                "name": name,
                "state": PASS,
                "detail": "test step",
                "commands": [],
                "checks": [],
                "deployment": None,
                "smoke": None,
                "evidence": [],
            }
            for name in STEP_NAMES
        ],
        "evidence": [
            {
                "kind": "previous-deployment",
                "path": evidence_path.name,
                "sha256": sha256_file(evidence_path),
            }
        ],
    }
    payload.update(overrides)
    path = artifacts / "rollback-rehearsal.json"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def _gpu(
    artifacts: Path,
    manifest_path: Path,
    manifest: dict[str, Any],
    **overrides: Any,
) -> Path:
    api_gpu = next(image for image in manifest["images"] if image["name"] == "api-gpu")
    payload: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": GENERATED_AT,
        "executed": True,
        "state": PASS,
        "verified": True,
        "manifest_sha256": sha256_file(manifest_path),
        "subject": _subject(manifest),
        "gpu": {
            "name": "NVIDIA A10",
            "driver_version": "535.104.05",
            "memory": "24564 MiB",
            "runtime": "nvidia",
            "image": f"{api_gpu['repository']}@{api_gpu['digest']}",
            "image_digest": api_gpu["digest"],
            "container_cuda": True,
        },
        "checks": _passing_checks(GPU_REQUIRED_CHECKS),
    }
    payload.update(overrides)
    path = artifacts / "gpu-runtime.json"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def _qualify(manifest_path: Path, artifacts: Path, **overrides: Any) -> dict[str, Any]:
    options: dict[str, Any] = {
        "artifacts_dir": artifacts,
        "profile": "production_qualification",
        "scope": "full",
        "expected_tag": TAG,
        "expected_commit": COMMIT,
        "expected_repository": SOURCE_REPOSITORY,
        "repo_root": REPO_ROOT,
        "identity_verifier": _accept_identity,
        "now": lambda: GENERATED_AT,
    }
    options.update(overrides)
    return qualify_release(manifest_path, **options)


def _full_evidence(
    tmp_path: Path,
) -> tuple[Path, Path, dict[str, Any], dict[str, Path]]:
    manifest_path, artifacts, manifest = make_release(tmp_path)
    verification_path, _ = _verification(manifest_path, artifacts)
    publication_path, _ = _publication(artifacts, manifest)
    return (
        manifest_path,
        artifacts,
        manifest,
        {
            "verification_report_path": verification_path,
            "publication_report_path": publication_path,
            "deployment_report_path": _deployment(artifacts, manifest_path, manifest),
            "rehearsal_report_path": _rehearsal(artifacts, manifest_path, manifest),
            "gpu_report_path": _gpu(artifacts, manifest_path, manifest),
        },
    )


def test_local_artifact_qualification_passes_with_bound_evidence(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest = make_release(tmp_path)
    verification_path, _ = _verification(manifest_path, artifacts, profile="local")
    report = _qualify(
        manifest_path,
        artifacts,
        profile="local_validation",
        scope="artifact",
        verification_report_path=verification_path,
    )
    assert report["overall_state"] == PASS
    assert report["qualified"] is True
    assert report["production_qualified"] is False
    assert report["generated_at"] == GENERATED_AT
    assert report["manifest_sha256"] == sha256_file(manifest_path)
    assert report["verification"]["profile"] == "local"
    assert report["verification"]["sha256"] == sha256_file(verification_path)
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["publication-report"]["state"] == NOT_RUN
    assert checks["attestation-trust:api"]["state"] == NOT_RUN
    assert checks["deployment-report"]["state"] == NOT_RUN
    assert checks["rollback-rehearsal"]["state"] == NOT_RUN
    assert checks["gpu-runtime"]["state"] == NOT_RUN
    evidence = {item["kind"]: item for item in report["evidence"]}
    assert evidence["manifest"]["sha256"] == sha256_file(manifest_path)
    assert evidence["verification-report"]["sha256"] == sha256_file(verification_path)
    images = {image["name"]: image for image in manifest["images"]}
    for name in ("api", "web", "api-gpu"):
        assert evidence[f"sbom:{name}"]["sha256"] == images[name]["sbom"]["sha256"]
        assert evidence[f"scan:{name}"]["sha256"] == images[name]["scan"]["log"]["sha256"]
        assert evidence[f"provenance:{name}"]["sha256"] == images[name]["provenance"]["evidence"]["sha256"]
        assert (
            evidence[f"sbom-attestation:{name}"]["sha256"]
            == images[name]["sbom_attestation"]["evidence"]["sha256"]
        )
    assert "production_qualified=False" in render_qualification_summary(report)


def test_local_artifact_qualification_requires_complete_publication_with_live_evidence(
    tmp_path: Path,
) -> None:
    manifest_path, artifacts, manifest = make_release(tmp_path)
    verification_path, _ = _verification(manifest_path, artifacts)
    publication_path, _ = _publication(artifacts, manifest)
    report = _qualify(
        manifest_path,
        artifacts,
        profile="local_validation",
        scope="artifact",
        verification_report_path=verification_path,
        publication_report_path=publication_path,
        require_live_evidence=True,
    )
    assert report["qualified"] is True
    assert report["publication"]["complete"] is True
    assert report["publication"]["digests"] == DIGESTS


def test_production_full_qualification_passes(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest, evidence = _full_evidence(tmp_path)
    report = _qualify(manifest_path, artifacts, **evidence)
    assert report["overall_state"] == PASS
    assert report["qualified"] is True
    assert report["production_qualified"] is True
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["verification-report"]["state"] == PASS
    assert checks["publication-report"]["state"] == PASS
    assert checks["deployment-report"]["state"] == PASS
    assert checks["rollback-rehearsal"]["state"] == PASS
    assert checks["gpu-runtime"]["state"] == PASS
    assert checks["attestation-trust:api"]["state"] == PASS
    kinds = {item["kind"] for item in report["evidence"]}
    assert {
        "manifest",
        "verification-report",
        "publication-report",
        "deployment-report",
        "rollback-rehearsal",
        "gpu-runtime",
    } <= kinds
    assert report["artifacts"]
    assert all(artifact["state"] == PASS for artifact in report["artifacts"])
    assert report["blockers"] == []


def test_production_qualification_requires_gpu_runtime(tmp_path: Path) -> None:
    manifest_path, artifacts, _, evidence = _full_evidence(tmp_path)
    evidence.pop("gpu_report_path")
    report = _qualify(manifest_path, artifacts, **evidence)
    assert report["overall_state"] == FAIL
    assert report["qualified"] is False
    assert report["production_qualified"] is False
    assert any(blocker.startswith("gpu-runtime:") for blocker in report["blockers"])


def test_full_scope_requires_rollback_rehearsal(tmp_path: Path) -> None:
    manifest_path, artifacts, _, evidence = _full_evidence(tmp_path)
    evidence.pop("rehearsal_report_path")
    report = _qualify(manifest_path, artifacts, **evidence)
    assert report["overall_state"] == FAIL
    assert report["qualified"] is False
    assert any(blocker.startswith("rollback-rehearsal:") for blocker in report["blockers"])


def test_deployment_scope_requires_bound_deployment_report(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest, evidence = _full_evidence(tmp_path)
    evidence["deployment_report_path"] = _deployment(
        artifacts,
        manifest_path,
        manifest,
        manifest_sha256="sha256:" + "0" * 64,
    )
    report = _qualify(manifest_path, artifacts, **evidence)
    assert report["overall_state"] == FAIL
    assert any(blocker.startswith("deployment-report:") for blocker in report["blockers"])
    assert "manifest_sha256 mismatch" in " ".join(report["blockers"])


def test_publication_digest_mismatch_fails_qualification(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest, evidence = _full_evidence(tmp_path)
    publication_path = evidence["publication_report_path"]
    payload = json.loads(publication_path.read_text(encoding="utf-8"))
    payload["digests"]["api"] = "sha256:" + "1" * 64
    publication_path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    report = _qualify(manifest_path, artifacts, **evidence)
    assert report["overall_state"] == FAIL
    assert any(blocker.startswith("publication-report:") for blocker in report["blockers"])
    assert "digest for api" in " ".join(report["blockers"])


def test_manifest_change_invalidates_qualification_report(tmp_path: Path) -> None:
    manifest_path, artifacts, _, evidence = _full_evidence(tmp_path)
    report = _qualify(manifest_path, artifacts, **evidence)
    assert report["qualified"] is True
    write_qualification_report(report, artifacts / "release-qualification.json")
    manifest = load_manifest(manifest_path)
    manifest["release"]["created_at"] = "2026-10-25T00:00:00Z"
    write_manifest(manifest, manifest_path)
    errors = qualification_report_errors(
        report,
        manifest,
        manifest_path=manifest_path,
        require_production=True,
    )
    assert any("manifest_sha256" in error for error in errors)
    assert any("verification binding" in error for error in errors)


def test_check_qualification_rejects_artifact_scope_for_production(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest = make_release(tmp_path)
    verification_path, _ = _verification(manifest_path, artifacts, profile="local")
    report = _qualify(
        manifest_path,
        artifacts,
        profile="local_validation",
        scope="artifact",
        verification_report_path=verification_path,
    )
    errors = qualification_report_errors(
        report,
        manifest,
        manifest_path=manifest_path,
        require_production=True,
    )
    assert any("production_qualification" in error for error in errors)
    assert any("scope must be 'full'" in error for error in errors)
    assert any("production_qualified" in error for error in errors)
    assert any("profile must be 'production'" in error for error in errors)


def test_check_qualification_accepts_full_production_report(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest, evidence = _full_evidence(tmp_path)
    report = _qualify(manifest_path, artifacts, **evidence)
    assert (
        qualification_report_errors(
            report,
            manifest,
            manifest_path=manifest_path,
            require_production=True,
            verification_report_path=evidence["verification_report_path"],
            publication_report_path=evidence["publication_report_path"],
            deployment_report_path=evidence["deployment_report_path"],
            rehearsal_report_path=evidence["rehearsal_report_path"],
            gpu_report_path=evidence["gpu_report_path"],
        )
        == []
    )


def test_check_qualification_rejects_changed_evidence_files(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest, evidence = _full_evidence(tmp_path)
    report = _qualify(manifest_path, artifacts, **evidence)
    evidence["verification_report_path"].write_text(
        evidence["verification_report_path"].read_text(encoding="utf-8") + "\n",
        encoding="utf-8",
    )
    evidence["publication_report_path"].write_text(
        evidence["publication_report_path"].read_text(encoding="utf-8") + "\n",
        encoding="utf-8",
    )
    errors = qualification_report_errors(
        report,
        manifest,
        manifest_path=manifest_path,
        require_production=True,
        verification_report_path=evidence["verification_report_path"],
        publication_report_path=evidence["publication_report_path"],
    )
    assert any("supplied verification report" in error for error in errors)
    assert any("supplied publication report" in error for error in errors)


def test_simulated_attestation_bundle_cannot_qualify(tmp_path: Path) -> None:
    manifest_path, artifacts, _ = make_release(tmp_path, bundle_content=SIMULATED_BUNDLE)
    verification_path, verification = _verification(manifest_path, artifacts, profile="local")
    assert verification["overall_state"] != PASS
    report = _qualify(
        manifest_path,
        artifacts,
        profile="local_validation",
        scope="artifact",
        verification_report_path=verification_path,
    )
    assert report["overall_state"] == FAIL
    assert report["qualified"] is False
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["verification-report"]["state"] == FAIL
    assert checks["attestation-bundle:api"]["state"] != PASS


def test_qualification_schema_matches_contract() -> None:
    schema = json.loads(
        (REPO_ROOT / "release" / "release-qualification.schema.json").read_text(encoding="utf-8")
    )
    assert set(schema["required"]) == set(QUALIFICATION_FIELDS)
    assert schema["properties"]["schema_version"]["const"] == 1
    assert set(schema["$defs"]["subject"]["required"]) == set(SUBJECT_FIELDS)
    assert set(schema["$defs"]["check"]["required"]) == set(CHECK_FIELDS)
    assert set(schema["$defs"]["artifact"]["required"]) == set(ARTIFACT_FIELDS)
    assert set(schema["$defs"]["evidence"]["required"]) == set(EVIDENCE_FIELDS)
    assert set(schema["properties"]["profile"]["enum"]) == set(QUALIFICATION_PROFILES)
    assert set(schema["properties"]["scope"]["enum"]) == set(SCOPES)
    assert "manifest_sha256" in schema["$defs"]["deploymentBinding"]["required"]
    assert "executed" in schema["$defs"]["rehearsalBinding"]["required"]
    assert "executed" in schema["$defs"]["gpuBinding"]["required"]


def _mutate(path: Path, mutate: Callable[[dict[str, Any]], None]) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    mutate(payload)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def test_production_rejects_unexecuted_rollback_rehearsal(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest, evidence = _full_evidence(tmp_path)
    evidence["rehearsal_report_path"] = _rehearsal(
        artifacts,
        manifest_path,
        manifest,
        executed=False,
        state=NOT_RUN,
        verified=False,
    )
    report = _qualify(manifest_path, artifacts, **evidence)
    assert report["overall_state"] == FAIL
    assert report["qualified"] is False
    assert report["production_qualified"] is False
    assert "rollback rehearsal was not executed" in " ".join(report["blockers"])


def test_production_rejects_rehearsal_evidence_hash_mismatch(tmp_path: Path) -> None:
    manifest_path, artifacts, _, evidence = _full_evidence(tmp_path)
    evidence_file = artifacts / "previous-rollback-deployment.json"
    evidence_file.write_text(
        evidence_file.read_text(encoding="utf-8") + "\n",
        encoding="utf-8",
    )
    report = _qualify(manifest_path, artifacts, **evidence)
    assert report["qualified"] is False
    assert "evidence hash does not match" in " ".join(report["blockers"])


def test_production_rejects_missing_rehearsal_evidence_file(tmp_path: Path) -> None:
    manifest_path, artifacts, _, evidence = _full_evidence(tmp_path)
    (artifacts / "previous-rollback-deployment.json").unlink()
    report = _qualify(manifest_path, artifacts, **evidence)
    assert report["qualified"] is False
    assert "evidence file is missing" in " ".join(report["blockers"])


def test_production_rejects_rehearsal_evidence_outside_report_directory(tmp_path: Path) -> None:
    manifest_path, artifacts, _, evidence = _full_evidence(tmp_path)
    report_path = evidence["rehearsal_report_path"]
    nested = artifacts / "nested" / report_path.name
    nested.parent.mkdir()
    nested.write_text(report_path.read_text(encoding="utf-8"), encoding="utf-8")
    evidence["rehearsal_report_path"] = nested
    report = _qualify(manifest_path, artifacts, **evidence)
    assert report["qualified"] is False
    assert "evidence file is missing" in " ".join(report["blockers"])


def test_production_rejects_failed_rehearsal_step(tmp_path: Path) -> None:
    manifest_path, artifacts, _, evidence = _full_evidence(tmp_path)

    def fail_verify_target(payload: dict[str, Any]) -> None:
        for step in payload["steps"]:
            if step["name"] == "verify-target":
                step["state"] = FAIL

    _mutate(evidence["rehearsal_report_path"], fail_verify_target)
    report = _qualify(manifest_path, artifacts, **evidence)
    assert report["qualified"] is False
    assert "rollback rehearsal step verify-target is 'FAIL', not PASS" in " ".join(report["blockers"])


def test_production_rejects_rehearsal_target_digest_mismatch(tmp_path: Path) -> None:
    manifest_path, artifacts, _, evidence = _full_evidence(tmp_path)

    def change_target_digest(payload: dict[str, Any]) -> None:
        payload["target"]["digests"]["api"] = "sha256:" + "9" * 64

    _mutate(evidence["rehearsal_report_path"], change_target_digest)
    report = _qualify(manifest_path, artifacts, **evidence)
    assert report["qualified"] is False
    assert "rollback rehearsal target digest for api does not match the manifest" in " ".join(
        report["blockers"]
    )


def test_production_rejects_rehearsal_previous_digest_coverage_gap(tmp_path: Path) -> None:
    manifest_path, artifacts, _, evidence = _full_evidence(tmp_path)

    def drop_previous_digest(payload: dict[str, Any]) -> None:
        payload["previous"]["digests"].pop("web")

    _mutate(evidence["rehearsal_report_path"], drop_previous_digest)
    report = _qualify(manifest_path, artifacts, **evidence)
    assert report["qualified"] is False
    assert "rollback rehearsal previous digests do not cover the target images" in " ".join(
        report["blockers"]
    )


def test_production_rejects_cpu_only_deployment(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest, evidence = _full_evidence(tmp_path)
    _deployment(artifacts, manifest_path, manifest, gpu=False)
    report = _qualify(manifest_path, artifacts, **evidence)
    assert report["qualified"] is False
    assert report["production_qualified"] is False
    assert "deployment report does not prove a GPU deployment" in " ".join(report["blockers"])


def test_production_rejects_failed_deployment_check(tmp_path: Path) -> None:
    manifest_path, artifacts, _, evidence = _full_evidence(tmp_path)

    def fail_preflight(payload: dict[str, Any]) -> None:
        for check in payload["checks"]:
            if check["name"] == "preflight":
                check["state"] = FAIL

    _mutate(evidence["deployment_report_path"], fail_preflight)
    report = _qualify(manifest_path, artifacts, **evidence)
    assert report["qualified"] is False
    assert "deployment report check preflight is 'FAIL', not PASS" in " ".join(report["blockers"])


def test_production_rejects_missing_deployment_preflight_check(tmp_path: Path) -> None:
    manifest_path, artifacts, _, evidence = _full_evidence(tmp_path)

    def remove_preflight(payload: dict[str, Any]) -> None:
        payload["checks"] = [check for check in payload["checks"] if check["name"] != "preflight"]

    _mutate(evidence["deployment_report_path"], remove_preflight)
    report = _qualify(manifest_path, artifacts, **evidence)
    assert report["qualified"] is False
    assert "deployment report has no preflight check" in " ".join(report["blockers"])


def test_production_rejects_gpu_runtime_without_container_cuda(tmp_path: Path) -> None:
    manifest_path, artifacts, _, evidence = _full_evidence(tmp_path)

    def disable_cuda(payload: dict[str, Any]) -> None:
        payload["gpu"]["container_cuda"] = False

    _mutate(evidence["gpu_report_path"], disable_cuda)
    report = _qualify(manifest_path, artifacts, **evidence)
    assert report["qualified"] is False
    assert report["production_qualified"] is False
    assert "does not prove container CUDA access" in " ".join(report["blockers"])


def test_production_rejects_unexecuted_gpu_runtime(tmp_path: Path) -> None:
    manifest_path, artifacts, _, evidence = _full_evidence(tmp_path)

    def mark_unexecuted(payload: dict[str, Any]) -> None:
        payload["executed"] = False

    _mutate(evidence["gpu_report_path"], mark_unexecuted)
    report = _qualify(manifest_path, artifacts, **evidence)
    assert report["qualified"] is False
    assert "GPU runtime qualification was not executed" in " ".join(report["blockers"])


def test_production_rejects_gpu_runtime_digest_mismatch(tmp_path: Path) -> None:
    manifest_path, artifacts, _, evidence = _full_evidence(tmp_path)

    def change_gpu_digest(payload: dict[str, Any]) -> None:
        payload["gpu"]["image_digest"] = "sha256:" + "9" * 64

    _mutate(evidence["gpu_report_path"], change_gpu_digest)
    report = _qualify(manifest_path, artifacts, **evidence)
    assert report["qualified"] is False
    assert "GPU runtime report image digest does not match the manifest" in " ".join(report["blockers"])


def test_check_qualification_rejects_missing_production_bindings(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest, evidence = _full_evidence(tmp_path)
    report = _qualify(manifest_path, artifacts, **evidence)
    tampered = json.loads(json.dumps(report))
    tampered["deployment"] = None
    tampered["rehearsal"] = None
    tampered["gpu_runtime"] = None
    errors = qualification_report_errors(
        tampered,
        manifest,
        manifest_path=manifest_path,
        require_production=True,
    )
    assert any("deployment-report binding is missing" in error for error in errors)
    assert any("rollback-rehearsal binding is missing" in error for error in errors)
    assert any("gpu-runtime binding is missing" in error for error in errors)


def test_check_qualification_rejects_changed_production_reports(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest, evidence = _full_evidence(tmp_path)
    report = _qualify(manifest_path, artifacts, **evidence)
    for key in ("deployment_report_path", "rehearsal_report_path", "gpu_report_path"):
        path = evidence[key]
        path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    errors = qualification_report_errors(
        report,
        manifest,
        manifest_path=manifest_path,
        require_production=True,
        deployment_report_path=evidence["deployment_report_path"],
        rehearsal_report_path=evidence["rehearsal_report_path"],
        gpu_report_path=evidence["gpu_report_path"],
    )
    assert any("deployment-report binding does not match the supplied report" in error for error in errors)
    assert any("rollback-rehearsal binding does not match the supplied report" in error for error in errors)
    assert any("gpu-runtime binding does not match the supplied report" in error for error in errors)


def test_check_qualification_rejects_mismatched_production_evidence(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest, evidence = _full_evidence(tmp_path)
    report = _qualify(manifest_path, artifacts, **evidence)
    tampered = json.loads(json.dumps(report))
    for item in tampered["evidence"]:
        if item["kind"] == "deployment-report":
            item["sha256"] = "sha256:" + "9" * 64
    errors = qualification_report_errors(
        tampered,
        manifest,
        manifest_path=manifest_path,
        require_production=True,
    )
    assert any("deployment-report evidence does not match its binding" in error for error in errors)
