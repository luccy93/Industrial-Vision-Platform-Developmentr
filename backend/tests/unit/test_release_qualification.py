"""V24 live release qualification and evidence-binding tests."""

from __future__ import annotations

import json
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
    EVIDENCE_FIELDS,
    FAIL,
    NOT_RUN,
    PASS,
    QUALIFICATION_FIELDS,
    QUALIFICATION_PROFILES,
    SCOPES,
    SUBJECT_FIELDS,
    qualification_report_errors,
    qualify_release,
    render_qualification_summary,
    write_qualification_report,
)
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
        "checks": [],
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
    payload: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": GENERATED_AT,
        "state": PASS,
        "verified": True,
        "manifest_sha256": sha256_file(manifest_path),
        "subject": _subject(manifest),
        "previous_manifest_sha256": "sha256:" + "b" * 64,
        "previous_subject": {
            "tag": "v1.2.2",
            "commit": "b" * 40,
            "source_repository": SOURCE_REPOSITORY,
        },
        "checks": [],
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
    payload: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": GENERATED_AT,
        "state": PASS,
        "verified": True,
        "manifest_sha256": sha256_file(manifest_path),
        "subject": _subject(manifest),
        "gpu": {"name": "NVIDIA A10", "runtime": "nvidia"},
        "checks": [],
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
