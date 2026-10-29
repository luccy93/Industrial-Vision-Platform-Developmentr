"""V25 release evidence collection and binding tests."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from backend.tests.unit.test_release_verification import (
    REPO_ROOT,
    TAG,
    make_release,
    make_runner,
)
from tools.release.evidence import (
    EVIDENCE_ARTIFACT_FIELDS,
    EVIDENCE_CHECK_FIELDS,
    EVIDENCE_REPORT_FIELDS,
    EVIDENCE_SUBJECT_FIELDS,
    EvidenceError,
    collect_release_evidence,
    evidence_report_errors,
    render_evidence_summary,
    write_evidence_report,
)
from tools.release.manifest import sha256_file
from tools.release.verification import FAIL, NOT_RUN, PASS, UNAVAILABLE

GENERATED_AT = "2026-10-25T00:00:00Z"


def _accept_identity(*args: Any, **kwargs: Any) -> None:
    del args, kwargs


def _release_payload(
    *,
    tag: str = TAG,
    repository: str = "octo/repo",
    draft: bool = False,
    prerelease: bool = False,
    url: str | None = None,
) -> str:
    return json.dumps(
        {
            "tagName": tag,
            "isDraft": draft,
            "isPrerelease": prerelease,
            "url": url or f"https://github.com/{repository}/releases/tag/{tag}",
        }
    )


def _runner(
    *,
    release_payload: str | None = None,
    release_failure: str | None = None,
) -> Any:
    base = make_runner()

    def run(args: Any, *, timeout: int = 180, env: Any = None) -> subprocess.CompletedProcess[str]:
        if args[:3] == ["gh", "release", "view"]:
            if release_failure is not None:
                return subprocess.CompletedProcess(args, 1, "", release_failure)
            return subprocess.CompletedProcess(args, 0, release_payload or _release_payload(), "")
        return base(args, timeout=timeout, env=env)

    return run


def _collect(
    manifest_path: Path,
    artifacts: Path,
    *,
    execute: bool = False,
    runner: Any | None = None,
    which: Any | None = None,
    **overrides: Any,
) -> dict[str, Any]:
    options: dict[str, Any] = {
        "artifacts_dir": artifacts,
        "repo_root": REPO_ROOT,
        "execute": execute,
        "runner": runner or _runner(),
        "which": which or (lambda name: f"/usr/bin/{name}"),
        "identity_verifier": _accept_identity,
        "now": lambda: GENERATED_AT,
    }
    options.update(overrides)
    return collect_release_evidence(manifest_path, **options)


def _checks(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {check["name"]: check for check in report["checks"]}


def test_local_evidence_collection_is_honest_and_hashes_artifacts(tmp_path: Path) -> None:
    manifest_path, artifacts, _ = make_release(tmp_path)
    report = _collect(manifest_path, artifacts)
    checks = _checks(report)
    assert report["generated_at"] == GENERATED_AT
    assert report["executed"] is False
    assert report["state"] == NOT_RUN
    assert report["verified"] is False
    assert report["production_verified"] is False
    assert checks["github-release"]["state"] == NOT_RUN
    assert report["verification"]["overall_state"] == PASS
    assert report["verification"]["production_verified"] is False
    artifacts_report = {item["name"]: item for item in report["artifacts"]}
    assert set(artifacts_report) == {"api", "web", "api-gpu"}
    assert artifacts_report["api"]["sbom_sha256"] == sha256_file(artifacts / "api.spdx.json")
    assert artifacts_report["api"]["scan_log_sha256"] == sha256_file(artifacts / "api.scan.txt")
    assert evidence_report_errors(
        report,
        json.loads(manifest_path.read_text(encoding="utf-8")),
        manifest_path=manifest_path,
        artifacts_dir=artifacts,
        require_live=False,
    ) == []
    assert "Release evidence: NOT_RUN" in render_evidence_summary(report)


def test_live_evidence_collection_requires_published_github_release(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest = make_release(tmp_path)
    report = _collect(manifest_path, artifacts, execute=True)
    assert report["executed"] is True
    assert report["state"] == PASS
    assert report["verified"] is True
    assert report["production_verified"] is True
    assert _checks(report)["github-release"]["state"] == PASS
    assert evidence_report_errors(
        report,
        manifest,
        manifest_path=manifest_path,
        artifacts_dir=artifacts,
        require_live=True,
    ) == []


def test_live_evidence_fails_for_draft_release(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest = make_release(tmp_path)
    report = _collect(
        manifest_path,
        artifacts,
        execute=True,
        runner=_runner(release_payload=_release_payload(draft=True)),
    )
    assert report["state"] == FAIL
    assert _checks(report)["github-release"]["state"] == FAIL
    assert "draft" in _checks(report)["github-release"]["detail"]
    errors = evidence_report_errors(
        report,
        manifest,
        manifest_path=manifest_path,
        artifacts_dir=artifacts,
        require_live=True,
    )
    assert any("published GitHub Release" in error for error in errors)


def test_live_evidence_is_unavailable_without_github_cli(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest = make_release(tmp_path)
    report = _collect(
        manifest_path,
        artifacts,
        execute=True,
        which=lambda name: None,
    )
    checks = _checks(report)
    assert report["state"] == UNAVAILABLE
    assert checks["github-release"]["state"] == UNAVAILABLE
    assert checks["registry:api"]["state"] == UNAVAILABLE
    errors = evidence_report_errors(
        report,
        manifest,
        manifest_path=manifest_path,
        artifacts_dir=artifacts,
        require_live=True,
    )
    assert any("state is 'UNAVAILABLE'" in error for error in errors)


def test_evidence_rejects_repository_mismatch(tmp_path: Path) -> None:
    manifest_path, artifacts, _ = make_release(tmp_path)
    try:
        _collect(manifest_path, artifacts, expected_repository="other/repo")
    except EvidenceError as exc:
        assert "does not match the manifest release" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected EvidenceError")


def test_evidence_report_errors_detect_artifact_tampering(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest = make_release(tmp_path)
    report = _collect(manifest_path, artifacts, execute=True)
    report_path = tmp_path / "release-evidence.json"
    write_evidence_report(report, report_path)
    assert evidence_report_errors(
        report,
        manifest,
        manifest_path=manifest_path,
        artifacts_dir=artifacts,
        require_live=True,
    ) == []
    (artifacts / "api.spdx.json").write_text("{}", encoding="utf-8")
    errors = evidence_report_errors(
        report,
        manifest,
        manifest_path=manifest_path,
        artifacts_dir=artifacts,
        require_live=True,
    )
    assert any("artifact hash does not match api.spdx.json" in error for error in errors)


def test_evidence_report_errors_detect_manifest_tampering(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest = make_release(tmp_path)
    report = _collect(manifest_path, artifacts, execute=True)
    tampered = dict(report)
    tampered["manifest_sha256"] = "sha256:" + "0" * 64
    errors = evidence_report_errors(
        tampered,
        manifest,
        manifest_path=manifest_path,
        artifacts_dir=artifacts,
        require_live=True,
    )
    assert any("not bound to the supplied manifest" in error for error in errors)


def test_release_evidence_schema_matches_contract() -> None:
    schema = json.loads(
        (REPO_ROOT / "release" / "release-evidence.schema.json").read_text(encoding="utf-8")
    )
    assert set(schema["required"]) == set(EVIDENCE_REPORT_FIELDS)
    assert set(schema["$defs"]["check"]["required"]) == set(EVIDENCE_CHECK_FIELDS)
    assert set(schema["$defs"]["artifact"]["required"]) == set(EVIDENCE_ARTIFACT_FIELDS)
    assert set(schema["$defs"]["subject"]["required"]) == set(EVIDENCE_SUBJECT_FIELDS)
