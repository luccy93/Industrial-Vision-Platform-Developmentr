"""V24 digest-pinned rollback rehearsal tests."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from backend.tests.unit.release_evidence import (
    previous_release_manifest,
    write_production_verification_report,
)
from backend.tests.unit.test_release_verification import make_release
from tools.release.manifest import sha256_file
from tools.release.rehearsal import (
    REHEARSAL_EVIDENCE_FIELDS,
    REHEARSAL_REPORT_FIELDS,
    REHEARSAL_SCHEMA_VERSION,
    REHEARSAL_STEP_FIELDS,
    REHEARSAL_SUBJECT_FIELDS,
    RehearsalError,
    render_rehearsal_summary,
    run_rollback_rehearsal,
    write_rehearsal_report,
)
from tools.release.verification import FAIL, NOT_RUN, PASS

GENERATED_AT = "2026-10-24T00:00:00Z"


class _DeploymentRunner:
    """Emulate a healthy digest-pinned Compose deployment for verification."""

    def __init__(self, image_ids: dict[str, str], *, fail_on: tuple[str, ...] = ()) -> None:
        self.image_ids = image_ids
        self.fail_on = fail_on
        self.environment: dict[str, str] = {}

    def __call__(
        self,
        args: Any,
        *,
        timeout: int = 120,
        env: Any = None,
    ) -> subprocess.CompletedProcess[str]:
        del timeout
        command = " ".join(str(part) for part in args)
        if any(marker in command for marker in self.fail_on):
            return subprocess.CompletedProcess(args, 1, "", "simulated failure")
        if "config" in args:
            self.environment = dict(env or {})
            services = {
                "migrate": {"image": self.environment["IVP_API_IMAGE"]},
                "api": {"image": self.environment["IVP_API_IMAGE"]},
                "web": {"image": self.environment["IVP_WEB_IMAGE"]},
            }
            return subprocess.CompletedProcess(args, 0, json.dumps({"services": services}), "")
        if "ps" in args:
            containers = [
                {"Service": "api", "State": "running", "Name": "api-1"},
                {"Service": "web", "State": "running", "Name": "web-1"},
            ]
            return subprocess.CompletedProcess(args, 0, json.dumps(containers), "")
        if args[:2] == ["docker", "inspect"]:
            name = str(args[-1])
            reference = (
                self.environment["IVP_WEB_IMAGE"]
                if name.startswith("web")
                else self.environment["IVP_API_IMAGE"]
            )
            digest = reference.split("@", 1)[1]
            return subprocess.CompletedProcess(args, 0, self.image_ids[digest] + "\n", "")
        if "logs" in args:
            return subprocess.CompletedProcess(args, 0, "", "")
        return subprocess.CompletedProcess(args, 0, "", "")


def _smoke(*args: Any, **kwargs: Any) -> dict[str, Any]:
    del args, kwargs
    return {
        "overall_state": PASS,
        "verified": True,
        "checks": [{"name": "api-health", "state": PASS, "required": True}],
    }


def _setup(
    tmp_path: Path,
) -> tuple[Path, dict[str, Any], Path, dict[str, Any], Path, Path, _DeploymentRunner]:
    manifest_path, artifacts, manifest = make_release(tmp_path)
    previous_path, previous = previous_release_manifest(tmp_path, manifest)
    target_report = tmp_path / "target-verification.json"
    previous_report = tmp_path / "previous-verification.json"
    write_production_verification_report(target_report, manifest_path, manifest)
    write_production_verification_report(previous_report, previous_path, previous)
    image_ids = {
        image["digest"]: image["image_id"]
        for document in (manifest, previous)
        for image in document["images"]
    }
    return (
        manifest_path,
        manifest,
        previous_path,
        previous,
        target_report,
        previous_report,
        _DeploymentRunner(image_ids),
    )


def _rehearse(
    manifest_path: Path,
    previous_path: Path,
    *,
    target_report: Path | None,
    previous_report: Path | None,
    runner: _DeploymentRunner,
    tmp_path: Path,
    **overrides: Any,
) -> dict[str, Any]:
    options: dict[str, Any] = {
        "compose_files": [tmp_path / "compose.yaml"],
        "execute": True,
        "target_verification_report": target_report,
        "previous_verification_report": previous_report,
        "smoke_api_url": "https://staging.example.com",
        "smoke_username": "smoke",
        "smoke_password": "test-password",
        "evidence_dir": tmp_path / "rehearsal-evidence",
        "runner": runner,
        "which": lambda name: f"/usr/bin/{name}",
        "base_environment": {},
        "smoke_runner": _smoke,
        "now": lambda: GENERATED_AT,
    }
    options.update(overrides)
    return run_rollback_rehearsal(manifest_path, previous_path, **options)


def test_rehearsal_without_execute_is_not_run(tmp_path: Path) -> None:
    manifest_path, manifest, previous_path, previous, _, _, runner = _setup(tmp_path)
    report = _rehearse(
        manifest_path,
        previous_path,
        target_report=None,
        previous_report=None,
        runner=runner,
        tmp_path=tmp_path,
        execute=False,
    )
    assert report["executed"] is False
    assert report["state"] == NOT_RUN
    assert report["verified"] is False
    assert report["generated_at"] == GENERATED_AT
    assert report["manifest_sha256"] == sha256_file(manifest_path)
    assert report["previous_manifest_sha256"] == sha256_file(previous_path)
    assert report["subject"]["tag"] == manifest["release"]["tag"]
    assert report["previous_subject"]["tag"] == previous["release"]["tag"]
    assert [step["state"] for step in report["steps"]] == [NOT_RUN] * len(report["steps"])
    assert report["evidence"] == []
    assert "Rollback rehearsal: NOT_RUN" in render_rehearsal_summary(report)


def test_rehearsal_rejects_identical_manifests(tmp_path: Path) -> None:
    manifest_path, _, _, _, _, _, runner = _setup(tmp_path)
    with pytest.raises(RehearsalError):
        _rehearse(
            manifest_path,
            manifest_path,
            target_report=None,
            previous_report=None,
            runner=runner,
            tmp_path=tmp_path,
        )


def test_rehearsal_fails_closed_without_reports_or_smoke(tmp_path: Path) -> None:
    manifest_path, _, previous_path, _, _, _, runner = _setup(tmp_path)
    report = _rehearse(
        manifest_path,
        previous_path,
        target_report=None,
        previous_report=None,
        runner=runner,
        tmp_path=tmp_path,
        smoke_api_url=None,
    )
    assert report["executed"] is False
    assert report["state"] == FAIL
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["target-verification-report"]["state"] == FAIL
    assert checks["previous-verification-report"]["state"] == FAIL
    assert checks["smoke-configuration"]["state"] == FAIL
    assert checks["execution"]["state"] == FAIL
    assert all(step["state"] == NOT_RUN for step in report["steps"])
    assert report["evidence"] == []


def test_rehearsal_executes_full_rollback_sequence(tmp_path: Path) -> None:
    manifest_path, manifest, previous_path, previous, target_report, previous_report, runner = _setup(
        tmp_path
    )
    report = _rehearse(
        manifest_path,
        previous_path,
        target_report=target_report,
        previous_report=previous_report,
        runner=runner,
        tmp_path=tmp_path,
    )
    assert report["executed"] is True
    assert report["state"] == PASS
    assert report["verified"] is True
    assert [step["name"] for step in report["steps"]] == [
        "deploy-previous",
        "verify-previous",
        "smoke-previous",
        "deploy-target",
        "verify-target",
        "smoke-target",
        "rollback-previous",
        "verify-after-rollback",
        "smoke-after-rollback",
    ]
    assert all(step["state"] == PASS for step in report["steps"])
    assert report["target"]["digests"]["api"] == manifest["images"][0]["digest"]
    assert report["previous"]["digests"]["api"] == previous["images"][0]["digest"]
    assert report["target"]["digests"] != report["previous"]["digests"]
    assert len(report["evidence"]) == 6
    for item in report["evidence"]:
        path = tmp_path / "rehearsal-evidence" / item["path"]
        assert path.is_file()
        assert item["sha256"] == sha256_file(path)
    assert "Rollback rehearsal: PASS" in render_rehearsal_summary(report)


def test_rehearsal_rolls_back_after_target_verification_failure(tmp_path: Path) -> None:
    manifest_path, _, previous_path, _, target_report, previous_report, runner = _setup(tmp_path)
    failed = json.loads(target_report.read_text(encoding="utf-8"))
    failed["overall_state"] = FAIL
    failed["verified"] = False
    failed["production_verified"] = False
    target_report.write_text(json.dumps(failed), encoding="utf-8")
    report = _rehearse(
        manifest_path,
        previous_path,
        target_report=target_report,
        previous_report=previous_report,
        runner=runner,
        tmp_path=tmp_path,
    )
    assert report["executed"] is True
    assert report["state"] == FAIL
    assert report["verified"] is False
    steps = {step["name"]: step for step in report["steps"]}
    assert steps["verify-target"]["state"] == FAIL
    assert steps["smoke-target"]["state"] == NOT_RUN
    assert steps["rollback-previous"]["state"] == PASS
    assert steps["verify-after-rollback"]["state"] == PASS
    assert steps["smoke-after-rollback"]["state"] == PASS
    assert report["blockers"]


def test_rehearsal_report_round_trip(tmp_path: Path) -> None:
    manifest_path, _, previous_path, _, target_report, previous_report, runner = _setup(tmp_path)
    report = _rehearse(
        manifest_path,
        previous_path,
        target_report=target_report,
        previous_report=previous_report,
        runner=runner,
        tmp_path=tmp_path,
    )
    path = tmp_path / "rollback-rehearsal.json"
    write_rehearsal_report(report, path)
    assert json.loads(path.read_text(encoding="utf-8"))["state"] == PASS


def test_rehearsal_schema_matches_contract() -> None:
    schema = json.loads(
        (Path(__file__).resolve().parents[3] / "release" / "rollback-rehearsal.schema.json").read_text(
            encoding="utf-8"
        )
    )
    assert set(schema["required"]) == set(REHEARSAL_REPORT_FIELDS)
    assert schema["properties"]["schema_version"]["const"] == REHEARSAL_SCHEMA_VERSION
    assert set(schema["$defs"]["subject"]["required"]) == set(REHEARSAL_SUBJECT_FIELDS)
    assert set(schema["$defs"]["step"]["required"]) == set(REHEARSAL_STEP_FIELDS)
    assert set(schema["$defs"]["evidence"]["required"]) == set(REHEARSAL_EVIDENCE_FIELDS)
