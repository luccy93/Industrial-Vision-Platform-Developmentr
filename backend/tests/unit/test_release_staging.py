"""V25 controlled staging qualification and mutation-gating tests."""

from __future__ import annotations

import copy
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from backend.tests.unit.release_evidence import (
    previous_release_manifest,
    write_production_verification_report,
)
from backend.tests.unit.test_release_verification import (
    COMMIT,
    REPO_ROOT,
    SOURCE_REPOSITORY,
    TAG,
    make_release,
)
from backend.tests.unit.test_release_verification import (
    make_runner as make_verification_runner,
)
from tools.release.deployment import deployment_environment
from tools.release.manifest import sha256_file
from tools.release.staging import (
    STAGING_CHECK_FIELDS,
    STAGING_EVIDENCE_FIELDS,
    STAGING_REPORT_FIELDS,
    STAGING_SUBJECT_FIELDS,
    STAGING_TARGET_FIELDS,
    STAGING_TARGET_RELEASE_FIELDS,
    STAGING_TARGET_REQUIRED_FIELDS,
    StagingError,
    load_staging_target,
    render_staging_summary,
    run_staging_qualification,
    staging_report_errors,
    staging_target_errors,
)
from tools.release.verification import FAIL, NOT_RUN, PASS, UNAVAILABLE

GENERATED_AT = "2026-10-25T00:00:00Z"
MUTATION_VERBS = {"up", "down", "deploy", "rm", "stop", "start", "restart", "kill"}
COMPOSE_MUTATION_VERBS = MUTATION_VERBS - {"rm", "deploy"}


def _target_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": 1,
        "name": "staging-east-1",
        "environment": "staging",
        "release": {
            "tag": TAG,
            "commit": COMMIT,
            "source_repository": SOURCE_REPOSITORY,
        },
        "api_url": "https://api.staging.example.test",
        "web_url": "https://web.staging.example.test",
        "ws_url": "wss://ws.staging.example.test",
        "smoke_username": "smoke@example.test",
        "smoke_password_env": "IVP_SMOKE_PASSWORD",
        "compose_project": "ivp-staging",
        "compose_files": ["compose.release.yaml"],
        "gpu": False,
    }
    payload.update(overrides)
    return payload


def _write_target(tmp_path: Path, payload: dict[str, Any] | None = None) -> Path:
    path = tmp_path / "staging-target.json"
    path.write_text(
        json.dumps(payload if payload is not None else _target_payload()),
        encoding="utf-8",
    )
    return path


def _compose_payload(manifest: dict[str, Any]) -> str:
    environment = deployment_environment(manifest, gpu=False)
    return json.dumps(
        {
            "services": {
                "migrate": {"image": environment["IVP_API_IMAGE"]},
                "api": {"image": environment["IVP_API_IMAGE"]},
                "web": {"image": environment["IVP_WEB_IMAGE"]},
                "postgres": {
                    "image": "postgres:16-alpine",
                    "volumes": [
                        {
                            "type": "volume",
                            "source": "postgres-data",
                            "target": "/var/lib/postgresql/data",
                        }
                    ],
                },
            },
            "volumes": {"postgres-data": {}},
        }
    )


def _runner(manifest: dict[str, Any], calls: list[list[str]]) -> Any:
    payload = _compose_payload(manifest)
    verification_runner = make_verification_runner()

    def run(args: Any, *, timeout: int = 120, env: Any = None) -> subprocess.CompletedProcess[str]:
        calls.append(list(args))
        if "config" in args:
            return subprocess.CompletedProcess(args, 0, payload, "")
        if args[:2] == ["docker", "--version"]:
            return subprocess.CompletedProcess(args, 0, "Docker version 29.5.3, build test\n", "")
        if args[:3] == ["docker", "version", "--format"]:
            return subprocess.CompletedProcess(args, 0, "29.5.3\n", "")
        if args[:3] == ["docker", "compose", "version"]:
            return subprocess.CompletedProcess(args, 0, "Docker Compose version v2.30.0\n", "")
        if args[:3] == ["gh", "release", "view"]:
            release_payload = {
                "tagName": TAG,
                "isDraft": False,
                "isPrerelease": False,
                "url": f"https://github.com/{SOURCE_REPOSITORY}/releases/tag/{TAG}",
            }
            return subprocess.CompletedProcess(args, 0, json.dumps(release_payload), "")
        return verification_runner(args, timeout=timeout, env=env)

    return run


def _accept_identity(*args: Any, **kwargs: Any) -> None:
    del args, kwargs


def _run(
    tmp_path: Path,
    *,
    manifest_path: Path,
    artifacts: Path,
    manifest: dict[str, Any],
    target_path: Path | None = None,
    **overrides: Any,
) -> tuple[dict[str, Any], list[list[str]]]:
    calls: list[list[str]] = []
    output = tmp_path / "staging-qualification.json"
    options: dict[str, Any] = {
        "repo_root": REPO_ROOT,
        "artifacts_dir": artifacts,
        "output": output,
        "runner": _runner(manifest, calls),
        "which": lambda name: f"/usr/bin/{name}",
        "base_environment": {},
        "identity_verifier": _accept_identity,
        "now": lambda: GENERATED_AT,
    }
    options.update(overrides)
    report = run_staging_qualification(
        target_path or _write_target(tmp_path),
        manifest_path,
        **options,
    )
    return report, calls


def _authorized_run(
    tmp_path: Path,
    *,
    manifest_path: Path,
    artifacts: Path,
    manifest: dict[str, Any],
    **overrides: Any,
) -> tuple[dict[str, Any], list[list[str]], list[dict[str, Any]], list[dict[str, Any]]]:
    deployed: list[dict[str, Any]] = []
    smoked: list[dict[str, Any]] = []

    def deployment_executor(path: Path, **kwargs: Any) -> dict[str, Any]:
        deployed.append(kwargs)
        return {
            "schema_version": 1,
            "generated_at": GENERATED_AT,
            "manifest_sha256": sha256_file(path),
            "state": PASS,
            "verified": True,
            "blockers": [],
        }

    def smoke_runner(api_url: str, **kwargs: Any) -> dict[str, Any]:
        smoked.append({"api_url": api_url, **kwargs})
        return {
            "schema_version": 1,
            "generated_at": GENERATED_AT,
            "manifest_sha256": sha256_file(kwargs["manifest_path"]),
            "state": PASS,
            "verified": True,
            "blockers": [],
        }

    report, calls = _run(
        tmp_path,
        manifest_path=manifest_path,
        artifacts=artifacts,
        manifest=manifest,
        execute=True,
        authorize="staging-east-1",
        deployment_executor=deployment_executor,
        smoke_runner=smoke_runner,
        **overrides,
    )
    return report, calls, deployed, smoked


def _checks(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {check["name"]: check for check in report["checks"]}


def test_staging_target_rejects_production_environment() -> None:
    errors = staging_target_errors(_target_payload(environment="production"))
    assert any("environment must be exactly 'staging'" in error for error in errors)


def test_staging_target_rejects_production_like_name_and_hosts() -> None:
    name_errors = staging_target_errors(_target_payload(name="production-api"))
    assert any("name looks like a production target" in error for error in name_errors)
    host_errors = staging_target_errors(_target_payload(api_url="https://api.prod.example.test"))
    assert any("api_url hostname looks like a production host" in error for error in host_errors)
    dot_errors = staging_target_errors(_target_payload(web_url="https://web.production.example.test"))
    assert any("web_url hostname looks like a production host" in error for error in dot_errors)


def test_staging_target_rejects_credentials_and_insecure_urls() -> None:
    errors = staging_target_errors(
        _target_payload(
            api_url="http://user:password@staging.example.test",
            ws_url="ws://staging.example.test",
        )
    )
    assert any("api_url must use https://" in error for error in errors)
    assert any("api_url must not embed credentials" in error for error in errors)
    assert any("ws_url must use wss://" in error for error in errors)


def test_staging_target_rejects_unknown_and_unsafe_paths() -> None:
    errors = staging_target_errors(
        _target_payload(
            unexpected="value",
            compose_files=["../outside.yaml"],
        )
    )
    assert any("unknown fields: unexpected" in error for error in errors)
    assert any("compose_files[0] must not contain parent-directory segments" in error for error in errors)


def test_load_staging_target_requires_compose_file_inside_repository(tmp_path: Path) -> None:
    target_path = _write_target(
        tmp_path,
        _target_payload(compose_files=["missing-compose.yaml"]),
    )
    with pytest.raises(StagingError, match="compose file does not exist"):
        load_staging_target(target_path, repo_root=REPO_ROOT)


def test_preflight_only_run_never_qualifies_or_mutates(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest = make_release(tmp_path)
    report, calls = _run(
        tmp_path,
        manifest_path=manifest_path,
        artifacts=artifacts,
        manifest=manifest,
    )
    checks = _checks(report)
    assert report["generated_at"] == GENERATED_AT
    assert report["mode"] == "preflight"
    assert report["authorized"] is False
    assert report["staging_qualified"] is False
    assert report["production_qualified"] is False
    assert checks["preflight"]["state"] == PASS
    assert checks["authorization"]["state"] == NOT_RUN
    assert checks["deployment-execution"]["state"] == NOT_RUN
    assert checks["smoke"]["state"] == NOT_RUN
    assert checks["evidence-collection"]["state"] == NOT_RUN
    assert report["blockers"]
    assert "Staging qualification: NOT_RUN" in render_staging_summary(report)
    commands = [args for args in calls]
    assert commands
    assert all(not (MUTATION_VERBS & set(args)) for args in commands)
    assert all("compose" in args for args in commands)
    evidence = {item["kind"]: item for item in report["evidence"]}
    assert evidence["preflight"]["sha256"] == sha256_file(tmp_path / "preflight.json")


def test_authorize_requires_execute_and_exact_target_name(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest = make_release(tmp_path)
    target_path = _write_target(tmp_path)
    with pytest.raises(StagingError, match="--authorize requires --execute"):
        run_staging_qualification(
            target_path,
            manifest_path,
            repo_root=REPO_ROOT,
            artifacts_dir=artifacts,
            output=tmp_path / "report.json",
            authorize="staging-east-1",
        )
    calls: list[list[str]] = []
    with pytest.raises(StagingError, match="does not match the staging target name"):
        run_staging_qualification(
            target_path,
            manifest_path,
            repo_root=REPO_ROOT,
            artifacts_dir=artifacts,
            output=tmp_path / "report.json",
            execute=True,
            authorize="staging-west-1",
            runner=_runner(manifest, calls),
            which=lambda name: f"/usr/bin/{name}",
            base_environment={},
        )
    assert calls == []


def test_authorized_mutation_without_live_evidence_does_not_deploy(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest = make_release(tmp_path)
    report, calls = _run(
        tmp_path,
        manifest_path=manifest_path,
        artifacts=artifacts,
        manifest=manifest,
        execute=True,
        authorize="staging-east-1",
        which=lambda name: None,
    )
    checks = _checks(report)
    assert report["mode"] == "authorized-mutation"
    assert report["authorized"] is True
    assert report["staging_qualified"] is False
    assert checks["authorization"]["state"] == PASS
    assert checks["evidence-collection"]["state"] == UNAVAILABLE
    assert checks["deployment-execution"]["state"] == FAIL
    assert checks["smoke"]["state"] == FAIL
    assert all(not (MUTATION_VERBS & set(args)) for args in calls)


def test_authorized_mutation_executes_controlled_deployment_and_smoke(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest = make_release(tmp_path)
    report, calls, deployed, smoked = _authorized_run(
        tmp_path,
        manifest_path=manifest_path,
        artifacts=artifacts,
        manifest=manifest,
    )
    checks = _checks(report)
    assert report["mode"] == "authorized-mutation"
    assert report["authorized"] is True
    assert report["staging_qualified"] is True
    assert checks["authorization"]["state"] == PASS
    assert checks["evidence-collection"]["state"] == PASS
    assert checks["migration-compatibility"]["state"] == PASS
    assert checks["deployment-execution"]["state"] == PASS
    assert checks["smoke"]["state"] == PASS
    assert report["deployment"]["state"] == PASS
    assert report["smoke"]["state"] == PASS
    assert report["publication"]["github_release"]["state"] == PASS
    assert len(deployed) == 1
    assert len(smoked) == 1
    assert all(not (COMPOSE_MUTATION_VERBS & set(args)) for args in calls)
    assert (
        staging_report_errors(
            report,
            manifest,
            manifest_path=manifest_path,
            evidence_dir=tmp_path,
        )
        == []
    )


def test_staging_requires_gpu_runtime_and_inference_when_requested(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest = make_release(tmp_path)
    runtime_calls: list[dict[str, Any]] = []
    inference_calls: list[dict[str, Any]] = []

    def gpu_runtime_runner(path: Path, **kwargs: Any) -> dict[str, Any]:
        runtime_calls.append(kwargs)
        return {
            "schema_version": 1,
            "generated_at": GENERATED_AT,
            "manifest_sha256": sha256_file(path),
            "state": PASS,
            "verified": True,
            "blockers": [],
        }

    def gpu_inference_runner(path: Path, **kwargs: Any) -> dict[str, Any]:
        inference_calls.append(kwargs)
        return {
            "schema_version": 1,
            "generated_at": GENERATED_AT,
            "manifest_sha256": sha256_file(path),
            "state": PASS,
            "verified": True,
            "blockers": [],
        }

    report, _, _, _ = _authorized_run(
        tmp_path,
        manifest_path=manifest_path,
        artifacts=artifacts,
        manifest=manifest,
        require_gpu_runtime=True,
        gpu_runtime_runner=gpu_runtime_runner,
        gpu_inference_runner=gpu_inference_runner,
    )
    checks = _checks(report)
    assert checks["gpu-runtime"]["state"] == PASS
    assert checks["gpu-inference"]["state"] == PASS
    assert report["gpu_runtime"]["state"] == PASS
    assert report["gpu_inference"]["state"] == PASS
    assert report["staging_qualified"] is True
    assert len(runtime_calls) == 1
    assert len(inference_calls) == 1
    assert (
        staging_report_errors(
            report,
            manifest,
            manifest_path=manifest_path,
            evidence_dir=tmp_path,
        )
        == []
    )


def test_staging_rehearsal_is_bound_to_migration_safety(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest = make_release(tmp_path)
    previous_path, previous = previous_release_manifest(tmp_path, manifest)
    previous_report = tmp_path / "previous-verification.json"
    write_production_verification_report(previous_report, previous_path, previous)
    rehearsal_calls: list[dict[str, Any]] = []

    def rehearsal_runner(
        target_path: Path,
        previous_manifest_path: Path,
        **kwargs: Any,
    ) -> dict[str, Any]:
        rehearsal_calls.append({"previous": previous_manifest_path, **kwargs})
        return {
            "schema_version": 1,
            "generated_at": GENERATED_AT,
            "manifest_sha256": sha256_file(target_path),
            "state": PASS,
            "verified": True,
            "blockers": [],
        }

    report, _, _, _ = _authorized_run(
        tmp_path,
        manifest_path=manifest_path,
        artifacts=artifacts,
        manifest=manifest,
        previous_manifest_path=previous_path,
        previous_verification_report_path=previous_report,
        require_rollback=True,
        rehearsal_runner=rehearsal_runner,
    )
    checks = _checks(report)
    assert checks["rollback-rehearsal"]["state"] == PASS
    assert report["rehearsal"]["state"] == PASS
    assert report["staging_qualified"] is True
    assert len(rehearsal_calls) == 1
    migration_path = rehearsal_calls[0]["migration_report_path"]
    assert migration_path.is_file()
    assert report["migration"]["sha256"] == sha256_file(migration_path)
    assert (
        staging_report_errors(
            report,
            manifest,
            manifest_path=manifest_path,
            evidence_dir=tmp_path,
        )
        == []
    )


def test_live_read_mode_reports_missing_tools_honestly(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest = make_release(tmp_path)
    report, calls = _run(
        tmp_path,
        manifest_path=manifest_path,
        artifacts=artifacts,
        manifest=manifest,
        execute=True,
        which=lambda name: None,
    )
    checks = _checks(report)
    assert report["mode"] == "live-read"
    assert report["authorized"] is False
    assert report["staging_qualified"] is False
    assert checks["docker-cli"]["state"] == UNAVAILABLE
    assert checks["docker-daemon"]["state"] == UNAVAILABLE
    assert checks["docker-compose"]["state"] == UNAVAILABLE
    assert checks["github-cli"]["state"] == UNAVAILABLE
    assert all(not (MUTATION_VERBS & set(args)) for args in calls)


def test_staging_report_errors_detect_evidence_tampering(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest = make_release(tmp_path)
    report, _, _, _ = _authorized_run(
        tmp_path,
        manifest_path=manifest_path,
        artifacts=artifacts,
        manifest=manifest,
    )
    candidate = copy.deepcopy(report)
    assert (
        staging_report_errors(
            candidate,
            manifest,
            manifest_path=manifest_path,
            evidence_dir=tmp_path,
        )
        == []
    )

    preflight_path = tmp_path / "preflight.json"
    preflight_path.write_text(preflight_path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    errors = staging_report_errors(
        candidate,
        manifest,
        manifest_path=manifest_path,
        evidence_dir=tmp_path,
    )
    assert any("staging preflight evidence hash does not match" in error for error in errors)
    assert any("staging report evidence hash does not match preflight.json" in error for error in errors)


def test_staging_report_errors_require_authorized_pass_and_matching_manifest(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest = make_release(tmp_path)
    report, _ = _run(
        tmp_path,
        manifest_path=manifest_path,
        artifacts=artifacts,
        manifest=manifest,
    )
    errors = staging_report_errors(
        report,
        manifest,
        manifest_path=manifest_path,
        evidence_dir=tmp_path,
    )
    assert any("explicitly authorized mutation mode" in error for error in errors)
    assert any("staging report state is 'NOT_RUN'" in error for error in errors)
    assert any("staging_qualified is not true" in error for error in errors)

    tampered = copy.deepcopy(report)
    tampered["manifest_sha256"] = "sha256:" + "0" * 64
    errors = staging_report_errors(
        tampered,
        manifest,
        manifest_path=manifest_path,
        evidence_dir=tmp_path,
    )
    assert any("not bound to the supplied manifest" in error for error in errors)


def test_staging_schemas_match_runtime_contracts() -> None:
    target_schema = json.loads(
        (REPO_ROOT / "release" / "staging-target.schema.json").read_text(encoding="utf-8")
    )
    assert set(target_schema["required"]) == set(STAGING_TARGET_REQUIRED_FIELDS)
    assert set(target_schema["properties"]) == set(STAGING_TARGET_FIELDS)
    assert set(target_schema["properties"]["release"]["required"]) == set(STAGING_TARGET_RELEASE_FIELDS)
    assert target_schema["properties"]["environment"]["const"] == "staging"

    report_schema = json.loads(
        (REPO_ROOT / "release" / "staging-qualification.schema.json").read_text(encoding="utf-8")
    )
    assert set(report_schema["required"]) == set(STAGING_REPORT_FIELDS)
    assert set(report_schema["$defs"]["check"]["required"]) == set(STAGING_CHECK_FIELDS)
    assert set(report_schema["$defs"]["evidence"]["required"]) == set(STAGING_EVIDENCE_FIELDS)
    assert set(report_schema["$defs"]["subject"]["required"]) == set(STAGING_SUBJECT_FIELDS)
    assert report_schema["properties"]["production_qualified"]["const"] is False
