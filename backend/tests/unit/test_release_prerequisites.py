"""V24 qualification prerequisite probe tests (offline, injected runners)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from backend.tests.unit.test_release_verification import COMMIT, REPO_ROOT, SOURCE_REPOSITORY, TAG
from tools.release.prerequisites import probe_prerequisites, render_prerequisites_summary
from tools.release.verification import FAIL, NOT_RUN, PASS, UNAVAILABLE

TOOLS = ("git", "gh", "docker", "nvidia-smi")


def _which(name: str) -> str | None:
    return f"/usr/bin/{name}" if name in TOOLS else None


def _runner(
    *,
    docker_daemon: bool = True,
    nvidia: bool = True,
    compose: bool = True,
) -> Any:
    def runner(args: Any, *, timeout: int = 60, env: Any = None) -> subprocess.CompletedProcess[str]:
        del timeout, env
        if args[:2] == ["git", "--version"]:
            return subprocess.CompletedProcess(args, 0, "git version 2.45.0\n", "")
        if args[0] == "git":
            if "rev-parse" in args and "--is-inside-work-tree" in args:
                return subprocess.CompletedProcess(args, 0, "true\n", "")
            if "rev-parse" in args:
                return subprocess.CompletedProcess(args, 0, COMMIT + "\n", "")
            if "cat-file" in args or "merge-base" in args:
                return subprocess.CompletedProcess(args, 0, "", "")
        if args[:2] == ["gh", "--version"]:
            return subprocess.CompletedProcess(args, 0, "gh version 2.60.0\n", "")
        if args[:4] == ["gh", "attestation", "verify", "--help"]:
            flags = (
                "--signer-workflow --source-digest --source-ref --deny-self-hosted-runners --predicate-type"
            )
            return subprocess.CompletedProcess(args, 0, flags + "\n", "")
        if args[0] == "docker":
            if "--version" in args:
                return subprocess.CompletedProcess(args, 0, "Docker version 27.0.0\n", "")
            if "version" in args and "--format" in args:
                if docker_daemon:
                    return subprocess.CompletedProcess(args, 0, "27.0.0\n", "")
                return subprocess.CompletedProcess(args, 1, "", "cannot connect to the daemon")
            if "compose" in args:
                if compose:
                    return subprocess.CompletedProcess(args, 0, "Docker Compose version v2.30.0\n", "")
                return subprocess.CompletedProcess(args, 1, "", "compose unavailable")
            if "info" in args:
                if nvidia:
                    return subprocess.CompletedProcess(args, 0, '{"nvidia":{}}\n', "")
                return subprocess.CompletedProcess(args, 0, '{"runc":{}}\n', "")
        if args[0] == "nvidia-smi":
            if nvidia:
                return subprocess.CompletedProcess(args, 0, "NVIDIA A10\n", "")
            return subprocess.CompletedProcess(args, 1, "", "nvidia-smi: not found")
        return subprocess.CompletedProcess(args, 1, "", "unexpected command")

    return runner


def _artifacts(tmp_path: Path, *, include_verification: bool = True) -> dict[str, Path]:
    artifacts = tmp_path / "release-artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    (artifacts / "release-manifest.json").write_text("{}", encoding="utf-8")
    verification = artifacts / "release-verification.json"
    if include_verification:
        verification.write_text("{}", encoding="utf-8")
    publication = artifacts / "publication-report.json"
    publication.write_text("{}", encoding="utf-8")
    deployment = artifacts / "deployment-report.json"
    deployment.write_text("{}", encoding="utf-8")
    rehearsal = artifacts / "rollback-rehearsal.json"
    rehearsal.write_text("{}", encoding="utf-8")
    gpu = artifacts / "gpu-runtime.json"
    gpu.write_text("{}", encoding="utf-8")
    return {
        "artifacts_dir": artifacts,
        "verification_report": verification,
        "publication_report": publication,
        "deployment_report": deployment,
        "rehearsal_report": rehearsal,
        "gpu_report": gpu,
    }


def _probe(tmp_path: Path, **overrides: Any) -> dict[str, Any]:
    options: dict[str, Any] = {
        "repo_root": REPO_ROOT,
        "profile": "local_validation",
        "scope": "artifact",
        "expected_tag": TAG,
        "expected_commit": COMMIT,
        "expected_repository": SOURCE_REPOSITORY,
        "main_ref": "origin/main",
        "runner": _runner(),
        "which": _which,
        "network_probe": lambda host, port: True,
        "env": {"GH_TOKEN": "test-token-not-a-real-secret"},
        "now": lambda: "2026-10-24T00:00:00Z",
    }
    options.update(_artifacts(tmp_path))
    options.update(overrides)
    return probe_prerequisites(**options)


def test_prerequisites_ready_when_required_tools_are_present(tmp_path: Path) -> None:
    report = _probe(tmp_path)
    assert report["ready"] is True
    assert report["overall_state"] == PASS
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["git-cli"]["state"] == PASS
    assert checks["repository"]["state"] == PASS
    assert checks["tag"]["state"] == PASS
    assert checks["commit"]["state"] == PASS
    assert checks["main-reachability"]["state"] == PASS
    assert checks["github-cli"]["state"] == NOT_RUN
    assert checks["docker-cli"]["state"] == NOT_RUN
    assert checks["gpu-driver"]["state"] == NOT_RUN
    assert checks["release-manifest"]["state"] == PASS
    assert checks["release-verification"]["state"] == PASS
    assert checks["publication-report"]["state"] == NOT_RUN


def test_missing_gh_is_unavailable_for_staging(tmp_path: Path) -> None:
    def which(name: str) -> str | None:
        return None if name == "gh" else _which(name)

    report = _probe(tmp_path, profile="staging_qualification", which=which)
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["github-cli"]["state"] == UNAVAILABLE
    assert report["ready"] is False
    assert any(blocker.startswith("github-cli:") for blocker in report["blockers"])


def test_missing_token_is_unavailable_and_never_echoed(tmp_path: Path) -> None:
    secret = "super-secret-token-value"
    report = _probe(
        tmp_path,
        profile="staging_qualification",
        env={"GH_TOKEN": secret},
    )
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["github-token"]["state"] == PASS
    assert secret not in json.dumps(report)

    report = _probe(tmp_path, profile="staging_qualification", env={})
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["github-token"]["state"] == UNAVAILABLE
    assert "neither GH_TOKEN nor GITHUB_TOKEN is set" in checks["github-token"]["detail"]


def test_missing_docker_daemon_blocks_deployment_scope(tmp_path: Path) -> None:
    report = _probe(tmp_path, scope="deployment", runner=_runner(docker_daemon=False))
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["docker-cli"]["state"] == PASS
    assert checks["docker-daemon"]["state"] == UNAVAILABLE
    assert checks["docker-compose"]["state"] == PASS
    assert report["ready"] is False
    assert any(blocker.startswith("docker-daemon:") for blocker in report["blockers"])


def test_missing_gpu_blocks_production_qualification(tmp_path: Path) -> None:
    report = _probe(
        tmp_path,
        profile="production_qualification",
        scope="full",
        production_authorized=True,
        runner=_runner(nvidia=False),
    )
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["gpu-driver"]["state"] == UNAVAILABLE
    assert checks["gpu-runtime"]["state"] == UNAVAILABLE
    assert checks["production-authorization"]["state"] == PASS
    assert report["ready"] is False
    assert any(blocker.startswith("gpu-driver:") for blocker in report["blockers"])


def test_production_authorization_is_required(tmp_path: Path) -> None:
    report = _probe(
        tmp_path,
        profile="production_qualification",
        scope="full",
        production_authorized=False,
    )
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["production-authorization"]["state"] == FAIL
    assert report["ready"] is False

    report = _probe(
        tmp_path,
        profile="production_qualification",
        scope="full",
        production_authorized=True,
    )
    assert report["ready"] is True


def test_network_failure_is_unavailable(tmp_path: Path) -> None:
    report = _probe(
        tmp_path,
        profile="staging_qualification",
        network_probe=lambda host, port: False,
    )
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["network-ghcr"]["state"] == UNAVAILABLE
    assert checks["network-github"]["state"] == UNAVAILABLE
    assert report["ready"] is False


def test_missing_release_artifacts_blocks_qualification(tmp_path: Path) -> None:
    report = _probe(tmp_path, artifacts_dir=tmp_path / "missing")
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["release-artifacts"]["state"] == FAIL
    assert checks["release-manifest"]["state"] == FAIL
    assert report["ready"] is False
    assert "Qualification prerequisites: FAIL" in render_prerequisites_summary(report)


def test_missing_verification_report_blocks_qualification(tmp_path: Path) -> None:
    report = _probe(tmp_path, **_artifacts(tmp_path / "second", include_verification=False))
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["release-verification"]["state"] == FAIL
    assert report["ready"] is False
