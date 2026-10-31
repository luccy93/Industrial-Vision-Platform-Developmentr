"""Opt-in V28 live infrastructure verification.

Run explicitly with::

    pytest -m live backend/tests/live/test_v28_live_infrastructure.py -q

Every test requires an explicitly authorized staging target and real evidence
supplied through environment variables. Missing prerequisites skip with the
exact missing variable or tool name; they never become a pass. The tests are
bounded and read-only: no release, tag, registry, container, database, volume,
network, or deployment is created, changed, or deleted.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from tools.release import connectivity, docker_host
from tools.release.staging import staging_target_errors, staging_target_live_errors

REPO_ROOT = Path(__file__).resolve().parents[3]
CLI = [sys.executable, "-m", "tools.release.cli"]
DEFAULT_TIMEOUT = 15.0
MAX_TIMEOUT = 60.0

pytestmark = pytest.mark.live


def _missing_env(*names: str) -> list[str]:
    return [name for name in names if not os.environ.get(name)]


def _require_env(*names: str) -> None:
    missing = _missing_env(*names)
    if missing:
        pytest.skip("live prerequisites are not configured: " + ", ".join(missing))


def _require_file(variable: str) -> Path:
    path = Path(os.environ[variable])
    if not path.is_file():
        pytest.skip(f"live prerequisite file does not exist: {variable}={path}")
    return path


def _require_docker() -> None:
    if shutil.which("docker") is None:
        pytest.skip("live prerequisite tool is not installed: docker")


def _require_github_auth() -> None:
    if shutil.which("gh") is None:
        pytest.skip("live prerequisite tool is not installed: gh")
    if not (os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")):
        pytest.skip("live prerequisites are not configured: GH_TOKEN or GITHUB_TOKEN")


def _timeout() -> float:
    raw = os.environ.get("IVP_LIVE_CONNECTIVITY_TIMEOUT")
    if raw is None:
        return DEFAULT_TIMEOUT
    try:
        value = float(raw)
    except ValueError:
        pytest.skip(f"IVP_LIVE_CONNECTIVITY_TIMEOUT is not a number: {raw!r}")
    if not 1.0 <= value <= MAX_TIMEOUT:
        pytest.skip(f"IVP_LIVE_CONNECTIVITY_TIMEOUT is outside 1..{MAX_TIMEOUT:g}: {value}")
    return value


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _run_cli(*args: str, timeout: int = 1800) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [*CLI, *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _assert_read_only_commands(commands: list[str]) -> None:
    allowed = ("version", "context inspect", "compose version", "ps -a", "info --format")
    for command in commands:
        assert any(marker in command for marker in allowed), f"unexpected Docker command: {command}"


def test_live_v28_staging_readiness_is_read_only() -> None:
    _require_env(
        "IVP_LIVE_MANIFEST",
        "IVP_LIVE_STAGING_TARGET",
        "IVP_LIVE_ARTIFACTS_DIR",
        "IVP_LIVE_DOCKER_CONTEXT",
        "IVP_LIVE_MIGRATION_REPORT",
        "IVP_LIVE_BACKUP_DOCUMENTATION",
        "IVP_LIVE_PREVIOUS_MANIFEST",
        "IVP_LIVE_PREVIOUS_VERIFICATION",
        "IVP_LIVE_ROLLBACK_EVIDENCE",
    )
    _require_docker()
    _require_github_auth()
    manifest = _require_file("IVP_LIVE_MANIFEST")
    target_path = _require_file("IVP_LIVE_STAGING_TARGET")
    artifacts = Path(os.environ["IVP_LIVE_ARTIFACTS_DIR"])
    if not artifacts.is_dir():
        pytest.skip(f"live prerequisite directory does not exist: IVP_LIVE_ARTIFACTS_DIR={artifacts}")
    target = _load(target_path)
    problems = staging_target_errors(target)
    if problems:
        pytest.fail("live staging target is invalid:\n- " + "\n- ".join(problems))
    live_problems = staging_target_live_errors(target)
    if live_problems:
        pytest.skip("live staging target does not satisfy V28 policy: " + "; ".join(live_problems))
    output_dir = Path(os.environ.get("IVP_LIVE_EVIDENCE_DIR", "release-artifacts"))
    if not output_dir.is_absolute():
        output_dir = REPO_ROOT / output_dir
    output = output_dir / "v28-staging-readiness.json"
    args = [
        "staging-readiness",
        "--manifest",
        str(manifest),
        "--target",
        str(target_path),
        "--artifacts-dir",
        str(artifacts),
        "--previous-manifest",
        str(_require_file("IVP_LIVE_PREVIOUS_MANIFEST")),
        "--previous-verification-report",
        str(_require_file("IVP_LIVE_PREVIOUS_VERIFICATION")),
        "--rollback-evidence",
        str(_require_file("IVP_LIVE_ROLLBACK_EVIDENCE")),
        "--migration-report",
        str(_require_file("IVP_LIVE_MIGRATION_REPORT")),
        "--backup-documentation",
        str(_require_file("IVP_LIVE_BACKUP_DOCUMENTATION")),
        "--docker-host",
        os.environ["IVP_LIVE_DOCKER_CONTEXT"],
        "--connectivity-timeout",
        f"{_timeout():g}",
        "--execute-live",
        "--output",
        str(output),
    ]
    for host in os.environ.get("IVP_LIVE_PRODUCTION_HOSTS", "").split(","):
        if host.strip():
            args.extend(["--production-host", host.strip()])
    result = _run_cli(*args)
    assert output.is_file(), result.stderr[-2000:]
    report = _load(output)
    assert report["inspection_profile"] == "v28"
    assert report["mode"] == "live-read-only"
    assert report["production_qualified"] is False
    assert report["deployment"]["authorized"] is False
    assert report["deployment"]["performed"] is False
    assert report["state"] == "PASS", " | ".join(str(item) for item in report["blockers"][:8])
    live_path = output.parent / "readiness-evidence" / "live-inspection.json"
    if live_path.is_file():
        live = _load(live_path)
        assert live["mutation"]["performed"] is False
        docker_commands = live.get("docker", {}).get("commands", [])
        if isinstance(docker_commands, list):
            _assert_read_only_commands([str(command) for command in docker_commands])


def test_live_v28_docker_host_is_read_only() -> None:
    _require_env("IVP_LIVE_DOCKER_CONTEXT", "IVP_LIVE_COMPOSE_PROJECT")
    _require_docker()
    context = os.environ["IVP_LIVE_DOCKER_CONTEXT"]
    checks, observation = docker_host.inspect_docker_host(
        context,
        compose_project=os.environ["IVP_LIVE_COMPOSE_PROJECT"],
        gpu_required=os.environ.get("IVP_LIVE_GPU_REQUIRED") == "1",
        which=shutil.which,
        timeout=_timeout(),
    )
    _assert_read_only_commands([str(command) for command in observation["commands"]])
    inspection_check = next(check for check in checks if check["name"] == "docker-host-inspection")
    assert inspection_check["state"] == "PASS", inspection_check["detail"]


def test_live_v28_bounded_connectivity() -> None:
    _require_env("IVP_LIVE_STAGING_TARGET")
    target_path = _require_file("IVP_LIVE_STAGING_TARGET")
    target = _load(target_path)
    problems = staging_target_errors(target) + staging_target_live_errors(target)
    if problems:
        pytest.fail("live staging target is invalid:\n- " + "\n- ".join(problems))
    checks, observation = connectivity.connectivity_checks(
        target,
        timeout=_timeout(),
        execute_live=True,
    )
    required = [check for check in checks if check["required"] is True]
    assert required
    assert all(check["state"] == "PASS" for check in required), "; ".join(
        f"{check['name']}: {check['state']} - {check['detail']}"
        for check in required
        if check["state"] != "PASS"
    )
    assert observation["timeout_seconds"] <= MAX_TIMEOUT
