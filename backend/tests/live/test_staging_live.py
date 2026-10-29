"""Opt-in live staging qualification checks (V25).

Run explicitly with::

    pytest -m live backend/tests/live -q

Every test requires real infrastructure and credentials supplied through
environment variables. A missing prerequisite skips with the exact missing
variable or tool name; it never converts missing evidence into a pass. A test
that does run fails unless the live evidence is actually ``PASS``.

Mutation is gated twice: the ``live`` marker selects the module, and
``IVP_LIVE_MUTATION_AUTHORIZED=1`` plus an ``IVP_LIVE_AUTHORIZE`` value equal to
the staging target name is required before any deployment command runs.
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

REPO_ROOT = Path(__file__).resolve().parents[3]
CLI = [sys.executable, "-m", "tools.release.cli"]

pytestmark = pytest.mark.live


def _missing_env(*names: str) -> list[str]:
    return [name for name in names if not os.environ.get(name)]


def _require_env(*names: str) -> None:
    missing = _missing_env(*names)
    if missing:
        pytest.skip("live prerequisites are not configured: " + ", ".join(missing))


def _require_github_auth() -> None:
    _require_env("IVP_LIVE_MANIFEST", "IVP_LIVE_ARTIFACTS_DIR")
    if shutil.which("gh") is None:
        pytest.skip("live prerequisite tool is not installed: gh")
    if not (os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")):
        pytest.skip("live prerequisites are not configured: GH_TOKEN or GITHUB_TOKEN")


def _run_cli(*args: str, timeout: int = 1800) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [*CLI, *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _fail_detail(report: dict[str, Any]) -> str:
    parts = [f"state={report.get('state')!r}"]
    blockers = report.get("blockers")
    if isinstance(blockers, list) and blockers:
        parts.append("blockers=" + "; ".join(str(item) for item in blockers[:8]))
    return " | ".join(parts)


def test_live_release_evidence_collection(tmp_path: Path) -> None:
    _require_github_auth()
    output = tmp_path / "release-evidence.json"
    result = _run_cli(
        "collect-evidence",
        "--manifest",
        os.environ["IVP_LIVE_MANIFEST"],
        "--artifacts-dir",
        os.environ["IVP_LIVE_ARTIFACTS_DIR"],
        "--repo-root",
        str(REPO_ROOT),
        "--execute",
        "--output",
        str(output),
    )
    assert output.is_file(), result.stderr[-2000:]
    report = _load(output)
    assert report["state"] == "PASS", _fail_detail(report)


def test_live_staging_qualification(tmp_path: Path) -> None:
    _require_env(
        "IVP_LIVE_STAGING_TARGET",
        "IVP_LIVE_MANIFEST",
        "IVP_LIVE_ARTIFACTS_DIR",
        "IVP_LIVE_MUTATION_AUTHORIZED",
    )
    if os.environ["IVP_LIVE_MUTATION_AUTHORIZED"] != "1":
        pytest.skip("IVP_LIVE_MUTATION_AUTHORIZED is not exactly 1")
    target_path = Path(os.environ["IVP_LIVE_STAGING_TARGET"])
    if not target_path.is_file():
        pytest.skip(f"live staging target file does not exist: {target_path}")
    target = _load(target_path)
    name = target.get("name")
    if not isinstance(name, str) or not name:
        pytest.fail("live staging target has no name")
    authorize = os.environ.get("IVP_LIVE_AUTHORIZE")
    if authorize != name:
        pytest.skip(
            "IVP_LIVE_AUTHORIZE does not exactly match the staging target name "
            f"{name!r}; mutation was not authorized"
        )
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    output = evidence_dir / "staging-qualification.json"
    result = _run_cli(
        "staging-qualify",
        "--target",
        str(target_path),
        "--manifest",
        os.environ["IVP_LIVE_MANIFEST"],
        "--artifacts-dir",
        os.environ["IVP_LIVE_ARTIFACTS_DIR"],
        "--repo-root",
        str(REPO_ROOT),
        "--output",
        str(output),
        "--evidence-dir",
        str(evidence_dir),
        "--execute",
        "--authorize",
        authorize,
    )
    assert output.is_file(), result.stderr[-2000:]
    report = _load(output)
    assert report["staging_qualified"] is True, _fail_detail(report)
    gate = _run_cli(
        "check-staging",
        "--report",
        str(output),
        "--manifest",
        os.environ["IVP_LIVE_MANIFEST"],
        "--evidence-dir",
        str(evidence_dir),
    )
    assert gate.returncode == 0, gate.stderr[-2000:]


def test_live_gpu_inference(tmp_path: Path) -> None:
    _require_env("IVP_LIVE_GPU_MANIFEST")
    if shutil.which("nvidia-smi") is None:
        pytest.skip("live prerequisite tool is not installed: nvidia-smi")
    output = tmp_path / "gpu-inference.json"
    result = _run_cli(
        "gpu-inference",
        "--manifest",
        os.environ["IVP_LIVE_GPU_MANIFEST"],
        "--output",
        str(output),
        "--execute",
    )
    assert output.is_file(), result.stderr[-2000:]
    report = _load(output)
    assert report["state"] == "PASS", _fail_detail(report)
