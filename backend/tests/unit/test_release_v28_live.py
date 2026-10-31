"""V28 live-readiness wiring tests for Docker hosts, connectivity, and rollback.

All tests are offline. Docker, GitHub, and network behavior is supplied through
deterministic fakes; no daemon, registry, release, or staging host is contacted.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from backend.tests.unit.test_release_readiness import (
    _assess,
    _environment,
    _FakeRunner,
    _inputs,
    _target_payload,
)
from backend.tests.unit.test_release_v28_inspection import _FakeGitHub
from backend.tests.unit.test_release_verification import make_release, make_runner
from tools.release import docker_host, rollback
from tools.release.manifest import sha256_file
from tools.release.readiness import (
    V28_CONNECTIVITY_CHECKS,
    V28_LIVE_CHECKS,
    ReadinessError,
    _v28_checks,
)
from tools.release.staging import STAGING_TARGET_STATEMENT
from tools.release.verification import FAIL, NOT_RUN, PASS, UNAVAILABLE

GENERATED_AT = "2026-10-31T00:00:00Z"


def _cp(args: Any, code: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args, code, stdout, stderr)


class _V28Runner:
    """Deterministic stand-in for Docker context, GHCR, and attestation probes."""

    def __init__(
        self,
        manifest: dict[str, Any],
        *,
        containers: list[dict[str, Any]] | None = None,
        gpu_runtime: bool = True,
        context_ok: bool = True,
        context_endpoint: str = "unix:///var/run/docker.sock",
    ) -> None:
        self.manifest = manifest
        self.containers = containers or []
        self.gpu_runtime = gpu_runtime
        self.context_ok = context_ok
        self.context_endpoint = context_endpoint
        self.digests = {image["name"]: image["digest"] for image in manifest["images"]}

    def __call__(
        self,
        args: Any,
        *,
        timeout: int = 120,
        env: Any = None,
    ) -> subprocess.CompletedProcess[str]:
        del timeout, env
        args = list(args)
        if args[:2] == ["docker", "--context"]:
            context = args[2]
            rest = args[3:]
            if rest[:1] == ["version"]:
                if not self.context_ok:
                    return _cp(args, 1, "", "Cannot connect to the Docker daemon")
                return _cp(args, 0, json.dumps({"Server": {"Version": "29.5.3"}}), "")
            if rest[:2] == ["context", "inspect"]:
                return _cp(
                    args,
                    0,
                    json.dumps(
                        {
                            "Name": context,
                            "Endpoints": {"docker": {"Host": self.context_endpoint}},
                        }
                    ),
                    "",
                )
            if rest[:2] == ["compose", "version"]:
                return _cp(args, 0, "Docker Compose version v2.30.0\n", "")
            if rest[:1] == ["ps"]:
                output = "\n".join(json.dumps(item) for item in self.containers)
                return _cp(args, 0, output, "")
            if rest[:1] == ["info"]:
                runtimes = {"runc": {}}
                if self.gpu_runtime:
                    runtimes["nvidia"] = {}
                return _cp(args, 0, json.dumps({"Runtimes": runtimes}), "")
        if args[:3] == ["docker", "buildx", "version"]:
            return _cp(args, 0, "github.com/docker/buildx v0.30.0\n", "")
        if args[:3] == ["docker", "buildx", "imagetools"]:
            if "--raw" in args:
                return _cp(args, 0, json.dumps({"manifests": []}), "")
            reference = args[-1]
            name = reference.rsplit("/", 1)[-1].split(":", 1)[0].split("@", 1)[0]
            digest = self.digests.get(name)
            if digest is None:
                return _cp(args, 1, "", "manifest unknown")
            return _cp(args, 0, digest + "\n", "")
        return _cp(args, 1, "", "unexpected command")


def _state(checks: list[dict[str, Any]], name: str) -> str:
    for check in checks:
        if check["name"] == name:
            return str(check["state"])
    raise AssertionError(f"no {name} check was produced")


# ---------------------------------------------------------------------------
# Docker host inspection
# ---------------------------------------------------------------------------


def test_docker_context_name_policy_rejects_urls_and_production() -> None:
    assert docker_host.docker_context_errors("staging-east") == []
    assert any("URL or SSH" in problem for problem in docker_host.docker_context_errors("ssh://host"))
    assert any("URL or SSH" in problem for problem in docker_host.docker_context_errors("user@host"))
    assert any("production" in problem for problem in docker_host.docker_context_errors("prod-host"))
    assert any("Docker context" in problem for problem in docker_host.docker_context_errors("bad context"))


def test_docker_host_without_context_is_not_run() -> None:
    checks, observation = docker_host.inspect_docker_host(
        None,
        compose_project="ivp-staging",
        gpu_required=False,
        which=lambda _: None,
        now=lambda: GENERATED_AT,
    )
    assert {check["name"] for check in checks} == set(docker_host.DOCKER_CHECKS)
    assert all(check["state"] == NOT_RUN for check in checks)
    assert observation["context"] is None


def test_docker_host_reports_unavailable_without_docker() -> None:
    checks, _ = docker_host.inspect_docker_host(
        "staging-east",
        compose_project="ivp-staging",
        gpu_required=False,
        which=lambda _: None,
        now=lambda: GENERATED_AT,
    )
    assert all(check["state"] == UNAVAILABLE for check in checks)


def test_docker_host_healthy_context_passes_read_only_checks(tmp_path: Path) -> None:
    _, _, manifest = make_release(tmp_path)
    checks, observation = docker_host.inspect_docker_host(
        "staging-east",
        compose_project="ivp-staging",
        gpu_required=False,
        runner=_V28Runner(manifest),
        which=lambda name: rf"C:\tools\{name}.exe",
        now=lambda: GENERATED_AT,
    )
    assert all(check["state"] == PASS for check in checks), checks
    assert _state(checks, "docker-host-gpu-runtime") == PASS
    assert checks[-1]["required"] is False
    assert observation["server_version"] == "29.5.3"
    assert observation["context_endpoint"] == "unix:///var/run/docker.sock"


def test_docker_host_rejects_restarting_project_containers(tmp_path: Path) -> None:
    _, _, manifest = make_release(tmp_path)
    checks, _ = docker_host.inspect_docker_host(
        "staging-east",
        compose_project="ivp-staging",
        gpu_required=False,
        runner=_V28Runner(
            manifest,
            containers=[{"Names": "ivp-api-1", "State": "restarting", "Status": "Restarting (1)"}],
        ),
        which=lambda name: rf"C:\tools\{name}.exe",
        now=lambda: GENERATED_AT,
    )
    assert _state(checks, "docker-host-containers") == FAIL


def test_docker_host_requires_gpu_runtime_only_when_gpu_is_required(tmp_path: Path) -> None:
    _, _, manifest = make_release(tmp_path)
    checks, _ = docker_host.inspect_docker_host(
        "staging-east",
        compose_project="ivp-staging",
        gpu_required=True,
        runner=_V28Runner(manifest, gpu_runtime=False),
        which=lambda name: rf"C:\tools\{name}.exe",
        now=lambda: GENERATED_AT,
    )
    assert _state(checks, "docker-host-gpu-runtime") == FAIL


def test_docker_host_rejects_production_context_endpoint(tmp_path: Path) -> None:
    _, _, manifest = make_release(tmp_path)
    checks, _ = docker_host.inspect_docker_host(
        "staging-east",
        compose_project="ivp-staging",
        gpu_required=False,
        runner=_V28Runner(manifest, context_endpoint="ssh://production.example.test"),
        which=lambda name: rf"C:\tools\{name}.exe",
        now=lambda: GENERATED_AT,
    )
    assert _state(checks, "docker-host-inspection") == FAIL


def test_docker_host_unreachable_daemon_is_unavailable(tmp_path: Path) -> None:
    _, _, manifest = make_release(tmp_path)
    checks, _ = docker_host.inspect_docker_host(
        "staging-east",
        compose_project="ivp-staging",
        gpu_required=False,
        runner=_V28Runner(manifest, context_ok=False),
        which=lambda name: rf"C:\tools\{name}.exe",
        now=lambda: GENERATED_AT,
    )
    assert _state(checks, "docker-host-inspection") == UNAVAILABLE


# ---------------------------------------------------------------------------
# Rollback prerequisites
# ---------------------------------------------------------------------------


def test_previous_digest_errors_require_distinct_images() -> None:
    current = {"images": [{"name": "api", "digest": "sha256:" + "a" * 64}]}
    previous = {"images": [{"name": "api", "digest": "sha256:" + "a" * 64}]}
    problems = rollback.previous_digest_errors(current, previous)
    assert any("api resolves to the same digest" in problem for problem in problems)


def test_previous_digest_errors_require_every_required_image() -> None:
    current = {"images": []}
    previous = {"images": []}
    problems = rollback.previous_digest_errors(current, previous)
    assert len(problems) == 3


def test_previous_digest_errors_accept_distinct_images() -> None:
    current = {
        "images": [{"name": name, "digest": "sha256:" + "a" * 64} for name in ("api", "web", "api-gpu")]
    }
    previous = {
        "images": [{"name": name, "digest": "sha256:" + "b" * 64} for name in ("api", "web", "api-gpu")]
    }
    assert rollback.previous_digest_errors(current, previous) == []


def _backup_document() -> str:
    return """# Backup and restore runbook

## PostgreSQL

Run `pg_dump` for the application database and store the dump in the encrypted
backup bucket. Restore it with `pg_restore` after stopping the API service.

## Redis

Snapshot Redis with `BGSAVE`, copy `dump.rdb`, and restore it before restarting
the worker and API containers.

## Volumes

Back up the named `postgres-data` and `redis-data` volumes with a read-only
tar archive. Restore the volumes before starting the Compose project again.

## Verification

Verify the backup by restoring it into an isolated staging project, checking
row counts, and confirming the API health endpoint reports ready=true.
"""


def test_backup_documentation_requires_full_coverage(tmp_path: Path) -> None:
    path = tmp_path / "backup.md"
    path.write_text(_backup_document(), encoding="utf-8")
    assert rollback.backup_documentation_errors(path) == []

    path.write_text(_backup_document().replace("Redis", "cache").replace("redis", "cache"), encoding="utf-8")
    assert any("redis" in problem for problem in rollback.backup_documentation_errors(path))


def test_backup_documentation_rejects_thin_or_binary_files(tmp_path: Path) -> None:
    short = tmp_path / "short.md"
    short.write_text("# Backup\nRestore the database.", encoding="utf-8")
    assert any("too short" in problem for problem in rollback.backup_documentation_errors(short))

    binary = tmp_path / "binary.md"
    binary.write_bytes(b"\xff\xfe\x00\x00")
    assert any("UTF-8" in problem for problem in rollback.backup_documentation_errors(binary))

    assert rollback.backup_documentation_errors(tmp_path / "missing.md")


# ---------------------------------------------------------------------------
# V28 live check wiring
# ---------------------------------------------------------------------------


def _connectivity_probe(
    target: dict[str, Any],
    *,
    timeout: float,
    execute_live: bool,
    now_iso: Any,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    del target, execute_live, now_iso
    checks = [
        {
            "name": name,
            "category": "connectivity",
            "state": PASS,
            "required": name != "service-identity",
            "mode": "live-read-only",
            "detail": "deterministic probe",
            "command": None,
        }
        for name in V28_CONNECTIVITY_CHECKS
    ]
    return checks, {
        "source": "bounded-network-probes",
        "timeout_seconds": timeout,
        "target": {"hosts": ["api.staging.example.test"]},
        "limitations": [],
    }


def _migration_report(tmp_path: Path, manifest_path: Path, manifest: dict[str, Any]) -> Path:
    report = {
        "schema_version": 1,
        "generated_at": GENERATED_AT,
        "manifest_sha256": sha256_file(manifest_path),
        "subject": dict(manifest["release"]),
        "previous_manifest_sha256": None,
        "revisions": [],
        "heads": [],
        "state": PASS,
        "verified": True,
        "checks": [],
        "blockers": [],
        "limitations": [],
    }
    path = tmp_path / "migration-report.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def test_v28_live_checks_wire_connectivity_docker_and_rollback(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest = make_release(tmp_path)
    target = _target_payload(
        staging_statement=STAGING_TARGET_STATEMENT,
        allowed_hostnames=[
            "api.staging.example.test",
            "web.staging.example.test",
            "ws.staging.example.test",
        ],
        production_hostnames=["api.example.com"],
    )
    backup = tmp_path / "backup.md"
    backup.write_text(_backup_document(), encoding="utf-8")
    migration = _migration_report(tmp_path, manifest_path, manifest)
    previous = {
        "images": [{"name": image["name"], "digest": "sha256:" + "b" * 64} for image in manifest["images"]]
    }
    previous_checks = [
        {"name": "previous-release", "state": PASS},
        {"name": "previous-verification", "state": PASS},
        {"name": "rollback-evidence", "state": PASS},
    ]

    checks, observation = _v28_checks(
        manifest=manifest,
        manifest_path=manifest_path,
        artifacts_dir=artifacts,
        target=target,
        target_live_errors=[],
        previous=previous,
        previous_checks=previous_checks,
        migration_report_path=migration,
        backup_documentation_path=backup,
        docker_host_name="staging-east",
        gpu_required=False,
        execute_live=True,
        environment={},
        runner=_V28Runner(manifest),
        which=lambda name: rf"C:\tools\{name}.exe" if name == "docker" else None,
        http_get=_FakeGitHub(manifest),
        connectivity_probe=_connectivity_probe,
        now=lambda: GENERATED_AT,
        timeout=10.0,
    )
    names = {check["name"] for check in checks}
    assert set(V28_LIVE_CHECKS) <= names
    assert _state(checks, "staging-target-live-policy") == PASS
    assert _state(checks, "docker-host-inspection") == PASS
    assert _state(checks, "docker-host-containers") == PASS
    assert _state(checks, "rollback-previous-digests") == PASS
    assert _state(checks, "rollback-migration-evidence") == PASS
    assert _state(checks, "rollback-backup-documentation") == PASS
    for name in V28_CONNECTIVITY_CHECKS:
        assert _state(checks, name) == PASS
    assert set(observation) >= {
        "github",
        "registry",
        "attestation",
        "artifacts",
        "connectivity",
        "docker",
        "rollback",
        "mutation",
    }
    assert observation["mutation"]["performed"] is False
    assert "no release" in observation["mutation"]["statement"]


def test_v28_live_checks_do_not_claim_mutation(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest = make_release(tmp_path)
    target = _target_payload(
        staging_statement=STAGING_TARGET_STATEMENT,
        allowed_hostnames=[
            "api.staging.example.test",
            "web.staging.example.test",
            "ws.staging.example.test",
        ],
        production_hostnames=[],
    )
    checks, observation = _v28_checks(
        manifest=manifest,
        manifest_path=manifest_path,
        artifacts_dir=artifacts,
        target=target,
        target_live_errors=[],
        previous=None,
        previous_checks=[],
        migration_report_path=None,
        backup_documentation_path=None,
        docker_host_name=None,
        gpu_required=False,
        execute_live=True,
        environment={},
        runner=_V28Runner(manifest),
        which=lambda name: rf"C:\tools\{name}.exe" if name == "docker" else None,
        http_get=_FakeGitHub(manifest),
        connectivity_probe=_connectivity_probe,
        now=lambda: GENERATED_AT,
        timeout=10.0,
    )
    assert _state(checks, "rollback-previous-digests") == FAIL
    assert _state(checks, "rollback-migration-evidence") == NOT_RUN
    assert _state(checks, "rollback-backup-documentation") == NOT_RUN
    assert observation["mutation"]["performed"] is False


class _V28AssessmentRunner(_FakeRunner):
    """V27 fake runner plus read-only V28 Docker context commands."""

    def __init__(self, manifest: dict[str, Any], **kwargs: Any) -> None:
        super().__init__(manifest, **kwargs)
        self._v28 = _V28Runner(manifest, **kwargs)
        self._attestations = make_runner()
        self.v28_calls: list[list[str]] = []

    def __call__(
        self,
        args: Any,
        *,
        timeout: int = 120,
        env: Any = None,
    ) -> subprocess.CompletedProcess[str]:
        args = list(args)
        self.v28_calls.append(args)
        if args[:2] == ["gh", "attestation"]:
            return self._attestations(args, timeout=timeout, env=env)
        if (
            args[:2] == ["docker", "--context"]
            or args[:3] == ["docker", "buildx", "version"]
            or args[:3] == ["docker", "buildx", "imagetools"]
        ):
            return self._v28(args, timeout=timeout, env=env)
        return super().__call__(args, timeout=timeout, env=env)


def test_v28_assessment_writes_live_inspection_and_evidence_bindings(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    manifest = inputs["manifest"]
    target = _target_payload(
        staging_statement=STAGING_TARGET_STATEMENT,
        allowed_hostnames=[
            "api.staging.example.test",
            "web.staging.example.test",
            "ws.staging.example.test",
        ],
        production_hostnames=[],
    )
    inputs["target_path"].write_text(json.dumps(target), encoding="utf-8")
    backup = tmp_path / "backup.md"
    backup.write_text(_backup_document(), encoding="utf-8")
    migration = _migration_report(tmp_path, inputs["manifest_path"], manifest)

    report = _assess(
        tmp_path,
        inputs,
        inspection_profile="v28",
        artifacts_dir=tmp_path / "release-artifacts",
        migration_report_path=migration,
        backup_documentation_path=backup,
        docker_host="staging-east",
        production_hosts=[],
        http_get=_FakeGitHub(manifest),
        connectivity_probe=_connectivity_probe,
        runner=_V28AssessmentRunner(manifest),
        env=_environment(),
        network_probe=lambda host, port: True,
    )

    evidence_dir = tmp_path / "readiness-evidence"
    live_path = evidence_dir / "live-inspection.json"
    assert live_path.is_file()
    live = json.loads(live_path.read_text(encoding="utf-8"))
    assert live["mode"] == "live-read-only"
    assert live["mutation"]["performed"] is False
    assert {"connectivity", "docker", "rollback"} <= set(live)
    assert live["target"]["name"] == target["name"]
    assert live["manifest_sha256"] == report["release"]["manifest_sha256"]

    assert report["inspection_profile"] == "v28"
    assert report["bindings"]["live_inspection"]["kind"] == "live-inspection"
    assert report["bindings"]["migration_report"]["kind"] == "migration-report"
    assert report["bindings"]["backup_documentation"]["kind"] == "backup-documentation"
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["staging-target-live-policy"]["state"] == PASS
    assert checks["docker-host-inspection"]["state"] == PASS
    assert checks["docker-host-containers"]["state"] == PASS
    assert checks["rollback-previous-digests"]["state"] == PASS
    assert checks["rollback-migration-evidence"]["state"] == PASS
    assert checks["rollback-backup-documentation"]["state"] == PASS
    assert all(checks[name]["state"] == PASS for name in V28_CONNECTIVITY_CHECKS)
    assert report["production_qualified"] is False
    assert report["deployment"]["authorized"] is False
    assert report["deployment"]["performed"] is False
    assert "No deployment" in report["deployment"]["statement"]


def test_v28_assessment_rejects_invalid_connectivity_timeout_up_front(
    tmp_path: Path,
) -> None:
    inputs = _inputs(tmp_path)
    for value in (0, 0.5, 61, True, "10"):
        with pytest.raises(ReadinessError, match="connectivity_timeout is invalid"):
            _assess(
                tmp_path,
                inputs,
                inspection_profile="v28",
                connectivity_timeout=value,
            )
