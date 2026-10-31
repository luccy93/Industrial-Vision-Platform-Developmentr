"""V26 staging readiness preflight, evidence, and gate tests."""

from __future__ import annotations

import copy
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

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
from tools.release.cli import main
from tools.release.deployment import deployment_environment
from tools.release.manifest import sha256_file
from tools.release.qualification import QUALIFICATION_PROFILES, qualification_report_errors
from tools.release.readiness import (
    DEPLOYMENT_FIELDS,
    MANDATORY_READINESS_CHECKS,
    READINESS_BINDING_FIELDS,
    READINESS_BINDING_NAMES,
    READINESS_CHECK_FIELDS,
    READINESS_CHECK_NAMES,
    READINESS_EVIDENCE_DIR_NAME,
    READINESS_EVIDENCE_FIELDS,
    READINESS_PROFILE,
    READINESS_REPORT_FIELDS,
    READINESS_SCHEMA_VERSION,
    RELEASE_FIELDS,
    REPOSITORY_FIELDS,
    ROLLBACK_REQUIRED_CHECKS,
    SUBJECT_FIELDS,
    TARGET_FIELDS,
    _find_executable,
    _resolve_command,
    assess_staging_readiness,
    readiness_report_errors,
    readiness_report_sha256,
    write_readiness_report,
)
from tools.release.rehearsal import STEP_NAMES
from tools.release.staging import (
    STAGING_MODES,
    STAGING_SCHEMA_VERSION,
    STAGING_TARGET_REQUIRED_FIELDS,
)
from tools.release.verification import (
    EVIDENCE_STATES,
    FAIL,
    NOT_RUN,
    PASS,
    SIMULATED,
    UNAVAILABLE,
)

GENERATED_AT = "2026-10-26T00:00:00Z"
TOKEN_SENTINEL = "ghp_readiness_sentinel_do_not_disclose"
REGISTRY_SENTINEL = "ghcr_readiness_sentinel_do_not_disclose"
SMOKE_SENTINEL = "smoke_readiness_sentinel_do_not_disclose"
WINDOWS_COMSPEC = r"C:\Windows\System32\cmd.exe"
WINDOWS_NPM_CMD = r"C:\Program Files\nodejs\npm.CMD"


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
    path.write_text(json.dumps(payload if payload is not None else _target_payload()), encoding="utf-8")
    return path


def _compose_payload(manifest: dict[str, Any], *, gpu: bool = False) -> str:
    environment = deployment_environment(manifest, gpu=gpu)
    api_image = environment["IVP_GPU_API_IMAGE"] if gpu else environment["IVP_API_IMAGE"]
    return json.dumps(
        {
            "services": {
                "migrate": {"image": environment["IVP_API_IMAGE"]},
                "api": {
                    "image": api_image,
                    "environment": {
                        "DATABASE_URL": "postgresql://postgres:${POSTGRES_PASSWORD}@postgres:5432/db",
                        "REDIS_URL": "redis://redis:6379/0",
                    },
                    "healthcheck": {
                        "test": ["CMD", "python", "-c", "urlopen('http://localhost:8000/ready')"]
                    },
                    "ports": [{"host_ip": "127.0.0.1", "published": "8000", "target": 8000}],
                },
                "web": {
                    "image": environment["IVP_WEB_IMAGE"],
                    "healthcheck": {"test": ["CMD", "wget", "-q", "http://localhost:3000"]},
                    "ports": [{"host_ip": "127.0.0.1", "published": "3000", "target": 3000}],
                },
                "postgres": {
                    "image": "postgres:16-alpine",
                    "environment": {"POSTGRES_PASSWORD": "${POSTGRES_PASSWORD}"},
                    "healthcheck": {"test": ["CMD-SHELL", "pg_isready"]},
                    "volumes": [
                        {
                            "type": "volume",
                            "source": "postgres-data",
                            "target": "/var/lib/postgresql/data",
                        }
                    ],
                },
                "redis": {
                    "image": "redis:7-alpine",
                    "healthcheck": {"test": ["CMD", "redis-cli", "ping"]},
                    "volumes": [{"type": "volume", "source": "redis-data", "target": "/data"}],
                },
            },
            "volumes": {"postgres-data": {}, "redis-data": {}},
        }
    )


class _FakeRunner:
    """Deterministic local stand-in for git, Docker, GitHub CLI, and Compose."""

    def __init__(
        self,
        manifest: dict[str, Any],
        *,
        gpu: bool = False,
        docker_daemon: bool = True,
        compose_ok: bool = True,
        gh_auth: bool = True,
        gh_release: bool = True,
        registry_ok: bool = True,
        git_clean: bool = True,
        git_reachable: bool = True,
    ) -> None:
        self.manifest = manifest
        self.gpu = gpu
        self.docker_daemon = docker_daemon
        self.compose_ok = compose_ok
        self.gh_auth = gh_auth
        self.gh_release = gh_release
        self.registry_ok = registry_ok
        self.git_clean = git_clean
        self.git_reachable = git_reachable
        self.calls: list[list[str]] = []

    def __call__(
        self,
        args: Any,
        *,
        timeout: int = 120,
        env: Any = None,
    ) -> subprocess.CompletedProcess[str]:
        del timeout, env
        args = list(args)
        self.calls.append(args)
        if args == ["git", "--version"]:
            return subprocess.CompletedProcess(args, 0, "git version 2.45.0\n", "")
        if args[:3] == ["git", "-C", str(REPO_ROOT)]:
            rest = args[3:]
            if rest[:2] == ["remote", "get-url"]:
                return subprocess.CompletedProcess(
                    args, 0, f"https://github.com/{SOURCE_REPOSITORY}.git\n", ""
                )
            if rest == ["rev-parse", "HEAD"]:
                return subprocess.CompletedProcess(args, 0, COMMIT + "\n", "")
            if rest == ["rev-parse", "--abbrev-ref", "HEAD"]:
                return subprocess.CompletedProcess(args, 0, "main\n", "")
            if rest[:2] == ["rev-parse", "--verify"]:
                return subprocess.CompletedProcess(args, 0, COMMIT + "\n", "")
            if rest[:1] == ["status"]:
                output = "" if self.git_clean else " M backend/app/main.py\n"
                return subprocess.CompletedProcess(args, 0, output, "")
            if rest[:2] == ["merge-base", "--is-ancestor"]:
                return subprocess.CompletedProcess(args, 0 if self.git_reachable else 1, "", "")
        if args == ["pytest", "--version"]:
            return subprocess.CompletedProcess(args, 0, "pytest 8.0.0\n", "")
        if args == ["ruff", "--version"]:
            return subprocess.CompletedProcess(args, 0, "ruff 0.6.0\n", "")
        if args == ["node", "--version"]:
            return subprocess.CompletedProcess(args, 0, "v20.0.0\n", "")
        if args == ["npm", "--version"]:
            return subprocess.CompletedProcess(args, 0, "10.0.0\n", "")
        if args == ["gh", "--version"]:
            return subprocess.CompletedProcess(args, 0, "gh version 2.0.0\n", "")
        if args == ["gh", "auth", "status"]:
            return subprocess.CompletedProcess(
                args, 0 if self.gh_auth else 1, "Logged in to github.com\n", ""
            )
        if args[:3] == ["gh", "release", "view"]:
            if not self.gh_release:
                return subprocess.CompletedProcess(args, 1, "", "not found")
            return subprocess.CompletedProcess(
                args,
                0,
                json.dumps({"tagName": TAG, "isDraft": False, "isPrerelease": False}),
                "",
            )
        if args == ["docker", "--version"]:
            return subprocess.CompletedProcess(args, 0, "Docker version 29.5.3\n", "")
        if args[:3] == ["docker", "version", "--format"]:
            return subprocess.CompletedProcess(
                args, 0 if self.docker_daemon else 1, "29.5.3\n" if self.docker_daemon else "", ""
            )
        if args[:3] == ["docker", "compose", "version"]:
            return subprocess.CompletedProcess(
                args,
                0 if self.compose_ok else 1,
                "Docker Compose version v2.30.0\n" if self.compose_ok else "",
                "",
            )
        if args[:3] == ["docker", "manifest", "inspect"]:
            return subprocess.CompletedProcess(
                args, 0 if self.registry_ok else 1, "{}" if self.registry_ok else "", ""
            )
        if args[:3] == ["docker", "info", "--format"]:
            return subprocess.CompletedProcess(args, 0, '{"runc":{},"nvidia":{}}', "")
        if "config" in args:
            return subprocess.CompletedProcess(
                args,
                0 if self.compose_ok else 1,
                _compose_payload(self.manifest, gpu=self.gpu) if self.compose_ok else "",
                "" if self.compose_ok else "compose failed",
            )
        return subprocess.CompletedProcess(args, 1, "", "unexpected command")


class _WindowsShimRunner(_FakeRunner):
    """Fake runner that recognizes the Windows ``cmd.exe call`` shim."""

    def __call__(
        self,
        args: Any,
        *,
        timeout: int = 120,
        env: Any = None,
    ) -> subprocess.CompletedProcess[str]:
        args = list(args)
        if args[:7] == [WINDOWS_COMSPEC, "/d", "/s", "/v:off", "/c", "call", WINDOWS_NPM_CMD]:
            self.calls.append(args)
            if args[7:] == ["--version"]:
                return subprocess.CompletedProcess(args, 0, "11.11.0\n", "")
            return subprocess.CompletedProcess(args, 1, "", "unexpected npm probe")
        return super().__call__(args, timeout=timeout, env=env)


class _NpmProbeRunner(_WindowsShimRunner):
    """Return or raise a configured result for the Windows npm probe."""

    def __init__(self, manifest: dict[str, Any], probe: Any) -> None:
        super().__init__(manifest)
        self.probe = probe

    def __call__(
        self,
        args: Any,
        *,
        timeout: int = 120,
        env: Any = None,
    ) -> subprocess.CompletedProcess[str]:
        args = list(args)
        if args[:7] == [WINDOWS_COMSPEC, "/d", "/s", "/v:off", "/c", "call", WINDOWS_NPM_CMD]:
            self.calls.append(args)
            return self.probe(args)
        return super().__call__(args, timeout=timeout, env=env)


def _windows_which(name: str) -> str | None:
    if name == "npm":
        return WINDOWS_NPM_CMD
    return rf"C:\tools\{name}.exe"


def _environment(**overrides: Any) -> dict[str, str]:
    environment = {
        "IVP_SMOKE_PASSWORD": SMOKE_SENTINEL,
        "POSTGRES_PASSWORD": "postgres-test-value",
        "GH_TOKEN": TOKEN_SENTINEL,
        "CR_PAT": REGISTRY_SENTINEL,
    }
    environment.update(overrides)
    return environment


def _write_rollback_report(
    tmp_path: Path,
    manifest_path: Path,
    manifest: dict[str, Any],
    previous_path: Path,
    previous: dict[str, Any],
    *,
    executed: bool = True,
    state: str = PASS,
    verified: bool = True,
) -> Path:
    log = tmp_path / "rollback.log"
    log.write_text("rollback completed\n", encoding="utf-8")

    def subject(document: dict[str, Any]) -> dict[str, Any]:
        release = document["release"]
        return {
            "tag": release["tag"],
            "commit": release["commit"],
            "source_repository": release["source_repository"],
        }

    def digests(document: dict[str, Any]) -> dict[str, Any]:
        return {image["name"]: image["digest"] for image in document["images"]}

    report = {
        "schema_version": 1,
        "generated_at": "2026-10-25T00:00:00Z",
        "executed": executed,
        "state": state,
        "verified": verified,
        "manifest_sha256": sha256_file(manifest_path),
        "subject": subject(manifest),
        "previous_manifest_sha256": sha256_file(previous_path),
        "previous_subject": subject(previous),
        "target": {
            "manifest_sha256": sha256_file(manifest_path),
            "subject": subject(manifest),
            "digests": digests(manifest),
        },
        "previous": {
            "manifest_sha256": sha256_file(previous_path),
            "subject": subject(previous),
            "digests": digests(previous),
        },
        "checks": [
            {"name": name, "state": PASS, "required": True, "detail": "simulated"}
            for name in ROLLBACK_REQUIRED_CHECKS
        ],
        "steps": [{"name": name, "state": PASS, "detail": "simulated"} for name in STEP_NAMES],
        "evidence": [{"kind": "rollback-log", "path": log.name, "sha256": sha256_file(log)}],
        "blockers": [],
        "limitations": [],
    }
    path = tmp_path / "rollback-rehearsal.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def _inputs(tmp_path: Path, *, gpu: bool = False) -> dict[str, Any]:
    manifest_path, _, manifest = make_release(tmp_path)
    previous_path, previous = previous_release_manifest(tmp_path, manifest)
    previous_report = tmp_path / "previous-verification.json"
    write_production_verification_report(previous_report, previous_path, previous)
    rollback_path = _write_rollback_report(
        tmp_path,
        manifest_path,
        manifest,
        previous_path,
        previous,
    )
    target = _target_payload(
        gpu=gpu,
        compose_files=["compose.gpu.release.yaml" if gpu else "compose.release.yaml"],
    )
    return {
        "manifest_path": manifest_path,
        "manifest": manifest,
        "previous_path": previous_path,
        "previous": previous,
        "previous_report": previous_report,
        "rollback_path": rollback_path,
        "target_path": _write_target(tmp_path, target),
        "runner": _FakeRunner(manifest, gpu=gpu),
    }


def _assess(tmp_path: Path, inputs: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    options: dict[str, Any] = {
        "repo_root": REPO_ROOT,
        "evidence_dir": tmp_path / "readiness-evidence",
        "manifest_path": inputs["manifest_path"],
        "target_path": inputs["target_path"],
        "previous_manifest_path": inputs["previous_path"],
        "previous_verification_report_path": inputs["previous_report"],
        "rollback_evidence_path": inputs["rollback_path"],
        "expected_tag": TAG,
        "expected_commit": COMMIT,
        "expected_repository": SOURCE_REPOSITORY,
        "expected_branch": "main",
        "main_ref": "origin/main",
        "env": _environment(),
        "runner": inputs["runner"],
        "which": lambda name: None if name == "nvidia-smi" else f"/usr/bin/{name}",
        "network_probe": lambda host, port: True,
        "execute_live": True,
        "now": lambda: GENERATED_AT,
    }
    options.update(overrides)
    return assess_staging_readiness(**options)


def _checks(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {check["name"]: check for check in report["checks"]}


def _write_report(tmp_path: Path, report: dict[str, Any]) -> tuple[Path, str]:
    path = tmp_path / "staging-readiness.json"
    digest = write_readiness_report(report, path)
    return path, digest


def _errors(
    report: dict[str, Any],
    manifest_path: Path,
    *,
    report_path: Path | None = None,
    evidence_dir: Path | None = None,
    expected_report_sha256: str | None = None,
) -> list[str]:
    return readiness_report_errors(
        report,
        manifest_path=manifest_path,
        report_path=report_path,
        evidence_dir=evidence_dir,
        expected_report_sha256=expected_report_sha256,
    )


def _readiness_schema() -> dict[str, Any]:
    return json.loads((REPO_ROOT / "release" / "staging-readiness.schema.json").read_text(encoding="utf-8"))


def _schema_errors(report: dict[str, Any]) -> list[str]:
    validator = Draft202012Validator(_readiness_schema())
    return [
        f"{'/'.join(str(part) for part in error.absolute_path)}: {error.message}"
        for error in validator.iter_errors(report)
    ]


def _incomplete_report(tmp_path: Path) -> dict[str, Any]:
    inputs = _inputs(tmp_path)
    return _assess(
        tmp_path,
        inputs,
        manifest_path=None,
        target_path=None,
        previous_manifest_path=None,
        previous_verification_report_path=None,
        rollback_evidence_path=None,
    )


def _pass_report(tmp_path: Path) -> tuple[dict[str, Any], dict[str, Any], Path, str]:
    inputs = _inputs(tmp_path)
    report = _assess(tmp_path, inputs)
    path, digest = _write_report(tmp_path, report)
    return inputs, report, path, digest


def test_readiness_pass_report_validates_and_never_authorizes_deployment(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    report = _assess(tmp_path, inputs)
    path, digest = _write_report(tmp_path, report)

    assert report["state"] == PASS
    assert report["ready"] is True
    assert report["profile"] == READINESS_PROFILE
    assert report["mode"] == "live-read-only"
    assert report["production_qualified"] is False
    assert report["deployment"] == {
        "authorized": False,
        "performed": False,
        "statement": report["deployment"]["statement"],
    }
    assert "No deployment was authorized or performed" in report["deployment"]["statement"]
    assert (
        _errors(
            report, inputs["manifest_path"], report_path=path, evidence_dir=tmp_path / "readiness-evidence"
        )
        == []
    )
    assert (
        _errors(
            report,
            inputs["manifest_path"],
            report_path=path,
            evidence_dir=tmp_path / "readiness-evidence",
            expected_report_sha256=digest,
        )
        == []
    )


def test_readiness_schema_matches_runtime_contracts() -> None:
    schema = json.loads((REPO_ROOT / "release" / "staging-readiness.schema.json").read_text(encoding="utf-8"))
    assert schema["properties"]["schema_version"]["const"] == READINESS_SCHEMA_VERSION
    assert schema["properties"]["profile"]["const"] == READINESS_PROFILE
    assert set(schema["required"]) == set(READINESS_REPORT_FIELDS)
    assert set(schema["properties"]) == set(READINESS_REPORT_FIELDS)
    assert set(schema["$defs"]["check"]["required"]) == set(READINESS_CHECK_FIELDS)
    assert set(schema["$defs"]["evidence"]["required"]) == set(READINESS_EVIDENCE_FIELDS)
    assert set(schema["$defs"]["binding"]["required"]) == set(READINESS_BINDING_FIELDS)
    assert set(schema["$defs"]["subject"]["required"]) == set(SUBJECT_FIELDS)
    assert set(schema["properties"]["repository"]["required"]) == set(REPOSITORY_FIELDS)
    assert set(schema["properties"]["release"]["required"]) == set(RELEASE_FIELDS)
    assert set(schema["$defs"]["staging_target"]["required"]) == set(TARGET_FIELDS)
    assert set(schema["properties"]["deployment"]["required"]) == set(DEPLOYMENT_FIELDS)
    assert schema["properties"]["production_qualified"]["const"] is False
    assert schema["properties"]["deployment"]["properties"]["authorized"]["const"] is False
    assert schema["properties"]["deployment"]["properties"]["performed"]["const"] is False
    assert "allOf" in schema
    assert set(schema["$defs"]["incomplete_subject"]["required"]) == set(SUBJECT_FIELDS)
    assert set(schema["$defs"]["pass_release"]["required"]) == set(RELEASE_FIELDS)
    assert set(schema["$defs"]["pass_bindings"]["required"]) == set(READINESS_BINDING_NAMES)


def test_readiness_schema_is_valid_and_accepts_incomplete_preflight_report(tmp_path: Path) -> None:
    Draft202012Validator.check_schema(_readiness_schema())
    report = _incomplete_report(tmp_path)

    assert report["state"] != PASS
    assert report["ready"] is False
    assert report["staging_target"] is None
    assert report["release"]["manifest_sha256"] is None
    assert report["release"]["subject"] == {
        "tag": None,
        "commit": None,
        "source_repository": None,
    }
    assert report["release"]["digests"] == {}
    assert set(report["bindings"]) == set(READINESS_BINDING_NAMES)
    assert all(binding is None for binding in report["bindings"].values())
    assert report["evidence"] == []
    assert _schema_errors(report) == []


@pytest.mark.parametrize("state", [FAIL, NOT_RUN, UNAVAILABLE, SIMULATED])
def test_schema_accepts_incomplete_non_pass_reports(tmp_path: Path, state: str) -> None:
    report = _incomplete_report(tmp_path)
    report["state"] = state

    assert report["ready"] is False
    assert _schema_errors(report) == []


def test_incomplete_report_cannot_be_schema_valid_as_pass(tmp_path: Path) -> None:
    report = _incomplete_report(tmp_path)
    report["state"] = PASS

    errors = _schema_errors(report)

    assert errors
    assert any("staging_target" in error or "release" in error for error in errors)


def test_schema_rejects_malformed_incomplete_report(tmp_path: Path) -> None:
    report = _incomplete_report(tmp_path)
    report["checks"] = "not-a-list"
    report["unexpected"] = True

    errors = _schema_errors(report)

    assert errors
    assert any("checks" in error for error in errors)
    assert any("unexpected" in error for error in errors)


def test_pass_report_is_schema_valid(tmp_path: Path) -> None:
    _, report, _, _ = _pass_report(tmp_path)

    assert report["state"] == PASS
    assert _schema_errors(report) == []


@pytest.mark.parametrize(
    "mutate",
    [
        lambda report: report["staging_target"].__setitem__("name", None),
        lambda report: report["release"].__setitem__("manifest_sha256", None),
        lambda report: report["release"]["subject"].__setitem__("tag", None),
        lambda report: report["repository"].__setitem__("commit", None),
    ],
)
def test_pass_schema_rejects_null_required_values(
    tmp_path: Path,
    mutate: Any,
) -> None:
    _, report, _, _ = _pass_report(tmp_path)
    mutate(report)

    assert _schema_errors(report)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda report: report["bindings"].__setitem__("manifest", None),
        lambda report: report["bindings"].pop("target"),
    ],
)
def test_pass_schema_rejects_missing_bindings(
    tmp_path: Path,
    mutate: Any,
) -> None:
    _, report, _, _ = _pass_report(tmp_path)
    mutate(report)

    assert _schema_errors(report)


@pytest.mark.parametrize("state", [FAIL, NOT_RUN, UNAVAILABLE, SIMULATED])
def test_pass_schema_rejects_non_pass_required_checks(tmp_path: Path, state: str) -> None:
    _, report, _, _ = _pass_report(tmp_path)
    check = next(item for item in report["checks"] if item["name"] == "manifest")
    check["state"] = state
    if state == SIMULATED:
        check["mode"] = "simulated"

    assert _schema_errors(report)


def test_pass_schema_rejects_preflight_live_checks(tmp_path: Path) -> None:
    _, report, _, _ = _pass_report(tmp_path)
    report["mode"] = "preflight"

    errors = _schema_errors(report)

    assert errors
    assert any("live-read-only" in error for error in errors)


def test_schema_rejects_contradictory_state_and_ready_flags(tmp_path: Path) -> None:
    _, report, _, _ = _pass_report(tmp_path)

    non_pass = copy.deepcopy(report)
    non_pass["state"] = FAIL
    assert _schema_errors(non_pass)

    not_ready = copy.deepcopy(report)
    not_ready["ready"] = False
    assert _schema_errors(not_ready)

    optional_gpu = copy.deepcopy(report)
    optional_gpu["gpu_ready"] = True
    assert _schema_errors(optional_gpu)

    required_gpu = copy.deepcopy(report)
    required_gpu["gpu_required"] = True
    assert _schema_errors(required_gpu)


def test_schema_rejects_tampered_binding_hash(tmp_path: Path) -> None:
    _, report, _, _ = _pass_report(tmp_path)
    report["bindings"]["manifest"]["sha256"] = "sha256:not-a-digest"

    assert _schema_errors(report)


def test_preflight_mode_stays_offline_and_does_not_validate_credentials(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    calls: list[list[str]] = []

    def forbidden_probe(host: str, port: int) -> bool:
        del host, port
        raise AssertionError("preflight must not probe the network")

    report = _assess(
        tmp_path,
        inputs,
        execute_live=False,
        network_probe=forbidden_probe,
        runner=_FakeRunner(inputs["manifest"], gh_auth=False, gh_release=False),
    )
    calls = inputs["runner"].calls
    checks = _checks(report)

    assert report["mode"] == "preflight"
    assert checks["github-auth-config"]["state"] == UNAVAILABLE
    assert checks["registry-auth-config"]["state"] == UNAVAILABLE
    assert checks["release-tag-remote"]["state"] == NOT_RUN
    assert checks["network-github"]["state"] == NOT_RUN
    assert checks["network-ghcr"]["state"] == NOT_RUN
    assert not any(call[:3] == ["gh", "auth", "status"] for call in calls)
    assert not any(call[:3] == ["gh", "release", "view"] for call in calls)
    assert not any(call[:3] == ["docker", "manifest", "inspect"] for call in calls)
    assert report["state"] != PASS


def test_missing_target_is_not_inferred_and_blocks_readiness(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    report = _assess(tmp_path, inputs, target_path=None)
    checks = _checks(report)

    assert checks["staging-target"]["state"] == FAIL
    assert checks["staging-target"]["required"] is True
    assert "never inferred" in checks["staging-target"]["detail"]
    assert report["staging_target"] is None
    assert report["ready"] is False
    assert any(blocker.startswith("staging-target:") for blocker in report["blockers"])


@pytest.mark.parametrize(
    ("overrides", "needle"),
    [
        ({"environment": "production"}, "environment must be exactly 'staging'"),
        ({"name": "production-api"}, "name looks like a production target"),
        ({"api_url": "http://staging.example.test"}, "api_url must use https://"),
        (
            {"api_url": "https://user:password@staging.example.test"},
            "api_url must not embed credentials",
        ),
        ({"api_url": "https://api.prod.example.test"}, "api_url hostname looks like a production host"),
        ({"ws_url": "ws://staging.example.test"}, "ws_url must use wss://"),
        ({"unexpected": "value"}, "unknown fields: unexpected"),
    ],
)
def test_invalid_target_values_fail_closed(
    tmp_path: Path,
    overrides: dict[str, Any],
    needle: str,
) -> None:
    inputs = _inputs(tmp_path)
    target_path = _write_target(tmp_path, _target_payload(**overrides))
    report = _assess(tmp_path, inputs, target_path=target_path)
    checks = _checks(report)

    assert checks["staging-target"]["state"] == FAIL
    assert needle in checks["staging-target"]["detail"]
    assert report["staging_target"] is None
    assert report["ready"] is False


def test_docker_cli_without_daemon_is_unavailable(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    report = _assess(
        tmp_path,
        inputs,
        runner=_FakeRunner(inputs["manifest"], docker_daemon=False),
    )
    checks = _checks(report)

    assert checks["docker-cli"]["state"] == PASS
    assert checks["docker-daemon"]["state"] == UNAVAILABLE
    assert "CLI installation alone" in checks["docker-daemon"]["detail"]
    assert report["state"] == UNAVAILABLE
    assert report["ready"] is False


def test_missing_gh_and_auth_are_unavailable(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    report = _assess(
        tmp_path,
        inputs,
        which=lambda name: None if name == "gh" else f"/usr/bin/{name}",
        runner=_FakeRunner(inputs["manifest"], gh_auth=False, gh_release=False),
    )
    checks = _checks(report)

    assert checks["github-cli"]["state"] == UNAVAILABLE
    assert checks["github-auth-config"]["state"] == UNAVAILABLE
    assert "gh is not installed" in checks["github-auth-config"]["detail"]
    assert report["state"] == UNAVAILABLE
    assert report["ready"] is False


def test_environment_presence_is_reported_without_disclosing_values(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    report = _assess(tmp_path, inputs)
    path, _ = _write_report(tmp_path, report)
    text = path.read_text(encoding="utf-8")
    checks = _checks(report)

    assert checks["smoke-credential"]["state"] == PASS
    assert "IVP_SMOKE_PASSWORD is set" in checks["smoke-credential"]["detail"]
    assert checks["github-auth-config"]["state"] == PASS
    assert "credential value was not inspected" in checks["github-auth-config"]["detail"]
    assert checks["registry-auth-config"]["state"] == PASS
    assert "no credential value was inspected" in checks["registry-auth-config"]["detail"]
    assert TOKEN_SENTINEL not in text
    assert REGISTRY_SENTINEL not in text
    assert SMOKE_SENTINEL not in text


def test_missing_manifest_and_digests_block_readiness(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    report = _assess(tmp_path, inputs, manifest_path=None)
    checks = _checks(report)

    assert checks["manifest"]["state"] == FAIL
    assert checks["manifest-digests"]["state"] == NOT_RUN
    assert checks["staging-target-release-binding"]["state"] == NOT_RUN
    assert checks["compose-config"]["state"] == NOT_RUN
    assert report["ready"] is False
    assert any(blocker.startswith("manifest:") for blocker in report["blockers"])


def test_placeholder_digest_blocks_readiness(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    placeholder = copy.deepcopy(inputs["manifest"])
    placeholder["images"][0]["digest"] = "sha256:" + "0" * 64
    placeholder_path = tmp_path / "placeholder-manifest.json"
    placeholder_path.write_text(json.dumps(placeholder), encoding="utf-8")

    report = _assess(tmp_path, inputs, manifest_path=placeholder_path)
    checks = _checks(report)

    assert checks["manifest-digests"]["state"] == FAIL
    assert "placeholder digest" in checks["manifest-digests"]["detail"]
    assert report["ready"] is False


def test_missing_compose_file_blocks_readiness(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    target_path = _write_target(
        tmp_path,
        _target_payload(compose_files=["missing-compose.yaml"]),
    )
    report = _assess(tmp_path, inputs, target_path=target_path)
    checks = _checks(report)

    assert checks["compose-files"]["state"] == FAIL
    assert "does not exist" in checks["compose-files"]["detail"]
    assert report["ready"] is False


def test_missing_smoke_credential_is_unavailable(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    environment = _environment()
    environment.pop("IVP_SMOKE_PASSWORD")
    report = _assess(tmp_path, inputs, env=environment)
    checks = _checks(report)

    assert checks["smoke-credential"]["state"] == UNAVAILABLE
    assert "IVP_SMOKE_PASSWORD is not set" in checks["smoke-credential"]["detail"]
    assert report["state"] == UNAVAILABLE
    assert report["ready"] is False


def test_missing_rollback_evidence_blocks_readiness(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    report = _assess(tmp_path, inputs, rollback_evidence_path=None)
    checks = _checks(report)

    assert checks["rollback-evidence"]["state"] == FAIL
    assert "no rollback rehearsal evidence" in checks["rollback-evidence"]["detail"]
    assert report["ready"] is False


def test_optional_gpu_checks_are_not_run_and_do_not_imply_gpu_readiness(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    report = _assess(tmp_path, inputs)
    checks = _checks(report)

    assert report["gpu_required"] is False
    assert report["gpu_ready"] is False
    for name in ("gpu-hardware", "gpu-driver", "gpu-container-runtime", "gpu-image-digest"):
        assert checks[name]["required"] is False
        assert checks[name]["state"] == NOT_RUN
        assert "CPU readiness does not imply GPU readiness" in checks[name]["detail"]


def test_required_gpu_without_hardware_is_unavailable(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path, gpu=True)
    report = _assess(
        tmp_path,
        inputs,
        require_gpu=True,
        runner=_FakeRunner(inputs["manifest"], gpu=True),
    )
    checks = _checks(report)

    assert report["gpu_required"] is True
    assert report["gpu_ready"] is False
    assert checks["gpu-profile"]["state"] == PASS
    assert checks["gpu-hardware"]["state"] == UNAVAILABLE
    assert checks["gpu-driver"]["state"] == UNAVAILABLE
    assert report["state"] == UNAVAILABLE
    assert report["ready"] is False


@pytest.mark.parametrize("state", [FAIL, NOT_RUN, UNAVAILABLE, SIMULATED])
def test_non_pass_states_never_satisfy_readiness_gate(tmp_path: Path, state: str) -> None:
    inputs = _inputs(tmp_path)
    report = _assess(tmp_path, inputs)
    path, _ = _write_report(tmp_path, report)
    tampered = copy.deepcopy(report)
    next(check for check in tampered["checks"] if check["name"] == "manifest")["state"] = state

    errors = _errors(
        tampered,
        inputs["manifest_path"],
        report_path=path,
        evidence_dir=tmp_path / "readiness-evidence",
    )
    assert any("required checks are not PASS" in error for error in errors)
    assert any("state contradicts" in error for error in errors)


def test_changed_report_bytes_are_rejected(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    report = _assess(tmp_path, inputs)
    path, digest = _write_report(tmp_path, report)
    path.write_text(path.read_text(encoding="utf-8") + " ", encoding="utf-8")

    errors = _errors(
        report,
        inputs["manifest_path"],
        report_path=path,
        evidence_dir=tmp_path / "readiness-evidence",
        expected_report_sha256=digest,
    )
    assert any("bytes changed" in error for error in errors)


def test_unknown_fields_and_binding_mismatch_are_rejected(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    report = _assess(tmp_path, inputs)
    path, _ = _write_report(tmp_path, report)

    unknown = copy.deepcopy(report)
    unknown["unexpected"] = True
    unknown_errors = _errors(
        unknown,
        inputs["manifest_path"],
        report_path=path,
        evidence_dir=tmp_path / "readiness-evidence",
    )
    assert any("unknown fields" in error for error in unknown_errors)

    mismatch = copy.deepcopy(report)
    mismatch["bindings"]["manifest"]["sha256"] = "sha256:" + "f" * 64
    mismatch_errors = _errors(
        mismatch,
        inputs["manifest_path"],
        report_path=path,
        evidence_dir=tmp_path / "readiness-evidence",
    )
    assert any("binding does not match its evidence" in error for error in mismatch_errors)


def test_readiness_profile_is_not_a_qualification_profile() -> None:
    assert READINESS_PROFILE == "staging_readiness"
    assert READINESS_PROFILE not in QUALIFICATION_PROFILES
    assert set(MANDATORY_READINESS_CHECKS).issubset(set(READINESS_CHECK_NAMES))


def test_cli_check_readiness_accepts_valid_report_and_rejects_tampered_report(
    tmp_path: Path,
    capsys: Any,
) -> None:
    inputs = _inputs(tmp_path)
    report = _assess(tmp_path, inputs)
    path, digest = _write_report(tmp_path, report)

    exit_code = main(
        [
            "check-readiness",
            "--report",
            str(path),
            "--manifest",
            str(inputs["manifest_path"]),
            "--report-sha256",
            digest,
        ]
    )
    assert exit_code == 0
    assert "does not authorize a deployment" in capsys.readouterr().out

    path.write_text(path.read_text(encoding="utf-8") + " ", encoding="utf-8")
    exit_code = main(
        [
            "check-readiness",
            "--report",
            str(path),
            "--manifest",
            str(inputs["manifest_path"]),
            "--report-sha256",
            digest,
        ]
    )
    assert exit_code == 1
    assert "bytes changed" in capsys.readouterr().err


def test_check_readiness_still_rejects_schema_valid_incomplete_report(
    tmp_path: Path,
    capsys: Any,
) -> None:
    report = _incomplete_report(tmp_path)
    manifest_path = tmp_path / "release-artifacts" / "release-manifest.json"
    assert _schema_errors(report) == []
    path, digest = _write_report(tmp_path, report)

    exit_code = main(
        [
            "check-readiness",
            "--report",
            str(path),
            "--manifest",
            str(manifest_path),
            "--report-sha256",
            digest,
        ]
    )

    assert exit_code == 1
    errors = capsys.readouterr().err
    assert "required checks are not PASS" in errors
    assert "staging target is missing" in errors
    assert "bindings are missing" in errors or "binding is missing" in errors
    assert "not bound to the supplied manifest" in errors


def test_readiness_report_sha256_binds_exact_report_bytes(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    report = _assess(tmp_path, inputs)
    path, digest = _write_report(tmp_path, report)

    assert readiness_report_sha256(path) == digest == sha256_file(path)

    path.write_text(path.read_text(encoding="utf-8") + " ", encoding="utf-8")
    assert readiness_report_sha256(path) != digest


def test_live_probe_failures_are_unavailable_not_pass(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    report = _assess(
        tmp_path,
        inputs,
        runner=_FakeRunner(inputs["manifest"], gh_auth=False, registry_ok=False),
        network_probe=lambda host, port: False,
    )
    checks = _checks(report)

    for name in ("github-auth-config", "registry-auth-config", "network-github", "network-ghcr"):
        assert checks[name]["state"] == UNAVAILABLE
        assert checks[name]["state"] != PASS
    assert report["state"] == UNAVAILABLE
    assert report["ready"] is False
    assert report["deployment"]["authorized"] is False
    assert report["production_qualified"] is False


def test_live_probes_issue_only_read_only_commands(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    _assess(tmp_path, inputs)
    forbidden = {
        "push",
        "publish",
        "deploy",
        "create",
        "delete",
        "rm",
        "down",
        "up",
        "tag",
        "login",
        "logout",
        "run",
    }

    for call in inputs["runner"].calls:
        assert not forbidden.intersection(call), call
        if call[0] == "gh":
            assert call[:2] in (["gh", "--version"], ["gh", "auth"], ["gh", "release"]), call
        if call[0] == "docker":
            assert call[1] in ("--version", "version", "compose", "manifest", "info"), call


def test_windows_npm_cmd_shim_is_discovered_and_probed(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    runner = _WindowsShimRunner(inputs["manifest"])
    report = _assess(
        tmp_path,
        inputs,
        runner=runner,
        which=_windows_which,
        platform_name="win32",
        env=_environment(COMSPEC=WINDOWS_COMSPEC),
    )
    checks = _checks(report)

    assert checks["node"]["state"] == PASS
    assert checks["npm"]["state"] == PASS
    assert checks["npm"]["detail"] == "11.11.0"
    assert [
        WINDOWS_COMSPEC,
        "/d",
        "/s",
        "/v:off",
        "/c",
        "call",
        WINDOWS_NPM_CMD,
        "--version",
    ] in runner.calls
    assert ["node", "--version"] in runner.calls


def test_windows_cmd_resolution_uses_comspec_call() -> None:
    command = _resolve_command(
        ["npm", "--version"],
        which=_windows_which,
        platform_name="win32",
        environment={"COMSPEC": WINDOWS_COMSPEC},
    )

    assert command == [
        WINDOWS_COMSPEC,
        "/d",
        "/s",
        "/v:off",
        "/c",
        "call",
        WINDOWS_NPM_CMD,
        "--version",
    ]


def test_windows_cmd_resolution_handles_spaces_and_parentheses() -> None:
    shim = r"C:\Program Files (x86)\nodejs\npm.CMD"

    command = _resolve_command(
        ["npm", "--version"],
        which=lambda name: shim if name == "npm" else None,
        platform_name="win32",
        environment={"COMSPEC": WINDOWS_COMSPEC},
    )

    assert command[6] == shim
    assert command[-1] == "--version"


def test_windows_non_shim_command_is_not_wrapped() -> None:
    command = _resolve_command(
        ["node", "--version"],
        which=lambda name: r"C:\Program Files\nodejs\node.exe",
        platform_name="win32",
        environment={"COMSPEC": WINDOWS_COMSPEC},
    )

    assert command == ["node", "--version"]


def test_posix_command_with_cmd_suffix_is_not_wrapped() -> None:
    command = _resolve_command(
        ["npm", "--version"],
        which=lambda name: "/usr/bin/npm.cmd",
        platform_name="linux",
        environment={},
    )

    assert command == ["npm", "--version"]


def test_windows_cmd_resolution_rejects_unsafe_arguments() -> None:
    with pytest.raises(ValueError, match="unsafe Windows"):
        _resolve_command(
            ["npm", "--version", "bad&whoami"],
            which=_windows_which,
            platform_name="win32",
            environment={"COMSPEC": WINDOWS_COMSPEC},
        )


def test_windows_cmd_resolution_rejects_unsafe_comspec() -> None:
    with pytest.raises(ValueError, match="unsafe Windows"):
        _resolve_command(
            ["npm", "--version"],
            which=_windows_which,
            platform_name="win32",
            environment={"COMSPEC": "cmd.exe & whoami"},
        )


def test_windows_cmd_fallback_requires_a_real_shim_file(tmp_path: Path) -> None:
    shim = tmp_path / "npm.cmd"
    shim.write_text("@echo off\n", encoding="utf-8")

    def which(name: str) -> str | None:
        return str(shim) if name == "npm.cmd" else None

    assert _find_executable("npm", which, "win32") == ("npm.cmd", str(shim))


def test_windows_cmd_fallback_ignores_nonexistent_shim(tmp_path: Path) -> None:
    def which(name: str) -> str | None:
        return str(tmp_path / "missing" / "npm.cmd") if name == "npm.cmd" else None

    assert _find_executable("npm", which, "win32") == (None, None)


def test_missing_executable_is_resolved_as_not_installed() -> None:
    with pytest.raises(ValueError, match="is not installed"):
        _resolve_command(
            ["npm", "--version"],
            which=lambda name: None,
            platform_name="win32",
            environment={"COMSPEC": WINDOWS_COMSPEC},
        )


@pytest.mark.parametrize("missing", ["node", "npm"])
def test_missing_windows_node_or_npm_is_unavailable(tmp_path: Path, missing: str) -> None:
    def which(name: str) -> str | None:
        if name in {missing, f"{missing}.cmd", f"{missing}.bat"}:
            return None
        return rf"C:\tools\{name}.exe"

    inputs = _inputs(tmp_path)
    report = _assess(
        tmp_path,
        inputs,
        runner=_WindowsShimRunner(inputs["manifest"]),
        which=which,
        platform_name="win32",
        env=_environment(COMSPEC=WINDOWS_COMSPEC),
    )
    checks = _checks(report)

    assert checks[missing]["state"] == UNAVAILABLE
    assert "is not installed" in checks[missing]["detail"]


def test_npm_version_probe_failure_is_unavailable(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    runner = _NpmProbeRunner(
        inputs["manifest"],
        lambda args: subprocess.CompletedProcess(args, 1, "", "failed"),
    )
    report = _assess(
        tmp_path,
        inputs,
        runner=runner,
        which=_windows_which,
        platform_name="win32",
        env=_environment(COMSPEC=WINDOWS_COMSPEC),
    )

    assert _checks(report)["npm"]["state"] == UNAVAILABLE
    assert "exit code 1" in _checks(report)["npm"]["detail"]


def test_npm_version_probe_timeout_is_unavailable(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)

    def timeout(args: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(args, 30)

    runner = _NpmProbeRunner(inputs["manifest"], timeout)
    report = _assess(
        tmp_path,
        inputs,
        runner=runner,
        which=_windows_which,
        platform_name="win32",
        env=_environment(COMSPEC=WINDOWS_COMSPEC),
    )

    assert _checks(report)["npm"]["state"] == UNAVAILABLE
    assert "timed out after 30s" in _checks(report)["npm"]["detail"]


def test_npm_invalid_executable_is_unavailable(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)

    def invalid(args: Any) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError(2, "missing executable")

    runner = _NpmProbeRunner(inputs["manifest"], invalid)
    report = _assess(
        tmp_path,
        inputs,
        runner=runner,
        which=_windows_which,
        platform_name="win32",
        env=_environment(COMSPEC=WINDOWS_COMSPEC),
    )

    assert _checks(report)["npm"]["state"] == UNAVAILABLE
    assert "could not be executed" in _checks(report)["npm"]["detail"]


def test_npm_probe_error_is_sanitized(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)

    def failed(args: Any) -> subprocess.CompletedProcess[str]:
        raise OSError("token=super_secret_value")

    runner = _NpmProbeRunner(inputs["manifest"], failed)
    report = _assess(
        tmp_path,
        inputs,
        runner=runner,
        which=_windows_which,
        platform_name="win32",
        env=_environment(COMSPEC=WINDOWS_COMSPEC),
    )
    path, _ = _write_report(tmp_path, report)
    text = path.read_text(encoding="utf-8")

    assert _checks(report)["npm"]["state"] == UNAVAILABLE
    assert "could not be executed" in _checks(report)["npm"]["detail"]
    assert "super_secret_value" not in text


def test_compose_plugin_absent_is_unavailable(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    report = _assess(
        tmp_path,
        inputs,
        runner=_FakeRunner(inputs["manifest"], compose_ok=False),
    )
    checks = _checks(report)

    assert checks["docker-cli"]["state"] == PASS
    assert checks["docker-daemon"]["state"] == PASS
    assert checks["docker-compose"]["state"] == UNAVAILABLE


def test_github_token_presence_without_live_probe_is_unavailable(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    report = _assess(tmp_path, inputs, execute_live=False)
    checks = _checks(report)

    assert checks["github-auth-config"]["state"] == UNAVAILABLE
    assert "not validated" in checks["github-auth-config"]["detail"]
    assert "credentials are not assumed valid" in checks["github-auth-config"]["detail"]


def test_required_gpu_without_docker_runtime_is_unavailable(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path, gpu=True)
    report = _assess(
        tmp_path,
        inputs,
        require_gpu=True,
        runner=_FakeRunner(inputs["manifest"], gpu=True),
        which=lambda name: None if name == "docker" else f"/usr/bin/{name}",
    )
    checks = _checks(report)

    assert checks["gpu-container-runtime"]["state"] == UNAVAILABLE
    assert "docker is not installed" in checks["gpu-container-runtime"]["detail"]


def test_retained_evidence_tampering_is_rejected(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    report = _assess(tmp_path, inputs)
    path, _ = _write_report(tmp_path, report)
    evidence_dir = tmp_path / READINESS_EVIDENCE_DIR_NAME

    target_evidence = evidence_dir / report["bindings"]["target"]["path"]
    target_payload = json.loads(target_evidence.read_text(encoding="utf-8"))
    target_payload["name"] = "production-east-1"
    target_evidence.write_text(json.dumps(target_payload), encoding="utf-8")
    target_errors = _errors(
        report,
        inputs["manifest_path"],
        report_path=path,
        evidence_dir=evidence_dir,
    )
    assert any("evidence hash does not match" in error for error in target_errors)
    assert any("target evidence is invalid" in error for error in target_errors)

    (tmp_path / "second").mkdir()
    inputs = _inputs(tmp_path / "second")
    report = _assess(tmp_path / "second", inputs)
    path, _ = _write_report(tmp_path / "second", report)
    evidence_dir = tmp_path / "second" / READINESS_EVIDENCE_DIR_NAME

    previous_evidence = evidence_dir / report["bindings"]["previous_manifest"]["path"]
    previous_payload = json.loads(previous_evidence.read_text(encoding="utf-8"))
    previous_payload["release"]["tag"] = "v0.0.1"
    previous_evidence.write_text(json.dumps(previous_payload), encoding="utf-8")
    previous_errors = _errors(
        report,
        inputs["manifest_path"],
        report_path=path,
        evidence_dir=evidence_dir,
    )
    assert any("evidence hash does not match" in error for error in previous_errors)
    assert any("previous manifest evidence is invalid" in error for error in previous_errors)

    (tmp_path / "third").mkdir()
    inputs = _inputs(tmp_path / "third")
    report = _assess(tmp_path / "third", inputs)
    path, _ = _write_report(tmp_path / "third", report)
    evidence_dir = tmp_path / "third" / READINESS_EVIDENCE_DIR_NAME

    verification_evidence = evidence_dir / report["bindings"]["previous_verification"]["path"]
    verification_payload = json.loads(verification_evidence.read_text(encoding="utf-8"))
    verification_payload["state"] = FAIL
    verification_evidence.write_text(json.dumps(verification_payload), encoding="utf-8")
    verification_errors = _errors(
        report,
        inputs["manifest_path"],
        report_path=path,
        evidence_dir=evidence_dir,
    )
    assert any("evidence hash does not match" in error for error in verification_errors)

    (tmp_path / "fourth").mkdir()
    inputs = _inputs(tmp_path / "fourth")
    report = _assess(tmp_path / "fourth", inputs)
    path, _ = _write_report(tmp_path / "fourth", report)
    evidence_dir = tmp_path / "fourth" / READINESS_EVIDENCE_DIR_NAME

    rollback_evidence = evidence_dir / report["bindings"]["rollback_evidence"]["path"]
    rollback_payload = json.loads(rollback_evidence.read_text(encoding="utf-8"))
    rollback_payload["verified"] = False
    rollback_evidence.write_text(json.dumps(rollback_payload), encoding="utf-8")
    rollback_errors = _errors(
        report,
        inputs["manifest_path"],
        report_path=path,
        evidence_dir=evidence_dir,
    )
    assert any("evidence hash does not match" in error for error in rollback_errors)
    assert any("rollback evidence is invalid" in error for error in rollback_errors)


def test_secret_bearing_rollback_evidence_is_not_retained_and_blocks(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    payload = json.loads(inputs["rollback_path"].read_text(encoding="utf-8"))
    payload["steps"][0]["detail"] = "password=rollback_secret_value"
    inputs["rollback_path"].write_text(json.dumps(payload), encoding="utf-8")

    report = _assess(tmp_path, inputs)
    report_path, _ = _write_report(tmp_path, report)
    text = report_path.read_text(encoding="utf-8")

    assert report["bindings"]["rollback_evidence"] is None
    assert report["state"] == FAIL
    assert report["ready"] is False
    assert any(blocker.startswith("evidence-retention: rollback_evidence") for blocker in report["blockers"])
    assert "rollback_secret_value" not in text
    assert not any(item.get("kind") == "rollback-evidence" for item in report["evidence"])


def test_report_classifies_local_live_and_simulated_inspection(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    live = _assess(tmp_path, inputs)
    live_checks = _checks(live)
    live_names = {
        "github-auth-config",
        "registry-auth-config",
        "network-github",
        "network-ghcr",
        "release-tag-remote",
    }

    assert live["mode"] == "live-read-only"
    assert all(check["mode"] in {"local", "live-read-only"} for check in live["checks"])
    for name in live_names:
        assert live_checks[name]["mode"] == "live-read-only"
    assert all(check["mode"] == "local" for name, check in live_checks.items() if name not in live_names)

    (tmp_path / "preflight").mkdir()
    preflight = _assess(
        tmp_path / "preflight",
        _inputs(tmp_path / "preflight"),
        execute_live=False,
    )
    assert preflight["mode"] == "preflight"
    assert all(check["mode"] == "local" for check in preflight["checks"])


def test_schema_version_and_profile_mismatches_are_rejected(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    report = _assess(tmp_path, inputs)
    path, _ = _write_report(tmp_path, report)
    tampered = copy.deepcopy(report)
    tampered["schema_version"] = READINESS_SCHEMA_VERSION + 1
    tampered["profile"] = "release_qualification"
    errors = _errors(
        tampered,
        inputs["manifest_path"],
        report_path=path,
        evidence_dir=tmp_path / READINESS_EVIDENCE_DIR_NAME,
    )

    assert any("schema_version must be 1" in error for error in errors)
    assert any("profile must be 'staging_readiness'" in error for error in errors)


def test_contradictory_aggregate_and_gpu_flags_are_rejected(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    report = _assess(tmp_path, inputs)
    path, _ = _write_report(tmp_path, report)
    evidence_dir = tmp_path / READINESS_EVIDENCE_DIR_NAME

    tampered = copy.deepcopy(report)
    tampered["state"] = FAIL
    errors = _errors(tampered, inputs["manifest_path"], report_path=path, evidence_dir=evidence_dir)
    assert any("state is 'FAIL', not PASS" in error for error in errors)
    assert any("state contradicts its checks" in error for error in errors)

    tampered = copy.deepcopy(report)
    tampered["ready"] = False
    errors = _errors(tampered, inputs["manifest_path"], report_path=path, evidence_dir=evidence_dir)
    assert any("ready is not true" in error for error in errors)
    assert any("ready flag contradicts its checks" in error for error in errors)

    tampered = copy.deepcopy(report)
    tampered["gpu_ready"] = True
    errors = _errors(tampered, inputs["manifest_path"], report_path=path, evidence_dir=evidence_dir)
    assert any("gpu_ready must be false when GPU is optional" in error for error in errors)

    tampered = copy.deepcopy(report)
    tampered["gpu_required"] = True
    errors = _errors(tampered, inputs["manifest_path"], report_path=path, evidence_dir=evidence_dir)
    assert any("gpu_ready is not true for a GPU-required profile" in error for error in errors)
    assert any("GPU check gpu-hardware required flag contradicts gpu_required" in error for error in errors)


def test_preflight_report_with_live_checks_is_rejected(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    report = _assess(tmp_path, inputs)
    path, _ = _write_report(tmp_path, report)
    tampered = copy.deepcopy(report)
    tampered["mode"] = "preflight"
    errors = _errors(
        tampered,
        inputs["manifest_path"],
        report_path=path,
        evidence_dir=tmp_path / READINESS_EVIDENCE_DIR_NAME,
    )

    assert any("preflight report contains live check" in error for error in errors)
    assert any("required flag contradicts the report mode" in error for error in errors)


def test_simulated_required_check_never_satisfies_gate(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    report = _assess(tmp_path, inputs)
    path, _ = _write_report(tmp_path, report)
    tampered = copy.deepcopy(report)
    check = next(item for item in tampered["checks"] if item["name"] == "manifest")
    check["state"] = SIMULATED
    check["mode"] = "simulated"
    errors = _errors(
        tampered,
        inputs["manifest_path"],
        report_path=path,
        evidence_dir=tmp_path / READINESS_EVIDENCE_DIR_NAME,
    )

    assert any("required check manifest is SIMULATED, not PASS" in error for error in errors)
    assert any("required checks are not PASS" in error for error in errors)
    assert any("state contradicts" in error for error in errors)


def test_deployment_authorization_and_production_claims_are_rejected(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    report = _assess(tmp_path, inputs)
    path, _ = _write_report(tmp_path, report)
    evidence_dir = tmp_path / READINESS_EVIDENCE_DIR_NAME

    tampered = copy.deepcopy(report)
    tampered["production_qualified"] = True
    errors = _errors(tampered, inputs["manifest_path"], report_path=path, evidence_dir=evidence_dir)
    assert any("must never claim production qualification" in error for error in errors)

    tampered = copy.deepcopy(report)
    tampered["deployment"]["authorized"] = True
    errors = _errors(tampered, inputs["manifest_path"], report_path=path, evidence_dir=evidence_dir)
    assert any("must never authorize deployment" in error for error in errors)

    tampered = copy.deepcopy(report)
    tampered["deployment"]["performed"] = True
    errors = _errors(tampered, inputs["manifest_path"], report_path=path, evidence_dir=evidence_dir)
    assert any("must never claim a deployment was performed" in error for error in errors)

    tampered = copy.deepcopy(report)
    tampered["deployment"]["statement"] = "deployed"
    errors = _errors(tampered, inputs["manifest_path"], report_path=path, evidence_dir=evidence_dir)
    assert any("deployment statement is not explicit" in error for error in errors)


def test_unknown_check_evidence_and_binding_fields_are_rejected(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    report = _assess(tmp_path, inputs)
    path, _ = _write_report(tmp_path, report)
    tampered = copy.deepcopy(report)
    tampered["checks"][0]["extra"] = True
    tampered["evidence"][0]["extra"] = True
    tampered["bindings"]["target"]["extra"] = True
    errors = _errors(
        tampered,
        inputs["manifest_path"],
        report_path=path,
        evidence_dir=tmp_path / READINESS_EVIDENCE_DIR_NAME,
    )

    assert any("readiness check has unknown fields" in error for error in errors)
    assert any("evidence entry has unexpected fields" in error for error in errors)
    assert any("target binding has unexpected fields" in error for error in errors)


def test_missing_required_check_and_binding_are_rejected(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    report = _assess(tmp_path, inputs)
    path, _ = _write_report(tmp_path, report)
    tampered = copy.deepcopy(report)
    tampered["checks"] = [check for check in tampered["checks"] if check["name"] != "manifest"]
    tampered["bindings"].pop("target")
    errors = _errors(
        tampered,
        inputs["manifest_path"],
        report_path=path,
        evidence_dir=tmp_path / READINESS_EVIDENCE_DIR_NAME,
    )

    assert any("has no manifest check" in error for error in errors)
    assert any("target binding is missing" in error for error in errors)


def test_report_bound_to_a_different_manifest_is_rejected(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    report = _assess(tmp_path, inputs)
    path, _ = _write_report(tmp_path, report)

    errors = _errors(
        report,
        inputs["previous_path"],
        report_path=path,
        evidence_dir=tmp_path / READINESS_EVIDENCE_DIR_NAME,
    )

    assert any("not bound to the supplied manifest" in error for error in errors)
    assert any("release subject.tag does not match the manifest" in error for error in errors)
    assert any("digest for api does not match the manifest" in error for error in errors)


def test_target_summary_must_match_retained_target_evidence(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    report = _assess(tmp_path, inputs)
    path, _ = _write_report(tmp_path, report)
    tampered = copy.deepcopy(report)
    tampered["staging_target"]["name"] = "staging-west-1"
    errors = _errors(
        tampered,
        inputs["manifest_path"],
        report_path=path,
        evidence_dir=tmp_path / READINESS_EVIDENCE_DIR_NAME,
    )

    assert any("staging target name does not match its evidence" in error for error in errors)


def test_evidence_state_and_binding_kind_mismatches_are_rejected(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    report = _assess(tmp_path, inputs)
    path, _ = _write_report(tmp_path, report)
    evidence_dir = tmp_path / READINESS_EVIDENCE_DIR_NAME

    tampered = copy.deepcopy(report)
    tampered["evidence"][0]["state"] = FAIL
    errors = _errors(tampered, inputs["manifest_path"], report_path=path, evidence_dir=evidence_dir)
    assert any("state is not PASS" in error for error in errors)

    tampered = copy.deepcopy(report)
    tampered["bindings"]["target"]["kind"] = "previous-manifest"
    errors = _errors(tampered, inputs["manifest_path"], report_path=path, evidence_dir=evidence_dir)
    assert any("target binding has the wrong evidence kind" in error for error in errors)
    assert any("target binding does not match its evidence" in error for error in errors)


def test_cli_check_readiness_rejects_forged_deployment_authorization(
    tmp_path: Path,
    capsys: Any,
) -> None:
    inputs = _inputs(tmp_path)
    report = _assess(tmp_path, inputs)
    tampered = copy.deepcopy(report)
    tampered["production_qualified"] = True
    tampered["deployment"]["authorized"] = True
    path, digest = _write_report(tmp_path, tampered)

    exit_code = main(
        [
            "check-readiness",
            "--report",
            str(path),
            "--manifest",
            str(inputs["manifest_path"]),
            "--report-sha256",
            digest,
        ]
    )

    assert exit_code == 1
    errors = capsys.readouterr().err
    assert "must never authorize deployment" in errors
    assert "must never claim production qualification" in errors


def test_readiness_report_cannot_satisfy_qualification_gate(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    report = _assess(tmp_path, inputs)

    errors = qualification_report_errors(
        report,
        inputs["manifest"],
        manifest_path=inputs["manifest_path"],
        require_production=True,
    )

    assert any("profile 'staging_readiness' is not recognized" in error for error in errors)
    assert any("profile must be 'production_qualification'" in error for error in errors)
    assert any("qualification report is not bound" in error for error in errors)


def test_v22_v25_contracts_remain_unchanged() -> None:
    assert EVIDENCE_STATES == (PASS, FAIL, NOT_RUN, UNAVAILABLE, SIMULATED)
    assert QUALIFICATION_PROFILES == (
        "local_validation",
        "staging_qualification",
        "production_qualification",
    )
    assert STAGING_SCHEMA_VERSION == 1
    assert STAGING_MODES == ("preflight", "live-read", "authorized-mutation")
    assert STAGING_TARGET_REQUIRED_FIELDS == (
        "schema_version",
        "name",
        "environment",
        "release",
        "api_url",
        "web_url",
        "ws_url",
        "smoke_username",
        "smoke_password_env",
        "compose_project",
        "compose_files",
        "gpu",
    )
    assert READINESS_PROFILE not in QUALIFICATION_PROFILES
