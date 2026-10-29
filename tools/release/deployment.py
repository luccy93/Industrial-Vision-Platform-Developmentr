"""Digest-pinned deployment verification and rollback planning (V23/V24).

Verification resolves the Compose configuration with the manifest's exact
digests, rejects local build definitions, can require an independently produced
production verification report, can require a bound deployment preflight, can
scan recent service logs for leaked credentials, and can compare a running
stack's container image IDs with the manifest. Rollback planning always
redeploys previous digests; it never reverses migrations automatically and
never deletes the PostgreSQL volume.

A rollback plan is refused unless it is backed by a production verification
report for the target manifest, or the operator explicitly accepts an
unverified emergency rollback.

V24 deployment reports bind the exact manifest bytes and release subject so
qualification cannot reuse them for a different release.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from tools.release.manifest import (
    ManifestError,
    load_manifest,
    manifest_errors,
    sha256_file,
    utc_now_iso,
)
from tools.release.verification import (
    FAIL,
    NOT_RUN,
    PASS,
    UNAVAILABLE,
    VERIFICATION_SCHEMA_VERSION,
    CommandRunner,
    default_runner,
    is_placeholder_digest,
)

SERVICE_IMAGES = {
    False: {"migrate": "api", "api": "api", "web": "web"},
    True: {"migrate": "api", "api": "api-gpu", "web": "web"},
}
RUNNING_SERVICES = {
    False: {"api": "api", "web": "web"},
    True: {"api": "api-gpu", "web": "web"},
}
DEFAULT_CPU_COMPOSE = ("compose.yaml", "compose.release.yaml")
DEFAULT_GPU_COMPOSE = ("compose.yaml", "compose.gpu.release.yaml")
DEPLOYMENT_SCHEMA_VERSION = 1
DEPLOYMENT_EXECUTION_SCHEMA_VERSION = 1
DEPLOYMENT_REPORT_FIELDS = (
    "schema_version",
    "generated_at",
    "manifest_sha256",
    "subject",
    "gpu",
    "state",
    "checks",
)
DEPLOYMENT_SUBJECT_FIELDS = ("tag", "commit", "source_repository")
DEPLOYMENT_CHECK_FIELDS = ("name", "state", "required", "detail", "command")

# High-signal credential patterns. Redaction markers are deliberately excluded
# so the log filter's own output never causes a false positive. Only pattern
# names are reported; matched values are never echoed.
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    (
        "github-token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    ),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    (
        "authorization-header",
        re.compile(
            r"(?i)\b(?:proxy-)?authorization\s*:\s*(?:bearer|basic|digest)\s+"
            r"(?!\[redacted\]|\*{3,}|<redacted>)\S{8,}"
        ),
    ),
    (
        "credential-url",
        re.compile(
            r"(?i)\b(?:postgres(?:ql)?(?:\+[a-z0-9]+)?|redis|amqp|https?|wss?)://"
            r"[^\s:/@]+:(?!\[redacted\]|\*{3,}|<redacted>)[^\s@/]{8,}@"
        ),
    ),
    (
        "secret-assignment",
        re.compile(
            r"(?i)\b(?:password|passwd|secret|client[_-]?secret|api[_-]?key|"
            r"access[_-]?token|refresh[_-]?token)\b\s*[=:]\s*[\"']?"
            r"(?!\[redacted\]|\*{3,}|<redacted>|redacted\b)[^\s\"',}]{12,}"
        ),
    ),
    (
        "csrf-or-ticket",
        re.compile(
            r"(?i)\b(?:csrf[_-]?token|ws[_-]?ticket|session[_-]?token)\b\s*[=:]\s*"
            r"[\"']?(?!\[redacted\]|\*{3,}|<redacted>)[A-Za-z0-9._~-]{16,}"
        ),
    ),
)


class DeploymentError(RuntimeError):
    """A deployment configuration or rollback request is invalid."""


def _image_refs(manifest: Mapping[str, Any]) -> dict[str, str]:
    images = manifest.get("images")
    if not isinstance(images, list):
        raise DeploymentError("manifest images must be an array")
    refs: dict[str, str] = {}
    for image in images:
        if not isinstance(image, Mapping):
            continue
        name = image.get("name")
        repository = image.get("repository")
        digest = image.get("digest")
        if isinstance(name, str) and isinstance(repository, str) and isinstance(digest, str):
            if is_placeholder_digest(digest):
                raise DeploymentError(f"manifest image {name} has a placeholder digest")
            refs[name] = f"{repository}@{digest}"
    missing = sorted(set(SERVICE_IMAGES[False].values()) - set(refs))
    if missing:
        raise DeploymentError(f"manifest is missing deployment images: {', '.join(missing)}")
    return refs


def _subject(manifest: Mapping[str, Any]) -> dict[str, Any]:
    release = manifest.get("release")
    if not isinstance(release, Mapping):
        return {"tag": None, "commit": None, "source_repository": None}
    return {
        "tag": release.get("tag"),
        "commit": release.get("commit"),
        "source_repository": release.get("source_repository"),
    }


def deployment_environment(manifest: Mapping[str, Any], *, gpu: bool) -> dict[str, str]:
    refs = _image_refs(manifest)
    environment = {"IVP_API_IMAGE": refs["api"], "IVP_WEB_IMAGE": refs["web"]}
    if gpu:
        if "api-gpu" not in refs:
            raise DeploymentError("manifest is missing the api-gpu deployment image")
        environment["IVP_CPU_API_IMAGE"] = refs["api"]
        environment["IVP_GPU_API_IMAGE"] = refs["api-gpu"]
    return environment


def verification_report_errors(
    report: Any,
    manifest: Mapping[str, Any],
    *,
    manifest_path: Path,
    require_production: bool = True,
) -> list[str]:
    """Return every reason a verification report cannot authorize deployment.

    The report must be bound to the exact manifest bytes and release subject,
    and it must be an independent production verification. A local, simulated,
    partially run, or unavailable verification never authorizes a deployment.
    """
    if not isinstance(report, Mapping):
        return ["verification report must be a JSON object"]
    errors: list[str] = []
    if report.get("schema_version") != VERIFICATION_SCHEMA_VERSION:
        errors.append(f"verification report schema_version must be {VERIFICATION_SCHEMA_VERSION}")
    try:
        expected_sha = sha256_file(manifest_path)
    except OSError as exc:
        return [f"could not hash manifest {manifest_path}: {exc}"]
    if report.get("manifest_sha256") != expected_sha:
        errors.append("verification report is not bound to the supplied manifest (manifest_sha256 mismatch)")

    release = manifest.get("release") if isinstance(manifest.get("release"), Mapping) else {}
    subject = report.get("subject")
    if not isinstance(subject, Mapping):
        errors.append("verification report subject is missing")
    else:
        for field in ("tag", "commit", "source_repository"):
            if subject.get(field) != release.get(field):
                errors.append(f"verification report subject.{field} does not match the manifest release")

    if require_production and report.get("profile") != "production":
        errors.append("verification report profile must be 'production' for deployment")
    if report.get("overall_state") != PASS:
        errors.append(f"verification report overall_state is {report.get('overall_state')!r}, not PASS")
    if report.get("verified") is not True:
        errors.append("verification report verified is not true")
    if report.get("production_verified") is not True:
        errors.append("verification report production_verified is not true")

    artifact_status = report.get("artifact_status")
    if not isinstance(artifact_status, Mapping):
        errors.append("verification report artifact_status is missing")
    else:
        for variant in ("cpu", "gpu"):
            status = artifact_status.get(variant)
            if not isinstance(status, Mapping):
                errors.append(f"verification report artifact_status.{variant} is missing")
            elif status.get("state") != PASS:
                errors.append(
                    f"verification report artifact_status.{variant}.state is "
                    f"{status.get('state')!r}, not PASS"
                )
    return errors


def _load_verification_report(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise DeploymentError(f"could not read verification report {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise DeploymentError(f"verification report {path} is not valid JSON: {exc}") from exc


def _report_checks(
    manifest: Mapping[str, Any],
    *,
    manifest_path: Path,
    report_path: Path | None,
    require_verified: bool,
    gpu: bool,
) -> list[dict[str, Any]]:
    label = "verification-report"
    if report_path is None:
        if require_verified:
            return [
                _check(
                    label,
                    FAIL,
                    "a production verification report is required; pass --report",
                )
            ]
        return [
            _check(
                label,
                NOT_RUN,
                "no verification report supplied; deployment evidence was not independently verified",
            )
        ]
    try:
        report = _load_verification_report(report_path)
    except DeploymentError as exc:
        return [_check(label, FAIL, str(exc))]
    errors = verification_report_errors(report, manifest, manifest_path=manifest_path)
    if errors:
        return [_check(label, FAIL, "; ".join(errors[:8]))]
    checks = [
        _check(
            label,
            PASS,
            f"production verification report matches the manifest and release subject ({report_path})",
        )
    ]
    artifact_status = report.get("artifact_status")
    cpu = artifact_status.get("cpu") if isinstance(artifact_status, Mapping) else None
    checks.append(
        _check(
            "verification-cpu-artifacts",
            PASS,
            "CPU artifacts are independently verified",
        )
        if isinstance(cpu, Mapping) and cpu.get("state") == PASS
        else _check("verification-cpu-artifacts", FAIL, "CPU artifacts are not verified")
    )
    if gpu:
        gpu_status = artifact_status.get("gpu") if isinstance(artifact_status, Mapping) else None
        if isinstance(gpu_status, Mapping) and gpu_status.get("state") == PASS:
            checks.append(
                _check("verification-gpu-artifacts", PASS, "GPU artifacts are independently verified")
            )
        else:
            checks.append(_check("verification-gpu-artifacts", FAIL, "GPU artifacts are not verified"))
        if isinstance(gpu_status, Mapping) and gpu_status.get("runtime_verified") is True:
            checks.append(_check("verification-gpu-runtime", PASS, "GPU runtime was verified"))
        else:
            checks.append(
                _check(
                    "verification-gpu-runtime",
                    NOT_RUN,
                    "GPU runtime was not verified; run the smoke tool on the GPU host "
                    "before relying on acceleration",
                    required=False,
                )
            )
    return checks


def _compose_args(
    compose_files: Sequence[Path],
    project: str | None,
    command: Sequence[str],
) -> list[str]:
    args = ["docker", "compose"]
    if project:
        args.extend(["--project-name", project])
    for compose_file in compose_files:
        args.extend(["-f", str(compose_file)])
    args.extend(command)
    return args


def _command_text(args: Sequence[str]) -> str:
    return " ".join(shlex.quote(str(part)) for part in args)


def _check(
    name: str,
    state: str,
    detail: str,
    command: str | None = None,
    *,
    required: bool = True,
) -> dict[str, Any]:
    return {
        "name": name,
        "state": state,
        "detail": detail,
        "command": command,
        "required": required,
    }


def _load_compose_json(text: str) -> Any:
    stripped = text.strip()
    if not stripped:
        raise DeploymentError("compose command returned no output")
    return json.loads(stripped)


def _running_containers(text: str) -> dict[str, Mapping[str, Any]]:
    stripped = text.strip()
    if not stripped:
        return {}
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        payload = [json.loads(line) for line in stripped.splitlines() if line.strip()]
    items = payload if isinstance(payload, list) else [payload]
    result: dict[str, Mapping[str, Any]] = {}
    for item in items:
        if isinstance(item, Mapping) and isinstance(item.get("Service"), str):
            result[item["Service"]] = item
    return result


def _aggregate(checks: Sequence[Mapping[str, Any]]) -> str:
    states = {check.get("state") for check in checks}
    required_states = {check.get("state") for check in checks if check.get("required", True) is True}
    if FAIL in states:
        return FAIL
    if UNAVAILABLE in required_states:
        return UNAVAILABLE
    if NOT_RUN in required_states:
        return NOT_RUN
    return PASS


def scan_log_text(text: str) -> list[str]:
    """Return the names of credential patterns found in deployment logs."""
    found: set[str] = set()
    for name, pattern in SECRET_PATTERNS:
        if pattern.search(text):
            found.add(name)
    return sorted(found)


def _log_check(
    *,
    compose_files: Sequence[Path],
    project: str | None,
    environment: Mapping[str, str],
    runner: CommandRunner,
    tail: int,
) -> dict[str, Any]:
    args = _compose_args(compose_files, project, ["logs", "--no-color", "--tail", str(tail)])
    command = _command_text(args)
    try:
        result = runner(args, timeout=120, env=dict(environment))
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _check("log-secrets", UNAVAILABLE, f"compose logs failed: {exc}", command)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "no output").strip()
        return _check("log-secrets", UNAVAILABLE, f"compose logs failed: {detail[:500]}", command)
    findings = scan_log_text(f"{result.stdout}\n{result.stderr}")
    if findings:
        return _check(
            "log-secrets",
            FAIL,
            "deployment logs contain credential-like values "
            f"({', '.join(findings)}); rotate the exposed credentials and fix the log source",
            command,
        )
    return _check("log-secrets", PASS, f"no credential patterns found in the last {tail} log lines", command)


def deployment_config_checks(
    manifest_path: Path,
    *,
    compose_files: Sequence[Path],
    gpu: bool = False,
    project: str | None = None,
    expected_tag: str | None = None,
    expected_commit: str | None = None,
    runner: CommandRunner = default_runner,
    which: Callable[[str], str | None] = shutil.which,
    base_environment: Mapping[str, str] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, str] | None, dict[str, Any] | None]:
    """Resolve the digest-pinned Compose configuration and return its checks.

    The returned environment is ``None`` when Docker or Compose is
    unavailable, and the returned payload is the parsed Compose JSON when
    resolution succeeded. Preflight reuses these checks instead of running
    Compose twice.
    """
    try:
        manifest = load_manifest(manifest_path)
    except ManifestError as exc:
        raise DeploymentError(str(exc)) from exc
    errors = manifest_errors(
        manifest,
        expected_tag=expected_tag,
        expected_commit=expected_commit,
    )
    if errors:
        raise DeploymentError("manifest is invalid:\n- " + "\n- ".join(errors))
    checks: list[dict[str, Any]] = []
    try:
        refs = _image_refs(manifest)
    except DeploymentError as exc:
        checks.append(_check("manifest-digests", FAIL, str(exc)))
        return manifest, checks, None, None
    checks.append(_check("manifest-digests", PASS, "all deployment images have immutable digests"))

    if which("docker") is None:
        checks.append(_check("compose-tool", UNAVAILABLE, "docker is not installed"))
        return manifest, checks, None, None

    environment = dict(base_environment or os.environ)
    try:
        environment.update(deployment_environment(manifest, gpu=gpu))
    except DeploymentError as exc:
        checks.append(_check("manifest-digests", FAIL, str(exc)))
        return manifest, checks, None, None
    config_args = _compose_args(compose_files, project, ["config", "--format", "json"])
    config_command = _command_text(config_args)
    try:
        result = runner(config_args, timeout=120, env=environment)
    except (OSError, subprocess.TimeoutExpired) as exc:
        checks.append(_check("compose-config", UNAVAILABLE, f"compose config failed: {exc}", config_command))
        return manifest, checks, environment, None
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "no output").strip()
        checks.append(_check("compose-config", FAIL, detail[:500], config_command))
        return manifest, checks, environment, None
    try:
        payload = _load_compose_json(result.stdout)
    except (DeploymentError, json.JSONDecodeError) as exc:
        checks.append(_check("compose-config", FAIL, f"invalid compose JSON: {exc}", config_command))
        return manifest, checks, environment, None
    services = payload.get("services") if isinstance(payload, Mapping) else None
    if not isinstance(services, Mapping):
        checks.append(_check("compose-config", FAIL, "compose JSON has no services object", config_command))
        return manifest, checks, environment, None
    checks.append(_check("compose-config", PASS, "compose configuration resolves", config_command))

    expected = {service: refs[image_name] for service, image_name in SERVICE_IMAGES[gpu].items()}
    for service, expected_ref in expected.items():
        entry = services.get(service)
        if not isinstance(entry, Mapping):
            checks.append(_check(f"compose-pin:{service}", FAIL, f"service {service} is missing"))
            continue
        if entry.get("build"):
            checks.append(
                _check(
                    f"compose-pin:{service}",
                    FAIL,
                    f"service {service} still has a local build definition",
                )
            )
            continue
        observed = entry.get("image")
        if observed != expected_ref:
            checks.append(
                _check(
                    f"compose-pin:{service}",
                    FAIL,
                    f"service {service} uses {observed!r}, expected {expected_ref}",
                )
            )
            continue
        checks.append(
            _check(f"compose-pin:{service}", PASS, f"service {service} is pinned to {expected_ref}")
        )
    return manifest, checks, environment, payload if isinstance(payload, Mapping) else None


def _preflight_check(
    manifest: Mapping[str, Any],
    manifest_path: Path,
    path: Path,
) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        return _check("preflight", FAIL, f"could not read preflight report {path}: {exc}")
    except json.JSONDecodeError as exc:
        return _check("preflight", FAIL, f"preflight report {path} is not valid JSON: {exc}")
    from tools.release.preflight import preflight_report_errors

    errors = preflight_report_errors(payload, manifest, manifest_path=manifest_path)
    if errors:
        return _check("preflight", FAIL, "; ".join(errors[:8]))
    return _check("preflight", PASS, f"preflight report is bound to the manifest ({path})")


def _deployment_report(
    manifest_path: Path,
    manifest: Mapping[str, Any],
    *,
    gpu: bool,
    checks: Sequence[Mapping[str, Any]],
    now: Callable[[], str],
) -> dict[str, Any]:
    try:
        manifest_sha = sha256_file(manifest_path)
    except OSError as exc:
        raise DeploymentError(f"could not hash manifest {manifest_path}: {exc}") from exc
    return {
        "schema_version": DEPLOYMENT_SCHEMA_VERSION,
        "generated_at": now(),
        "manifest_sha256": manifest_sha,
        "subject": _subject(manifest),
        "gpu": gpu,
        "state": _aggregate(checks),
        "checks": list(checks),
    }


def verify_deployment(
    manifest_path: Path,
    *,
    compose_files: Sequence[Path],
    gpu: bool = False,
    project: str | None = None,
    running: bool = False,
    report_path: Path | None = None,
    require_verified: bool = False,
    preflight_report_path: Path | None = None,
    check_logs: bool = False,
    logs_tail: int = 500,
    expected_tag: str | None = None,
    expected_commit: str | None = None,
    runner: CommandRunner = default_runner,
    which: Callable[[str], str | None] = shutil.which,
    base_environment: Mapping[str, str] | None = None,
    now: Callable[[], str] = utc_now_iso,
) -> dict[str, Any]:
    manifest, config_checks, environment, payload = deployment_config_checks(
        manifest_path,
        compose_files=compose_files,
        gpu=gpu,
        project=project,
        expected_tag=expected_tag,
        expected_commit=expected_commit,
        runner=runner,
        which=which,
        base_environment=base_environment,
    )
    checks: list[dict[str, Any]] = _report_checks(
        manifest,
        manifest_path=manifest_path,
        report_path=report_path,
        require_verified=require_verified,
        gpu=gpu,
    )
    checks.extend(config_checks)
    if preflight_report_path is not None:
        checks.append(_preflight_check(manifest, manifest_path, preflight_report_path))

    if payload is not None and check_logs:
        checks.append(
            _log_check(
                compose_files=compose_files,
                project=project,
                environment=environment or {},
                runner=runner,
                tail=logs_tail,
            )
        )

    if payload is not None and running:
        ps_args = _compose_args(compose_files, project, ["ps", "--format", "json"])
        ps_command = _command_text(ps_args)
        try:
            ps_result = runner(ps_args, timeout=120, env=environment or {})
        except (OSError, subprocess.TimeoutExpired) as exc:
            checks.append(_check("running-services", UNAVAILABLE, f"compose ps failed: {exc}", ps_command))
        else:
            if ps_result.returncode != 0:
                detail = (ps_result.stderr or ps_result.stdout or "no output").strip()
                checks.append(_check("running-services", FAIL, detail[:500], ps_command))
            else:
                try:
                    containers = _running_containers(ps_result.stdout)
                except (json.JSONDecodeError, TypeError) as exc:
                    checks.append(
                        _check("running-services", FAIL, f"invalid compose ps JSON: {exc}", ps_command)
                    )
                    containers = {}
                for service in RUNNING_SERVICES[gpu]:
                    container = containers.get(service)
                    if not isinstance(container, Mapping):
                        checks.append(
                            _check(
                                f"running-service:{service}",
                                FAIL,
                                f"no container is reported for service {service}",
                            )
                        )
                        continue
                    state = str(container.get("State", ""))
                    status = str(container.get("Status", ""))
                    if state != "running" and not status.startswith("Up"):
                        checks.append(
                            _check(
                                f"running-service:{service}",
                                FAIL,
                                f"service {service} is not running (state={state!r}, status={status!r})",
                            )
                        )
                        continue
                    checks.append(
                        _check(
                            f"running-service:{service}",
                            PASS,
                            f"service {service} is running",
                        )
                    )
                    name = container.get("Name") or container.get("Names")
                    if not isinstance(name, str) or not name:
                        checks.append(
                            _check(
                                f"running-service:{service}", FAIL, f"service {service} has no container name"
                            )
                        )
                        continue
                    inspect_args = ["docker", "inspect", "--format", "{{.Image}}", name]
                    inspect_command = _command_text(inspect_args)
                    try:
                        inspect_result = runner(inspect_args, timeout=60)
                    except (OSError, subprocess.TimeoutExpired) as exc:
                        checks.append(
                            _check(
                                f"running-image:{service}",
                                UNAVAILABLE,
                                f"docker inspect failed: {exc}",
                                inspect_command,
                            )
                        )
                        continue
                    if inspect_result.returncode != 0:
                        detail = (inspect_result.stderr or inspect_result.stdout or "no output").strip()
                        checks.append(
                            _check(
                                f"running-image:{service}",
                                FAIL,
                                detail[:500],
                                inspect_command,
                            )
                        )
                        continue
                    observed_id = inspect_result.stdout.strip()
                    expected_id = next(
                        (
                            image.get("image_id")
                            for image in manifest.get("images") or []
                            if isinstance(image, Mapping)
                            and image.get("name") == RUNNING_SERVICES[gpu][service]
                        ),
                        None,
                    )
                    if observed_id != expected_id:
                        checks.append(
                            _check(
                                f"running-image:{service}",
                                FAIL,
                                f"running image ID {observed_id} does not match manifest {expected_id}",
                                inspect_command,
                            )
                        )
                    else:
                        checks.append(
                            _check(
                                f"running-image:{service}",
                                PASS,
                                f"service {service} is running the manifest image",
                                inspect_command,
                            )
                        )

    return _deployment_report(manifest_path, manifest, gpu=gpu, checks=checks, now=now)


def _run_deploy_command(
    runner: CommandRunner,
    args: Sequence[str],
    environment: Mapping[str, str],
    *,
    timeout: int = 900,
) -> dict[str, Any]:
    command = _command_text(args)
    try:
        result = runner(args, timeout=timeout, env=dict(environment))
    except (OSError, subprocess.SubprocessError) as exc:
        return _check(command, UNAVAILABLE, f"command could not run: {exc}", command)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "no output").strip()
        return _check(command, FAIL, detail[:500], command)
    return _check(command, PASS, "command succeeded", command)


def _preflight_binding_errors(
    report: Any,
    manifest: Mapping[str, Any],
    manifest_path: Path,
) -> list[str]:
    if not isinstance(report, Mapping):
        return ["preflight report must be a JSON object"]
    errors: list[str] = []
    try:
        expected_sha = sha256_file(manifest_path)
    except OSError as exc:
        return [f"could not hash manifest {manifest_path}: {exc}"]
    if report.get("manifest_sha256") != expected_sha:
        errors.append("preflight report is not bound to the supplied manifest")
    release = manifest.get("release") if isinstance(manifest.get("release"), Mapping) else {}
    subject = report.get("subject")
    if not isinstance(subject, Mapping):
        errors.append("preflight report subject is missing")
    else:
        for field in ("tag", "commit", "source_repository"):
            if subject.get(field) != release.get(field):
                errors.append(f"preflight report subject.{field} does not match the manifest release")
    if report.get("state") != PASS:
        errors.append(f"preflight report state is {report.get('state')!r}, not PASS")
    if report.get("verified") is not True:
        errors.append("preflight report verified is not true")
    return errors


def deploy_release(
    manifest_path: Path,
    *,
    compose_files: Sequence[Path],
    verification_report_path: Path | None = None,
    preflight_report_path: Path | None = None,
    gpu: bool = False,
    project: str | None = None,
    execute: bool = False,
    expected_tag: str | None = None,
    expected_commit: str | None = None,
    runner: CommandRunner = default_runner,
    which: Callable[[str], str | None] = shutil.which,
    base_environment: Mapping[str, str] | None = None,
    now: Callable[[], str] = utc_now_iso,
) -> dict[str, Any]:
    """Deploy a digest-pinned release, or report an honest NOT_RUN.

    Execution requires a production verification report and a bound deployment
    preflight. The manifest is re-resolved before any command, and the running
    stack is verified against manifest image IDs after ``up``. A failed pull or
    ``up`` stops the sequence; no rollback is attempted here.
    """
    try:
        manifest = load_manifest(manifest_path)
        manifest_sha = sha256_file(manifest_path)
    except (ManifestError, OSError) as exc:
        raise DeploymentError(str(exc)) from exc
    errors = manifest_errors(
        manifest,
        expected_tag=expected_tag,
        expected_commit=expected_commit,
    )
    if errors:
        raise DeploymentError("manifest is invalid:\n- " + "\n- ".join(errors))
    checks: list[dict[str, Any]] = []
    if not execute:
        checks.append(
            _check(
                "deployment-execution",
                NOT_RUN,
                "deployment execution was not requested; pass --execute",
            )
        )
    else:
        if verification_report_path is None:
            raise DeploymentError("deployment execution requires a production verification report")
        if preflight_report_path is None:
            raise DeploymentError("deployment execution requires a bound deployment preflight report")
        try:
            verification_report = _load_verification_report(verification_report_path)
        except DeploymentError as exc:
            checks.append(_check("verification", FAIL, True, str(exc)))
            verification_report = None
        if verification_report is not None:
            verification_errors = verification_report_errors(
                verification_report,
                manifest,
                manifest_path=manifest_path,
            )
            checks.append(
                _check(
                    "verification",
                    PASS if not verification_errors else FAIL,
                    "production verification authorizes deployment"
                    if not verification_errors
                    else "; ".join(verification_errors[:8]),
                )
            )
        try:
            preflight_report = json.loads(preflight_report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            checks.append(_check("preflight", FAIL, True, f"could not read preflight report: {exc}"))
            preflight_report = None
        if preflight_report is not None:
            preflight_errors = _preflight_binding_errors(
                preflight_report,
                manifest,
                manifest_path,
            )
            checks.append(
                _check(
                    "preflight",
                    PASS if not preflight_errors else FAIL,
                    "deployment preflight authorizes deployment"
                    if not preflight_errors
                    else "; ".join(preflight_errors[:8]),
                )
            )
        if any(check["state"] != PASS for check in checks):
            checks.append(
                _check(
                    "deployment-execution",
                    FAIL,
                    "deployment was not attempted because its required evidence is not PASS",
                )
            )
        else:
            try:
                _, config_checks, environment, payload = deployment_config_checks(
                    manifest_path,
                    compose_files=compose_files,
                    gpu=gpu,
                    project=project,
                    expected_tag=expected_tag,
                    expected_commit=expected_commit,
                    runner=runner,
                    which=which,
                    base_environment=base_environment,
                )
            except DeploymentError as exc:
                checks.append(_check("compose-config", FAIL, True, str(exc)))
                payload = None
                environment = None
                config_checks = []
            checks.extend(config_checks)
            if payload is None or environment is None:
                checks.append(
                    _check(
                        "deployment-execution",
                        FAIL,
                        "deployment was not attempted because the Compose configuration did not resolve",
                    )
                )
            else:
                pull = _run_deploy_command(
                    runner,
                    _compose_args(compose_files, project, ["pull"]),
                    environment,
                )
                pull["name"] = "pull"
                checks.append(pull)
                if pull["state"] != PASS:
                    checks.append(
                        _check(
                            "deployment-execution",
                            FAIL,
                            "deployment stopped because pulling the digest-pinned images failed",
                        )
                    )
                else:
                    up = _run_deploy_command(
                        runner,
                        _compose_args(compose_files, project, ["up", "-d"]),
                        environment,
                    )
                    up["name"] = "up"
                    checks.append(up)
                    if up["state"] != PASS:
                        checks.append(
                            _check(
                                "deployment-execution",
                                FAIL,
                                "deployment stopped because starting the stack failed",
                            )
                        )
                    else:
                        verified = verify_deployment(
                            manifest_path,
                            compose_files=compose_files,
                            gpu=gpu,
                            project=project,
                            running=True,
                            report_path=verification_report_path,
                            require_verified=True,
                            preflight_report_path=preflight_report_path,
                            expected_tag=expected_tag,
                            expected_commit=expected_commit,
                            runner=runner,
                            which=which,
                            base_environment=base_environment,
                            now=now,
                        )
                        checks.append(
                            _check(
                                "post-deploy-verification",
                                str(verified.get("state")),
                                f"running stack verification is {verified.get('state')}",
                            )
                        )
                        checks.append(
                            _check(
                                "deployment-execution",
                                str(verified.get("state")),
                                "deployment executed and the running stack matches the manifest"
                                if verified.get("state") == PASS
                                else "deployment executed but post-deploy verification did not pass",
                            )
                        )
    overall = _aggregate(checks)
    blockers = [
        f"{check['name']}: {check['state']} - {check['detail']}"
        for check in checks
        if check.get("required") is True and check.get("state") != PASS
    ]
    limitations = [
        f"{check['name']}: {check['state']} - {check['detail']}"
        for check in checks
        if check.get("required") is not True and check.get("state") != PASS
    ]
    return {
        "schema_version": DEPLOYMENT_EXECUTION_SCHEMA_VERSION,
        "generated_at": now(),
        "executed": execute,
        "manifest_sha256": manifest_sha,
        "subject": _subject(manifest),
        "gpu": gpu,
        "project": project,
        "compose_files": [str(path) for path in compose_files],
        "state": overall,
        "checks": checks,
        "blockers": blockers,
        "limitations": limitations,
    }


def render_rollback_plan(
    manifest_path: Path,
    *,
    gpu: bool = False,
    backup_file: str = "backup.sql",
    current_manifest_path: Path | None = None,
    verification_report_path: Path | None = None,
    allow_unverified: bool = False,
    expected_tag: str | None = None,
    expected_commit: str | None = None,
) -> str:
    try:
        target = load_manifest(manifest_path)
    except ManifestError as exc:
        raise DeploymentError(str(exc)) from exc
    errors = manifest_errors(
        target,
        expected_tag=expected_tag,
        expected_commit=expected_commit,
    )
    if errors:
        raise DeploymentError("rollback target manifest is invalid:\n- " + "\n- ".join(errors))
    release = target.get("release") if isinstance(target.get("release"), Mapping) else {}
    target_tag = release.get("tag")
    target_commit = release.get("commit")
    if current_manifest_path is not None:
        try:
            current = load_manifest(current_manifest_path)
        except ManifestError as exc:
            raise DeploymentError(str(exc)) from exc
        current_release = current.get("release") if isinstance(current.get("release"), Mapping) else {}
        if current_release.get("commit") == target_commit:
            raise DeploymentError("rollback target is the current release; nothing to roll back")

    report_detail = ""
    if verification_report_path is None:
        if not allow_unverified:
            raise DeploymentError(
                "a production verification report is required for rollback; pass --report, "
                "or --allow-unverified only for a documented emergency"
            )
        report_detail = (
            "WARNING: no verification report was supplied. This is an unverified emergency "
            "rollback; record the incident and verify the digests independently."
        )
    else:
        report = _load_verification_report(verification_report_path)
        report_errors = verification_report_errors(report, target, manifest_path=manifest_path)
        if report_errors:
            raise DeploymentError(
                "rollback verification report is not valid:\n- " + "\n- ".join(report_errors)
            )
        report_detail = (
            f"Verified by production report {verification_report_path} "
            f"({report.get('overall_state')}, manifest {report.get('manifest_sha256')})."
        )

    environment = deployment_environment(target, gpu=gpu)
    compose_files = DEFAULT_GPU_COMPOSE if gpu else DEFAULT_CPU_COMPOSE
    compose = " ".join(f"-f {name}" for name in compose_files)
    lines = [
        f"Rollback plan for {target_tag} ({target_commit})",
        "",
        report_detail,
        "Policy: tags and image digests are immutable; never move or delete a release tag.",
        "Redeploy the previous release by digest. Do not reverse Alembic migrations automatically.",
        "",
        "1. Record the current release and take a database backup before changing anything:",
        f"   docker compose {compose} exec -T postgres pg_dump "
        "-U <postgres-user> <database> > before-rollback.sql",
        "",
        "2. Set the previous release digests in the current shell:",
    ]
    for name, value in environment.items():
        lines.append(f'   $env:{name}="{value}"')
    lines.extend(
        [
            "",
            "3. Pull and start the previous digests:",
            f"   docker compose {compose} pull",
            f"   docker compose {compose} up -d",
            "",
            "4. Verify the running stack:",
            f"   docker compose {compose} ps",
            "   python -m tools.release.cli verify-deploy --manifest <previous-manifest.json> "
            f"--running --require-verified --report <previous-release-verification.json>"
            f"{' --gpu' if gpu else ''}",
            "",
            "5. Only if the previous application is incompatible with the current schema, restore",
            f"   the pre-upgrade backup ({backup_file}) into an empty/recreated database:",
            f"   Get-Content -Raw {backup_file} | docker compose {compose} exec -T postgres "
            "psql -U <postgres-user> -d <database>",
            "",
            "6. Never run `docker compose down -v`; it deletes the PostgreSQL volume.",
        ]
    )
    return "\n".join(lines) + "\n"
