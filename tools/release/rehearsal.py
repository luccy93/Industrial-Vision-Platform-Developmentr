"""Digest-pinned rollback rehearsal evidence (V24).

A rollback plan is not a rollback rehearsal. This module actually deploys the
previous release by digest, verifies it, deploys the target release, verifies
it, rolls back to the previous digests, and verifies the restored stack. Every
step is recorded; a rehearsal that was not executed is ``NOT_RUN`` and can
never be reported as a pass.

The rehearsal requires independent production verification reports for both the
target and the previous release, a healthy smoke check for both, and Docker on
the target host. If a target deployment or verification fails, the rehearsal
still attempts the rollback so recovery is proven, but the overall result
remains ``FAIL``.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from tools.release.deployment import (
    DeploymentError,
    deployment_environment,
    verify_deployment,
)
from tools.release.manifest import (
    ManifestError,
    load_manifest,
    manifest_errors,
    sha256_file,
    utc_now_iso,
)
from tools.release.migrations import migration_report_errors
from tools.release.smoke import SmokeError, run_smoke
from tools.release.verification import (
    FAIL,
    NOT_RUN,
    PASS,
    UNAVAILABLE,
    CommandRunner,
    default_runner,
)

REHEARSAL_SCHEMA_VERSION = 1
REHEARSAL_REPORT_FIELDS = (
    "schema_version",
    "generated_at",
    "executed",
    "state",
    "verified",
    "manifest_sha256",
    "subject",
    "previous_manifest_sha256",
    "previous_subject",
    "target",
    "previous",
    "checks",
    "steps",
    "evidence",
    "blockers",
    "limitations",
)
REHEARSAL_SUBJECT_FIELDS = ("tag", "commit", "source_repository")
REHEARSAL_STEP_FIELDS = (
    "name",
    "state",
    "detail",
    "commands",
    "checks",
    "deployment",
    "smoke",
    "evidence",
)
REHEARSAL_EVIDENCE_FIELDS = ("kind", "path", "sha256")
STEP_NAMES = (
    "deploy-previous",
    "verify-previous",
    "smoke-previous",
    "deploy-target",
    "verify-target",
    "smoke-target",
    "rollback-previous",
    "verify-after-rollback",
    "smoke-after-rollback",
)


class RehearsalError(RuntimeError):
    """The rollback rehearsal request is invalid."""


def _check(
    name: str,
    state: str,
    required: bool,
    detail: str,
    command: str | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "state": state,
        "required": required,
        "detail": detail,
        "command": command,
    }


def _aggregate(checks: Sequence[Mapping[str, Any]]) -> str:
    states = {str(check.get("state")) for check in checks}
    required_states = {str(check.get("state")) for check in checks if check.get("required") is True}
    if FAIL in states:
        return FAIL
    if UNAVAILABLE in required_states:
        return UNAVAILABLE
    if NOT_RUN in required_states:
        return NOT_RUN
    return PASS


def _subject(manifest: Mapping[str, Any]) -> dict[str, Any]:
    release = manifest.get("release")
    if not isinstance(release, Mapping):
        return {"tag": None, "commit": None, "source_repository": None}
    return {
        "tag": release.get("tag"),
        "commit": release.get("commit"),
        "source_repository": release.get("source_repository"),
    }


def _digests(manifest: Mapping[str, Any]) -> dict[str, str]:
    return {
        image.get("name"): image.get("digest")
        for image in manifest.get("images") or []
        if isinstance(image, Mapping) and isinstance(image.get("name"), str)
    }


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


def _run_command(
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
        return _check(
            command,
            UNAVAILABLE,
            True,
            f"command could not run: {exc}",
            command,
        )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "no output").strip()
        return _check(command, FAIL, True, detail[:500], command)
    return _check(command, PASS, True, "command succeeded", command)


def _deploy(
    manifest: Mapping[str, Any],
    *,
    compose_files: Sequence[Path],
    project: str | None,
    gpu: bool,
    runner: CommandRunner,
    base_environment: Mapping[str, str] | None,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    environment = dict(base_environment) if base_environment is not None else dict(os.environ)
    environment.update(deployment_environment(manifest, gpu=gpu))
    checks: list[dict[str, Any]] = []
    pull = _run_command(
        runner,
        _compose_args(compose_files, project, ["pull"]),
        environment,
    )
    pull["name"] = "pull"
    checks.append(pull)
    if pull["state"] != PASS:
        return checks, environment
    up = _run_command(
        runner,
        _compose_args(compose_files, project, ["up", "-d"]),
        environment,
    )
    up["name"] = "up"
    checks.append(up)
    return checks, environment


def _summary(report: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "state": report.get("state") or report.get("overall_state"),
        "verified": report.get("verified"),
        "checks": [
            {
                "name": check.get("name"),
                "state": check.get("state"),
                "required": check.get("required"),
            }
            for check in report.get("checks") or []
            if isinstance(check, Mapping)
        ],
    }


def _write_evidence(
    report: Mapping[str, Any] | None,
    evidence_dir: Path | None,
    filename: str,
    evidence: list[dict[str, Any]],
) -> dict[str, Any] | None:
    if report is None or evidence_dir is None:
        return None
    path = evidence_dir / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    item = {
        "kind": filename.removesuffix(".json"),
        "path": path.name,
        "sha256": sha256_file(path),
    }
    evidence.append(item)
    return item


def _step(
    name: str,
    state: str,
    detail: str,
    *,
    commands: Sequence[str] = (),
    checks: Sequence[Mapping[str, Any]] = (),
    deployment: Mapping[str, Any] | None = None,
    smoke: Mapping[str, Any] | None = None,
    evidence: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    return {
        "name": name,
        "state": state,
        "detail": detail,
        "commands": list(commands),
        "checks": [
            {
                "name": check.get("name"),
                "state": check.get("state"),
                "required": check.get("required"),
            }
            for check in checks
            if isinstance(check, Mapping)
        ],
        "deployment": _summary(deployment) if deployment is not None else None,
        "smoke": _summary(smoke) if smoke is not None else None,
        "evidence": list(evidence),
    }


def _planned_steps(
    target: Mapping[str, Any],
    previous: Mapping[str, Any],
    *,
    compose_files: Sequence[Path],
    project: str | None,
    gpu: bool,
) -> list[dict[str, Any]]:
    del target, previous, gpu
    pull = _command_text(_compose_args(compose_files, project, ["pull"]))
    up = _command_text(_compose_args(compose_files, project, ["up", "-d"]))
    return [
        {
            "name": name,
            "state": NOT_RUN,
            "detail": "not executed; run the rehearsal on the target host",
            "commands": [pull, up]
            if name in ("deploy-previous", "deploy-target", "rollback-previous")
            else [],
            "checks": [],
            "deployment": None,
            "smoke": None,
            "evidence": [],
        }
        for name in STEP_NAMES
    ]


def _not_run_steps(
    checks: list[dict[str, Any]],
    steps: list[dict[str, Any]],
    names: Sequence[str],
    detail: str,
) -> None:
    for name in names:
        checks.append(_check(name, NOT_RUN, True, detail))
        steps.append(
            _step(
                name,
                NOT_RUN,
                detail,
            )
        )


def _report(
    *,
    target: Mapping[str, Any],
    previous: Mapping[str, Any],
    target_sha: str,
    previous_sha: str,
    executed: bool,
    checks: Sequence[Mapping[str, Any]],
    steps: Sequence[Mapping[str, Any]],
    evidence: Sequence[Mapping[str, Any]],
    now: Callable[[], str],
) -> dict[str, Any]:
    overall = _aggregate(checks)
    verified = overall == PASS and all(
        check.get("state") == PASS for check in checks if check.get("required") is True
    )
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
        "schema_version": REHEARSAL_SCHEMA_VERSION,
        "generated_at": now(),
        "executed": executed,
        "state": overall,
        "verified": verified,
        "manifest_sha256": target_sha,
        "subject": _subject(target),
        "previous_manifest_sha256": previous_sha,
        "previous_subject": _subject(previous),
        "target": {
            "manifest_sha256": target_sha,
            "subject": _subject(target),
            "digests": _digests(target),
        },
        "previous": {
            "manifest_sha256": previous_sha,
            "subject": _subject(previous),
            "digests": _digests(previous),
        },
        "checks": list(checks),
        "steps": list(steps),
        "evidence": list(evidence),
        "blockers": blockers,
        "limitations": limitations,
    }


def _migration_safety_check(
    migration_report_path: Path | None,
    target: Mapping[str, Any],
    *,
    manifest_path: Path,
) -> dict[str, Any]:
    if migration_report_path is None:
        return _check(
            "migration-safety",
            NOT_RUN,
            False,
            "no migration compatibility report was supplied; migration safety was not bound",
        )
    try:
        report = json.loads(migration_report_path.read_text(encoding="utf-8"))
    except OSError as exc:
        return _check(
            "migration-safety",
            FAIL,
            True,
            f"migration compatibility report could not be read: {exc}",
        )
    except json.JSONDecodeError as exc:
        return _check(
            "migration-safety",
            FAIL,
            True,
            f"migration compatibility report is not valid JSON: {exc}",
        )
    errors = migration_report_errors(report, target, manifest_path=manifest_path)
    return _check(
        "migration-safety",
        PASS if not errors else FAIL,
        True,
        "migration compatibility is PASS and bound to the target manifest"
        if not errors
        else "; ".join(errors[:8]),
    )


def _verify_step(
    label: str,
    manifest_path: Path,
    *,
    verification_report: Path,
    compose_files: Sequence[Path],
    project: str | None,
    gpu: bool,
    expected_tag: str | None,
    expected_commit: str | None,
    runner: CommandRunner,
    which: Callable[[str], str | None],
    base_environment: Mapping[str, str] | None,
    now: Callable[[], str],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    try:
        report = verify_deployment(
            manifest_path,
            compose_files=compose_files,
            gpu=gpu,
            project=project,
            running=True,
            report_path=verification_report,
            require_verified=True,
            check_logs=True,
            expected_tag=expected_tag,
            expected_commit=expected_commit,
            runner=runner,
            which=which,
            base_environment=base_environment,
            now=now,
        )
    except DeploymentError as exc:
        return _check(label, FAIL, True, str(exc)), None
    state = str(report.get("state"))
    failures = [
        check.get("name")
        for check in report.get("checks") or []
        if isinstance(check, Mapping) and check.get("required") is True and check.get("state") != PASS
    ]
    detail = (
        "deployment verification passed"
        if state == PASS
        else (
            f"deployment verification is {state}; failing checks: {', '.join(str(item) for item in failures)}"
        )
    )
    return _check(label, state, True, detail), report


def _smoke_step(
    label: str,
    manifest_path: Path,
    *,
    smoke_api_url: str,
    smoke_web_url: str | None,
    smoke_username: str,
    smoke_password: str,
    smoke_timeout: float,
    smoke_verify_tls: bool,
    expected_tag: str | None,
    expected_commit: str | None,
    smoke_runner: Callable[..., dict[str, Any]],
    now: Callable[[], str],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    try:
        report = smoke_runner(
            smoke_api_url,
            web_url=smoke_web_url,
            username=smoke_username,
            password=smoke_password,
            timeout=smoke_timeout,
            verify_tls=smoke_verify_tls,
            manifest_path=manifest_path,
            expected_tag=expected_tag,
            expected_commit=expected_commit,
            now=now,
        )
    except SmokeError as exc:
        return _check(label, FAIL, True, str(exc)), None
    state = str(report.get("overall_state"))
    failures = [
        check.get("name")
        for check in report.get("checks") or []
        if isinstance(check, Mapping) and check.get("required") is True and check.get("state") != PASS
    ]
    detail = (
        "smoke passed"
        if state == PASS
        else f"smoke is {state}; failing checks: {', '.join(str(item) for item in failures)}"
    )
    return _check(label, state, True, detail), report


def run_rollback_rehearsal(
    manifest_path: Path,
    previous_manifest_path: Path,
    *,
    compose_files: Sequence[Path],
    gpu: bool = False,
    project: str | None = None,
    execute: bool = False,
    target_verification_report: Path | None = None,
    previous_verification_report: Path | None = None,
    migration_report_path: Path | None = None,
    smoke_api_url: str | None = None,
    smoke_web_url: str | None = None,
    smoke_username: str | None = None,
    smoke_password: str | None = None,
    smoke_timeout: float = 10.0,
    smoke_verify_tls: bool = True,
    expected_tag: str | None = None,
    expected_commit: str | None = None,
    expected_previous_tag: str | None = None,
    expected_previous_commit: str | None = None,
    evidence_dir: Path | None = None,
    runner: CommandRunner = default_runner,
    which: Callable[[str], str | None] = shutil.which,
    base_environment: Mapping[str, str] | None = None,
    smoke_runner: Callable[..., dict[str, Any]] = run_smoke,
    now: Callable[[], str] = utc_now_iso,
) -> dict[str, Any]:
    if execute and evidence_dir is None:
        raise RehearsalError(
            "an executed rollback rehearsal requires an evidence directory so every step is hash-verifiable"
        )
    try:
        target = load_manifest(manifest_path)
        previous = load_manifest(previous_manifest_path)
    except ManifestError as exc:
        raise RehearsalError(str(exc)) from exc
    target_errors = manifest_errors(
        target,
        expected_tag=expected_tag,
        expected_commit=expected_commit,
    )
    previous_errors = manifest_errors(
        previous,
        expected_tag=expected_previous_tag,
        expected_commit=expected_previous_commit,
    )
    if target_errors:
        raise RehearsalError("target manifest is invalid:\n- " + "\n- ".join(target_errors))
    if previous_errors:
        raise RehearsalError("previous manifest is invalid:\n- " + "\n- ".join(previous_errors))
    try:
        target_sha = sha256_file(manifest_path)
        previous_sha = sha256_file(previous_manifest_path)
    except OSError as exc:
        raise RehearsalError(f"could not hash rehearsal manifests: {exc}") from exc
    if target_sha == previous_sha:
        raise RehearsalError("target and previous manifests are identical")
    target_release = target.get("release") if isinstance(target.get("release"), Mapping) else {}
    previous_release = previous.get("release") if isinstance(previous.get("release"), Mapping) else {}
    if target_release.get("commit") == previous_release.get("commit"):
        raise RehearsalError("target and previous manifests have the same commit")
    target_digests = _digests(target)
    previous_digests = _digests(previous)
    shared = set(target_digests) & set(previous_digests)
    if not shared or all(target_digests[name] == previous_digests[name] for name in shared):
        raise RehearsalError("target and previous manifests do not contain different image digests")

    checks: list[dict[str, Any]] = [
        _check("target-manifest", PASS, True, "target manifest is valid and digest-pinned"),
        _check("previous-manifest", PASS, True, "previous manifest is valid and digest-pinned"),
        _check(
            "distinct-release",
            PASS,
            True,
            "target and previous manifests have different commits and image digests",
        ),
    ]
    migration_check = _migration_safety_check(
        migration_report_path,
        target,
        manifest_path=manifest_path,
    )
    checks.append(migration_check)
    steps: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []

    if not execute:
        checks.append(
            _check(
                "execution",
                NOT_RUN,
                True,
                "rollback rehearsal was not executed; pass --execute on the target host",
            )
        )
        steps = _planned_steps(
            target,
            previous,
            compose_files=compose_files,
            project=project,
            gpu=gpu,
        )
        for name in STEP_NAMES:
            checks.append(_check(name, NOT_RUN, True, "rollback rehearsal was not executed"))
        return _report(
            target=target,
            previous=previous,
            target_sha=target_sha,
            previous_sha=previous_sha,
            executed=False,
            checks=checks,
            steps=steps,
            evidence=evidence,
            now=now,
        )

    if migration_check["state"] == FAIL:
        checks.append(
            _check(
                "execution",
                FAIL,
                True,
                "rollback rehearsal was not executed because migration safety did not pass",
            )
        )
        for name in STEP_NAMES:
            checks.append(_check(name, NOT_RUN, True, "migration safety did not pass"))
        return _report(
            target=target,
            previous=previous,
            target_sha=target_sha,
            previous_sha=previous_sha,
            executed=False,
            checks=checks,
            steps=steps,
            evidence=evidence,
            now=now,
        )

    preconditions: list[dict[str, Any]] = []
    preconditions.append(
        _check(
            "target-verification-report",
            PASS if target_verification_report is not None else FAIL,
            True,
            str(target_verification_report)
            if target_verification_report is not None
            else "a target production verification report is required",
        )
    )
    preconditions.append(
        _check(
            "previous-verification-report",
            PASS if previous_verification_report is not None else FAIL,
            True,
            str(previous_verification_report)
            if previous_verification_report is not None
            else "a previous production verification report is required",
        )
    )
    if smoke_api_url is None:
        smoke_state = FAIL
        smoke_detail = "a smoke API URL is required to prove the deployed stack is healthy"
    elif smoke_username is None or smoke_password is None:
        smoke_state = FAIL
        smoke_detail = "smoke username and password are required to prove authentication"
    else:
        smoke_state = PASS
        smoke_detail = "smoke target and credentials are configured"
    preconditions.append(_check("smoke-configuration", smoke_state, True, smoke_detail))
    preconditions.append(
        _check(
            "docker",
            PASS if which("docker") is not None else UNAVAILABLE,
            True,
            "docker is installed" if which("docker") is not None else "docker is not installed",
        )
    )
    checks.extend(preconditions)
    if any(check["state"] != PASS for check in preconditions):
        execution_state = FAIL if any(check["state"] == FAIL for check in preconditions) else UNAVAILABLE
        checks.append(
            _check(
                "execution",
                execution_state,
                True,
                "rollback rehearsal was not executed because preconditions were not met",
            )
        )
        for name in STEP_NAMES:
            checks.append(_check(name, NOT_RUN, True, "preconditions were not met"))
        return _report(
            target=target,
            previous=previous,
            target_sha=target_sha,
            previous_sha=previous_sha,
            executed=False,
            checks=checks,
            steps=steps,
            evidence=evidence,
            now=now,
        )

    checks.append(_check("execution", PASS, True, "rollback rehearsal was executed on the target host"))
    assert target_verification_report is not None
    assert previous_verification_report is not None
    assert smoke_api_url is not None
    assert smoke_username is not None
    assert smoke_password is not None

    deploy_checks, _ = _deploy(
        previous,
        compose_files=compose_files,
        project=project,
        gpu=gpu,
        runner=runner,
        base_environment=base_environment,
    )
    checks.extend(deploy_checks)
    steps.append(
        _step(
            "deploy-previous",
            _aggregate(deploy_checks),
            "previous release digests were pulled and started",
            commands=[check["command"] for check in deploy_checks if check.get("command")],
            checks=deploy_checks,
        )
    )
    if _aggregate(deploy_checks) != PASS:
        _not_run_steps(
            checks,
            steps,
            STEP_NAMES[1:],
            "not run because the previous release could not be deployed",
        )
        return _report(
            target=target,
            previous=previous,
            target_sha=target_sha,
            previous_sha=previous_sha,
            executed=True,
            checks=checks,
            steps=steps,
            evidence=evidence,
            now=now,
        )

    check, deployment = _verify_step(
        "verify-previous",
        previous_manifest_path,
        verification_report=previous_verification_report,
        compose_files=compose_files,
        project=project,
        gpu=gpu,
        expected_tag=expected_previous_tag,
        expected_commit=expected_previous_commit,
        runner=runner,
        which=which,
        base_environment=base_environment,
        now=now,
    )
    checks.append(check)
    item = _write_evidence(
        deployment,
        evidence_dir,
        "previous-deployment.json",
        evidence,
    )
    steps.append(
        _step(
            "verify-previous",
            check["state"],
            check["detail"],
            deployment=deployment,
            evidence=[item] if item else [],
        )
    )
    if check["state"] != PASS:
        _not_run_steps(
            checks,
            steps,
            STEP_NAMES[2:],
            "not run because the previous release did not verify",
        )
        return _report(
            target=target,
            previous=previous,
            target_sha=target_sha,
            previous_sha=previous_sha,
            executed=True,
            checks=checks,
            steps=steps,
            evidence=evidence,
            now=now,
        )

    check, smoke = _smoke_step(
        "smoke-previous",
        previous_manifest_path,
        smoke_api_url=smoke_api_url,
        smoke_web_url=smoke_web_url,
        smoke_username=smoke_username,
        smoke_password=smoke_password,
        smoke_timeout=smoke_timeout,
        smoke_verify_tls=smoke_verify_tls,
        expected_tag=expected_previous_tag,
        expected_commit=expected_previous_commit,
        smoke_runner=smoke_runner,
        now=now,
    )
    checks.append(check)
    item = _write_evidence(smoke, evidence_dir, "previous-smoke.json", evidence)
    steps.append(
        _step(
            "smoke-previous",
            check["state"],
            check["detail"],
            smoke=smoke,
            evidence=[item] if item else [],
        )
    )
    if check["state"] != PASS:
        _not_run_steps(
            checks,
            steps,
            STEP_NAMES[3:],
            "not run because the previous release did not pass smoke checks",
        )
        return _report(
            target=target,
            previous=previous,
            target_sha=target_sha,
            previous_sha=previous_sha,
            executed=True,
            checks=checks,
            steps=steps,
            evidence=evidence,
            now=now,
        )

    target_deploy_checks, _ = _deploy(
        target,
        compose_files=compose_files,
        project=project,
        gpu=gpu,
        runner=runner,
        base_environment=base_environment,
    )
    checks.extend(target_deploy_checks)
    steps.append(
        _step(
            "deploy-target",
            _aggregate(target_deploy_checks),
            "target release digests were pulled and started",
            commands=[check["command"] for check in target_deploy_checks if check.get("command")],
            checks=target_deploy_checks,
        )
    )
    if _aggregate(target_deploy_checks) == PASS:
        check, deployment = _verify_step(
            "verify-target",
            manifest_path,
            verification_report=target_verification_report,
            compose_files=compose_files,
            project=project,
            gpu=gpu,
            expected_tag=expected_tag,
            expected_commit=expected_commit,
            runner=runner,
            which=which,
            base_environment=base_environment,
            now=now,
        )
        checks.append(check)
        item = _write_evidence(
            deployment,
            evidence_dir,
            "target-deployment.json",
            evidence,
        )
        steps.append(
            _step(
                "verify-target",
                check["state"],
                check["detail"],
                deployment=deployment,
                evidence=[item] if item else [],
            )
        )
        if check["state"] == PASS:
            smoke_check, smoke = _smoke_step(
                "smoke-target",
                manifest_path,
                smoke_api_url=smoke_api_url,
                smoke_web_url=smoke_web_url,
                smoke_username=smoke_username,
                smoke_password=smoke_password,
                smoke_timeout=smoke_timeout,
                smoke_verify_tls=smoke_verify_tls,
                expected_tag=expected_tag,
                expected_commit=expected_commit,
                smoke_runner=smoke_runner,
                now=now,
            )
        else:
            smoke_check, smoke = (
                _check("smoke-target", NOT_RUN, True, "target verification did not pass"),
                None,
            )
        checks.append(smoke_check)
        item = _write_evidence(smoke, evidence_dir, "target-smoke.json", evidence)
        steps.append(
            _step(
                "smoke-target",
                smoke_check["state"],
                smoke_check["detail"],
                smoke=smoke,
                evidence=[item] if item else [],
            )
        )
    else:
        checks.append(_check("verify-target", NOT_RUN, True, "target deployment did not succeed"))
        checks.append(_check("smoke-target", NOT_RUN, True, "target deployment did not succeed"))
        steps.append(_step("verify-target", NOT_RUN, "target deployment did not succeed"))
        steps.append(_step("smoke-target", NOT_RUN, "target deployment did not succeed"))

    rollback_checks, _ = _deploy(
        previous,
        compose_files=compose_files,
        project=project,
        gpu=gpu,
        runner=runner,
        base_environment=base_environment,
    )
    checks.extend(rollback_checks)
    steps.append(
        _step(
            "rollback-previous",
            _aggregate(rollback_checks),
            "previous release digests were redeployed after the target attempt",
            commands=[check["command"] for check in rollback_checks if check.get("command")],
            checks=rollback_checks,
        )
    )
    if _aggregate(rollback_checks) != PASS:
        _not_run_steps(
            checks,
            steps,
            ("verify-after-rollback", "smoke-after-rollback"),
            "not run because the rollback deployment did not succeed",
        )
        return _report(
            target=target,
            previous=previous,
            target_sha=target_sha,
            previous_sha=previous_sha,
            executed=True,
            checks=checks,
            steps=steps,
            evidence=evidence,
            now=now,
        )

    check, deployment = _verify_step(
        "verify-after-rollback",
        previous_manifest_path,
        verification_report=previous_verification_report,
        compose_files=compose_files,
        project=project,
        gpu=gpu,
        expected_tag=expected_previous_tag,
        expected_commit=expected_previous_commit,
        runner=runner,
        which=which,
        base_environment=base_environment,
        now=now,
    )
    checks.append(check)
    item = _write_evidence(
        deployment,
        evidence_dir,
        "previous-rollback-deployment.json",
        evidence,
    )
    steps.append(
        _step(
            "verify-after-rollback",
            check["state"],
            check["detail"],
            deployment=deployment,
            evidence=[item] if item else [],
        )
    )
    check, smoke = _smoke_step(
        "smoke-after-rollback",
        previous_manifest_path,
        smoke_api_url=smoke_api_url,
        smoke_web_url=smoke_web_url,
        smoke_username=smoke_username,
        smoke_password=smoke_password,
        smoke_timeout=smoke_timeout,
        smoke_verify_tls=smoke_verify_tls,
        expected_tag=expected_previous_tag,
        expected_commit=expected_previous_commit,
        smoke_runner=smoke_runner,
        now=now,
    )
    checks.append(check)
    item = _write_evidence(smoke, evidence_dir, "previous-rollback-smoke.json", evidence)
    steps.append(
        _step(
            "smoke-after-rollback",
            check["state"],
            check["detail"],
            smoke=smoke,
            evidence=[item] if item else [],
        )
    )
    return _report(
        target=target,
        previous=previous,
        target_sha=target_sha,
        previous_sha=previous_sha,
        executed=True,
        checks=checks,
        steps=steps,
        evidence=evidence,
        now=now,
    )


def write_rehearsal_report(report: Mapping[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def render_rehearsal_summary(report: Mapping[str, Any]) -> str:
    subject = report.get("subject") or {}
    previous_subject = report.get("previous_subject") or {}
    lines = [
        f"Rollback rehearsal: {report.get('state')} "
        f"(executed={report.get('executed')}, verified={report.get('verified')})",
        f"Target: {subject.get('tag')} at {subject.get('commit')}",
        f"Previous: {previous_subject.get('tag')} at {previous_subject.get('commit')}",
        f"Target manifest: {report.get('manifest_sha256')}",
        f"Previous manifest: {report.get('previous_manifest_sha256')}",
    ]
    for check in report.get("checks") or []:
        required = "required" if check.get("required") else "informational"
        lines.append(f"- {check.get('name')}: {check.get('state')} ({required}) - {check.get('detail')}")
    blockers = report.get("blockers") or []
    if blockers:
        lines.append("Blockers:")
        lines.extend(f"- {item}" for item in blockers)
    limitations = report.get("limitations") or []
    if limitations:
        lines.append("Limitations:")
        lines.extend(f"- {item}" for item in limitations)
    return "\n".join(lines) + "\n"
