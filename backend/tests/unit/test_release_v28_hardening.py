"""V28 hardening tests for external readiness verification.

The tests are deterministic and offline. They exercise the complete V28 live
report path with fake GitHub, GHCR, attestation, Docker, and network evidence,
then prove that the runtime gate rejects tampering, secret retention, policy
violations, and any mutation claim.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from backend.tests.unit.test_release_readiness import (
    SMOKE_SENTINEL,
    TOKEN_SENTINEL,
    _assess,
    _environment,
    _inputs,
    _readiness_schema,
    _target_payload,
)
from backend.tests.unit.test_release_v28_inspection import _FakeGitHub
from backend.tests.unit.test_release_v28_live import (
    GENERATED_AT,
    _backup_document,
    _connectivity_probe,
    _migration_report,
    _state,
    _V28AssessmentRunner,
    _V28Runner,
)
from backend.tests.unit.test_release_verification import make_release
from tools.release.manifest import sha256_file
from tools.release.readiness import (
    READINESS_ALL_BINDING_NAMES,
    READINESS_OPTIONAL_BINDING_NAMES,
    V28_CONNECTIVITY_CHECKS,
    V28_LIVE_CHECKS,
    _v28_checks,
    _v28_rollback_checks,
    readiness_report_errors,
    write_readiness_report,
)
from tools.release.staging import STAGING_TARGET_STATEMENT
from tools.release.verification import FAIL, NOT_RUN, PASS


def _target() -> dict[str, Any]:
    return _target_payload(
        staging_statement=STAGING_TARGET_STATEMENT,
        allowed_hostnames=[
            "api.staging.example.test",
            "web.staging.example.test",
            "ws.staging.example.test",
        ],
        production_hostnames=[],
    )


def _live_assessment(
    tmp_path: Path,
    *,
    target: dict[str, Any] | None = None,
    backup_text: str | None = None,
    environment: dict[str, str] | None = None,
    connectivity_probe: Any = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], _V28AssessmentRunner]:
    inputs = _inputs(tmp_path)
    manifest = inputs["manifest"]
    payload = _target() if target is None else target
    inputs["target_path"].write_text(json.dumps(payload), encoding="utf-8")
    backup = tmp_path / "backup.md"
    backup.write_text(backup_text or _backup_document(), encoding="utf-8")
    migration = _migration_report(tmp_path, inputs["manifest_path"], manifest)
    runner = _V28AssessmentRunner(manifest)
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
        connectivity_probe=connectivity_probe or _connectivity_probe,
        runner=runner,
        env=environment or _environment(),
        network_probe=lambda host, port: True,
    )
    return inputs, payload, report, runner


def _write_report(tmp_path: Path, report: dict[str, Any]) -> tuple[Path, str]:
    path = tmp_path / "staging-readiness.json"
    return path, write_readiness_report(report, path)


def _gate_errors(
    inputs: dict[str, Any],
    report: dict[str, Any],
    path: Path,
    *,
    expected_report_sha256: str | None = None,
) -> list[str]:
    return readiness_report_errors(
        report,
        manifest_path=inputs["manifest_path"],
        report_path=path,
        evidence_dir=path.parent / "readiness-evidence",
        expected_report_sha256=expected_report_sha256,
    )


def _schema_errors(report: dict[str, Any]) -> list[str]:
    validator = Draft202012Validator(_readiness_schema())
    return [
        f"{'/'.join(str(part) for part in error.absolute_path)}: {error.message}"
        for error in validator.iter_errors(report)
    ]


def _refresh_evidence(report: dict[str, Any], evidence_dir: Path, kind: str) -> None:
    path: str | None = None
    for item in report["evidence"]:
        if item["kind"] == kind:
            item["sha256"] = sha256_file(evidence_dir / item["path"])
            path = item["path"]
    assert path is not None
    for binding in report["bindings"].values():
        if isinstance(binding, dict) and binding.get("kind") == kind:
            binding["sha256"] = sha256_file(evidence_dir / path)


def _rewrite_live(
    tmp_path: Path,
    report: dict[str, Any],
    mutate: Any,
) -> Path:
    evidence_dir = tmp_path / "readiness-evidence"
    live_path = evidence_dir / "live-inspection.json"
    live = json.loads(live_path.read_text(encoding="utf-8"))
    mutate(live)
    live_path.write_text(
        json.dumps(live, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    _refresh_evidence(report, evidence_dir, "live-inspection")
    return live_path


def test_v28_all_pass_report_satisfies_runtime_gate_and_schema(tmp_path: Path) -> None:
    inputs, _, report, _ = _live_assessment(tmp_path)
    path, digest = _write_report(tmp_path, report)

    assert report["inspection_profile"] == "v28"
    assert report["mode"] == "live-read-only"
    assert report["state"] == PASS
    assert report["ready"] is True
    assert report["production_qualified"] is False
    assert report["deployment"]["authorized"] is False
    assert report["deployment"]["performed"] is False
    assert len(report["checks"]) == 81
    assert set(report["bindings"]) == set(READINESS_ALL_BINDING_NAMES)
    assert _schema_errors(report) == []
    assert _gate_errors(inputs, report, path, expected_report_sha256=digest) == []


def test_v28_gate_rejects_non_pass_required_live_check(tmp_path: Path) -> None:
    inputs, _, report, _ = _live_assessment(tmp_path)
    path, _ = _write_report(tmp_path, report)
    tampered = copy.deepcopy(report)
    next(check for check in tampered["checks"] if check["name"] == "dns-resolution")["state"] = FAIL

    errors = _gate_errors(inputs, tampered, path)

    assert any("required checks are not PASS" in error and "dns-resolution" in error for error in errors)


def test_v28_gate_rejects_missing_live_inspection_binding(tmp_path: Path) -> None:
    inputs, _, report, _ = _live_assessment(tmp_path)
    path, _ = _write_report(tmp_path, report)
    tampered = copy.deepcopy(report)
    del tampered["bindings"]["live_inspection"]

    errors = _gate_errors(inputs, tampered, path)

    assert any("live_inspection binding is missing" in error for error in errors)


def test_v28_gate_rejects_mutation_claim_in_live_evidence(tmp_path: Path) -> None:
    inputs, _, report, _ = _live_assessment(tmp_path)
    path, _ = _write_report(tmp_path, report)

    def mutate(live: dict[str, Any]) -> None:
        live["mutation"]["performed"] = True

    _rewrite_live(tmp_path, report, mutate)

    errors = _gate_errors(inputs, report, path)

    assert any("must never claim mutation" in error for error in errors)


def test_v28_gate_rejects_missing_live_evidence_sections(tmp_path: Path) -> None:
    inputs, _, report, _ = _live_assessment(tmp_path)
    path, _ = _write_report(tmp_path, report)

    def mutate(live: dict[str, Any]) -> None:
        del live["connectivity"]

    _rewrite_live(tmp_path, report, mutate)

    errors = _gate_errors(inputs, report, path)

    assert any("connectivity evidence is missing" in error for error in errors)


def test_v28_gate_rejects_live_target_mismatch(tmp_path: Path) -> None:
    inputs, _, report, _ = _live_assessment(tmp_path)
    path, _ = _write_report(tmp_path, report)

    def mutate(live: dict[str, Any]) -> None:
        live["target"]["name"] = "staging-other"

    _rewrite_live(tmp_path, report, mutate)

    errors = _gate_errors(inputs, report, path)

    assert any("target.name does not match" in error for error in errors)


def test_v28_gate_rejects_changed_report_bytes(tmp_path: Path) -> None:
    inputs, _, report, _ = _live_assessment(tmp_path)
    path, digest = _write_report(tmp_path, report)
    path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8", newline="\n")

    errors = _gate_errors(inputs, report, path, expected_report_sha256=digest)

    assert any("bytes changed" in error for error in errors)


def test_v28_live_policy_failure_skips_all_network_probes(tmp_path: Path) -> None:
    manifest_path, artifacts, manifest = make_release(tmp_path)
    calls: list[Any] = []

    def forbidden_probe(*args: Any, **kwargs: Any) -> Any:
        calls.append(args)
        raise AssertionError("a network probe must not run before the live policy passes")

    checks, observation = _v28_checks(
        manifest=manifest,
        manifest_path=manifest_path,
        artifacts_dir=artifacts,
        target=_target_payload(),
        target_live_errors=["staging_statement is required before live inspection"],
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
        connectivity_probe=forbidden_probe,
        now=lambda: GENERATED_AT,
        timeout=10.0,
    )

    assert calls == []
    assert _state(checks, "staging-target-live-policy") == FAIL
    assert all(_state(checks, name) == NOT_RUN for name in V28_CONNECTIVITY_CHECKS)
    assert observation["connectivity"]["state"] == "NOT_RUN"


def test_v28_assessment_without_statement_never_contacts_the_target(tmp_path: Path) -> None:
    calls: list[Any] = []

    def forbidden_probe(*args: Any, **kwargs: Any) -> Any:
        calls.append(args)
        raise AssertionError("the target must not be contacted without an explicit statement")

    target = _target()
    target.pop("staging_statement")
    inputs, _, report, _ = _live_assessment(
        tmp_path,
        target=target,
        connectivity_probe=forbidden_probe,
    )

    checks = {check["name"]: check for check in report["checks"]}
    assert calls == []
    assert report["ready"] is False
    assert checks["staging-target-live-policy"]["state"] == FAIL
    assert all(checks[name]["state"] == NOT_RUN for name in V28_CONNECTIVITY_CHECKS)


def test_v28_assessment_never_writes_tokens_or_smoke_passwords(tmp_path: Path) -> None:
    inputs, _, report, _ = _live_assessment(tmp_path)
    path, digest = _write_report(tmp_path, report)

    rendered = json.dumps(report, sort_keys=True)
    assert TOKEN_SENTINEL not in rendered
    assert SMOKE_SENTINEL not in rendered
    assert _gate_errors(inputs, report, path, expected_report_sha256=digest) == []
    for evidence in (tmp_path / "readiness-evidence").iterdir():
        text = evidence.read_text(encoding="utf-8")
        assert TOKEN_SENTINEL not in text
        assert SMOKE_SENTINEL not in text


def test_v28_secret_bearing_backup_documentation_is_not_retained(tmp_path: Path) -> None:
    sentinel = "v28_backup_password_sentinel_do_not_disclose"
    backup_text = _backup_document() + f"\npassword={sentinel}\n"

    _, _, report, _ = _live_assessment(tmp_path, backup_text=backup_text)

    assert report["bindings"]["backup_documentation"] is None
    assert report["state"] == FAIL
    assert report["ready"] is False
    assert any("evidence-retention: backup_documentation" in blocker for blocker in report["blockers"])
    assert sentinel not in json.dumps(report, sort_keys=True)
    for evidence in (tmp_path / "readiness-evidence").iterdir():
        assert sentinel not in evidence.read_text(encoding="utf-8")


def test_v28_assessment_issues_only_read_only_commands(tmp_path: Path) -> None:
    _, _, _, runner = _live_assessment(tmp_path)

    forbidden = (
        ("git", "push"),
        ("git", "tag"),
        ("git", "reset"),
        ("git", "clean"),
        ("git", "checkout"),
        ("gh", "release", "create"),
        ("gh", "release", "delete"),
        ("gh", "release", "edit"),
        ("gh", "workflow", "run"),
        ("docker", "push"),
        ("docker", "pull"),
        ("docker", "run"),
        ("docker", "rm"),
        ("docker", "rmi"),
        ("docker", "tag"),
        ("docker", "login"),
        ("docker", "logout"),
        ("docker", "create"),
        ("docker", "start"),
        ("docker", "stop"),
        ("docker", "restart"),
        ("docker", "compose", "up"),
        ("docker", "compose", "down"),
        ("docker", "volume", "rm"),
        ("docker", "image", "rm"),
    )
    assert runner.v28_calls
    for args in runner.v28_calls:
        effective = args[3:] if args[:2] == ["docker", "--context"] else args
        for command in forbidden:
            assert not any(
                tuple(effective[index : index + len(command)]) == command for index in range(len(effective))
            ), f"mutating command issued: {' '.join(args)}"


def test_v28_rollback_rejects_migration_report_bound_to_other_manifest(
    tmp_path: Path,
) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    migration = _migration_report(tmp_path, manifest_path, manifest)
    other_path = tmp_path / "other-manifest.json"
    other = copy.deepcopy(manifest)
    other["release"]["tag"] = "v9.9.9"
    other_path.write_text(json.dumps(other), encoding="utf-8")
    previous = {
        "images": [{"name": image["name"], "digest": "sha256:" + "b" * 64} for image in manifest["images"]]
    }

    checks, _ = _v28_rollback_checks(
        manifest=manifest,
        manifest_path=other_path,
        previous=previous,
        previous_checks=[
            {"name": name, "state": PASS}
            for name in ("previous-release", "previous-verification", "rollback-evidence")
        ],
        migration_report_path=migration,
        backup_documentation_path=None,
        now=lambda: GENERATED_AT,
    )

    assert _state(checks, "rollback-migration-evidence") == FAIL


def test_v28_uses_gh_token_before_github_token_and_never_records_either(
    tmp_path: Path,
) -> None:
    manifest_path, artifacts, manifest = make_release(tmp_path)
    primary = "v28_primary_token_sentinel_do_not_disclose"
    secondary = "v28_secondary_token_sentinel_do_not_disclose"
    fake = _FakeGitHub(manifest)

    checks, observation = _v28_checks(
        manifest=manifest,
        manifest_path=manifest_path,
        artifacts_dir=artifacts,
        target=_target(),
        target_live_errors=[],
        previous=None,
        previous_checks=[],
        migration_report_path=None,
        backup_documentation_path=None,
        docker_host_name=None,
        gpu_required=False,
        execute_live=True,
        environment={"GH_TOKEN": primary, "GITHUB_TOKEN": secondary},
        runner=_V28Runner(manifest),
        which=lambda name: rf"C:\tools\{name}.exe" if name == "docker" else None,
        http_get=fake,
        connectivity_probe=_connectivity_probe,
        now=lambda: GENERATED_AT,
        timeout=10.0,
    )

    assert fake.requests
    assert all(request["headers"].get("Authorization") == f"Bearer {primary}" for request in fake.requests)
    rendered = json.dumps({"checks": checks, "observation": observation}, sort_keys=True)
    assert primary not in rendered
    assert secondary not in rendered


def test_v28_preflight_does_not_require_live_evidence_bindings(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    report = _assess(tmp_path, inputs, inspection_profile="v28", execute_live=False)
    path, digest = _write_report(tmp_path, report)

    assert report["mode"] == "preflight"
    for name in READINESS_OPTIONAL_BINDING_NAMES:
        assert report["bindings"][name] is None
    checks = {check["name"]: check for check in report["checks"]}
    for name in V28_LIVE_CHECKS:
        assert checks[name]["required"] is False
        assert checks[name]["state"] == NOT_RUN
    assert _schema_errors(report) == []
    errors = _gate_errors(inputs, report, path, expected_report_sha256=digest)
    assert not any("evidence kinds do not match" in error for error in errors)
