"""Focused V33 continuous-integrity audit tests.

Every fixture is synthetic and local: generated Ed25519 keys live under
pytest's temporary directory, no network or external transparency service is
contacted, and no credential is read or written. The tests assert the two
structural guarantees of V33: protected V30-V32 inputs are read-only, and a
confirmed failure can never be reported as an overall PASS.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from backend.app.core.config import AppEnv, Settings
from backend.app.integrity.constants import AuditStatus, AuditTrigger, ScopeStatus
from backend.app.integrity.errors import DuplicateAuditRunError
from backend.app.integrity.models import AuditRun
from backend.app.integrity.runner import AuditRunner
from backend.app.integrity.scheduler import IntegrityScheduler
from backend.app.integrity.store import MonitoringStore
from backend.tests.unit.v32_support import V32Workspace, build_workspace


def _settings(tmp_path: Path, **overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "app_name": "industrial-vision-platform",
        "app_env": AppEnv.testing,
        "log_level": "WARNING",
        "database_url": f"sqlite:///{tmp_path}/test.db",
        "integrity_monitoring_db_url": f"sqlite:///{tmp_path}/monitor.db",
        "_env_file": None,
    }
    values.update(overrides)
    return Settings(**values)


def _copy_tree_inputs(workspace: V32Workspace, root: Path) -> dict[str, Path]:
    heads = root / "tree-heads"
    inclusion = root / "inclusion"
    consistency = root / "consistency"
    for directory in (heads, inclusion, consistency):
        directory.mkdir(parents=True, exist_ok=True)
    for size in (1, 2, 3):
        workspace.head_path(size).replace(heads / f"head-{size}.json")
    for size in (1, 2, 3):
        for index in range(size):
            workspace.inclusion_path(size, index).replace(inclusion / f"inclusion-{size}-{index}.json")
    for old in (1, 2):
        for new in range(old + 1, 4):
            workspace.proof_path(old, new).replace(consistency / f"consistency-{old}-{new}.json")
    return {"heads": heads, "inclusion": inclusion, "consistency": consistency}


def _workspace_settings(tmp_path: Path, workspace: V32Workspace, inputs: dict[str, Path]) -> Settings:
    return _settings(
        tmp_path,
        integrity_transparency_log=str(workspace.log_path),
        integrity_tree_heads_dir=str(inputs["heads"]),
        integrity_inclusion_proofs_dir=str(inputs["inclusion"]),
        integrity_consistency_proofs_dir=str(inputs["consistency"]),
        integrity_transparency_trust_store=str(workspace.trust_store_path),
    )


def _store(settings: Settings) -> MonitoringStore:
    store = MonitoringStore(settings.integrity_store_url)
    store.initialize()
    return store


def _digest_tree(root: Path) -> dict[str, str]:
    digests: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            digests[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return digests


def test_full_audit_verifies_transparency_and_never_claims_external_anchor(
    tmp_path: Path,
) -> None:
    workspace = build_workspace(tmp_path / "ws")
    inputs = _copy_tree_inputs(workspace, tmp_path / "inputs")
    settings = _workspace_settings(tmp_path, workspace, inputs)
    store = _store(settings)
    runner = AuditRunner(settings=settings, store=store)

    run = runner.execute(scopes=["FULL"], trigger=AuditTrigger.MANUAL)

    detail = store.get_run_detail(run.audit_run_id)
    assert detail is not None
    scope_status = {item["scope"]: item["status"] for item in detail["scope_results"]}
    for scope in (
        "TRANSPARENCY_LOG",
        "TREE_HEADS",
        "INCLUSION_PROOFS",
        "CONSISTENCY_PROOFS",
        "TRUST_STATE",
    ):
        assert scope_status[scope] == ScopeStatus.PASS.value, (scope, scope_status)
    # Evidence and checkpoint inputs are intentionally unconfigured here.
    assert scope_status["EVIDENCE"] == ScopeStatus.UNAVAILABLE.value
    assert scope_status["SIGNED_CHECKPOINTS"] == ScopeStatus.UNAVAILABLE.value
    assert run.status is AuditStatus.PARTIAL
    assert run.external_anchor_configured is False
    assert all(finding["reason_code"].endswith("NOT_CONFIGURED") for finding in detail["findings"])
    assert detail["audit"]["external_anchor_configured"] is False


def test_tampered_tree_head_is_a_confirmed_failure_not_a_pass(tmp_path: Path) -> None:
    workspace = build_workspace(tmp_path / "ws")
    inputs = _copy_tree_inputs(workspace, tmp_path / "inputs")
    tampered_path = inputs["heads"] / "head-2.json"
    payload = json.loads(tampered_path.read_text(encoding="utf-8"))
    payload["signature"] = ("0" if payload["signature"][0] != "0" else "1") + payload["signature"][1:]
    tampered_path.write_text(json.dumps(payload), encoding="utf-8")

    settings = _workspace_settings(tmp_path, workspace, inputs)
    store = _store(settings)
    runner = AuditRunner(settings=settings, store=store)
    run = runner.execute(scopes=["TREE_HEADS"])

    detail = store.get_run_detail(run.audit_run_id)
    assert detail is not None
    assert run.status is AuditStatus.FAIL
    assert detail["scope_results"][0]["status"] == ScopeStatus.FAIL.value
    assert "TREE_HEAD_INVALID" in detail["scope_results"][0]["reason_codes"]
    assert detail["findings_total"] >= 1
    assert all(finding["severity"] != "INFO" for finding in detail["findings"])
    assert run.external_anchor_configured is False


def test_unconfigured_scopes_are_unavailable_and_never_pass(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = _store(settings)
    runner = AuditRunner(settings=settings, store=store)

    run = runner.execute(scopes=["FULL"])

    detail = store.get_run_detail(run.audit_run_id)
    assert detail is not None
    assert run.status is AuditStatus.UNAVAILABLE
    statuses = {item["status"] for item in detail["scope_results"]}
    assert statuses == {ScopeStatus.UNAVAILABLE.value}
    codes = {code for item in detail["scope_results"] for code in item["reason_codes"]}
    for expected in (
        "EVIDENCE_NOT_CONFIGURED",
        "CHECKPOINT_NOT_CONFIGURED",
        "TRANSPARENCY_LOG_NOT_CONFIGURED",
        "TREE_HEAD_NOT_CONFIGURED",
        "INCLUSION_PROOFS_NOT_CONFIGURED",
        "CONSISTENCY_PROOFS_NOT_CONFIGURED",
        "TRUST_STATE_NOT_CONFIGURED",
    ):
        assert expected in codes, (expected, sorted(codes))


def test_audit_is_read_only_for_every_protected_input(tmp_path: Path) -> None:
    workspace = build_workspace(tmp_path / "ws")
    inputs = _copy_tree_inputs(workspace, tmp_path / "inputs")
    settings = _workspace_settings(tmp_path, workspace, inputs)
    store = _store(settings)
    runner = AuditRunner(settings=settings, store=store)

    before = _digest_tree(workspace.root) | _digest_tree(tmp_path / "inputs")
    run = runner.execute(scopes=["FULL"])
    after = _digest_tree(workspace.root) | _digest_tree(tmp_path / "inputs")

    assert run.audit_run_id
    assert before == after
    # The monitoring store is the only new state and lives beside the app DB.
    assert Path(settings.integrity_store_url.removeprefix("sqlite:///")).exists()


def test_idempotency_and_duplicate_run_prevention(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = _store(settings)
    runner = AuditRunner(settings=settings, store=store)

    first = runner.execute(scopes=["TRUST_STATE"], idempotency_key="daily-2026-01-01")
    replay = runner.execute(scopes=["TRUST_STATE"], idempotency_key="daily-2026-01-01")
    assert replay.audit_run_id == first.audit_run_id
    assert store.list_runs()[1] == 1

    lease = store.acquire_execution_lease("test-owner", slots=1, ttl_seconds=60)
    assert lease is not None
    try:
        with pytest.raises(DuplicateAuditRunError):
            runner.execute(scopes=["TRUST_STATE"])
    finally:
        store.release_execution_lease(lease, "test-owner")


def test_store_pagination_filters_and_retention(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = _store(settings)
    runner = AuditRunner(settings=settings, store=store)
    for index in range(3):
        runner.execute(scopes=["TRUST_STATE"], idempotency_key=f"run-{index}")

    page_one, total = store.list_runs(page=1, page_size=2)
    page_two, total_two = store.list_runs(page=2, page_size=2)
    assert total == total_two == 3
    assert len(page_one) == 2 and len(page_two) == 1
    assert store.list_runs(status="UNAVAILABLE")[1] == 3
    assert store.list_runs(status="PASS")[1] == 0
    assert store.list_runs(trigger="MANUAL")[1] == 3

    old = AuditRun(
        audit_run_id="audit-old",
        trigger=AuditTrigger.SCHEDULED,
        requested_scopes=[],
        completed_scopes=[],
        status=AuditStatus.PASS,
        started_at="2020-01-01T00:00:00.000Z",
        created_at="2020-01-01T00:00:00.000Z",
        completed_at="2020-01-01T00:00:01.000Z",
    )
    assert store.create_run(old)
    assert store.prune(retention_days=30) >= 1
    assert store.get_run("audit-old") is None
    assert store.get_run_by_schedule_slot("never-used") is None


def test_metrics_use_bounded_labels_and_never_claim_external_anchor() -> None:
    from backend.app.core.metrics import metrics_payload, record_integrity_audit

    record_integrity_audit(
        trigger="MANUAL",
        status="FAIL",
        duration_seconds=0.25,
        artifacts_by_scope={"TREE_HEADS": 2},
        findings_by_severity={"HIGH": 1},
        failed_scopes={"TREE_HEADS": 1},
        external_anchor_configured=False,
    )
    text = metrics_payload().decode("utf-8")
    assert "ivp_integrity_audit_runs_total" in text
    assert "ivp_integrity_findings_total" in text
    assert "ivp_integrity_external_anchor_configured" in text
    assert "artifact_id=" not in text
    assert "finding_id=" not in text
    assert "run_id=" not in text


def test_reason_vocabulary_covers_mission_codes_and_unavailable_is_not_failure() -> None:
    from backend.app.integrity.constants import REASON_CODES, IntegrityScope, map_reason_code

    required = {
        "EVIDENCE_MISSING",
        "EVIDENCE_MODIFIED",
        "EVIDENCE_REPLACED",
        "CHECKPOINT_MISSING",
        "CHECKPOINT_SIGNATURE_INVALID",
        "CHECKPOINT_REPLAY",
        "TRUST_KEY_UNKNOWN",
        "TRUST_KEY_REVOKED",
        "TRUST_KEY_EXPIRED",
        "TREE_HEAD_INVALID",
        "TREE_HEAD_REPLAY",
        "TREE_HEAD_TIMESTAMP_REGRESSION",
        "INCLUSION_PROOF_INVALID",
        "CONSISTENCY_PROOF_INVALID",
        "TRUST_STATE_INVALID",
        "VERIFICATION_UNAVAILABLE",
        "AUDIT_CANCELLED",
        "AUDIT_TIMEOUT",
        "AUDIT_EXECUTION_ERROR",
        "AUDIT_ALREADY_RUNNING",
        "AUDIT_RETRY_EXHAUSTED",
        "BATCH_LIMIT_REACHED",
        "FINDINGS_TRUNCATED",
        "CONCURRENT_EVIDENCE_CHANGE",
        "AUDIT_INTERRUPTED",
    }
    assert required <= REASON_CODES
    assert (
        map_reason_code("SOMETHING_UNAVAILABLE", scope=IntegrityScope.TRUST_STATE)
        == "VERIFICATION_UNAVAILABLE"
    )
    assert map_reason_code("UNAVAILABLE", scope=IntegrityScope.TREE_HEADS) == "VERIFICATION_UNAVAILABLE"
    assert map_reason_code(None, scope=IntegrityScope.TREE_HEADS) == "VERIFICATION_FAILED"


def test_scheduler_slot_dedup_and_stale_run_recovery(tmp_path: Path) -> None:
    settings = _settings(tmp_path, integrity_scheduler_enabled=True)
    store = _store(settings)
    runner = AuditRunner(settings=settings, store=store)
    scheduler = IntegrityScheduler(settings=settings, store=store, runner=runner)

    stale = AuditRun(
        audit_run_id="audit-stale",
        trigger=AuditTrigger.SCHEDULED,
        requested_scopes=[],
        completed_scopes=[],
        status=AuditStatus.RUNNING,
        started_at="2020-01-01T00:00:00.000Z",
        created_at="2020-01-01T00:00:00.000Z",
    )
    assert store.create_run(stale)

    reference = datetime(2026, 5, 1, 12, 0, 0, tzinfo=UTC)
    first = scheduler.run_once(now=reference)
    assert first["recovered"] == 1
    assert first["started"] is True
    assert first["audit_status"] == AuditStatus.UNAVAILABLE.value
    assert store.get_run("audit-stale").status is AuditStatus.UNAVAILABLE  # type: ignore[union-attr]

    second = scheduler.run_once(now=reference + timedelta(seconds=1))
    assert second["skipped"] is True
    assert store.list_runs(trigger="SCHEDULED")[1] == 2

    third = scheduler.run_once(now=reference + timedelta(seconds=3600))
    assert third["started"] is True
    assert store.list_runs(trigger="SCHEDULED")[1] == 3
    status = scheduler.status()
    assert status["enabled"] is True
    assert status["cycles"] == 3
    assert status["runs_started"] == 2
