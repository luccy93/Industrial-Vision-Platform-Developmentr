"""V32 adversarial, resource, lifecycle, redaction, and CLI hardening tests.

All keys, checkpoints, logs, proofs, receipts, trust stores, and trust states are
synthetic and live under pytest's temporary directory. No external transparency
service, cloud KMS, GitHub API, registry, staging system, production endpoint, or
real credential is contacted. Private keys are generated per test and are never
printed or committed.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from backend.app.core.redaction import dump_sanitized_json
from backend.tests.unit.v32_support import (
    T0,
    build_trust_store,
    build_workspace,
    evidence_trust_store,
    make_checkpoint,
    make_head,
)
from tools.release import merkle as M
from tools.release import transparency as T
from tools.release.integrity import CHECKPOINT_FIELDS, IntegrityError, validate_checkpoint
from tools.release.trust import (
    KEY_PURPOSE_EVIDENCE_CHECKPOINT,
    KEY_PURPOSE_TRANSPARENCY_TREE_HEAD,
    SIGNED_CHECKPOINT_DOMAIN,
    SIGNED_CHECKPOINT_PROFILE,
    SIGNED_CHECKPOINT_SCHEMA_VERSION,
    SUPPORTED_KEY_PURPOSES,
    TrustInvalid,
    export_public_key,
    new_trust_store,
    register_public_key,
    validate_trust_store,
    verify_signed_checkpoint,
)
from tools.release.verification import FAIL, PASS

REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture()
def workspace(tmp_path: Path):
    return build_workspace(tmp_path / "hardening space" / "v32", leaf_count=6)


def _provider(workspace, **overrides) -> T.LocalTestAnchorProvider:
    arguments = {
        "provider_id": "local-test-anchor",
        "receipt_dir": workspace.root / "receipts",
        "private_key_path": workspace.tree_head_private_key,
        "key_id": "local-test-provider",
        "tree_head_dir": workspace.root / "provider-heads",
        "proof_dir": workspace.root / "provider-proofs",
    }
    arguments.update(overrides)
    return T.LocalTestAnchorProvider(**arguments)


def _seed_state(
    workspace,
    size: int = 3,
    *,
    updated_at: str = "2026-01-10T00:00:00Z",
) -> Path:
    state_path = workspace.root / "transparency-state.json"
    result = T.verify_tree_head(
        workspace.head(size).to_dict(),
        trust_store_path=workspace.trust_store_path,
        trust_state_path=state_path,
        update_trust_state=True,
        state_updated_at=updated_at,
    )
    assert result.outcome == PASS, result.to_dict()
    assert result.state_update == "updated"
    return state_path


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "tools.transparency_log", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
    )


# ---------------------------------------------------------------------------
# Strict parsing and bounded metadata inputs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        b'{"schema_version":1,"schema_version":1}',
        b'{"a":' + b"[" * 24 + b"0" + b"]" * 24 + b"}",
        b"[]",
        b"{",
        b"\xff\xfe",
        b"",
    ],
)
def test_tree_head_loader_rejects_malformed_or_duplicate_json(tmp_path: Path, payload: bytes):
    path = tmp_path / "tree-head.json"
    path.write_bytes(payload)
    with pytest.raises(T.TransparencyInvalid) as excinfo:
        T.load_tree_head(path)
    assert excinfo.value.reason_code == T.TREE_HEAD_SCHEMA_INVALID


@pytest.mark.parametrize(
    "loader, name",
    [
        (T.load_inclusion_proof, "inclusion.json"),
        (T.load_consistency_proof, "consistency.json"),
        (T.load_receipt, "receipt.json"),
    ],
)
def test_proof_and_receipt_loaders_reject_duplicate_json_fields(tmp_path: Path, loader, name):
    path = tmp_path / name
    path.write_text('{"a":1,"a":2}', encoding="utf-8")
    with pytest.raises(T.TransparencyInvalid):
        loader(path)


def test_transparency_state_loader_rejects_non_object_and_malformed_json(tmp_path: Path):
    for payload in ("[]", '{"schema_version":1,"schema_version":1}', "{"):
        path = tmp_path / "state.json"
        path.write_text(payload, encoding="utf-8")
        with pytest.raises(T.TransparencyInvalid):
            T.load_transparency_state(path)


def test_tree_head_file_size_limit(tmp_path: Path, workspace, monkeypatch):
    path = workspace.head_path(6)
    monkeypatch.setattr(T, "MAX_TREE_HEAD_BYTES", 8)
    with pytest.raises(T.TransparencyInvalid) as excinfo:
        T.load_tree_head(path)
    assert excinfo.value.reason_code == T.TREE_HEAD_SCHEMA_INVALID


def test_proof_file_size_limits(workspace, monkeypatch):
    inclusion_path = workspace.inclusion_path(6, 0)
    consistency_path = workspace.proof_path(3, 6)
    monkeypatch.setattr(T, "MAX_PROOF_BYTES", 8)
    with pytest.raises(T.TransparencyInvalid):
        T.load_inclusion_proof(inclusion_path)
    with pytest.raises(T.TransparencyInvalid):
        T.load_consistency_proof(consistency_path)


def test_receipt_file_size_limit(workspace, monkeypatch):
    provider = _provider(workspace)
    receipt = provider.submit_tree_head(workspace.head(6), timestamp="2026-01-09T00:00:00Z")
    path = workspace.root / "receipt.json"
    T.write_receipt(path, receipt)
    monkeypatch.setattr(T, "MAX_RECEIPT_BYTES", 8)
    with pytest.raises(T.TransparencyInvalid) as excinfo:
        T.load_receipt(path)
    assert excinfo.value.reason_code == T.RECEIPT_SCHEMA_INVALID


def test_transparency_state_size_and_entry_limits(workspace, monkeypatch):
    state_path = _seed_state(workspace, 3)
    monkeypatch.setattr(T, "MAX_TRANSPARENCY_STATE_BYTES", 8)
    with pytest.raises(T.TransparencyInvalid):
        T.load_transparency_state(state_path)

    monkeypatch.undo()
    state = T.load_transparency_state(state_path)
    assert state is not None
    payload = state.to_dict()
    payload["tree_heads"].append(T.transparency_state_entry(workspace.head(2)).to_dict())
    monkeypatch.setattr(T, "MAX_TRANSPARENCY_STATE_ENTRIES", 1)
    with pytest.raises(T.TransparencyInvalid):
        T.validate_transparency_state(payload)


def test_merkle_resource_limits(workspace, monkeypatch):
    monkeypatch.setattr(M, "MAX_MERKLE_LEAVES", 2)
    with pytest.raises(M.MerkleError):
        M.MerkleTree([b"a", b"b", b"c"])

    monkeypatch.undo()
    monkeypatch.setattr(M, "MAX_LEAF_BYTES", 4)
    with pytest.raises(M.MerkleError):
        M.MerkleTree([b"12345"])

    monkeypatch.undo()
    monkeypatch.setattr(M, "MAX_PROOF_SIBLINGS", 1)
    with pytest.raises(M.MerkleError):
        M.InclusionProof.from_dict(workspace.tree(6).inclusion_proof(2).to_dict())

    with pytest.raises(M.MerkleError):
        M.validate_json_depth({"a": {"b": {"c": 1}}}, max_depth=2)


def test_merkle_many_leaf_proofs_remain_consistent():
    leaves = [f"leaf-{index}".encode() for index in range(256)]
    tree = M.MerkleTree(leaves)
    for leaf_index in (0, 1, 127, 128, 254, 255):
        proof = tree.inclusion_proof(leaf_index)
        result = M.verify_inclusion_proof(
            proof.to_dict(),
            expected_root=tree.root,
            expected_tree_size=256,
            leaf_bytes=leaves[leaf_index],
        )
        assert result.outcome == PASS, (leaf_index, result.to_dict())
    for old_size in (0, 1, 127, 128, 255):
        proof = tree.consistency_proof(old_size)
        result = M.verify_consistency_proof(
            proof.to_dict(),
            expected_old_root=M.MerkleTree(leaves[:old_size]).root,
            expected_new_root=tree.root,
            expected_old_tree_size=old_size,
            expected_new_tree_size=256,
        )
        assert result.outcome == PASS, (old_size, result.to_dict())


# ---------------------------------------------------------------------------
# Key lifecycle policy
# ---------------------------------------------------------------------------


def _tree_head_descriptor(workspace):
    return export_public_key(
        private_key_path=workspace.tree_head_private_key,
        key_id="tree-head-1",
    )


def test_tree_head_rejects_expired_key(workspace):
    store = build_trust_store(
        workspace.root / "expired-store.json",
        key_id="tree-head-1",
        descriptor=_tree_head_descriptor(workspace),
        activated_at=T0,
        expires_at="2026-01-02T00:00:00Z",
    )
    result = T.verify_tree_head(workspace.head(3).to_dict(), trust_store_path=store)
    assert result.outcome == FAIL
    assert T.TREE_HEAD_KEY_EXPIRED in result.reason_codes


def test_tree_head_rejects_not_yet_valid_key(workspace):
    store = build_trust_store(
        workspace.root / "future-store.json",
        key_id="tree-head-1",
        descriptor=_tree_head_descriptor(workspace),
        activated_at="2026-02-01T00:00:00Z",
    )
    result = T.verify_tree_head(workspace.head(3).to_dict(), trust_store_path=store)
    assert result.outcome == FAIL
    assert T.TREE_HEAD_KEY_NOT_YET_VALID in result.reason_codes


def test_tree_head_rejects_key_revoked_before_signing(workspace):
    store = build_trust_store(
        workspace.root / "revoked-store.json",
        key_id="tree-head-1",
        descriptor=_tree_head_descriptor(workspace),
        revoked_at="2026-01-02T00:00:00Z",
        reason="test revocation",
    )
    result = T.verify_tree_head(workspace.head(3).to_dict(), trust_store_path=store)
    assert result.outcome == FAIL
    assert T.TREE_HEAD_KEY_REVOKED in result.reason_codes


def test_tree_head_allows_historical_key_with_explicit_policy(workspace):
    store = build_trust_store(
        workspace.root / "historical-store.json",
        key_id="tree-head-1",
        descriptor=_tree_head_descriptor(workspace),
        revoked_at="2026-01-04T00:00:00Z",
        reason="rotated after signing",
    )
    result = T.verify_tree_head(workspace.head(3).to_dict(), trust_store_path=store)
    assert result.outcome == PASS, result.to_dict()
    assert result.trust["status"] == "revoked_historical"
    assert result.trust["historical"] is True


# ---------------------------------------------------------------------------
# Transparency trust-state conflicts
# ---------------------------------------------------------------------------


def _two_head_state(workspace) -> Path:
    state_path = workspace.root / "two-head-state.json"
    first = T.verify_tree_head(
        workspace.head(1).to_dict(),
        trust_store_path=workspace.trust_store_path,
        trust_state_path=state_path,
        update_trust_state=True,
        state_updated_at="2026-01-10T00:00:00Z",
    )
    assert first.outcome == PASS, first.to_dict()
    second = T.verify_tree_head(
        workspace.head(2).to_dict(),
        trust_store_path=workspace.trust_store_path,
        trust_state_path=state_path,
        consistency_proof=workspace.tree(2).consistency_proof(1).to_dict(),
        update_trust_state=True,
        state_updated_at="2026-01-10T00:00:01Z",
    )
    assert second.outcome == PASS, second.to_dict()
    return state_path


def test_state_rejects_duplicate_ids_conflicting_roots_and_tampering(workspace):
    state_path = _two_head_state(workspace)
    state = T.load_transparency_state(state_path)
    assert state is not None
    payload = state.to_dict()

    duplicate = json.loads(json.dumps(payload))
    duplicate["tree_heads"].append(dict(duplicate["tree_heads"][0]))
    with pytest.raises(T.TransparencyInvalid) as duplicate_error:
        T.validate_transparency_state(duplicate)
    assert duplicate_error.value.reason_code == T.TRANSPARENCY_STATE_INVALID

    fake_head = make_head(
        workspace,
        2,
        merkle_root="sha256:" + ("f" * 64),
        timestamp="2026-01-12T00:00:00Z",
    )
    conflicting = json.loads(json.dumps(payload))
    conflicting["tree_heads"].append(T.transparency_state_entry(fake_head).to_dict())
    with pytest.raises(T.TransparencyInvalid) as conflict_error:
        T.validate_transparency_state(conflicting)
    assert conflict_error.value.reason_code == T.TRANSPARENCY_STATE_INVALID

    tampered = json.loads(json.dumps(payload))
    tampered["state_digest"] = "sha256:" + ("0" * 64)
    with pytest.raises(T.TransparencyInvalid):
        T.validate_transparency_state(tampered)

    extra = json.loads(json.dumps(payload))
    extra["unexpected"] = True
    with pytest.raises(T.TransparencyInvalid):
        T.validate_transparency_state(extra)


def test_advance_state_is_idempotent_and_rejects_regressed_update_time(workspace):
    state_path = _seed_state(workspace, 3)
    before = state_path.read_bytes()
    entry = T.transparency_state_entry(workspace.head(3))
    unchanged = T.advance_transparency_state(
        state_path,
        entry,
        updated_at="2026-01-10T00:00:05Z",
    )
    assert unchanged["state_digest"] == T.load_transparency_state(state_path).state_digest
    assert state_path.read_bytes() == before

    newer_same_size = make_head(workspace, 3, timestamp="2026-01-05T00:00:00Z")
    with pytest.raises(T.TransparencyConflict) as excinfo:
        T.advance_transparency_state(
            state_path,
            T.transparency_state_entry(newer_same_size),
            updated_at="2026-01-01T00:00:00Z",
        )
    assert excinfo.value.reason_code == T.TRANSPARENCY_STATE_INVALID
    assert state_path.read_bytes() == before


# ---------------------------------------------------------------------------
# Rollback, replay, split-view, and failed-update behavior
# ---------------------------------------------------------------------------


def test_rollback_replay_conflict_and_timestamp_regression(workspace):
    state_path = _seed_state(workspace, 3)

    replay = T.verify_tree_head(
        workspace.head(3).to_dict(),
        trust_store_path=workspace.trust_store_path,
        trust_state_path=state_path,
    )
    assert replay.outcome == FAIL
    assert T.TREE_HEAD_REPLAY in replay.reason_codes

    rollback = T.verify_tree_head(
        workspace.head(2).to_dict(),
        trust_store_path=workspace.trust_store_path,
        trust_state_path=state_path,
    )
    assert rollback.outcome == FAIL
    assert T.TREE_SIZE_ROLLBACK in rollback.reason_codes

    conflicting_head = make_head(
        workspace,
        3,
        merkle_root="sha256:" + ("f" * 64),
        timestamp="2026-01-05T00:00:00Z",
    )
    conflict = T.verify_tree_head(
        conflicting_head.to_dict(),
        trust_store_path=workspace.trust_store_path,
        trust_state_path=state_path,
    )
    assert conflict.outcome == FAIL
    assert T.TREE_ROOT_CONFLICT in conflict.reason_codes

    timestamp_regression = make_head(
        workspace,
        4,
        timestamp="2026-01-01T00:00:00Z",
    )
    regression = T.verify_tree_head(
        timestamp_regression.to_dict(),
        trust_store_path=workspace.trust_store_path,
        trust_state_path=state_path,
    )
    assert regression.outcome == FAIL
    assert T.TREE_HEAD_TIMESTAMP_REGRESSION in regression.reason_codes

    missing_proof = T.verify_tree_head(
        workspace.head(4).to_dict(),
        trust_store_path=workspace.trust_store_path,
        trust_state_path=state_path,
    )
    assert missing_proof.outcome == FAIL
    assert T.CONSISTENCY_PROOF_MISSING in missing_proof.reason_codes

    wrong_proof = T.verify_tree_head(
        workspace.head(4).to_dict(),
        trust_store_path=workspace.trust_store_path,
        trust_state_path=state_path,
        consistency_proof=workspace.tree(4).consistency_proof(2).to_dict(),
    )
    assert wrong_proof.outcome == FAIL
    assert wrong_proof.reason_codes


def test_failed_verification_never_overwrites_trust_state(workspace):
    state_path = _seed_state(workspace, 3)
    before = state_path.read_bytes()

    tampered = workspace.head(4).to_dict()
    tampered["signature"] = "0" * 128
    result = T.verify_tree_head(
        tampered,
        trust_store_path=workspace.trust_store_path,
        trust_state_path=state_path,
        update_trust_state=True,
        state_updated_at="2026-01-10T00:00:09Z",
    )
    assert result.outcome == FAIL
    assert result.state_update == "refused_after_failure"
    assert state_path.read_bytes() == before


def test_update_without_state_path_fails_closed(workspace):
    result = T.verify_tree_head(
        workspace.head(3).to_dict(),
        trust_store_path=workspace.trust_store_path,
        update_trust_state=True,
    )
    assert result.outcome == FAIL
    assert T.TRANSPARENCY_STATE_MISSING in result.reason_codes
    assert result.state_update == "failed"


def test_detect_split_view_and_rollback_against_state(workspace):
    state_path = _seed_state(workspace, 3)
    state = T.load_transparency_state(state_path)
    assert state is not None

    clean = T.detect_split_view([workspace.head(3)], state=state)
    assert clean.outcome == PASS, clean.to_dict()

    conflicting_head = make_head(
        workspace,
        3,
        merkle_root="sha256:" + ("f" * 64),
        timestamp="2026-01-05T00:00:00Z",
    )
    split = T.detect_split_view([workspace.head(3), conflicting_head], state=state)
    assert split.outcome == FAIL
    assert split.reason_code == T.TREE_ROOT_CONFLICT

    rolled_back = T.detect_split_view([workspace.head(2)], state=state)
    assert rolled_back.outcome == FAIL
    assert rolled_back.reason_code == T.TREE_SIZE_ROLLBACK


# ---------------------------------------------------------------------------
# V30/V31 regressions and trust-purpose boundary
# ---------------------------------------------------------------------------


def test_v30_unsigned_checkpoint_contract_unchanged(workspace):
    unsigned = {
        "schema_version": 1,
        "record_count": 1,
        "final_record_hash": "sha256:" + ("a" * 64),
        "final_event_id": "evt-1",
        "final_timestamp": T0,
        "source": None,
    }
    normalized = validate_checkpoint(unsigned)
    assert normalized["schema_version"] == 1
    assert set(normalized) == set(CHECKPOINT_FIELDS)
    with pytest.raises(IntegrityError):
        validate_checkpoint(workspace.checkpoints[-1])


def test_v31_signed_checkpoint_contract_and_trust_purpose_unchanged(workspace):
    assert SIGNED_CHECKPOINT_SCHEMA_VERSION == 2
    assert SIGNED_CHECKPOINT_PROFILE == "evidence_checkpoint_signed"
    assert SIGNED_CHECKPOINT_DOMAIN == b"industrial-vision-platform:evidence-checkpoint:v1\x00"
    assert set(SUPPORTED_KEY_PURPOSES) == {
        KEY_PURPOSE_EVIDENCE_CHECKPOINT,
        KEY_PURPOSE_TRANSPARENCY_TREE_HEAD,
    }

    verification = verify_signed_checkpoint(
        workspace.checkpoints[-1],
        trust_store_path=evidence_trust_store(workspace),
    )
    checks = {check.name: check for check in verification.checks}
    for name in (
        "signed-checkpoint-schema",
        "signed-checkpoint-id",
        "signed-checkpoint-payload-digest",
        "signed-checkpoint-algorithm",
        "trust-key-purpose",
        "signed-checkpoint-signature",
    ):
        assert checks[name].outcome == PASS, checks[name].to_dict()
    assert verification.outcome == FAIL
    assert "CHECKPOINT_MANIFEST_MISSING" in verification.reason_codes


def test_trust_store_rejects_unknown_purpose(workspace):
    store = new_trust_store()
    store = register_public_key(
        store,
        _tree_head_descriptor(workspace),
        purpose=KEY_PURPOSE_TRANSPARENCY_TREE_HEAD,
        activated_at=T0,
    )
    payload = store.to_dict()
    payload["keys"][0]["purpose"] = "unsupported_purpose"
    with pytest.raises(TrustInvalid) as excinfo:
        validate_trust_store(payload)
    assert excinfo.value.reason_code == "TRUST_KEY_PURPOSE_INVALID"


# ---------------------------------------------------------------------------
# Redaction and private-key non-disclosure
# ---------------------------------------------------------------------------


def test_tree_head_results_redact_secrets_and_private_keys(workspace):
    result = T.verify_tree_head(
        workspace.head(6).to_dict(),
        trust_store_path=workspace.trust_store_path,
    )
    assert result.outcome == PASS
    result.limitations.append("password=hunter2 token=supersecretvalue")
    document = dump_sanitized_json(result.to_dict())
    assert "hunter2" not in document
    assert "supersecretvalue" not in document
    assert "PRIVATE KEY" not in document
    assert "private_key" not in document
    assert workspace.tree_head_private_key.read_text(encoding="utf-8") not in document


def test_receipt_results_redact_secrets_and_private_keys(workspace):
    provider = _provider(workspace)
    receipt = provider.submit_tree_head(workspace.head(6), timestamp="2026-01-09T00:00:00Z")
    result = provider.verify_receipt(receipt, tree_head=workspace.head(6))
    assert result.outcome == PASS
    result.limitations.append("api_key=abcd1234")
    document = dump_sanitized_json(result.to_dict())
    assert "abcd1234" not in document
    assert "PRIVATE KEY" not in document
    assert "private_key" not in document
    assert workspace.tree_head_private_key.read_text(encoding="utf-8") not in document


def test_status_report_redacts_and_never_claims_external_anchoring(workspace):
    report = T.build_status_report(log_path=workspace.log_path)
    document = dump_sanitized_json(report)
    assert "PRIVATE KEY" not in document
    assert "private_key" not in document
    assert workspace.tree_head_private_key.read_text(encoding="utf-8") not in document
    assert report["external_anchoring"] is False
    assert report["external_anchor"] == T.ANCHOR_NOT_CONFIGURED


# ---------------------------------------------------------------------------
# Cross-platform paths and line endings
# ---------------------------------------------------------------------------


def test_paths_with_spaces_and_unicode_round_trip(tmp_path: Path):
    workspace = build_workspace(tmp_path / "path with spaces" / "unicode ü" / "v32", leaf_count=6)
    assert T.verify_log(workspace.log_path).outcome == PASS
    head_path = workspace.head_path(6)
    assert T.load_tree_head(head_path).tree_head_id == workspace.head(6).tree_head_id

    provider = _provider(workspace)
    receipt = provider.submit_tree_head(workspace.head(6), timestamp="2026-01-09T00:00:00Z")
    receipt_path = workspace.root / "receipt copy.json"
    T.write_receipt(receipt_path, receipt)
    assert T.load_receipt(receipt_path) == receipt

    inclusion_path = workspace.inclusion_path(6, 0)
    assert T.load_inclusion_proof(inclusion_path).tree_size == 6
    consistency_path = workspace.proof_path(3, 6)
    assert T.load_consistency_proof(consistency_path).new_tree_size == 6


def test_crlf_log_is_rejected_on_every_platform(workspace):
    original = workspace.log_path.read_bytes()
    workspace.log_path.write_bytes(original.replace(b"\n", b"\r\n"))
    with pytest.raises(T.TransparencyInvalid) as excinfo:
        T.read_log(workspace.log_path)
    assert excinfo.value.reason_code == T.TRANSPARENCY_LOG_SCHEMA_INVALID
    assert T.verify_log(workspace.log_path).outcome == FAIL


def test_empty_log_has_documented_empty_root(tmp_path: Path):
    path = tmp_path / "empty log.jsonl"
    header = T.init_log(path, log_id="empty-log", timestamp=T0)
    assert header.log_id == "empty-log"
    result = T.verify_log(path)
    assert result.outcome == PASS
    assert result.tree_size == 0
    assert result.merkle_root == T.EMPTY_ROOT


# ---------------------------------------------------------------------------
# Provider idempotency and conflict behavior
# ---------------------------------------------------------------------------


def test_provider_idempotency_and_conflicting_tree_head(workspace):
    provider = _provider(workspace)
    first = provider.submit_tree_head(workspace.head(6), timestamp="2026-01-09T00:00:00Z")
    same = provider.submit_tree_head(workspace.head(6), timestamp="2026-01-09T00:00:00Z")
    assert same == first

    later = provider.submit_tree_head(workspace.head(6), timestamp="2026-01-09T00:00:01Z")
    assert later.receipt_id != first.receipt_id
    assert provider.retrieve_receipt(later.receipt_id) == later

    conflicting_head = make_head(
        workspace,
        6,
        merkle_root="sha256:" + ("f" * 64),
        timestamp="2026-01-09T00:00:02Z",
    )
    with pytest.raises(T.ProviderUnavailable):
        provider.submit_tree_head(conflicting_head, timestamp="2026-01-09T00:00:03Z")
    stored = provider.retrieve_anchored_tree_head(log_id=workspace.log.log_id, tree_size=6)
    assert stored.tree_head_id == workspace.head(6).tree_head_id


def test_receipt_freshness_boundaries(workspace):
    provider = _provider(workspace)
    receipt = provider.submit_tree_head(workspace.head(6), timestamp="2026-01-09T00:00:00Z")

    exactly_old = T.verify_receipt(receipt, now="2026-01-16T00:00:00Z")
    assert exactly_old.outcome == PASS, exactly_old.to_dict()

    stale = T.verify_receipt(receipt, now="2026-01-16T00:00:01Z")
    assert stale.outcome == FAIL
    assert T.RECEIPT_STALE in stale.reason_codes

    exactly_future = T.verify_receipt(receipt, now="2026-01-08T23:55:00Z")
    assert exactly_future.outcome == PASS, exactly_future.to_dict()

    too_future = T.verify_receipt(receipt, now="2026-01-08T23:54:59Z")
    assert too_future.outcome == FAIL
    assert T.RECEIPT_TIMESTAMP_INVALID in too_future.reason_codes

    with pytest.raises(T.TransparencyInvalid):
        T.verify_receipt(receipt, now="not-a-timestamp")


# ---------------------------------------------------------------------------
# CLI exit-code contract and no-update-after-failure
# ---------------------------------------------------------------------------


def test_cli_basic_exit_codes_and_provider_status(workspace):
    new_log = workspace.root / "cli-new.jsonl"
    created = _run_cli(
        "init-log",
        "--log",
        str(new_log),
        "--log-id",
        "cli-log",
        "--timestamp",
        T0,
        "--json",
    )
    assert created.returncode == 0, created.stderr

    assert _run_cli("verify-log", "--log", str(workspace.log_path), "--json").returncode == 0
    assert _run_cli("verify-log", "--log", str(workspace.root / "missing.jsonl"), "--json").returncode == 2
    assert _run_cli("verify-log").returncode == 4
    assert _run_cli("bogus-command").returncode == 4
    assert _run_cli("init-log", "--log", str(workspace.log_path), "--timestamp", T0).returncode == 1

    unconfigured = _run_cli("provider-status", "--provider", "none", "--json")
    assert unconfigured.returncode == 2
    assert json.loads(unconfigured.stdout)["anchor_status"] == "NOT_CONFIGURED"

    missing_provider = _run_cli(
        "anchor-tree-head",
        "--tree-head",
        str(workspace.head_path(6)),
        "--json",
    )
    assert missing_provider.returncode == 2
    assert json.loads(missing_provider.stdout)["anchor_status"] == "NOT_CONFIGURED"
    assert json.loads(missing_provider.stdout)["external_anchoring"] is False


def test_cli_tree_head_verification_and_state_never_updates_after_failure(workspace):
    head_path = workspace.head_path(6)
    state_path = workspace.root / "cli-state.json"
    base = [
        "verify-tree-head",
        "--tree-head",
        str(head_path),
        "--trust-store",
        str(workspace.trust_store_path),
        "--trust-state",
        str(state_path),
    ]
    first = _run_cli(
        *base,
        "--update-trust-state",
        "--state-updated-at",
        "2026-01-10T00:00:00Z",
        "--json",
    )
    assert first.returncode == 0, first.stderr
    payload = json.loads(first.stdout)
    assert payload["outcome"] == PASS
    assert payload["state_update"] == "updated"
    assert payload["external_anchoring"] is False
    before = state_path.read_bytes()

    tampered = workspace.head(6).to_dict()
    tampered["signature"] = "0" * 128
    tampered_path = workspace.root / "tampered-head.json"
    tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
    failed = _run_cli(
        "verify-tree-head",
        "--tree-head",
        str(tampered_path),
        "--trust-store",
        str(workspace.trust_store_path),
        "--trust-state",
        str(state_path),
        "--update-trust-state",
        "--state-updated-at",
        "2026-01-10T00:00:01Z",
        "--json",
    )
    assert failed.returncode == 1
    assert state_path.read_bytes() == before
    assert "not updated" in failed.stderr
    assert json.loads(failed.stdout)["state_update"] == "refused_after_failure"

    replay = _run_cli(
        *base,
        "--update-trust-state",
        "--state-updated-at",
        "2026-01-10T00:00:02Z",
        "--json",
    )
    assert replay.returncode == 1
    assert state_path.read_bytes() == before

    no_trust = _run_cli("verify-tree-head", "--tree-head", str(head_path), "--json")
    assert no_trust.returncode == 2
    assert T.TREE_HEAD_TRUST_STORE_MISSING in json.loads(no_trust.stdout)["reason_codes"]

    no_state_path = _run_cli(
        "verify-tree-head",
        "--tree-head",
        str(head_path),
        "--trust-store",
        str(workspace.trust_store_path),
        "--update-trust-state",
        "--json",
    )
    assert no_state_path.returncode == 4


def test_cli_proof_and_receipt_verification(workspace):
    root = workspace.tree(6).root
    inclusion_path = workspace.inclusion_path(6, 2)
    leaf_path = workspace.root / "leaf bytes.bin"
    leaf_path.write_bytes(workspace.log.entries[2].canonical_bytes())
    inclusion_ok = _run_cli(
        "verify-inclusion",
        "--proof",
        str(inclusion_path),
        "--expected-root",
        root,
        "--log-id",
        workspace.log.log_id,
        "--tree-size",
        "6",
        "--leaf",
        str(leaf_path),
        "--json",
    )
    assert inclusion_ok.returncode == 0, inclusion_ok.stderr
    assert json.loads(inclusion_ok.stdout)["outcome"] == PASS

    inclusion_bad = _run_cli(
        "verify-inclusion",
        "--proof",
        str(inclusion_path),
        "--expected-root",
        "sha256:" + ("0" * 64),
        "--json",
    )
    assert inclusion_bad.returncode == 1

    missing_proof = _run_cli(
        "verify-inclusion",
        "--proof",
        str(workspace.root / "missing-proof.json"),
        "--expected-root",
        root,
        "--json",
    )
    assert missing_proof.returncode == 2

    consistency_path = workspace.proof_path(3, 6)
    consistency_ok = _run_cli(
        "verify-consistency",
        "--proof",
        str(consistency_path),
        "--expected-old-root",
        workspace.tree(3).root,
        "--expected-new-root",
        root,
        "--log-id",
        workspace.log.log_id,
        "--old-tree-size",
        "3",
        "--new-tree-size",
        "6",
        "--json",
    )
    assert consistency_ok.returncode == 0, consistency_ok.stderr

    consistency_bad = _run_cli(
        "verify-consistency",
        "--proof",
        str(consistency_path),
        "--expected-old-root",
        workspace.tree(3).root,
        "--expected-new-root",
        "sha256:" + ("1" * 64),
        "--json",
    )
    assert consistency_bad.returncode == 1

    provider = _provider(workspace)
    receipt = provider.submit_tree_head(workspace.head(6), timestamp="2026-01-09T00:00:00Z")
    receipt_path = workspace.root / "cli-receipt.json"
    T.write_receipt(receipt_path, receipt)
    receipt_ok = _run_cli(
        "verify-receipt",
        "--receipt",
        str(receipt_path),
        "--tree-head",
        str(workspace.head_path(6)),
        "--provider-id",
        "local-test-anchor",
        "--provider-fingerprint",
        provider.fingerprint,
        "--now",
        "2026-01-10T00:00:00Z",
        "--json",
    )
    assert receipt_ok.returncode == 0, receipt_ok.stderr
    receipt_payload = json.loads(receipt_ok.stdout)
    assert receipt_payload["anchor_status"] == "SIMULATED"
    assert receipt_payload["external_anchoring"] is False

    receipt_bad = _run_cli(
        "verify-receipt",
        "--receipt",
        str(receipt_path),
        "--tree-head",
        str(workspace.head_path(5)),
        "--now",
        "2026-01-10T00:00:00Z",
        "--json",
    )
    assert receipt_bad.returncode == 1

    missing_receipt = _run_cli(
        "verify-receipt",
        "--receipt",
        str(workspace.root / "missing-receipt.json"),
        "--json",
    )
    assert missing_receipt.returncode == 2


def test_cli_anchor_provider_and_status_report(workspace):
    provider_status = _run_cli(
        "provider-status",
        "--provider",
        "local-test",
        "--provider-key",
        str(workspace.tree_head_private_key),
        "--receipt-dir",
        str(workspace.root / "cli-receipts"),
        "--json",
    )
    assert provider_status.returncode == 0, provider_status.stderr
    status_payload = json.loads(provider_status.stdout)
    assert status_payload["anchor_status"] == "SIMULATED"
    assert status_payload["external_anchoring"] is False

    anchored = _run_cli(
        "anchor-tree-head",
        "--tree-head",
        str(workspace.head_path(6)),
        "--provider-key",
        str(workspace.tree_head_private_key),
        "--receipt-dir",
        str(workspace.root / "cli-receipts"),
        "--timestamp",
        "2026-01-09T00:00:05Z",
        "--json",
    )
    assert anchored.returncode == 0, anchored.stderr
    anchored_payload = json.loads(anchored.stdout)
    assert anchored_payload["anchor_status"] == "SIMULATED"
    assert anchored_payload["assurance"] == "simulated"
    assert anchored_payload["external_anchoring"] is False
    assert anchored_payload["receipt"]["anchor_status"] == "SIMULATED"
    receipt_path = workspace.root / "cli-receipts" / f"{anchored_payload['receipt']['receipt_id']}.json"
    assert receipt_path.is_file()

    report = _run_cli("status", "--log", str(workspace.log_path), "--json")
    assert report.returncode == 0, report.stderr
    report_payload = json.loads(report.stdout)
    assert report_payload["outcome"] == PASS
    assert report_payload["assurance"] == "local-only"
    assert report_payload["external_anchor"] == "NOT_CONFIGURED"
    assert report_payload["external_anchoring"] is False
    assert report_payload["provider"]["anchor_status"] == "NOT_CONFIGURED"

    full_report = _run_cli(
        "status",
        "--log",
        str(workspace.log_path),
        "--tree-head",
        str(workspace.head_path(6)),
        "--receipt",
        str(receipt_path),
        "--trust-store",
        str(workspace.trust_store_path),
        "--provider",
        "local-test",
        "--provider-key",
        str(workspace.tree_head_private_key),
        "--receipt-dir",
        str(workspace.root / "cli-receipts"),
        "--now",
        "2026-01-10T00:00:00Z",
        "--json",
    )
    assert full_report.returncode == 0, full_report.stderr
    full_payload = json.loads(full_report.stdout)
    assert full_payload["outcome"] == PASS
    assert full_payload["assurance"] == "simulated"
    assert full_payload["external_anchoring"] is False


def test_cli_create_artifacts_append_and_failure_paths(workspace):
    head_output = workspace.root / "cli-tree-head.json"
    created = _run_cli(
        "create-tree-head",
        "--log",
        str(workspace.log_path),
        "--private-key",
        str(workspace.tree_head_private_key),
        "--key-id",
        "tree-head-1",
        "--output",
        str(head_output),
        "--timestamp",
        "2026-01-09T00:00:00Z",
        "--json",
    )
    assert created.returncode == 0, created.stderr
    assert head_output.is_file()
    assert "PRIVATE KEY" not in created.stdout
    assert workspace.tree_head_private_key.read_text(encoding="utf-8") not in created.stdout
    assert T.load_tree_head(head_output).tree_size == 6

    inclusion_output = workspace.root / "cli-inclusion.json"
    inclusion = _run_cli(
        "create-inclusion-proof",
        "--log",
        str(workspace.log_path),
        "--leaf-index",
        "1",
        "--output",
        str(inclusion_output),
        "--json",
    )
    assert inclusion.returncode == 0, inclusion.stderr
    assert T.load_inclusion_proof(inclusion_output).leaf_index == 1

    consistency_output = workspace.root / "cli-consistency.json"
    consistency = _run_cli(
        "create-consistency-proof",
        "--log",
        str(workspace.log_path),
        "--old-tree-size",
        "3",
        "--output",
        str(consistency_output),
        "--json",
    )
    assert consistency.returncode == 0, consistency.stderr
    assert T.load_consistency_proof(consistency_output).old_tree_size == 3

    checkpoint = make_checkpoint(workspace, 7)
    checkpoint_path = workspace.root / "checkpoint-7.json"
    from tools.release.trust import write_signed_checkpoint

    write_signed_checkpoint(checkpoint_path, checkpoint)
    appended = _run_cli(
        "append-checkpoint",
        "--log",
        str(workspace.log_path),
        "--checkpoint",
        str(checkpoint_path),
        "--timestamp",
        "2026-01-07T00:00:01Z",
        "--json",
    )
    assert appended.returncode == 0, appended.stderr
    assert T.verify_log(workspace.log_path).tree_size == 7

    unsigned_path = workspace.root / "unsigned-checkpoint.json"
    unsigned_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "record_count": 1,
                "final_record_hash": "sha256:" + ("a" * 64),
                "final_event_id": "evt-1",
                "final_timestamp": T0,
                "source": None,
            }
        ),
        encoding="utf-8",
    )
    rejected = _run_cli(
        "append-checkpoint",
        "--log",
        str(workspace.log_path),
        "--checkpoint",
        str(unsigned_path),
        "--timestamp",
        "2026-01-08T00:00:01Z",
    )
    assert rejected.returncode == 1
    assert "error:" in rejected.stderr

    missing_key = _run_cli(
        "create-tree-head",
        "--log",
        str(workspace.log_path),
        "--private-key",
        str(workspace.root / "missing.key"),
        "--key-id",
        "tree-head-1",
        "--output",
        str(workspace.root / "missing-head.json"),
    )
    assert missing_key.returncode == 2
