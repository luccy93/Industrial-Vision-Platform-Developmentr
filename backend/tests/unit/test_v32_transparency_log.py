"""V32 Merkle-tree, transparency-log, and signed-tree-head tests.

All keys, checkpoints, logs, tree heads, and trust stores are synthetic and live
under pytest's temporary directory. No network service, cloud KMS, registry,
release endpoint, or real credential is contacted. Private keys are generated
per test and are never printed or committed.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from backend.app.core.redaction import dump_sanitized_json
from backend.tests.unit.v32_support import (
    T0,
    build_trust_store,
    build_workspace,
    evidence_trust_store,
    make_head,
)
from tools.release import transparency as T
from tools.release.merkle import (
    EMPTY_ROOT,
    MAX_LEAF_BYTES,
    MerkleError,
    MerkleTree,
    leaf_digest,
    leaf_hash,
    node_hash,
)
from tools.release.trust import (
    KEY_PURPOSE_EVIDENCE_CHECKPOINT,
    KEY_PURPOSE_TRANSPARENCY_TREE_HEAD,
    export_public_key,
    verify_signed_checkpoint,
)
from tools.release.verification import FAIL, PASS, UNAVAILABLE

REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture()
def workspace(tmp_path: Path):
    return build_workspace(tmp_path / "space dir" / "v32")


def _read_schema(name: str) -> dict:
    return json.loads((REPO_ROOT / "release" / name).read_text(encoding="utf-8"))


def _rewrite_log(path: Path, lines: list[bytes], *, final_newline: bool = True) -> None:
    data = b"\n".join(lines)
    if final_newline:
        data += b"\n"
    path.write_bytes(data)


def test_empty_root_and_domain_separation():
    assert EMPTY_ROOT == "sha256:" + hashlib.sha256(b"").hexdigest()
    assert MerkleTree([]).root == EMPTY_ROOT
    assert leaf_hash(b"leaf") == hashlib.sha256(b"\x00leaf").digest()
    assert leaf_digest(b"leaf") == "sha256:" + hashlib.sha256(b"\x00leaf").hexdigest()
    assert node_hash(b"a" * 32, b"b" * 32) == hashlib.sha256(b"\x01" + b"a" * 32 + b"b" * 32).digest()
    assert MerkleTree([b"leaf"]).root == leaf_digest(b"leaf")


def test_single_odd_non_power_of_two_and_duplicate_leaves_are_deterministic():
    single = MerkleTree([b"only"])
    assert single.root == leaf_digest(b"only")

    for count in (3, 5, 7, 9):
        leaves = [f"leaf-{index}".encode() for index in range(count)]
        first = MerkleTree(leaves).root
        second = MerkleTree(leaves).root
        assert first == second

    duplicate_a = MerkleTree([b"same", b"same", b"tail"]).root
    duplicate_b = MerkleTree([b"same", b"same", b"tail"]).root
    assert duplicate_a == duplicate_b
    assert MerkleTree([b"a", b"b"]).root != MerkleTree([b"b", b"a"]).root
    assert MerkleTree([b"a", b"b"]).root != MerkleTree([b"a", b"a"]).root


def test_leaf_size_and_leaf_type_validation():
    with pytest.raises(MerkleError):
        MerkleTree([b"x" * (MAX_LEAF_BYTES + 1)])
    with pytest.raises(MerkleError):
        MerkleTree(["not-bytes"])  # type: ignore[list-item]
    with pytest.raises(MerkleError):
        MerkleTree(b"not-a-sequence")


def test_log_append_verify_and_stable_root(workspace):
    result = T.verify_log(workspace.log_path)
    assert result.outcome == PASS
    assert result.tree_size == 3
    assert result.merkle_root == workspace.log.merkle_root
    assert result.head_entry_digest == workspace.log.entries[-1].digest()
    assert [entry.entry_index for entry in workspace.log.entries] == [0, 1, 2]
    assert workspace.log.entries[0].previous_entry_digest == T.TRANSPARENCY_LOG_GENESIS_PREVIOUS
    assert workspace.log.entries[1].previous_entry_digest == workspace.log.entries[0].digest()
    assert len({entry.entry_id for entry in workspace.log.entries}) == 3
    assert len({entry.checkpoint_id for entry in workspace.log.entries}) == 3

    # Re-reading the same bytes produces the same root and entry digests.
    reread = T.read_log(workspace.log_path)
    assert reread.merkle_root == workspace.log.merkle_root
    assert [entry.digest() for entry in reread.entries] == [entry.digest() for entry in workspace.log.entries]


def test_log_header_and_entry_schemas(workspace):
    header_schema = _read_schema("transparency-log-header.schema.json")
    entry_schema = _read_schema("transparency-log-entry.schema.json")
    Draft202012Validator.check_schema(header_schema)
    Draft202012Validator.check_schema(entry_schema)
    Draft202012Validator(header_schema).validate(workspace.log.header.to_dict())
    for entry in workspace.log.entries:
        Draft202012Validator(entry_schema).validate(entry.to_dict())

    extra_header = workspace.log.header.to_dict()
    extra_header["unexpected"] = True
    assert list(Draft202012Validator(header_schema).iter_errors(extra_header))
    extra_entry = workspace.log.entries[0].to_dict()
    extra_entry["unexpected"] = True
    assert list(Draft202012Validator(entry_schema).iter_errors(extra_entry))


@pytest.mark.parametrize(
    "mutation",
    [
        "reorder",
        "duplicate-entry",
        "duplicate-checkpoint",
        "tamper-digest",
        "blank-line",
        "truncate-final-newline",
        "crlf",
    ],
)
def test_log_rejects_malformed_or_tampered_entries(workspace, mutation):
    lines = workspace.log_path.read_bytes().split(b"\n")[:-1]
    if mutation == "reorder":
        lines = [lines[0], lines[2], lines[1], lines[3]]
        _rewrite_log(workspace.log_path, lines)
    elif mutation == "duplicate-entry":
        lines = [*lines, lines[1]]
        _rewrite_log(workspace.log_path, lines)
    elif mutation == "duplicate-checkpoint":
        entry = json.loads(lines[2])
        entry["entry_index"] = 3
        entry["previous_entry_digest"] = workspace.log.entries[2].digest()
        entry["entry_id"] = T.derive_log_entry_id(entry)
        lines = [*lines, json.dumps(entry, sort_keys=True).encode()]
        _rewrite_log(workspace.log_path, lines)
    elif mutation == "tamper-digest":
        entry = json.loads(lines[1])
        entry["checkpoint_digest"] = "sha256:" + ("e" * 64)
        lines[1] = json.dumps(entry, sort_keys=True).encode()
        _rewrite_log(workspace.log_path, lines)
    elif mutation == "blank-line":
        lines = [lines[0], b"", *lines[1:]]
        _rewrite_log(workspace.log_path, lines)
    elif mutation == "truncate-final-newline":
        _rewrite_log(workspace.log_path, lines, final_newline=False)
    elif mutation == "crlf":
        workspace.log_path.write_bytes(workspace.log_path.read_bytes().replace(b"\n", b"\r\n"))

    result = T.verify_log(workspace.log_path)
    assert result.outcome == FAIL, result.to_dict()
    assert result.reason_codes


def test_append_rejects_sequence_timestamp_and_log_regressions(workspace):
    checkpoint = workspace.checkpoints[-1]
    with pytest.raises(T.TransparencyConflict) as sequence_error:
        T.append_checkpoint(
            workspace.log_path,
            workspace.root / "checkpoint-3.json",
            timestamp="2026-01-10T00:00:00Z",
        )
    assert sequence_error.value.reason_code == T.TRANSPARENCY_LOG_SEQUENCE_INVALID
    assert checkpoint["checkpoint_sequence"] == 3

    with pytest.raises(T.TransparencyConflict) as timestamp_error:
        T.append_checkpoint(
            workspace.log_path,
            workspace.root / "checkpoint-3.json",
            timestamp="2026-01-01T00:00:00Z",
        )
    assert timestamp_error.value.reason_code == T.TRANSPARENCY_LOG_TIMESTAMP_INVALID

    with pytest.raises(T.TransparencyConflict) as log_id_error:
        T.append_checkpoint(
            workspace.log_path,
            workspace.root / "checkpoint-3.json",
            log_id="different-log",
            timestamp="2026-01-10T00:00:00Z",
        )
    assert log_id_error.value.reason_code == T.TRANSPARENCY_LOG_HEADER_INVALID


def test_log_resource_limits(workspace, monkeypatch):
    monkeypatch.setattr(T, "MAX_LOG_BYTES", 10)
    result = T.verify_log(workspace.log_path)
    assert result.outcome == FAIL
    assert T.TRANSPARENCY_LOG_TOO_LARGE in result.reason_codes

    monkeypatch.setattr(T, "MAX_LOG_BYTES", 64 * 1024 * 1024)
    monkeypatch.setattr(T, "MAX_LOG_LINE_BYTES", 10)
    result = T.verify_log(workspace.log_path)
    assert result.outcome == FAIL
    assert T.TRANSPARENCY_LOG_HEADER_INVALID in result.reason_codes

    monkeypatch.setattr(T, "MAX_LOG_LINE_BYTES", 64 * 1024)
    monkeypatch.setattr(T, "MAX_LOG_ENTRIES", 1)
    result = T.verify_log(workspace.log_path)
    assert result.outcome == FAIL
    assert T.TRANSPARENCY_LOG_TOO_LARGE in result.reason_codes


def test_tree_head_verifies_against_v31_trust_store_and_state(workspace):
    state_path = workspace.root / "transparency-state.json"
    result = T.verify_tree_head(
        workspace.head(3).to_dict(),
        trust_store_path=workspace.trust_store_path,
        trust_state_path=state_path,
        update_trust_state=True,
        state_updated_at="2026-01-10T00:00:00Z",
    )
    assert result.outcome == PASS, result.to_dict()
    assert result.assurance == "reduced"
    assert result.to_dict()["external_anchoring"] is False
    assert result.state_update == "updated"
    assert state_path.is_file()
    state = T.load_transparency_state(state_path)
    assert state is not None
    assert len(state.entries) == 1
    assert state.entries[0].tree_head_id == workspace.head(3).tree_head_id
    assert state.entries[0].tree_head_digest == workspace.head(3).document_digest()


def test_tree_head_without_trust_material_is_unavailable(workspace):
    result = T.verify_tree_head(workspace.head(3).to_dict())
    assert result.outcome == UNAVAILABLE
    assert T.TREE_HEAD_TRUST_STORE_MISSING in result.reason_codes


def test_tree_head_fingerprint_pin_and_wrong_pin(workspace):
    pinned = T.verify_tree_head(
        workspace.head(3).to_dict(),
        trusted_key_fingerprint=workspace.tree_head_info["fingerprint"],
    )
    assert pinned.outcome == PASS, pinned.to_dict()
    assert pinned.trust["source"] == "fingerprint_pin"

    wrong = T.verify_tree_head(
        workspace.head(3).to_dict(),
        trusted_key_fingerprint="sha256:" + ("0" * 64),
    )
    assert wrong.outcome == FAIL
    assert T.TREE_HEAD_KEY_UNTRUSTED in wrong.reason_codes


def test_tree_head_wrong_purpose_and_unknown_key(workspace):
    tree_head_descriptor = export_public_key(
        private_key_path=workspace.tree_head_private_key, key_id="tree-head-1"
    )
    wrong_purpose_store = build_trust_store(
        workspace.root / "wrong-purpose-store.json",
        key_id="tree-head-1",
        descriptor=tree_head_descriptor,
        purpose=KEY_PURPOSE_EVIDENCE_CHECKPOINT,
    )
    wrong_purpose = T.verify_tree_head(workspace.head(3).to_dict(), trust_store_path=wrong_purpose_store)
    assert wrong_purpose.outcome == FAIL
    assert T.TREE_HEAD_KEY_PURPOSE_INVALID in wrong_purpose.reason_codes

    # A key with the right purpose but a different key_id is unknown.
    head = make_head(workspace, 3, key_id="unknown-tree-head")
    unknown = T.verify_tree_head(head.to_dict(), trust_store_path=workspace.trust_store_path)
    assert unknown.outcome == FAIL
    assert T.TREE_HEAD_KEY_UNKNOWN in unknown.reason_codes


def test_tree_head_tampering_and_unsupported_algorithms(workspace):
    tampered_signature = workspace.head(3).to_dict()
    tampered_signature["signature"] = "0" * 128
    signature_result = T.verify_tree_head(tampered_signature, trust_store_path=workspace.trust_store_path)
    assert signature_result.outcome == FAIL
    assert T.TREE_HEAD_SIGNATURE_MISMATCH in signature_result.reason_codes

    tampered_payload = workspace.head(3).to_dict()
    tampered_payload["merkle_root"] = "sha256:" + ("f" * 64)
    payload_result = T.verify_tree_head(tampered_payload, trust_store_path=workspace.trust_store_path)
    assert payload_result.outcome == FAIL
    assert T.TREE_HEAD_ID_MISMATCH in payload_result.reason_codes

    tampered_digest = workspace.head(3).to_dict()
    tampered_digest["payload_digest"] = "sha256:" + ("f" * 64)
    digest_result = T.verify_tree_head(tampered_digest, trust_store_path=workspace.trust_store_path)
    assert digest_result.outcome == FAIL
    assert T.TREE_HEAD_PAYLOAD_DIGEST_MISMATCH in digest_result.reason_codes

    unknown_algorithm = workspace.head(3).to_dict()
    unknown_algorithm["signature_algorithm"] = "rsa-pss"
    unknown_algorithm["tree_head_id"] = T.derive_tree_head_id(unknown_algorithm)
    unknown_algorithm["payload_digest"] = T.tree_head_payload_digest(
        {field: unknown_algorithm[field] for field in T.TREE_HEAD_PAYLOAD_FIELDS}
    )
    algorithm_result = T.verify_tree_head(unknown_algorithm, trust_store_path=workspace.trust_store_path)
    assert algorithm_result.outcome == FAIL
    assert T.TREE_HEAD_ALGORITHM_UNKNOWN in algorithm_result.reason_codes

    extra_field = workspace.head(3).to_dict()
    extra_field["unexpected"] = True
    extra_result = T.verify_tree_head(extra_field, trust_store_path=workspace.trust_store_path)
    assert extra_result.outcome == FAIL
    assert T.TREE_HEAD_SCHEMA_INVALID in extra_result.reason_codes


def test_tree_head_schema_and_empty_root_rules(workspace):
    schema = _read_schema("transparency-tree-head.schema.json")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(workspace.head(3).to_dict())

    invalid = workspace.head(3).to_dict()
    invalid["unexpected"] = True
    assert list(Draft202012Validator(schema).iter_errors(invalid))

    with pytest.raises(T.TransparencyInvalid):
        T.build_tree_head_payload(
            log_id="v32-test-log",
            tree_size=0,
            merkle_root="sha256:" + ("1" * 64),
            timestamp=T0,
            key_id="tree-head-1",
            public_key=workspace.tree_head_info["public_key"],
            public_key_fingerprint_value=workspace.tree_head_info["fingerprint"],
        )

    empty_head = T.build_tree_head_payload(
        log_id="v32-test-log",
        tree_size=0,
        merkle_root=EMPTY_ROOT,
        timestamp=T0,
        key_id="tree-head-1",
        public_key=workspace.tree_head_info["public_key"],
        public_key_fingerprint_value=workspace.tree_head_info["fingerprint"],
    )
    assert empty_head["tree_size"] == 0
    assert empty_head["merkle_root"] == EMPTY_ROOT


def test_tree_head_and_log_never_disclose_private_key_material(workspace):
    private_bytes = workspace.tree_head_private_key.read_bytes()
    assert b"PRIVATE KEY" in private_bytes

    log_document = json.dumps(
        {
            "header": workspace.log.header.to_dict(),
            "entries": [entry.to_dict() for entry in workspace.log.entries],
        }
    )
    head_document = dump_sanitized_json(workspace.head(3).to_dict())
    for document in (log_document, head_document):
        assert "PRIVATE KEY" not in document
        assert "private_key" not in document
        assert workspace.tree_head_private_key.read_text(encoding="utf-8") not in document

    assert len(workspace.head(3).public_key) == 43
    assert workspace.head(3).public_key_fingerprint == workspace.tree_head_info["fingerprint"]


def test_v31_signed_checkpoint_payload_semantics_unchanged(workspace):
    from tools.release.trust import (
        SIGNED_CHECKPOINT_DOMAIN,
        SIGNED_CHECKPOINT_PROFILE,
        SIGNED_CHECKPOINT_SCHEMA_VERSION,
    )

    assert SIGNED_CHECKPOINT_SCHEMA_VERSION == 2
    assert SIGNED_CHECKPOINT_PROFILE == "evidence_checkpoint_signed"
    assert SIGNED_CHECKPOINT_DOMAIN == b"industrial-vision-platform:evidence-checkpoint:v1\x00"
    checkpoint = workspace.checkpoints[-1]
    assert checkpoint["schema_version"] == 2
    assert checkpoint["profile"] == SIGNED_CHECKPOINT_PROFILE
    verification = verify_signed_checkpoint(checkpoint, trust_store_path=evidence_trust_store(workspace))
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
    # V30 report/manifest/audit binding remains required and is unchanged by V32.
    assert verification.outcome == FAIL
    assert "CHECKPOINT_MANIFEST_MISSING" in verification.reason_codes


def test_v31_rejects_transparency_purpose_key_for_checkpoint(workspace):
    descriptor = export_public_key(private_key_path=workspace.checkpoint_private_key, key_id="checkpoint-1")
    transparency_store = build_trust_store(
        workspace.root / "checkpoint-transparency-store.json",
        key_id="checkpoint-1",
        descriptor=descriptor,
        purpose=KEY_PURPOSE_TRANSPARENCY_TREE_HEAD,
    )
    verification = verify_signed_checkpoint(workspace.checkpoints[-1], trust_store_path=transparency_store)
    assert verification.outcome == FAIL
    assert "TRUST_KEY_PURPOSE_INVALID" in verification.reason_codes
