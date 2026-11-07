"""V32 inclusion, consistency, receipt, and provider tests.

All keys, checkpoints, logs, proofs, receipts, and providers are synthetic and
local. No external transparency service, cloud KMS, registry, or credential is
contacted. The local test provider issues only SIMULATED receipts.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from backend.tests.unit.v32_support import build_workspace
from tools.release import transparency as T
from tools.release.merkle import (
    EMPTY_ROOT,
    MerkleError,
    MerkleTree,
    verify_consistency_proof,
    verify_inclusion_proof,
)
from tools.release.verification import FAIL, PASS, UNAVAILABLE

REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture()
def workspace(tmp_path: Path):
    return build_workspace(tmp_path / "v32 proofs", leaf_count=8)


def _read_schema(name: str) -> dict:
    return json.loads((REPO_ROOT / "release" / name).read_text(encoding="utf-8"))


def _leaves(workspace) -> list[bytes]:
    return [entry.canonical_bytes() for entry in workspace.log.entries]


def _proof_payload(workspace, size: int, leaf_index: int) -> dict:
    return workspace.tree(size).inclusion_proof(leaf_index).to_dict()


def _consistency_payload(workspace, old_size: int, new_size: int) -> dict:
    return workspace.tree(new_size).consistency_proof(old_size).to_dict()


def test_inclusion_proofs_for_every_leaf_and_size(workspace):
    leaves = _leaves(workspace)
    for size in range(1, 9):
        tree = workspace.tree(size)
        for leaf_index in range(size):
            result = verify_inclusion_proof(
                tree.inclusion_proof(leaf_index).to_dict(),
                expected_root=tree.root,
                expected_log_id=workspace.log.log_id,
                expected_tree_size=size,
                leaf_bytes=leaves[leaf_index],
            )
            assert result.outcome == PASS, (size, leaf_index, result.to_dict())


def test_empty_tree_has_no_inclusion_proof(workspace):
    with pytest.raises(MerkleError):
        workspace.tree(0).inclusion_proof(0)


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong-root",
        "wrong-tree-size",
        "wrong-log-id",
        "modified-leaf",
        "modified-sibling",
        "wrong-position",
        "missing-sibling",
        "extra-sibling",
        "unknown-algorithm",
        "extra-field",
        "bad-root-format",
        "bad-sibling-format",
        "leaf-bytes-mismatch",
    ],
)
def test_inclusion_proof_rejections(workspace, mutation):
    proof = _proof_payload(workspace, 8, 3)
    leaf_bytes = _leaves(workspace)[3]
    expected_root = workspace.tree(8).root
    expected_size = 8
    expected_log_id = workspace.log.log_id
    if mutation == "wrong-root":
        expected_root = "sha256:" + ("0" * 64)
    elif mutation == "wrong-tree-size":
        expected_size = 7
    elif mutation == "wrong-log-id":
        expected_log_id = "different-log"
    elif mutation == "modified-leaf":
        proof["leaf_digest"] = "sha256:" + ("1" * 64)
    elif mutation == "modified-sibling":
        proof["siblings"][0]["hash"] = "sha256:" + ("2" * 64)
    elif mutation == "wrong-position":
        proof["siblings"][0]["position"] = "left" if proof["siblings"][0]["position"] == "right" else "right"
    elif mutation == "missing-sibling":
        proof["siblings"].pop()
    elif mutation == "extra-sibling":
        proof["siblings"].append({"position": "left", "hash": "sha256:" + ("3" * 64)})
    elif mutation == "unknown-algorithm":
        proof["algorithm"] = "rfc6962-sha512-v1"
    elif mutation == "extra-field":
        proof["unexpected"] = True
    elif mutation == "bad-root-format":
        proof["root"] = "0" * 64
    elif mutation == "bad-sibling-format":
        proof["siblings"][0]["hash"] = "sha256:ABC"
    elif mutation == "leaf-bytes-mismatch":
        leaf_bytes = b"not-the-log-entry"

    result = verify_inclusion_proof(
        proof,
        expected_root=expected_root,
        expected_log_id=expected_log_id,
        expected_tree_size=expected_size,
        leaf_bytes=leaf_bytes,
    )
    assert result.outcome == FAIL, result.to_dict()
    assert result.reason_codes


def test_inclusion_requires_separately_trusted_root(workspace):
    proof = _proof_payload(workspace, 8, 0)
    result = verify_inclusion_proof(proof, expected_root=None)
    assert result.outcome == UNAVAILABLE
    assert result.reason_codes == ["MERKLE_PROOF_EXPECTED_ROOT_MISSING"]


def test_inclusion_proof_without_leaf_bytes_binds_digest_only(workspace):
    proof = _proof_payload(workspace, 8, 5)
    result = verify_inclusion_proof(proof, expected_root=workspace.tree(8).root, expected_tree_size=8)
    assert result.outcome == PASS, result.to_dict()
    leaf_check = next(check for check in result.checks if check.name == "merkle-proof-leaf")
    assert leaf_check.outcome == "NOT_RUN"
    assert leaf_check.required is False


def test_consistency_proofs_for_every_transition(workspace):
    for new_size in range(0, 9):
        new_tree = workspace.tree(new_size)
        for old_size in range(0, new_size + 1):
            old_tree = workspace.tree(old_size)
            proof = new_tree.consistency_proof(old_size)
            result = verify_consistency_proof(
                proof.to_dict(),
                expected_old_root=old_tree.root,
                expected_new_root=new_tree.root,
                expected_log_id=workspace.log.log_id,
                expected_old_tree_size=old_size,
                expected_new_tree_size=new_size,
            )
            assert result.outcome == PASS, (old_size, new_size, result.to_dict())


def test_consistency_special_transitions(workspace):
    empty_to_empty = workspace.tree(0).consistency_proof(0)
    assert empty_to_empty.proof == ()
    assert empty_to_empty.old_root == EMPTY_ROOT
    assert empty_to_empty.new_root == EMPTY_ROOT

    empty_to_nonempty = workspace.tree(8).consistency_proof(0)
    assert empty_to_nonempty.proof == ()
    assert empty_to_nonempty.old_root == EMPTY_ROOT
    assert empty_to_nonempty.new_root == workspace.tree(8).root

    single_leaf_growth = workspace.tree(2).consistency_proof(1)
    assert (
        verify_consistency_proof(
            single_leaf_growth.to_dict(),
            expected_old_root=workspace.tree(1).root,
            expected_new_root=workspace.tree(2).root,
            expected_old_tree_size=1,
            expected_new_tree_size=2,
        ).outcome
        == PASS
    )

    power_of_two = workspace.tree(8).consistency_proof(4)
    assert (
        verify_consistency_proof(
            power_of_two.to_dict(),
            expected_old_root=workspace.tree(4).root,
            expected_new_root=workspace.tree(8).root,
            expected_old_tree_size=4,
            expected_new_tree_size=8,
        ).outcome
        == PASS
    )

    for old_size, new_size in ((3, 5), (5, 6), (1, 8), (6, 7), (7, 8)):
        proof = workspace.tree(new_size).consistency_proof(old_size)
        assert (
            verify_consistency_proof(
                proof.to_dict(),
                expected_old_root=workspace.tree(old_size).root,
                expected_new_root=workspace.tree(new_size).root,
                expected_old_tree_size=old_size,
                expected_new_tree_size=new_size,
            ).outcome
            == PASS
        ), (old_size, new_size)


@pytest.mark.parametrize(
    "mutation",
    [
        "modified-node",
        "truncated",
        "extended",
        "wrong-old-root",
        "wrong-new-root",
        "missing-proof",
        "wrong-old-size",
        "wrong-new-size",
        "wrong-log-id",
        "unknown-algorithm",
    ],
)
def test_consistency_proof_rejections(workspace, mutation):
    proof = _consistency_payload(workspace, 3, 8)
    expected_old_root = workspace.tree(3).root
    expected_new_root = workspace.tree(8).root
    expected_old_size = 3
    expected_new_size = 8
    expected_log_id = workspace.log.log_id
    if mutation == "modified-node":
        proof["proof"][0] = "sha256:" + ("4" * 64)
    elif mutation == "truncated":
        proof["proof"].pop()
    elif mutation == "extended":
        proof["proof"].append("sha256:" + ("5" * 64))
    elif mutation == "wrong-old-root":
        expected_old_root = "sha256:" + ("6" * 64)
    elif mutation == "wrong-new-root":
        expected_new_root = "sha256:" + ("7" * 64)
    elif mutation == "missing-proof":
        proof["proof"] = []
    elif mutation == "wrong-old-size":
        expected_old_size = 2
    elif mutation == "wrong-new-size":
        expected_new_size = 7
    elif mutation == "wrong-log-id":
        expected_log_id = "different-log"
    elif mutation == "unknown-algorithm":
        proof["algorithm"] = "rfc6962-sha512-v1"

    result = verify_consistency_proof(
        proof,
        expected_old_root=expected_old_root,
        expected_new_root=expected_new_root,
        expected_log_id=expected_log_id,
        expected_old_tree_size=expected_old_size,
        expected_new_tree_size=expected_new_size,
    )
    assert result.outcome == FAIL, result.to_dict()
    assert result.reason_codes


def test_consistency_rejects_impossible_and_noncanonical_shapes(workspace):
    with pytest.raises(MerkleError):
        T.ConsistencyProof.from_dict(
            {
                **_consistency_payload(workspace, 3, 8),
                "old_tree_size": 9,
            }
        )
    equal_size = _consistency_payload(workspace, 8, 8)
    assert equal_size["proof"] == []
    with pytest.raises(MerkleError):
        T.ConsistencyProof.from_dict({**equal_size, "old_root": "sha256:" + ("8" * 64)})
    with pytest.raises(MerkleError):
        T.ConsistencyProof.from_dict(
            {
                **_consistency_payload(workspace, 0, 8),
                "proof": ["sha256:" + ("9" * 64)],
            }
        )
    with pytest.raises(MerkleError):
        T.ConsistencyProof.from_dict({**_consistency_payload(workspace, 3, 8), "algorithm": "unknown"})


def test_consistency_rejects_reordered_or_replaced_history(workspace):
    leaves = _leaves(workspace)
    original_old_root = workspace.tree(3).root
    original_new_root = workspace.tree(8).root

    reversed_tree = MerkleTree(list(reversed(leaves)), log_id=workspace.log.log_id)
    reversed_proof = reversed_tree.consistency_proof(3)
    reversed_result = verify_consistency_proof(
        reversed_proof.to_dict(),
        expected_old_root=original_old_root,
        expected_new_root=original_new_root,
        expected_old_tree_size=3,
        expected_new_tree_size=8,
    )
    assert reversed_result.outcome == FAIL

    replaced = list(leaves)
    replaced[2] = b"replaced historical entry"
    replaced_tree = MerkleTree(replaced, log_id=workspace.log.log_id)
    replaced_result = verify_consistency_proof(
        replaced_tree.consistency_proof(3).to_dict(),
        expected_old_root=original_old_root,
        expected_new_root=original_new_root,
        expected_old_tree_size=3,
        expected_new_tree_size=8,
    )
    assert replaced_result.outcome == FAIL


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


def test_local_test_provider_capabilities_and_receipt_lifecycle(workspace):
    provider = _provider(workspace)
    capabilities = provider.capabilities
    assert capabilities.provider_type == "local_test"
    assert capabilities.anchor_status == "SIMULATED"
    assert capabilities.external is False
    assert capabilities.independent is False
    assert capabilities.assurance == "simulated"
    assert capabilities.supports_submit_tree_head is True
    assert capabilities.supports_receipt_retrieval is True
    assert capabilities.supports_anchored_tree_head_retrieval is True
    assert capabilities.supports_consistency_proof_retrieval is True
    assert capabilities.to_dict()["external_anchoring"] is False

    receipt = provider.submit_tree_head(workspace.head(8), timestamp="2026-01-09T00:00:00Z")
    assert receipt.anchor_status == "SIMULATED"
    assert receipt.provider_type == "local_test"
    assert receipt.tree_head_digest == workspace.head(8).document_digest()
    assert receipt.tree_size == 8
    assert receipt.merkle_root == workspace.head(8).merkle_root

    result = provider.verify_receipt(receipt, tree_head=workspace.head(8))
    assert result.outcome == PASS, result.to_dict()
    assert result.anchor_status == "SIMULATED"
    assert result.assurance == "simulated"
    assert result.to_dict()["external_anchoring"] is False

    assert provider.retrieve_receipt(receipt.receipt_id) == receipt
    stored_head = provider.retrieve_anchored_tree_head(log_id=workspace.log.log_id, tree_size=8)
    assert stored_head.tree_head_id == workspace.head(8).tree_head_id

    proof_dir = workspace.root / "provider-proofs" / workspace.log.log_id
    T.write_consistency_proof(proof_dir / "7-8.json", workspace.tree(8).consistency_proof(7))
    retrieved_proof = provider.retrieve_consistency_proof(
        log_id=workspace.log.log_id, old_tree_size=7, new_tree_size=8
    )
    assert retrieved_proof.old_tree_size == 7
    assert retrieved_proof.new_tree_size == 8

    status = T.provider_status(provider)
    assert status["configured"] is True
    assert status["anchor_status"] == "SIMULATED"
    assert status["external_anchoring"] is False


def test_receipt_schema_and_round_trip(workspace):
    provider = _provider(workspace)
    receipt = provider.submit_tree_head(workspace.head(8), timestamp="2026-01-09T00:00:00Z")
    schema = _read_schema("transparency-anchor-receipt.schema.json")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(receipt.to_dict())

    path = workspace.root / "receipt-copy.json"
    T.write_receipt(path, receipt)
    assert T.load_receipt(path) == receipt

    invalid = receipt.to_dict()
    invalid["unexpected"] = True
    assert list(Draft202012Validator(schema).iter_errors(invalid))

    external_claim = receipt.to_dict()
    external_claim["provider_type"] = "external"
    external_claim["anchor_status"] = "EXTERNAL_VERIFIED"
    # The schema permits a genuinely external receipt shape; V32 runtime
    # verification still refuses it because no external provider is configured.
    assert list(Draft202012Validator(schema).iter_errors(external_claim)) == []

    local_external = receipt.to_dict()
    local_external["anchor_status"] = "EXTERNAL_VERIFIED"
    assert list(Draft202012Validator(schema).iter_errors(local_external))

    external_simulated = receipt.to_dict()
    external_simulated["provider_type"] = "external"
    assert list(Draft202012Validator(schema).iter_errors(external_simulated))


def test_receipt_rejections(workspace):
    provider = _provider(workspace)
    receipt = provider.submit_tree_head(workspace.head(8), timestamp="2026-01-09T00:00:00Z")

    bound_to_other_head = provider.submit_tree_head(workspace.head(7), timestamp="2026-01-09T00:00:00Z")
    binding = provider.verify_receipt(bound_to_other_head, tree_head=workspace.head(8))
    assert binding.outcome == FAIL
    assert T.RECEIPT_TREE_HEAD_MISMATCH in binding.reason_codes

    wrong_provider = T.verify_receipt(
        receipt,
        tree_head=workspace.head(8),
        expected_provider_id="other-provider",
    )
    assert wrong_provider.outcome == FAIL
    assert T.RECEIPT_PROVIDER_MISMATCH in wrong_provider.reason_codes

    wrong_pin = T.verify_receipt(
        receipt,
        tree_head=workspace.head(8),
        trusted_provider_fingerprint="sha256:" + ("0" * 64),
    )
    assert wrong_pin.outcome == FAIL
    assert T.RECEIPT_PROVIDER_MISMATCH in wrong_pin.reason_codes

    tampered_signature = receipt.to_dict()
    tampered_signature["signature"] = "0" * 128
    signature = T.verify_receipt(tampered_signature, tree_head=workspace.head(8))
    assert signature.outcome == FAIL
    assert T.RECEIPT_SIGNATURE_MISMATCH in signature.reason_codes

    tampered_root = receipt.to_dict()
    tampered_root["merkle_root"] = "sha256:" + ("1" * 64)
    root_result = T.verify_receipt(tampered_root, tree_head=workspace.head(8))
    assert root_result.outcome == FAIL

    external_claim = receipt.to_dict()
    external_claim["provider_type"] = "external"
    external_claim["anchor_status"] = "EXTERNAL_VERIFIED"
    external_claim["receipt_id"] = T.derive_receipt_id(external_claim)
    external_claim["payload_digest"] = T.receipt_payload_digest(
        {field: external_claim[field] for field in T.RECEIPT_PAYLOAD_FIELDS}
    )
    external = T.verify_receipt(
        T.TransparencyAnchorReceipt.from_dict(external_claim),
        tree_head=workspace.head(8),
    )
    assert external.outcome == FAIL
    assert T.PROVIDER_NOT_CONFIGURED in external.reason_codes

    stale = T.verify_receipt(
        receipt,
        tree_head=workspace.head(8),
        now="2026-03-01T00:00:00Z",
    )
    assert stale.outcome == FAIL
    assert T.RECEIPT_STALE in stale.reason_codes

    future = T.verify_receipt(
        receipt,
        tree_head=workspace.head(8),
        now="2026-01-01T00:00:00Z",
    )
    assert future.outcome == FAIL
    assert T.RECEIPT_TIMESTAMP_INVALID in future.reason_codes

    before_head = provider.submit_tree_head(workspace.head(8), timestamp="2026-01-01T00:00:00Z")
    order = provider.verify_receipt(before_head, tree_head=workspace.head(8))
    assert order.outcome == FAIL
    assert T.RECEIPT_TIMESTAMP_INVALID in order.reason_codes


def test_provider_unavailable_paths(workspace):
    provider = _provider(workspace)
    with pytest.raises(T.ProviderUnavailable):
        provider.retrieve_receipt("rcpt-" + ("0" * 32))
    with pytest.raises(T.ProviderUnavailable):
        provider.retrieve_anchored_tree_head(log_id=workspace.log.log_id, tree_size=8)
    with pytest.raises(T.ProviderUnavailable):
        provider.retrieve_consistency_proof(log_id=workspace.log.log_id, old_tree_size=7, new_tree_size=8)

    no_proof_dir = _provider(workspace, proof_dir=None)
    assert no_proof_dir.capabilities.supports_consistency_proof_retrieval is False
    with pytest.raises(T.ProviderUnavailable):
        no_proof_dir.retrieve_consistency_proof(log_id=workspace.log.log_id, old_tree_size=7, new_tree_size=8)

    class BrokenProvider:
        provider_id = "broken-provider"

        @property
        def capabilities(self):
            raise RuntimeError("capability metadata unavailable")

    broken = T.provider_status(BrokenProvider())
    assert broken["anchor_status"] == "UNAVAILABLE"
    assert broken["external_anchoring"] is False


def test_unconfigured_provider_status():
    status = T.provider_status(None)
    assert status["configured"] is False
    assert status["anchor_status"] == "NOT_CONFIGURED"
    assert status["assurance"] == "none"
    assert status["external_anchoring"] is False
