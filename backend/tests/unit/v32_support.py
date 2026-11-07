"""Shared synthetic V32 transparency fixtures.

Every key, checkpoint, log, tree head, receipt, and trust state is synthetic and
lives under pytest's temporary directory. These helpers never contact a network
service, cloud KMS, registry, release endpoint, or real credential. Private keys
are generated per test and are never printed or committed.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tools.release import transparency as T
from tools.release.merkle import MerkleTree
from tools.release.trust import (
    KEY_PURPOSE_EVIDENCE_CHECKPOINT,
    KEY_PURPOSE_TRANSPARENCY_TREE_HEAD,
    build_signed_checkpoint_payload,
    export_public_key,
    generate_key_files,
    load_private_key,
    new_trust_store,
    register_public_key,
    sign_checkpoint_payload,
    write_signed_checkpoint,
    write_trust_store,
)

T0 = "2026-01-01T00:00:00Z"
T1 = "2026-01-02T00:00:00Z"
T2 = "2026-01-03T00:00:00Z"
T3 = "2026-01-04T00:00:00Z"


def checkpoint_timestamp(sequence: int) -> str:
    return f"2026-01-{sequence:02d}T00:00:00Z"


def append_timestamp(sequence: int) -> str:
    return f"2026-01-{sequence:02d}T00:00:01Z"


def head_timestamp(size: int) -> str:
    return f"2026-01-{size:02d}T00:00:02Z"


@dataclass
class V32Workspace:
    root: Path
    checkpoint_private_key: Path
    tree_head_private_key: Path
    checkpoint_info: dict[str, Any]
    tree_head_info: dict[str, Any]
    trust_store_path: Path
    log_path: Path
    checkpoints: list[dict[str, Any]]
    log: T.TransparencyLog
    trees: dict[int, MerkleTree]
    heads: list[T.TransparencyTreeHead]

    def tree(self, size: int) -> MerkleTree:
        return self.trees[size]

    def head(self, size: int) -> T.TransparencyTreeHead:
        return self.heads[size - 1]

    def head_path(self, size: int) -> Path:
        path = self.root / f"tree-head-{size}.json"
        T.write_tree_head(path, self.head(size), overwrite=True)
        return path

    def proof_path(self, old_size: int, new_size: int) -> Path:
        proof = self.tree(new_size).consistency_proof(old_size)
        path = self.root / f"consistency-{old_size}-{new_size}.json"
        T.write_consistency_proof(path, proof, overwrite=True)
        return path

    def inclusion_path(self, size: int, leaf_index: int) -> Path:
        proof = self.tree(size).inclusion_proof(leaf_index)
        path = self.root / f"inclusion-{size}-{leaf_index}.json"
        T.write_inclusion_proof(path, proof, overwrite=True)
        return path


def build_trust_store(
    path: Path,
    *,
    key_id: str,
    descriptor: dict[str, Any],
    purpose: str = KEY_PURPOSE_TRANSPARENCY_TREE_HEAD,
    activated_at: str = T0,
    expires_at: str | None = None,
    revoked_at: str | None = None,
    reason: str | None = None,
) -> Path:
    store = new_trust_store()
    store = register_public_key(
        store,
        descriptor,
        purpose=purpose,
        activated_at=activated_at,
        expires_at=expires_at,
    )
    if revoked_at is not None:
        from tools.release.trust import revoke_key

        store = revoke_key(store, key_id, revoked_at=revoked_at, reason=reason)
    write_trust_store(path, store, overwrite=True)
    return path


def _build_checkpoint(
    private_key_path: Path,
    info: dict[str, Any],
    sequence: int,
    *,
    created_at: str | None = None,
    key_id: str = "checkpoint-1",
    public_key: str | None = None,
    fingerprint: str | None = None,
) -> dict[str, Any]:
    private_key = load_private_key(private_key_path)
    payload = build_signed_checkpoint_payload(
        evidence_report_id="report:sha256:" + ("a" * 64),
        audit_chain_terminal_hash="sha256:" + ("b" * 64),
        audit_chain_terminal_event_id=f"evt-{sequence}",
        audit_chain_terminal_timestamp=checkpoint_timestamp(sequence),
        audit_record_count=sequence,
        evidence_manifest_digest="sha256:" + ("c" * 64),
        checkpoint_sequence=sequence,
        created_at=created_at or checkpoint_timestamp(sequence),
        key_id=key_id,
        public_key=public_key or info["public_key"],
        public_key_fingerprint_value=fingerprint or info["fingerprint"],
    )
    return sign_checkpoint_payload(payload, private_key)


def make_checkpoint(
    workspace: V32Workspace,
    sequence: int,
    *,
    created_at: str | None = None,
    private_key_path: Path | None = None,
    key_id: str = "checkpoint-1",
    public_key: str | None = None,
    fingerprint: str | None = None,
) -> dict[str, Any]:
    return _build_checkpoint(
        private_key_path or workspace.checkpoint_private_key,
        workspace.checkpoint_info,
        sequence,
        created_at=created_at,
        key_id=key_id,
        public_key=public_key,
        fingerprint=fingerprint,
    )


def make_head(
    workspace: V32Workspace,
    size: int,
    *,
    timestamp: str | None = None,
    merkle_root: str | None = None,
    private_key_path: Path | None = None,
    key_id: str = "tree-head-1",
    public_key: str | None = None,
    fingerprint: str | None = None,
) -> T.TransparencyTreeHead:
    tree = workspace.tree(size)
    private_key = load_private_key(private_key_path or workspace.tree_head_private_key)
    info = workspace.tree_head_info
    payload = T.build_tree_head_payload(
        log_id=workspace.log.log_id,
        tree_size=size,
        merkle_root=merkle_root or tree.root,
        timestamp=timestamp or head_timestamp(size),
        key_id=key_id,
        public_key=public_key or info["public_key"],
        public_key_fingerprint_value=fingerprint or info["fingerprint"],
    )
    return T.sign_tree_head_payload(payload, private_key)


def build_workspace(root: Path, *, leaf_count: int = 3) -> V32Workspace:
    root.mkdir(parents=True, exist_ok=True)
    checkpoint_key = root / "checkpoint.key"
    tree_head_key = root / "tree-head.key"
    checkpoint_info = generate_key_files(key_id="checkpoint-1", private_key_path=checkpoint_key)
    tree_head_info = generate_key_files(key_id="tree-head-1", private_key_path=tree_head_key)
    tree_head_descriptor = export_public_key(private_key_path=tree_head_key, key_id="tree-head-1")
    trust_store_path = build_trust_store(
        root / "trust-store.json",
        key_id="tree-head-1",
        descriptor=tree_head_descriptor,
    )
    log_path = root / "log.jsonl"
    T.init_log(log_path, log_id="v32-test-log", timestamp=T0)
    checkpoints: list[dict[str, Any]] = []
    for sequence in range(1, leaf_count + 1):
        checkpoint = _build_checkpoint(
            checkpoint_key,
            checkpoint_info,
            sequence,
        )
        path = root / f"checkpoint-{sequence}.json"
        write_signed_checkpoint(path, checkpoint)
        T.append_checkpoint(log_path, path, timestamp=append_timestamp(sequence))
        checkpoints.append(checkpoint)
    log = T.read_log(log_path)
    leaves = [entry.canonical_bytes() for entry in log.entries]
    trees = {size: MerkleTree(leaves[:size], log_id=log.log_id) for size in range(0, leaf_count + 1)}
    workspace = V32Workspace(
        root=root,
        checkpoint_private_key=checkpoint_key,
        tree_head_private_key=tree_head_key,
        checkpoint_info=checkpoint_info,
        tree_head_info=tree_head_info,
        trust_store_path=trust_store_path,
        log_path=log_path,
        checkpoints=checkpoints,
        log=log,
        trees=trees,
        heads=[],
    )
    workspace.heads = [make_head(workspace, size) for size in range(1, leaf_count + 1)]
    return workspace


def evidence_trust_store(workspace: V32Workspace) -> Path:
    """Create a V31 checkpoint-purpose trust store for regression tests."""
    descriptor = export_public_key(private_key_path=workspace.checkpoint_private_key, key_id="checkpoint-1")
    return build_trust_store(
        workspace.root / "evidence-trust-store.json",
        key_id="checkpoint-1",
        descriptor=descriptor,
        purpose=KEY_PURPOSE_EVIDENCE_CHECKPOINT,
    )


__all__ = [
    "T0",
    "T1",
    "T2",
    "T3",
    "V32Workspace",
    "append_timestamp",
    "build_trust_store",
    "build_workspace",
    "checkpoint_timestamp",
    "evidence_trust_store",
    "head_timestamp",
    "make_checkpoint",
    "make_head",
]
