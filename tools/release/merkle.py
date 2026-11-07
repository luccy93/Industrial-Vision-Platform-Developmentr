"""V32 deterministic RFC 6962 Merkle trees, inclusion proofs, and consistency proofs.

This module implements the Certificate Transparency Merkle tree convention from
RFC 6962 / RFC 9162 with explicit domain separation:

* empty tree root: ``SHA256(b"")``;
* leaf hash: ``SHA256(0x00 || canonical_leaf_bytes)``;
* internal node hash: ``SHA256(0x01 || left_hash || right_hash)``.

A leaf is an opaque canonical byte string. The transparency log supplies the
canonical JSON bytes of one log entry; the tree never interprets them. Roots are
deterministic for the same ordered leaves and change when a leaf or its position
changes.

Inclusion proofs use the RFC 6962 ``PATH`` construction. Consistency proofs use
the RFC 6962 ``PROOF`` / ``SUBPROOF`` construction and the RFC 9162 verification
algorithm. Empty-tree consistency (``old_size == 0``) is defined as the trivial
prefix relation: an empty tree is consistent with every tree and its proof is
empty. This is documented explicitly because RFC 6962 does not define a
consistency proof from the empty tree.

The module is pure and offline. It performs no I/O and contacts no service. A
Merkle root proves only that a set of leaf bytes hashes to that root; it does not
prove that the leaves are truthful, complete, or correctly collected.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from backend.app.core.redaction import redact_text
from tools.release.identity import DIGEST_PATTERN
from tools.release.verification import FAIL, NOT_RUN, PASS, UNAVAILABLE

MERKLE_ALGORITHM = "rfc6962-sha256-v1"
HASH_ALGORITHM = "sha256"
MERKLE_SCHEMA_VERSION = 1
INCLUSION_PROOF_PROFILE = "merkle_inclusion_proof"
CONSISTENCY_PROOF_PROFILE = "merkle_consistency_proof"

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

EMPTY_ROOT_RAW = hashlib.sha256(b"").digest()
EMPTY_ROOT = f"sha256:{EMPTY_ROOT_RAW.hex()}"

MAX_MERKLE_LEAVES = 100_000
MAX_PROOF_SIBLINGS = 64
MAX_PROOF_BYTES = 1024 * 1024
MAX_LEAF_BYTES = 64 * 1024
MAX_JSON_DEPTH = 16

SAFE_LOG_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
CONTROL_CHARACTER = re.compile(r"[\x00-\x1f\x7f]")
PROOF_POSITIONS = ("left", "right")

INCLUSION_PROOF_FIELDS = (
    "schema_version",
    "profile",
    "algorithm",
    "log_id",
    "tree_size",
    "leaf_index",
    "leaf_digest",
    "siblings",
    "root",
)
CONSISTENCY_PROOF_FIELDS = (
    "schema_version",
    "profile",
    "algorithm",
    "log_id",
    "old_tree_size",
    "new_tree_size",
    "old_root",
    "new_root",
    "proof",
)
PROOF_SIBLING_FIELDS = ("position", "hash")

MERKLE_ALGORITHM_UNKNOWN = "MERKLE_ALGORITHM_UNKNOWN"
MERKLE_PROOF_SCHEMA_INVALID = "MERKLE_PROOF_SCHEMA_INVALID"
MERKLE_PROOF_ROOT_MISMATCH = "MERKLE_PROOF_ROOT_MISMATCH"
MERKLE_PROOF_LEAF_INVALID = "MERKLE_PROOF_LEAF_INVALID"
MERKLE_PROOF_TREE_SIZE_INVALID = "MERKLE_PROOF_TREE_SIZE_INVALID"
MERKLE_PROOF_INDEX_INVALID = "MERKLE_PROOF_INDEX_INVALID"
MERKLE_PROOF_SIBLING_INVALID = "MERKLE_PROOF_SIBLING_INVALID"
MERKLE_PROOF_SIBLING_COUNT = "MERKLE_PROOF_SIBLING_COUNT"
MERKLE_PROOF_POSITION_MISMATCH = "MERKLE_PROOF_POSITION_MISMATCH"
MERKLE_PROOF_LOG_MISMATCH = "MERKLE_PROOF_LOG_MISMATCH"
MERKLE_PROOF_VERIFICATION_FAILED = "MERKLE_PROOF_VERIFICATION_FAILED"
MERKLE_PROOF_EXPECTED_ROOT_MISSING = "MERKLE_PROOF_EXPECTED_ROOT_MISSING"
MERKLE_CONSISTENCY_SIZE_INVALID = "MERKLE_CONSISTENCY_SIZE_INVALID"
MERKLE_CONSISTENCY_PROOF_INVALID = "MERKLE_CONSISTENCY_PROOF_INVALID"
MERKLE_CONSISTENCY_OLD_ROOT_MISMATCH = "MERKLE_CONSISTENCY_OLD_ROOT_MISMATCH"
MERKLE_CONSISTENCY_NEW_ROOT_MISMATCH = "MERKLE_CONSISTENCY_NEW_ROOT_MISMATCH"


class MerkleError(ValueError):
    """A Merkle input, proof, or proof request is invalid."""

    def __init__(self, message: str, *, reason_code: str = MERKLE_PROOF_SCHEMA_INVALID) -> None:
        super().__init__(message)
        self.reason_code = reason_code


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MerkleError("JSON document contains a duplicate field")
        result[key] = value
    return result


def loads_strict(text: str) -> Any:
    """Parse JSON while rejecting duplicate object fields."""
    import json

    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
    except MerkleError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise MerkleError("document is not valid JSON") from exc


def validate_json_depth(value: Any, *, max_depth: int = MAX_JSON_DEPTH) -> None:
    """Reject documents whose nesting depth exceeds *max_depth*."""
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            raise MerkleError("document nesting depth exceeds the supported limit")
        if isinstance(current, Mapping):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, (list, tuple)):
            stack.extend((item, depth + 1) for item in current)


def _safe_text(value: Any, *, field_name: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value:
        raise MerkleError(f"{field_name} must be a non-empty string")
    if CONTROL_CHARACTER.search(value):
        raise MerkleError(f"{field_name} contains a control character")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise MerkleError(f"{field_name} contains unsupported characters")
    return value


def _exact_fields(payload: Mapping[str, Any], expected: tuple[str, ...], *, label: str) -> None:
    if sorted(payload) != sorted(expected):
        raise MerkleError(f"{label} has unexpected or missing fields")


def _digest(value: Any, *, field_name: str, reason_code: str = MERKLE_PROOF_SCHEMA_INVALID) -> str:
    if not isinstance(value, str) or DIGEST_PATTERN.fullmatch(value) is None:
        raise MerkleError(f"{field_name} must be sha256:<64 lowercase hex>", reason_code=reason_code)
    return value


def _int(value: Any, *, field_name: str, minimum: int, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise MerkleError(f"{field_name} must be an integer >= {minimum}")
    if maximum is not None and value > maximum:
        raise MerkleError(f"{field_name} exceeds the supported maximum")
    return value


def _raw_digest(value: str) -> bytes:
    return bytes.fromhex(value[len("sha256:") :])


def sha256_digest(data: bytes) -> str:
    """Return a release-style ``sha256:<hex>`` digest."""
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def leaf_hash(leaf_bytes: bytes) -> bytes:
    """Return the raw domain-separated leaf hash."""
    if not isinstance(leaf_bytes, (bytes, bytearray, memoryview)):
        raise MerkleError("leaf must be bytes")
    data = bytes(leaf_bytes)
    if len(data) > MAX_LEAF_BYTES:
        raise MerkleError("leaf exceeds the supported size")
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """Return the raw domain-separated internal-node hash."""
    if not isinstance(left, bytes) or not isinstance(right, bytes):
        raise MerkleError("node children must be raw bytes")
    if len(left) != 32 or len(right) != 32:
        raise MerkleError("node children must be 32-byte digests")
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def leaf_digest(leaf_bytes: bytes) -> str:
    """Return the formatted domain-separated leaf hash."""
    return f"sha256:{leaf_hash(leaf_bytes).hex()}"


def largest_power_of_two_less_than(value: int) -> int:
    """Return the largest power of two strictly smaller than *value* (value > 1)."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 2:
        raise MerkleError("value must be an integer greater than one")
    return 1 << (value - 1).bit_length() - 1


def inclusion_path_directions(tree_size: int, leaf_index: int) -> tuple[str, ...]:
    """Return the expected sibling position at each proof level, leaf to root.

    ``"right"`` means the sibling is the right child of the current node;
    ``"left"`` means it is the left child.
    """
    _int(tree_size, field_name="tree_size", minimum=1, maximum=MAX_MERKLE_LEAVES)
    _int(leaf_index, field_name="leaf_index", minimum=0, maximum=tree_size - 1)

    def directions(size: int, index: int) -> tuple[str, ...]:
        if size == 1:
            return ()
        split = largest_power_of_two_less_than(size)
        if index < split:
            return directions(split, index) + ("right",)
        return directions(size - split, index - split) + ("left",)

    return directions(tree_size, leaf_index)


@dataclass(frozen=True)
class ProofSibling:
    """One inclusion-proof sibling with its verified side."""

    position: str
    hash: str

    def to_dict(self) -> dict[str, str]:
        return {"position": self.position, "hash": self.hash}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ProofSibling:
        if not isinstance(payload, Mapping):
            raise MerkleError("proof sibling must be a mapping")
        _exact_fields(payload, PROOF_SIBLING_FIELDS, label="proof sibling")
        position = payload.get("position")
        if position not in PROOF_POSITIONS:
            raise MerkleError("proof sibling position must be 'left' or 'right'")
        return cls(
            position=position,
            hash=_digest(payload.get("hash"), field_name="sibling hash"),
        )


@dataclass(frozen=True)
class InclusionProof:
    """A deterministic RFC 6962 Merkle inclusion proof."""

    log_id: str
    tree_size: int
    leaf_index: int
    leaf_digest: str
    siblings: tuple[ProofSibling, ...]
    root: str
    algorithm: str = MERKLE_ALGORITHM
    schema_version: int = MERKLE_SCHEMA_VERSION
    profile: str = INCLUSION_PROOF_PROFILE

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "profile": self.profile,
            "algorithm": self.algorithm,
            "log_id": self.log_id,
            "tree_size": self.tree_size,
            "leaf_index": self.leaf_index,
            "leaf_digest": self.leaf_digest,
            "siblings": [sibling.to_dict() for sibling in self.siblings],
            "root": self.root,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> InclusionProof:
        if not isinstance(payload, Mapping):
            raise MerkleError("inclusion proof must be a mapping")
        validate_json_depth(payload)
        _exact_fields(payload, INCLUSION_PROOF_FIELDS, label="inclusion proof")
        if payload.get("schema_version") != MERKLE_SCHEMA_VERSION:
            raise MerkleError("inclusion proof schema_version is unsupported")
        if payload.get("profile") != INCLUSION_PROOF_PROFILE:
            raise MerkleError("inclusion proof profile is unsupported")
        if payload.get("algorithm") != MERKLE_ALGORITHM:
            raise MerkleError(
                "inclusion proof algorithm is unsupported",
                reason_code=MERKLE_ALGORITHM_UNKNOWN,
            )
        log_id = _safe_text(payload.get("log_id"), field_name="log_id", pattern=SAFE_LOG_ID)
        tree_size = _int(
            payload.get("tree_size"),
            field_name="tree_size",
            minimum=1,
            maximum=MAX_MERKLE_LEAVES,
        )
        leaf_index = _int(
            payload.get("leaf_index"),
            field_name="leaf_index",
            minimum=0,
            maximum=tree_size - 1,
        )
        leaf = _digest(payload.get("leaf_digest"), field_name="leaf_digest")
        root = _digest(payload.get("root"), field_name="root")
        raw_siblings = payload.get("siblings")
        if not isinstance(raw_siblings, list):
            raise MerkleError("inclusion proof siblings must be a list")
        if len(raw_siblings) > MAX_PROOF_SIBLINGS:
            raise MerkleError("inclusion proof contains too many siblings")
        siblings = tuple(ProofSibling.from_dict(item) for item in raw_siblings)
        expected = len(inclusion_path_directions(tree_size, leaf_index))
        if len(siblings) != expected:
            raise MerkleError(
                "inclusion proof sibling count does not match the tree shape",
                reason_code=MERKLE_PROOF_SIBLING_COUNT,
            )
        for sibling, direction in zip(siblings, inclusion_path_directions(tree_size, leaf_index)):
            if sibling.position != direction:
                raise MerkleError(
                    "inclusion proof sibling position does not match the tree shape",
                    reason_code=MERKLE_PROOF_POSITION_MISMATCH,
                )
        return cls(
            log_id=log_id,
            tree_size=tree_size,
            leaf_index=leaf_index,
            leaf_digest=leaf,
            siblings=siblings,
            root=root,
        )


@dataclass(frozen=True)
class ConsistencyProof:
    """A deterministic RFC 6962 append-only consistency proof."""

    log_id: str
    old_tree_size: int
    new_tree_size: int
    old_root: str
    new_root: str
    proof: tuple[str, ...]
    algorithm: str = MERKLE_ALGORITHM
    schema_version: int = MERKLE_SCHEMA_VERSION
    profile: str = CONSISTENCY_PROOF_PROFILE

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "profile": self.profile,
            "algorithm": self.algorithm,
            "log_id": self.log_id,
            "old_tree_size": self.old_tree_size,
            "new_tree_size": self.new_tree_size,
            "old_root": self.old_root,
            "new_root": self.new_root,
            "proof": list(self.proof),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ConsistencyProof:
        if not isinstance(payload, Mapping):
            raise MerkleError("consistency proof must be a mapping")
        validate_json_depth(payload)
        _exact_fields(payload, CONSISTENCY_PROOF_FIELDS, label="consistency proof")
        if payload.get("schema_version") != MERKLE_SCHEMA_VERSION:
            raise MerkleError("consistency proof schema_version is unsupported")
        if payload.get("profile") != CONSISTENCY_PROOF_PROFILE:
            raise MerkleError("consistency proof profile is unsupported")
        if payload.get("algorithm") != MERKLE_ALGORITHM:
            raise MerkleError(
                "consistency proof algorithm is unsupported",
                reason_code=MERKLE_ALGORITHM_UNKNOWN,
            )
        log_id = _safe_text(payload.get("log_id"), field_name="log_id", pattern=SAFE_LOG_ID)
        old_size = _int(
            payload.get("old_tree_size"),
            field_name="old_tree_size",
            minimum=0,
            maximum=MAX_MERKLE_LEAVES,
        )
        new_size = _int(
            payload.get("new_tree_size"),
            field_name="new_tree_size",
            minimum=0,
            maximum=MAX_MERKLE_LEAVES,
        )
        if old_size > new_size:
            raise MerkleError(
                "old_tree_size must not exceed new_tree_size",
                reason_code=MERKLE_CONSISTENCY_SIZE_INVALID,
            )
        old_root = _digest(payload.get("old_root"), field_name="old_root")
        new_root = _digest(payload.get("new_root"), field_name="new_root")
        raw_proof = payload.get("proof")
        if not isinstance(raw_proof, list):
            raise MerkleError("consistency proof nodes must be a list")
        if len(raw_proof) > MAX_PROOF_SIBLINGS:
            raise MerkleError("consistency proof contains too many nodes")
        nodes = tuple(_digest(item, field_name="consistency proof node") for item in raw_proof)
        if old_size == new_size:
            if nodes:
                raise MerkleError("equal-size consistency proof must be empty")
            if old_root != new_root:
                raise MerkleError("equal-size consistency proof roots differ")
        if old_size == 0 and nodes:
            raise MerkleError("empty-tree consistency proof must be empty")
        if old_size > 0 and old_size < new_size and not nodes:
            raise MerkleError(
                "consistency proof is missing required nodes",
                reason_code=MERKLE_CONSISTENCY_PROOF_INVALID,
            )
        return cls(
            log_id=log_id,
            old_tree_size=old_size,
            new_tree_size=new_size,
            old_root=old_root,
            new_root=new_root,
            proof=nodes,
        )


@dataclass(frozen=True)
class MerkleCheck:
    """One stable Merkle verification check."""

    name: str
    outcome: str
    detail: str
    reason_code: str | None = None
    required: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "outcome": self.outcome,
            "detail": redact_text(self.detail)[:500],
            "reason_code": self.reason_code,
            "required": self.required,
        }


@dataclass
class MerkleVerification:
    """Result of verifying one Merkle proof."""

    proof_type: str
    outcome: str = NOT_RUN
    checks: list[MerkleCheck] = field(default_factory=list)
    reason_codes: list[str] = field(default_factory=list)
    computed_root: str | None = None
    expected_root: str | None = None
    tree_size: int | None = None
    leaf_index: int | None = None
    log_id: str | None = None

    def add(self, check: MerkleCheck) -> MerkleCheck:
        self.checks.append(check)
        return check

    def finalize(self) -> MerkleVerification:
        required = [check for check in self.checks if check.required]
        outcomes = {check.outcome for check in required}
        for state in (FAIL, UNAVAILABLE, NOT_RUN):
            if state in outcomes:
                self.outcome = state
                break
        else:
            self.outcome = PASS if required else NOT_RUN
        codes: list[str] = []
        for check in self.checks:
            if check.reason_code is not None and check.outcome != PASS and check.reason_code not in codes:
                codes.append(check.reason_code)
        self.reason_codes = codes
        return self

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "proof_type": self.proof_type,
            "outcome": self.outcome,
            "computed_root": self.computed_root,
            "expected_root": self.expected_root,
            "tree_size": self.tree_size,
            "leaf_index": self.leaf_index,
            "log_id": self.log_id,
            "reason_codes": sorted(set(self.reason_codes)),
            "checks": [check.to_dict() for check in self.checks],
        }
        return payload


class MerkleTree:
    """An immutable RFC 6962 Merkle tree over ordered canonical leaf bytes.

    The tree computes each subtree root once and memoizes it. Building is
    ``O(n)`` time and ``O(n)`` memory for ``n`` leaves; each inclusion or
    consistency proof then uses ``O(log n)`` memoized nodes. Generating proofs
    for every leaf is ``O(n log n)`` rather than recomputing the tree per proof.
    """

    def __init__(self, leaves: Sequence[bytes], *, log_id: str = "local-evidence-log") -> None:
        if isinstance(leaves, (str, bytes, bytearray)):
            raise MerkleError("leaves must be a sequence of byte strings")
        materialized = list(leaves)
        if len(materialized) > MAX_MERKLE_LEAVES:
            raise MerkleError("tree exceeds the supported leaf count")
        for leaf in materialized:
            if not isinstance(leaf, (bytes, bytearray, memoryview)):
                raise MerkleError("each leaf must be bytes")
            if len(leaf) > MAX_LEAF_BYTES:
                raise MerkleError("leaf exceeds the supported size")
        self._log_id = _safe_text(log_id, field_name="log_id", pattern=SAFE_LOG_ID)
        self._leaves = tuple(bytes(leaf) for leaf in materialized)
        self._leaf_hashes = tuple(leaf_hash(leaf) for leaf in self._leaves)
        self._roots: dict[tuple[int, int], bytes] = {}

    @property
    def leaf_count(self) -> int:
        return len(self._leaves)

    @property
    def log_id(self) -> str:
        return self._log_id

    @property
    def root_raw(self) -> bytes:
        return self._root(0, self.leaf_count)

    @property
    def root(self) -> str:
        return f"sha256:{self.root_raw.hex()}"

    def _root(self, start: int, size: int) -> bytes:
        if size == 0:
            return EMPTY_ROOT_RAW
        if size == 1:
            return self._leaf_hashes[start]
        key = (start, size)
        cached = self._roots.get(key)
        if cached is not None:
            return cached
        split = largest_power_of_two_less_than(size)
        value = node_hash(self._root(start, split), self._root(start + split, size - split))
        self._roots[key] = value
        return value

    def inclusion_proof(self, leaf_index: int) -> InclusionProof:
        """Return the RFC 6962 inclusion proof for one leaf."""
        if self.leaf_count == 0:
            raise MerkleError("an empty tree has no inclusion proof", reason_code=MERKLE_PROOF_INDEX_INVALID)
        _int(leaf_index, field_name="leaf_index", minimum=0, maximum=self.leaf_count - 1)
        siblings: list[ProofSibling] = []
        size = self.leaf_count
        index = leaf_index
        start = 0
        while size > 1:
            split = largest_power_of_two_less_than(size)
            if index < split:
                sibling = self._root(start + split, size - split)
                position = "right"
                size = split
            else:
                sibling = self._root(start, split)
                position = "left"
                start += split
                index -= split
                size -= split
            siblings.append(ProofSibling(position=position, hash=f"sha256:{sibling.hex()}"))
        siblings.reverse()
        return InclusionProof(
            log_id=self._log_id,
            tree_size=self.leaf_count,
            leaf_index=leaf_index,
            leaf_digest=f"sha256:{self._leaf_hashes[leaf_index].hex()}",
            siblings=tuple(siblings),
            root=self.root,
        )

    def consistency_proof(self, old_tree_size: int) -> ConsistencyProof:
        """Return the RFC 6962 consistency proof from *old_tree_size* to this tree."""
        _int(
            old_tree_size,
            field_name="old_tree_size",
            minimum=0,
            maximum=self.leaf_count,
        )
        if old_tree_size == 0:
            nodes: list[bytes] = []
        else:
            nodes = []
            self._subproof(old_tree_size, 0, self.leaf_count, True, nodes)
        return ConsistencyProof(
            log_id=self._log_id,
            old_tree_size=old_tree_size,
            new_tree_size=self.leaf_count,
            old_root=f"sha256:{self._root(0, old_tree_size).hex()}",
            new_root=self.root,
            proof=tuple(f"sha256:{node.hex()}" for node in nodes),
        )

    def _subproof(
        self,
        old_size: int,
        start: int,
        size: int,
        complete: bool,
        nodes: list[bytes],
    ) -> None:
        if old_size == size:
            if not complete:
                nodes.append(self._root(start, size))
            return
        split = largest_power_of_two_less_than(size)
        if old_size <= split:
            self._subproof(old_size, start, split, complete, nodes)
            nodes.append(self._root(start + split, size - split))
        else:
            self._subproof(old_size - split, start + split, size - split, False, nodes)
            nodes.append(self._root(start, split))


def merkle_root(leaves: Sequence[bytes], *, log_id: str = "local-evidence-log") -> str:
    """Return the formatted root for ordered canonical leaf bytes."""
    return MerkleTree(leaves, log_id=log_id).root


def verify_inclusion_proof(
    proof: Mapping[str, Any] | InclusionProof,
    *,
    expected_root: str | None,
    expected_log_id: str | None = None,
    expected_tree_size: int | None = None,
    leaf_bytes: bytes | None = None,
) -> MerkleVerification:
    """Verify an inclusion proof against a separately supplied root.

    The root inside the proof is never trusted. ``expected_root`` must come from
    a verified tree head or receipt. If it is missing, the result is
    ``UNAVAILABLE`` rather than a pass.
    """
    result = MerkleVerification(proof_type="inclusion")
    if expected_root is None:
        result.add(
            MerkleCheck(
                "merkle-expected-root",
                UNAVAILABLE,
                "a separately trusted Merkle root is required; the proof's own root is not trusted",
                reason_code=MERKLE_PROOF_EXPECTED_ROOT_MISSING,
            )
        )
        return result.finalize()
    try:
        expected = _digest(expected_root, field_name="expected_root")
    except MerkleError as exc:
        result.add(MerkleCheck("merkle-expected-root", FAIL, str(exc), reason_code=exc.reason_code))
        return result.finalize()
    try:
        parsed = proof if isinstance(proof, InclusionProof) else InclusionProof.from_dict(proof)
    except MerkleError as exc:
        result.add(MerkleCheck("merkle-proof-schema", FAIL, str(exc), reason_code=exc.reason_code))
        return result.finalize()
    result.expected_root = expected
    result.tree_size = parsed.tree_size
    result.leaf_index = parsed.leaf_index
    result.log_id = parsed.log_id
    result.add(
        MerkleCheck(
            "merkle-proof-schema",
            PASS,
            f"inclusion proof schema is valid for tree size {parsed.tree_size}",
        )
    )
    if expected_log_id is not None and parsed.log_id != expected_log_id:
        result.add(
            MerkleCheck(
                "merkle-proof-log",
                FAIL,
                "inclusion proof log identifier does not match the trusted tree head",
                reason_code=MERKLE_PROOF_LOG_MISMATCH,
            )
        )
    else:
        result.add(MerkleCheck("merkle-proof-log", PASS, "inclusion proof log identifier is consistent"))
    if expected_tree_size is not None and parsed.tree_size != expected_tree_size:
        result.add(
            MerkleCheck(
                "merkle-proof-tree-size",
                FAIL,
                "inclusion proof tree size does not match the trusted tree head",
                reason_code=MERKLE_PROOF_TREE_SIZE_INVALID,
            )
        )
    else:
        result.add(MerkleCheck("merkle-proof-tree-size", PASS, "inclusion proof tree size is consistent"))
    if parsed.root != expected:
        result.add(
            MerkleCheck(
                "merkle-proof-root",
                FAIL,
                "inclusion proof root does not match the separately trusted root",
                reason_code=MERKLE_PROOF_ROOT_MISMATCH,
            )
        )
    else:
        result.add(MerkleCheck("merkle-proof-root", PASS, "inclusion proof root matches the trusted root"))
    if leaf_bytes is not None:
        try:
            computed_leaf = leaf_digest(leaf_bytes)
        except MerkleError as exc:
            result.add(
                MerkleCheck(
                    "merkle-proof-leaf",
                    FAIL,
                    str(exc),
                    reason_code=MERKLE_PROOF_LEAF_INVALID,
                )
            )
        else:
            if computed_leaf != parsed.leaf_digest:
                result.add(
                    MerkleCheck(
                        "merkle-proof-leaf",
                        FAIL,
                        "supplied leaf bytes do not hash to the proof leaf digest",
                        reason_code=MERKLE_PROOF_LEAF_INVALID,
                    )
                )
            else:
                result.add(
                    MerkleCheck(
                        "merkle-proof-leaf",
                        PASS,
                        "supplied leaf bytes match the proof leaf digest",
                    )
                )
    else:
        result.add(
            MerkleCheck(
                "merkle-proof-leaf",
                NOT_RUN,
                "no leaf bytes were supplied; the proof binds the claimed leaf digest only",
                required=False,
            )
        )
    current = _raw_digest(parsed.leaf_digest)
    for sibling in parsed.siblings:
        sibling_raw = _raw_digest(sibling.hash)
        if sibling.position == "right":
            current = node_hash(current, sibling_raw)
        else:
            current = node_hash(sibling_raw, current)
    computed = f"sha256:{current.hex()}"
    result.computed_root = computed
    if computed != expected:
        result.add(
            MerkleCheck(
                "merkle-proof-path",
                FAIL,
                "sibling path does not reconstruct the trusted root",
                reason_code=MERKLE_PROOF_VERIFICATION_FAILED,
            )
        )
    else:
        result.add(
            MerkleCheck(
                "merkle-proof-path",
                PASS,
                "sibling path reconstructs the trusted root",
            )
        )
    return result.finalize()


def _verify_consistency_algorithm(
    old_size: int,
    new_size: int,
    old_root_raw: bytes,
    new_root_raw: bytes,
    proof_raw: list[bytes],
) -> bool:
    if old_size == 0:
        return not proof_raw and old_root_raw == EMPTY_ROOT_RAW
    if old_size == new_size:
        return not proof_raw and old_root_raw == new_root_raw
    if old_size > new_size or not proof_raw:
        return False
    nodes = list(proof_raw)
    if old_size & (old_size - 1) == 0:
        nodes.insert(0, old_root_raw)
    first = old_size - 1
    second = new_size - 1
    while first & 1:
        first >>= 1
        second >>= 1
    first_hash = nodes[0]
    second_hash = nodes[0]
    for node in nodes[1:]:
        if second == 0:
            return False
        if (first & 1) or first == second:
            first_hash = node_hash(node, first_hash)
            second_hash = node_hash(node, second_hash)
            while first != 0 and (first & 1) == 0:
                first >>= 1
                second >>= 1
        else:
            second_hash = node_hash(second_hash, node)
        first >>= 1
        second >>= 1
    return first_hash == old_root_raw and second_hash == new_root_raw and second == 0


def verify_consistency_proof(
    proof: Mapping[str, Any] | ConsistencyProof,
    *,
    expected_old_root: str | None,
    expected_new_root: str | None,
    expected_log_id: str | None = None,
    expected_old_tree_size: int | None = None,
    expected_new_tree_size: int | None = None,
) -> MerkleVerification:
    """Verify an append-only consistency proof against separately trusted roots."""
    result = MerkleVerification(proof_type="consistency")
    if expected_old_root is None or expected_new_root is None:
        result.add(
            MerkleCheck(
                "merkle-expected-roots",
                UNAVAILABLE,
                "separately trusted old and new roots are required; proof roots are not trusted",
                reason_code=MERKLE_PROOF_EXPECTED_ROOT_MISSING,
            )
        )
        return result.finalize()
    try:
        old_expected = _digest(expected_old_root, field_name="expected_old_root")
        new_expected = _digest(expected_new_root, field_name="expected_new_root")
    except MerkleError as exc:
        result.add(MerkleCheck("merkle-expected-roots", FAIL, str(exc), reason_code=exc.reason_code))
        return result.finalize()
    try:
        parsed = proof if isinstance(proof, ConsistencyProof) else ConsistencyProof.from_dict(proof)
    except MerkleError as exc:
        result.add(MerkleCheck("merkle-proof-schema", FAIL, str(exc), reason_code=exc.reason_code))
        return result.finalize()
    result.expected_root = new_expected
    result.tree_size = parsed.new_tree_size
    result.log_id = parsed.log_id
    result.add(
        MerkleCheck(
            "merkle-proof-schema",
            PASS,
            (
                f"consistency proof schema is valid for tree sizes "
                f"{parsed.old_tree_size} -> {parsed.new_tree_size}"
            ),
        )
    )
    if expected_log_id is not None and parsed.log_id != expected_log_id:
        result.add(
            MerkleCheck(
                "merkle-proof-log",
                FAIL,
                "consistency proof log identifier does not match the trusted tree head",
                reason_code=MERKLE_PROOF_LOG_MISMATCH,
            )
        )
    else:
        result.add(MerkleCheck("merkle-proof-log", PASS, "consistency proof log identifier is consistent"))
    if expected_old_tree_size is not None and parsed.old_tree_size != expected_old_tree_size:
        result.add(
            MerkleCheck(
                "merkle-proof-old-size",
                FAIL,
                "consistency proof old tree size does not match the trusted prior tree head",
                reason_code=MERKLE_CONSISTENCY_SIZE_INVALID,
            )
        )
    else:
        result.add(
            MerkleCheck("merkle-proof-old-size", PASS, "consistency proof old tree size is consistent")
        )
    if expected_new_tree_size is not None and parsed.new_tree_size != expected_new_tree_size:
        result.add(
            MerkleCheck(
                "merkle-proof-new-size",
                FAIL,
                "consistency proof new tree size does not match the trusted new tree head",
                reason_code=MERKLE_CONSISTENCY_SIZE_INVALID,
            )
        )
    else:
        result.add(
            MerkleCheck("merkle-proof-new-size", PASS, "consistency proof new tree size is consistent")
        )
    if parsed.old_root != old_expected:
        result.add(
            MerkleCheck(
                "merkle-proof-old-root",
                FAIL,
                "consistency proof old root does not match the trusted prior root",
                reason_code=MERKLE_CONSISTENCY_OLD_ROOT_MISMATCH,
            )
        )
    else:
        result.add(MerkleCheck("merkle-proof-old-root", PASS, "consistency proof old root matches trust"))
    if parsed.new_root != new_expected:
        result.add(
            MerkleCheck(
                "merkle-proof-new-root",
                FAIL,
                "consistency proof new root does not match the trusted new root",
                reason_code=MERKLE_CONSISTENCY_NEW_ROOT_MISMATCH,
            )
        )
    else:
        result.add(MerkleCheck("merkle-proof-new-root", PASS, "consistency proof new root matches trust"))
    if parsed.old_tree_size == 0:
        verified = not parsed.proof and old_expected == EMPTY_ROOT
    elif parsed.old_tree_size == parsed.new_tree_size:
        verified = not parsed.proof and old_expected == new_expected
    else:
        verified = _verify_consistency_algorithm(
            parsed.old_tree_size,
            parsed.new_tree_size,
            _raw_digest(old_expected),
            _raw_digest(new_expected),
            [_raw_digest(node) for node in parsed.proof],
        )
    if verified:
        result.add(
            MerkleCheck(
                "merkle-consistency",
                PASS,
                "append-only consistency proof verifies against both trusted roots",
            )
        )
    else:
        result.add(
            MerkleCheck(
                "merkle-consistency",
                FAIL,
                "append-only consistency proof does not verify against both trusted roots",
                reason_code=MERKLE_CONSISTENCY_PROOF_INVALID,
            )
        )
    return result.finalize()


__all__ = [
    "CONSISTENCY_PROOF_FIELDS",
    "CONSISTENCY_PROOF_PROFILE",
    "EMPTY_ROOT",
    "EMPTY_ROOT_RAW",
    "HASH_ALGORITHM",
    "INCLUSION_PROOF_FIELDS",
    "INCLUSION_PROOF_PROFILE",
    "MAX_JSON_DEPTH",
    "MAX_LEAF_BYTES",
    "MAX_MERKLE_LEAVES",
    "MAX_PROOF_BYTES",
    "MAX_PROOF_SIBLINGS",
    "MERKLE_ALGORITHM",
    "MERKLE_ALGORITHM_UNKNOWN",
    "MERKLE_CONSISTENCY_NEW_ROOT_MISMATCH",
    "MERKLE_CONSISTENCY_OLD_ROOT_MISMATCH",
    "MERKLE_CONSISTENCY_PROOF_INVALID",
    "MERKLE_CONSISTENCY_SIZE_INVALID",
    "MERKLE_PROOF_EXPECTED_ROOT_MISSING",
    "MERKLE_PROOF_INDEX_INVALID",
    "MERKLE_PROOF_LEAF_INVALID",
    "MERKLE_PROOF_LOG_MISMATCH",
    "MERKLE_PROOF_POSITION_MISMATCH",
    "MERKLE_PROOF_ROOT_MISMATCH",
    "MERKLE_PROOF_SCHEMA_INVALID",
    "MERKLE_PROOF_SIBLING_COUNT",
    "MERKLE_PROOF_SIBLING_INVALID",
    "MERKLE_PROOF_TREE_SIZE_INVALID",
    "MERKLE_PROOF_VERIFICATION_FAILED",
    "MERKLE_SCHEMA_VERSION",
    "PROOF_POSITIONS",
    "ConsistencyProof",
    "InclusionProof",
    "MerkleCheck",
    "MerkleError",
    "MerkleTree",
    "MerkleVerification",
    "ProofSibling",
    "inclusion_path_directions",
    "largest_power_of_two_less_than",
    "leaf_digest",
    "leaf_hash",
    "loads_strict",
    "merkle_root",
    "node_hash",
    "sha256_digest",
    "validate_json_depth",
    "verify_consistency_proof",
    "verify_inclusion_proof",
]
