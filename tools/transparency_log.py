"""Offline V32 transparency-log and independent-anchoring CLI.

Every command is offline and read-only by default. The only commands that write
are explicit: ``init-log``, ``append-checkpoint``, ``create-tree-head``,
``create-inclusion-proof``, ``create-consistency-proof``, ``anchor-tree-head``,
and ``verify-tree-head --update-trust-state``. No command contacts a network
service, cloud KMS, GitHub, GHCR, staging system, or production endpoint.

Exit codes are stable: ``0`` PASS, ``1`` FAIL, ``2`` UNAVAILABLE, ``3``
NOT_RUN, ``4`` invalid invocation. A local test provider always reports
``SIMULATED`` anchoring; V32 never claims external anchoring occurred.

Private keys are never printed, logged, embedded in JSON output, or committed.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from backend.app.core.redaction import dump_sanitized_json, redact_text
from tools.release.evidence_verification import verification_exit_code
from tools.release.merkle import MAX_LEAF_BYTES, MerkleError, verify_consistency_proof, verify_inclusion_proof
from tools.release.transparency import (
    ANCHOR_EXTERNAL_VERIFIED,
    ANCHOR_NOT_CONFIGURED,
    ANCHOR_SIMULATED,
    ANCHOR_UNAVAILABLE,
    DEFAULT_LOG_ID,
    LocalTestAnchorProvider,
    ProviderUnavailable,
    TransparencyConflict,
    TransparencyError,
    TransparencyInvalid,
    TransparencyUnavailable,
    append_checkpoint,
    build_status_report,
    consistency_proof_for_log,
    create_tree_head,
    inclusion_proof_for_log,
    init_log,
    load_consistency_proof,
    load_inclusion_proof,
    load_receipt,
    load_tree_head,
    provider_status,
    read_log,
    verify_log,
    verify_receipt,
    verify_tree_head,
    write_consistency_proof,
    write_inclusion_proof,
    write_tree_head,
)
from tools.release.trust import TrustError, TrustUnavailable
from tools.release.verification import PASS


class _Parser(argparse.ArgumentParser):
    """Argument parser that maps invalid invocations to exit code 4."""

    def error(self, message: str) -> None:  # pragma: no cover - argparse path
        self.print_usage(sys.stderr)
        self.exit(4, f"{self.prog}: error: {message}\n")


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="transparency_log.py",
        description="Offline V32 append-only transparency log and anchor verification.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init-log", help="create a header-only transparency log")
    init.add_argument("--log", type=Path, required=True)
    init.add_argument("--log-id", default=DEFAULT_LOG_ID)
    init.add_argument("--timestamp")
    init.add_argument("--json", action="store_true", dest="json_output")

    append = subparsers.add_parser(
        "append-checkpoint",
        help="append one V31 signed-checkpoint reference to the log",
    )
    append.add_argument("--log", type=Path, required=True)
    append.add_argument("--checkpoint", type=Path, required=True)
    append.add_argument("--log-id")
    append.add_argument("--timestamp")
    append.add_argument("--full-verify", action="store_true")
    append.add_argument("--json", action="store_true", dest="json_output")

    create_head = subparsers.add_parser(
        "create-tree-head",
        help="sign the current Merkle root of a verified transparency log",
    )
    create_head.add_argument("--log", type=Path, required=True)
    create_head.add_argument("--private-key", type=Path, required=True)
    create_head.add_argument("--key-id", required=True)
    create_head.add_argument("--output", type=Path, required=True)
    create_head.add_argument("--timestamp")
    create_head.add_argument("--json", action="store_true", dest="json_output")

    verify_log_parser = subparsers.add_parser("verify-log", help="verify the complete log")
    verify_log_parser.add_argument("--log", type=Path, required=True)
    verify_log_parser.add_argument("--json", action="store_true", dest="json_output")

    create_inclusion = subparsers.add_parser(
        "create-inclusion-proof",
        help="create an RFC 6962 inclusion proof for one log entry",
    )
    create_inclusion.add_argument("--log", type=Path, required=True)
    create_inclusion.add_argument("--leaf-index", type=int, required=True)
    create_inclusion.add_argument("--output", type=Path, required=True)
    create_inclusion.add_argument("--json", action="store_true", dest="json_output")

    create_consistency = subparsers.add_parser(
        "create-consistency-proof",
        help="create an RFC 6962 consistency proof from an older tree size",
    )
    create_consistency.add_argument("--log", type=Path, required=True)
    create_consistency.add_argument("--old-tree-size", type=int, required=True)
    create_consistency.add_argument("--output", type=Path, required=True)
    create_consistency.add_argument("--json", action="store_true", dest="json_output")

    verify_inclusion = subparsers.add_parser(
        "verify-inclusion",
        help="verify an inclusion proof against a separately trusted root",
    )
    verify_inclusion.add_argument("--proof", type=Path, required=True)
    verify_inclusion.add_argument("--expected-root", required=True)
    verify_inclusion.add_argument("--log-id")
    verify_inclusion.add_argument("--tree-size", type=int)
    leaf_source = verify_inclusion.add_mutually_exclusive_group()
    leaf_source.add_argument("--leaf", type=Path, help="exact canonical leaf bytes")
    leaf_source.add_argument("--log", type=Path, help="log used to derive the leaf bytes")
    verify_inclusion.add_argument("--leaf-index", type=int)
    verify_inclusion.add_argument("--json", action="store_true", dest="json_output")

    verify_consistency = subparsers.add_parser(
        "verify-consistency",
        help="verify an append-only consistency proof against separately trusted roots",
    )
    verify_consistency.add_argument("--proof", type=Path, required=True)
    verify_consistency.add_argument("--expected-old-root", required=True)
    verify_consistency.add_argument("--expected-new-root", required=True)
    verify_consistency.add_argument("--log-id")
    verify_consistency.add_argument("--old-tree-size", type=int)
    verify_consistency.add_argument("--new-tree-size", type=int)
    verify_consistency.add_argument("--json", action="store_true", dest="json_output")

    verify_head = subparsers.add_parser(
        "verify-tree-head",
        help="verify a signed tree head against explicit V31 trust material",
    )
    verify_head.add_argument("--tree-head", type=Path, required=True)
    verify_head.add_argument("--trust-store", type=Path)
    verify_head.add_argument("--trusted-key-fingerprint")
    verify_head.add_argument("--trust-state", type=Path)
    verify_head.add_argument("--consistency-proof", type=Path)
    verify_head.add_argument("--require-trust-state", action="store_true")
    verify_head.add_argument("--update-trust-state", action="store_true")
    verify_head.add_argument("--state-updated-at")
    verify_head.add_argument("--json", action="store_true", dest="json_output")

    verify_receipt_parser = subparsers.add_parser(
        "verify-receipt",
        help="verify a provider receipt offline",
    )
    verify_receipt_parser.add_argument("--receipt", type=Path, required=True)
    verify_receipt_parser.add_argument("--tree-head", type=Path)
    verify_receipt_parser.add_argument("--provider-id")
    verify_receipt_parser.add_argument("--provider-fingerprint")
    verify_receipt_parser.add_argument("--now")
    verify_receipt_parser.add_argument("--json", action="store_true", dest="json_output")

    anchor = subparsers.add_parser(
        "anchor-tree-head",
        help="submit a tree head to the local deterministic test provider",
    )
    anchor.add_argument("--tree-head", type=Path, required=True)
    anchor.add_argument("--provider", choices=["local-test"], default="local-test")
    anchor.add_argument("--provider-id", default="local-test-anchor")
    anchor.add_argument("--provider-key", type=Path)
    anchor.add_argument("--provider-key-id", default="local-test-provider")
    anchor.add_argument("--receipt-dir", type=Path)
    anchor.add_argument("--tree-head-dir", type=Path)
    anchor.add_argument("--proof-dir", type=Path)
    anchor.add_argument("--timestamp")
    anchor.add_argument("--json", action="store_true", dest="json_output")

    provider_status_parser = subparsers.add_parser(
        "provider-status",
        help="show explicit anchor-provider status and capabilities",
    )
    provider_status_parser.add_argument("--provider", choices=["none", "local-test"], default="none")
    provider_status_parser.add_argument("--provider-id", default="local-test-anchor")
    provider_status_parser.add_argument("--provider-key", type=Path)
    provider_status_parser.add_argument("--provider-key-id", default="local-test-provider")
    provider_status_parser.add_argument("--receipt-dir", type=Path)
    provider_status_parser.add_argument("--tree-head-dir", type=Path)
    provider_status_parser.add_argument("--proof-dir", type=Path)
    provider_status_parser.add_argument("--json", action="store_true", dest="json_output")

    status = subparsers.add_parser(
        "status",
        help="build a deterministic offline transparency status report",
    )
    status.add_argument("--log", type=Path)
    status.add_argument("--tree-head", type=Path)
    status.add_argument("--receipt", type=Path)
    status.add_argument("--trust-store", type=Path)
    status.add_argument("--trust-state", type=Path)
    status.add_argument("--consistency-proof", type=Path)
    status.add_argument("--provider", choices=["none", "local-test"], default="none")
    status.add_argument("--provider-id", default="local-test-anchor")
    status.add_argument("--provider-key", type=Path)
    status.add_argument("--provider-key-id", default="local-test-provider")
    status.add_argument("--receipt-dir", type=Path)
    status.add_argument("--tree-head-dir", type=Path)
    status.add_argument("--proof-dir", type=Path)
    status.add_argument("--now")
    status.add_argument("--json", action="store_true", dest="json_output")

    return parser


def _emit(payload: dict[str, Any], *, json_output: bool, lines: list[str]) -> None:
    if json_output:
        sys.stdout.write(dump_sanitized_json(payload))
    else:
        for line in lines:
            print(redact_text(line))


def _provider_from_args(args: argparse.Namespace) -> LocalTestAnchorProvider | None:
    if getattr(args, "provider", "none") == "none":
        return None
    if args.provider_key is None or args.receipt_dir is None:
        return None
    return LocalTestAnchorProvider(
        provider_id=args.provider_id,
        receipt_dir=args.receipt_dir,
        private_key_path=args.provider_key,
        key_id=args.provider_key_id,
        tree_head_dir=getattr(args, "tree_head_dir", None),
        proof_dir=getattr(args, "proof_dir", None),
    )


def _render_merkle(result: Any) -> list[str]:
    lines = [
        f"outcome: {result.outcome}",
        f"proof type: {result.proof_type}",
        f"log id: {result.log_id}",
        f"tree size: {result.tree_size}",
    ]
    if result.leaf_index is not None:
        lines.append(f"leaf index: {result.leaf_index}")
    lines.extend(
        [
            f"computed root: {result.computed_root}",
            f"expected root: {result.expected_root}",
        ]
    )
    lines.extend(f"reason: {code}" for code in result.reason_codes)
    return lines


def _render_log(result: Any) -> list[str]:
    lines = [
        f"outcome: {result.outcome}",
        f"log id: {result.log_id}",
        f"tree size: {result.tree_size}",
        f"Merkle root: {result.merkle_root}",
        f"head entry digest: {result.head_entry_digest}",
    ]
    lines.extend(f"reason: {code}" for code in result.reason_codes)
    lines.extend(f"limitation: {item}" for item in result.limitations)
    return lines


def _render_tree_head(result: Any) -> list[str]:
    lines = [
        f"outcome: {result.outcome}",
        f"assurance: {result.assurance}",
        f"external anchor: {ANCHOR_NOT_CONFIGURED}",
        f"state update: {result.state_update}",
    ]
    if result.tree_head is not None:
        lines.extend(
            [
                f"tree head id: {result.tree_head.tree_head_id}",
                f"log id: {result.tree_head.log_id}",
                f"tree size: {result.tree_head.tree_size}",
                f"Merkle root: {result.tree_head.merkle_root}",
                f"key id: {result.tree_head.key_id}",
                f"fingerprint: {result.tree_head.public_key_fingerprint}",
            ]
        )
    lines.extend(f"reason: {code}" for code in result.reason_codes)
    lines.extend(f"limitation: {item}" for item in result.limitations)
    return lines


def _render_receipt(result: Any) -> list[str]:
    lines = [
        f"outcome: {result.outcome}",
        f"anchor status: {result.anchor_status}",
        f"assurance: {result.assurance}",
        "external anchoring: false",
    ]
    if result.receipt is not None:
        lines.extend(
            [
                f"receipt id: {result.receipt.receipt_id}",
                f"provider id: {result.receipt.provider_id}",
                f"provider type: {result.receipt.provider_type}",
                f"log id: {result.receipt.log_id}",
                f"tree size: {result.receipt.tree_size}",
                f"Merkle root: {result.receipt.merkle_root}",
                f"tree head id: {result.receipt.tree_head_id}",
                f"tree head digest: {result.receipt.tree_head_digest}",
                f"receipt timestamp: {result.receipt.receipt_timestamp}",
            ]
        )
    lines.extend(f"reason: {code}" for code in result.reason_codes)
    lines.extend(f"limitation: {item}" for item in result.limitations)
    return lines


def _render_status(report: dict[str, Any]) -> list[str]:
    lines = [
        f"outcome: {report['outcome']}",
        f"assurance: {report['assurance']}",
        f"external anchor: {report['external_anchor']}",
        "external anchoring: false",
        f"provider status: {report['provider']['anchor_status']}",
    ]
    for name, component in report["components"].items():
        if name == "provider":
            continue
        lines.append(f"{name}: {component['outcome']}")
    lines.extend(f"limitation: {item}" for item in report["limitations"])
    return lines


def run(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "init-log":
            header = init_log(
                args.log,
                log_id=args.log_id,
                timestamp=args.timestamp,
            )
            _emit(
                header.to_dict(),
                json_output=args.json_output,
                lines=[
                    f"transparency log created: {args.log}",
                    f"log id: {header.log_id}",
                    f"created at: {header.created_at}",
                ],
            )
        elif args.command == "append-checkpoint":
            entry = append_checkpoint(
                args.log,
                args.checkpoint,
                log_id=args.log_id,
                timestamp=args.timestamp,
                full_verify=args.full_verify,
            )
            _emit(
                entry.to_dict(),
                json_output=args.json_output,
                lines=[
                    f"checkpoint reference appended: {args.log}",
                    f"entry index: {entry.entry_index}",
                    f"entry id: {entry.entry_id}",
                    f"checkpoint id: {entry.checkpoint_id}",
                    f"checkpoint sequence: {entry.checkpoint_sequence}",
                    f"entry digest: {entry.digest()}",
                ],
            )
        elif args.command == "create-tree-head":
            tree_head = create_tree_head(
                args.log,
                private_key_path=args.private_key,
                key_id=args.key_id,
                timestamp=args.timestamp,
            )
            write_tree_head(args.output, tree_head)
            _emit(
                tree_head.to_dict(),
                json_output=args.json_output,
                lines=[
                    f"signed tree head written: {args.output}",
                    f"tree head id: {tree_head.tree_head_id}",
                    f"log id: {tree_head.log_id}",
                    f"tree size: {tree_head.tree_size}",
                    f"Merkle root: {tree_head.merkle_root}",
                    f"key id: {tree_head.key_id}",
                    f"fingerprint: {tree_head.public_key_fingerprint}",
                    f"payload digest: {tree_head.payload_digest}",
                ],
            )
        elif args.command == "verify-log":
            result = verify_log(args.log)
            _emit(result.to_dict(), json_output=args.json_output, lines=_render_log(result))
            return verification_exit_code(result.outcome)
        elif args.command == "create-inclusion-proof":
            proof = inclusion_proof_for_log(args.log, args.leaf_index)
            write_inclusion_proof(args.output, proof)
            _emit(
                proof.to_dict(),
                json_output=args.json_output,
                lines=[
                    f"inclusion proof written: {args.output}",
                    f"log id: {proof.log_id}",
                    f"tree size: {proof.tree_size}",
                    f"leaf index: {proof.leaf_index}",
                    f"leaf digest: {proof.leaf_digest}",
                    f"root: {proof.root}",
                ],
            )
        elif args.command == "create-consistency-proof":
            proof = consistency_proof_for_log(args.log, args.old_tree_size)
            write_consistency_proof(args.output, proof)
            _emit(
                proof.to_dict(),
                json_output=args.json_output,
                lines=[
                    f"consistency proof written: {args.output}",
                    f"log id: {proof.log_id}",
                    f"old tree size: {proof.old_tree_size}",
                    f"new tree size: {proof.new_tree_size}",
                    f"old root: {proof.old_root}",
                    f"new root: {proof.new_root}",
                ],
            )
        elif args.command == "verify-inclusion":
            leaf_bytes: bytes | None = None
            if args.leaf is not None:
                if not args.leaf.is_file():
                    raise TransparencyUnavailable("leaf bytes file is missing or unreadable")
                leaf_bytes = args.leaf.read_bytes()
                if len(leaf_bytes) > MAX_LEAF_BYTES:
                    raise TransparencyInvalid("leaf bytes exceed the supported size")
            elif args.log is not None:
                if args.leaf_index is None:
                    parser.error("--leaf-index is required with --log")
                log_result = verify_log(args.log)
                if log_result.outcome != PASS:
                    _emit(
                        log_result.to_dict(),
                        json_output=args.json_output,
                        lines=_render_log(log_result),
                    )
                    return verification_exit_code(log_result.outcome)
                log = read_log(args.log)
                if args.leaf_index < 0 or args.leaf_index >= log.tree_size:
                    raise TransparencyInvalid("leaf index is outside the transparency log")
                leaf_bytes = log.entries[args.leaf_index].canonical_bytes()
            proof = load_inclusion_proof(args.proof)
            result = verify_inclusion_proof(
                proof.to_dict(),
                expected_root=args.expected_root,
                expected_log_id=args.log_id,
                expected_tree_size=args.tree_size,
                leaf_bytes=leaf_bytes,
            )
            _emit(result.to_dict(), json_output=args.json_output, lines=_render_merkle(result))
            return verification_exit_code(result.outcome)
        elif args.command == "verify-consistency":
            proof = load_consistency_proof(args.proof)
            result = verify_consistency_proof(
                proof.to_dict(),
                expected_old_root=args.expected_old_root,
                expected_new_root=args.expected_new_root,
                expected_log_id=args.log_id,
                expected_old_tree_size=args.old_tree_size,
                expected_new_tree_size=args.new_tree_size,
            )
            _emit(result.to_dict(), json_output=args.json_output, lines=_render_merkle(result))
            return verification_exit_code(result.outcome)
        elif args.command == "verify-tree-head":
            if args.update_trust_state and args.trust_state is None:
                parser.error("--update-trust-state requires --trust-state")
            tree_head = load_tree_head(args.tree_head)
            consistency_proof = (
                load_consistency_proof(args.consistency_proof).to_dict()
                if args.consistency_proof is not None
                else None
            )
            result = verify_tree_head(
                tree_head.to_dict(),
                trust_store_path=args.trust_store,
                trusted_key_fingerprint=args.trusted_key_fingerprint,
                trust_state_path=args.trust_state,
                consistency_proof=consistency_proof,
                require_trust_state=args.require_trust_state,
                update_trust_state=args.update_trust_state,
                state_updated_at=args.state_updated_at,
            )
            if args.update_trust_state and result.outcome != PASS:
                print(
                    "note: transparency trust state was not updated because verification did not pass",
                    file=sys.stderr,
                )
            _emit(result.to_dict(), json_output=args.json_output, lines=_render_tree_head(result))
            return verification_exit_code(result.outcome)
        elif args.command == "verify-receipt":
            tree_head = load_tree_head(args.tree_head) if args.tree_head is not None else None
            result = verify_receipt(
                load_receipt(args.receipt),
                tree_head=tree_head,
                expected_provider_id=args.provider_id,
                trusted_provider_fingerprint=args.provider_fingerprint,
                now=args.now,
            )
            _emit(result.to_dict(), json_output=args.json_output, lines=_render_receipt(result))
            return verification_exit_code(result.outcome)
        elif args.command == "anchor-tree-head":
            if args.provider_key is None or args.receipt_dir is None:
                payload = provider_status(None)
                payload["detail"] = (
                    "local test provider requires --provider-key and --receipt-dir; no provider is configured"
                )
                _emit(
                    payload,
                    json_output=args.json_output,
                    lines=[
                        f"anchor status: {payload['anchor_status']}",
                        payload["detail"],
                        "external anchoring: false",
                    ],
                )
                return 2
            provider = _provider_from_args(args)
            assert provider is not None
            receipt = provider.submit_tree_head(
                load_tree_head(args.tree_head),
                timestamp=args.timestamp,
            )
            receipt_path = args.receipt_dir / f"{receipt.receipt_id}.json"
            _emit(
                {
                    "schema_version": 1,
                    "profile": "transparency_anchor_submission",
                    "outcome": PASS,
                    "anchor_status": receipt.anchor_status,
                    "assurance": ("simulated" if receipt.anchor_status == ANCHOR_SIMULATED else "external"),
                    "external_anchor": ANCHOR_NOT_CONFIGURED,
                    "external_anchoring": False,
                    "provider_id": receipt.provider_id,
                    "provider_type": receipt.provider_type,
                    "receipt_path": str(receipt_path),
                    "receipt": receipt.to_dict(),
                },
                json_output=args.json_output,
                lines=[
                    f"anchor status: {receipt.anchor_status}",
                    "external anchoring: false",
                    f"receipt written: {receipt_path}",
                    f"receipt id: {receipt.receipt_id}",
                    f"provider id: {receipt.provider_id}",
                    f"provider type: {receipt.provider_type}",
                    f"log id: {receipt.log_id}",
                    f"tree size: {receipt.tree_size}",
                    f"Merkle root: {receipt.merkle_root}",
                    f"tree head id: {receipt.tree_head_id}",
                    f"tree head digest: {receipt.tree_head_digest}",
                    f"receipt timestamp: {receipt.receipt_timestamp}",
                ],
            )
        elif args.command == "provider-status":
            provider = _provider_from_args(args)
            payload = provider_status(provider)
            if args.provider == "local-test" and provider is None:
                payload["detail"] = (
                    "local test provider requires --provider-key and --receipt-dir; no provider is configured"
                )
            _emit(
                payload,
                json_output=args.json_output,
                lines=[
                    f"provider id: {payload['provider_id']}",
                    f"provider type: {payload['provider_type']}",
                    f"anchor status: {payload['anchor_status']}",
                    f"assurance: {payload['assurance']}",
                    f"external anchoring: {str(payload['external_anchoring']).lower()}",
                    f"detail: {payload['detail']}",
                ],
            )
            if payload["anchor_status"] in (ANCHOR_NOT_CONFIGURED, ANCHOR_UNAVAILABLE):
                return 2
            if payload["anchor_status"] == ANCHOR_EXTERNAL_VERIFIED:
                return 0
            if payload["anchor_status"] == ANCHOR_SIMULATED:
                return 0
            return 2
        elif args.command == "status":
            provider = _provider_from_args(args)
            report = build_status_report(
                log_path=args.log,
                tree_head_path=args.tree_head,
                receipt_path=args.receipt,
                trust_store_path=args.trust_store,
                trust_state_path=args.trust_state,
                consistency_proof_path=args.consistency_proof,
                provider=provider,
                now=args.now,
            )
            _emit(report, json_output=args.json_output, lines=_render_status(report))
            return verification_exit_code(report["outcome"])
        else:  # pragma: no cover - argparse rejects unknown commands
            parser.error("unknown command")
            return 4
    except TransparencyUnavailable as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ProviderUnavailable as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (TransparencyConflict, TransparencyInvalid, MerkleError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except TransparencyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except TrustUnavailable as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except TrustError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 4
    return 0


def main(argv: list[str] | None = None) -> int:
    return run(argv)


if __name__ == "__main__":
    raise SystemExit(main())
