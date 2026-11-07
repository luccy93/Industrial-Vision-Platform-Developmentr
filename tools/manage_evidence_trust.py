"""Offline V31 evidence trust-key lifecycle management.

This tool never contacts a network service, cloud KMS, registry, or release
endpoint. Every command is explicit: it generates a local Ed25519 key, exports
a public descriptor, computes a fingerprint, or edits a trust store/trust state
that the operator names on the command line.

Private keys are never printed, logged, embedded in JSON output, or committed.
Public-key descriptors contain only public material. A replacement key is not
trusted until it is explicitly registered in a trust store.

Examples::

    python tools/manage_evidence_trust.py generate-key \\
        --key-id evidence-2026-01 --private-key keys/evidence-2026-01.pem \\
        --public-key keys/evidence-2026-01.pub.json
    python tools/manage_evidence_trust.py init-store --store trust-store.json
    python tools/manage_evidence_trust.py register-key \\
        --store trust-store.json --public-key keys/evidence-2026-01.pub.json \\
        --activated-at 2026-11-01T00:00:00Z
    python tools/manage_evidence_trust.py revoke-key \\
        --store trust-store.json --key-id evidence-2026-01 \\
        --revoked-at 2027-01-01T00:00:00Z --reason "scheduled rotation"
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from backend.app.core.redaction import dump_sanitized_json
from tools.release.trust import (
    HISTORICAL_REVOCATION_POLICIES,
    SUPPORTED_KEY_PURPOSES,
    TrustError,
    activate_key,
    expire_key,
    export_public_key,
    generate_key_files,
    load_public_key_descriptor,
    load_trust_state,
    load_trust_store,
    new_trust_store,
    register_public_key,
    revoke_key,
    rotate_key,
    write_public_key_descriptor,
    write_trust_store,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="manage_evidence_trust.py",
        description="Offline V31 evidence trust-key lifecycle management.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser(
        "generate-key",
        help="generate a local unencrypted Ed25519 private key and public descriptor",
    )
    generate.add_argument("--key-id", required=True)
    generate.add_argument("--private-key", type=Path, required=True)
    generate.add_argument("--public-key", type=Path)
    generate.add_argument("--generated-at")
    generate.add_argument("--json", action="store_true", dest="json_output")

    export = subparsers.add_parser(
        "export-public-key",
        help="derive a public-key descriptor from an existing private key",
    )
    export.add_argument("--private-key", type=Path, required=True)
    export.add_argument("--key-id", required=True)
    export.add_argument("--output", type=Path)
    export.add_argument("--generated-at")
    export.add_argument("--json", action="store_true", dest="json_output")

    fingerprint = subparsers.add_parser(
        "fingerprint",
        help="compute the sha256 fingerprint of a private key's public half",
    )
    fingerprint.add_argument("--private-key", type=Path, required=True)
    fingerprint.add_argument("--key-id", required=True)
    fingerprint.add_argument("--json", action="store_true", dest="json_output")

    init_store = subparsers.add_parser("init-store", help="create an empty trust store")
    init_store.add_argument("--store", type=Path, required=True)
    init_store.add_argument("--policy-version", default="v31")
    init_store.add_argument(
        "--historical-revocation-policy",
        choices=HISTORICAL_REVOCATION_POLICIES,
        default=HISTORICAL_REVOCATION_POLICIES[0],
    )
    init_store.add_argument("--json", action="store_true", dest="json_output")

    register = subparsers.add_parser(
        "register-key",
        help="explicitly trust a public-key descriptor",
    )
    register.add_argument("--store", type=Path, required=True)
    register.add_argument("--public-key", type=Path, required=True)
    register.add_argument("--activated-at")
    register.add_argument("--expires-at")
    register.add_argument(
        "--purpose",
        choices=SUPPORTED_KEY_PURPOSES,
        default=SUPPORTED_KEY_PURPOSES[0],
        help="explicit key purpose; V31 checkpoints use evidence_checkpoint_signing",
    )
    register.add_argument("--json", action="store_true", dest="json_output")

    activate = subparsers.add_parser("activate-key", help="set a key's activation time")
    activate.add_argument("--store", type=Path, required=True)
    activate.add_argument("--key-id", required=True)
    activate.add_argument("--activated-at", required=True)
    activate.add_argument("--json", action="store_true", dest="json_output")

    expire = subparsers.add_parser("expire-key", help="set a key's expiration time")
    expire.add_argument("--store", type=Path, required=True)
    expire.add_argument("--key-id", required=True)
    expire.add_argument("--expires-at", required=True)
    expire.add_argument("--json", action="store_true", dest="json_output")

    revoke = subparsers.add_parser("revoke-key", help="revoke a trusted key")
    revoke.add_argument("--store", type=Path, required=True)
    revoke.add_argument("--key-id", required=True)
    revoke.add_argument("--revoked-at", required=True)
    revoke.add_argument("--reason")
    revoke.add_argument("--json", action="store_true", dest="json_output")

    rotate = subparsers.add_parser(
        "rotate-key",
        help="register a replacement key and optionally revoke the old key",
    )
    rotate.add_argument("--store", type=Path, required=True)
    rotate.add_argument("--public-key", type=Path, required=True)
    rotate.add_argument("--old-key-id")
    rotate.add_argument("--activated-at")
    rotate.add_argument("--expires-at")
    rotate.add_argument("--revoke-at")
    rotate.add_argument("--reason")
    rotate.add_argument(
        "--purpose",
        choices=SUPPORTED_KEY_PURPOSES,
        default=SUPPORTED_KEY_PURPOSES[0],
    )
    rotate.add_argument("--json", action="store_true", dest="json_output")

    show_store = subparsers.add_parser("show-store", help="validate and print a trust store")
    show_store.add_argument("--store", type=Path, required=True)
    show_store.add_argument("--json", action="store_true", dest="json_output")

    show_state = subparsers.add_parser(
        "show-state",
        help="validate and print a local trust-state reference",
    )
    show_state.add_argument("--trust-state", type=Path, required=True)
    show_state.add_argument("--json", action="store_true", dest="json_output")
    return parser


def _emit(payload: Any, *, json_output: bool, lines: list[str]) -> None:
    if json_output:
        sys.stdout.write(dump_sanitized_json(payload))
        return
    for line in lines:
        print(line)


def _key_summary(store: Any) -> dict[str, Any]:
    return {
        "policy_version": store.policy_version,
        "historical_revocation_policy": store.historical_revocation_policy,
        "key_count": len(store.keys),
        "keys": [
            {
                "key_id": key.key_id,
                "fingerprint": key.fingerprint,
                "purpose": key.purpose,
                "allowed_algorithms": list(key.allowed_algorithms),
                "activated_at": key.activated_at,
                "expires_at": key.expires_at,
                "revoked_at": key.revoked_at,
                "revocation_reason": key.revocation_reason,
            }
            for key in store.keys
        ],
    }


def _store_lines(store: Any) -> list[str]:
    lines = [
        f"policy version: {store.policy_version}",
        f"historical revocation policy: {store.historical_revocation_policy}",
        f"trusted keys: {len(store.keys)}",
    ]
    for key in store.keys:
        state = "revoked" if key.revoked_at is not None else "trusted"
        lines.append(
            f"  {key.key_id} {key.fingerprint} {state} "
            f"activated={key.activated_at} expires={key.expires_at or 'never'}"
        )
    return lines


def run(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "generate-key":
            result = generate_key_files(
                key_id=args.key_id,
                private_key_path=args.private_key,
                public_key_path=args.public_key,
                generated_at=args.generated_at,
            )
            _emit(
                result,
                json_output=args.json_output,
                lines=[
                    f"key id: {result['key_id']}",
                    f"algorithm: {result['algorithm']}",
                    f"fingerprint: {result['fingerprint']}",
                    f"private key: {result['private_key_path']} "
                    f"(permissions: {result['private_key_permissions']})",
                    f"public key: {result['public_key_path'] or 'not exported'}",
                ],
            )
        elif args.command == "export-public-key":
            descriptor = export_public_key(
                private_key_path=args.private_key,
                key_id=args.key_id,
                generated_at=args.generated_at,
            )
            if args.output is not None:
                write_public_key_descriptor(args.output, descriptor, overwrite=False)
            _emit(
                descriptor,
                json_output=args.json_output,
                lines=[
                    f"key id: {descriptor['key_id']}",
                    f"fingerprint: {descriptor['fingerprint']}",
                    f"public key: {descriptor['public_key']}",
                    f"written: {args.output}" if args.output is not None else "not written",
                ],
            )
        elif args.command == "fingerprint":
            descriptor = export_public_key(
                private_key_path=args.private_key,
                key_id=args.key_id,
            )
            _emit(
                {
                    "key_id": descriptor["key_id"],
                    "algorithm": descriptor["algorithm"],
                    "fingerprint": descriptor["fingerprint"],
                },
                json_output=args.json_output,
                lines=[
                    f"key id: {descriptor['key_id']}",
                    f"algorithm: {descriptor['algorithm']}",
                    f"fingerprint: {descriptor['fingerprint']}",
                ],
            )
        elif args.command == "init-store":
            store = new_trust_store(
                policy_version=args.policy_version,
                historical_revocation_policy=args.historical_revocation_policy,
            )
            write_trust_store(args.store, store, overwrite=False)
            _emit(
                store.to_dict(),
                json_output=args.json_output,
                lines=[f"trust store written: {args.store}", *_store_lines(store)],
            )
        elif args.command == "register-key":
            store = load_trust_store(args.store)
            descriptor = load_public_key_descriptor(args.public_key)
            updated = register_public_key(
                store,
                descriptor,
                activated_at=args.activated_at,
                expires_at=args.expires_at,
                purpose=args.purpose,
            )
            write_trust_store(args.store, updated)
            _emit(
                updated.to_dict(),
                json_output=args.json_output,
                lines=[f"registered key: {descriptor['key_id']}", *_store_lines(updated)],
            )
        elif args.command == "activate-key":
            store = load_trust_store(args.store)
            updated = activate_key(store, args.key_id, activated_at=args.activated_at)
            write_trust_store(args.store, updated)
            _emit(
                updated.to_dict(),
                json_output=args.json_output,
                lines=[f"activated key: {args.key_id}", *_store_lines(updated)],
            )
        elif args.command == "expire-key":
            store = load_trust_store(args.store)
            updated = expire_key(store, args.key_id, expires_at=args.expires_at)
            write_trust_store(args.store, updated)
            _emit(
                updated.to_dict(),
                json_output=args.json_output,
                lines=[f"expired key: {args.key_id}", *_store_lines(updated)],
            )
        elif args.command == "revoke-key":
            store = load_trust_store(args.store)
            updated = revoke_key(
                store,
                args.key_id,
                revoked_at=args.revoked_at,
                reason=args.reason,
            )
            write_trust_store(args.store, updated)
            _emit(
                updated.to_dict(),
                json_output=args.json_output,
                lines=[f"revoked key: {args.key_id}", *_store_lines(updated)],
            )
        elif args.command == "rotate-key":
            store = load_trust_store(args.store)
            descriptor = load_public_key_descriptor(args.public_key)
            updated = rotate_key(
                store,
                descriptor,
                activated_at=args.activated_at,
                expires_at=args.expires_at,
                revoke_old_key_id=args.old_key_id,
                revoke_at=args.revoke_at,
                reason=args.reason,
                purpose=args.purpose,
            )
            write_trust_store(args.store, updated)
            _emit(
                updated.to_dict(),
                json_output=args.json_output,
                lines=[
                    f"registered replacement key: {descriptor['key_id']}",
                    *([f"revoked old key: {args.old_key_id}"] if args.old_key_id is not None else []),
                    *_store_lines(updated),
                ],
            )
        elif args.command == "show-store":
            store = load_trust_store(args.store)
            _emit(
                _key_summary(store),
                json_output=args.json_output,
                lines=_store_lines(store),
            )
        elif args.command == "show-state":
            state = load_trust_state(args.trust_state)
            if state is None:
                print(f"error: trust state is missing: {args.trust_state}", file=sys.stderr)
                return 2
            payload = state.to_dict()
            _emit(
                payload,
                json_output=args.json_output,
                lines=[
                    f"updated at: {state.updated_at}",
                    f"recorded checkpoints: {len(state.entries)}",
                    *(
                        f"  {entry['evidence_report_id']} sequence="
                        f"{entry['checkpoint_sequence']} checkpoint={entry['checkpoint_id']}"
                        for entry in state.entries
                    ),
                ],
            )
        else:  # pragma: no cover - argparse rejects unknown commands
            parser.error("unknown command")
            return 4
    except TrustError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    return run(argv)


if __name__ == "__main__":
    raise SystemExit(main())
