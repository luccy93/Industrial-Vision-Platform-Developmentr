"""Command line entry point for V22 release validation.

Usage examples::

    python -m tools.release.cli validate-tag --tag v1.2.3
    python -m tools.release.cli verify-tag-commit --tag v1.2.3 --commit <40-hex>
    python -m tools.release.cli check-conflicts --tag v1.2.3 \\
        --release-exists false --image-tags-exist false
    python -m tools.release.cli generate --inputs inputs.json \\
        --artifacts-dir release-artifacts --output release-artifacts/release-manifest.json
    python -m tools.release.cli validate --manifest release-artifacts/release-manifest.json \\
        --artifacts-dir release-artifacts --tag v1.2.3 --commit <40-hex>
    python -m tools.release.cli audit-workflows --root .

Every command exits non-zero on a policy violation.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from tools.release.identity import (
    IdentityError,
    release_conflicts,
    validate_tag,
    verify_tag_commit,
)
from tools.release.manifest import (
    ManifestError,
    build_manifest,
    load_manifest,
    validate_manifest,
    write_manifest,
)
from tools.release.workflows import audit_workflows


def _parse_bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"true", "1", "yes"}:
        return True
    if normalized in {"false", "0", "no"}:
        return False
    raise argparse.ArgumentTypeError(f"expected true or false, got {value!r}")


def _load_inputs(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ManifestError(f"could not read release inputs {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ManifestError(f"release inputs {path} are not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ManifestError("release inputs must be a JSON object")
    return payload


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m tools.release.cli",
        description="Validate release identity, manifests, and workflow pinning.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    tag_parser = subparsers.add_parser("validate-tag", help="validate a stable SemVer release tag")
    tag_parser.add_argument("--tag", required=True)

    verify_parser = subparsers.add_parser(
        "verify-tag-commit",
        help="require the tag to match the workflow commit and be reachable from main",
    )
    verify_parser.add_argument("--tag", required=True)
    verify_parser.add_argument("--commit", required=True)
    verify_parser.add_argument("--repo-root", type=Path, default=Path("."))
    verify_parser.add_argument("--main-ref", default="origin/main")

    conflict_parser = subparsers.add_parser(
        "check-conflicts",
        help="refuse to reuse an existing release tag or published image tags",
    )
    conflict_parser.add_argument("--tag", required=True)
    conflict_parser.add_argument("--release-exists", type=_parse_bool, required=True)
    conflict_parser.add_argument("--image-tags-exist", type=_parse_bool, required=True)

    generate_parser = subparsers.add_parser(
        "generate", help="build and validate the release manifest from observed facts"
    )
    generate_parser.add_argument("--inputs", type=Path, required=True)
    generate_parser.add_argument("--artifacts-dir", type=Path, required=True)
    generate_parser.add_argument("--output", type=Path, required=True)

    validate_parser = subparsers.add_parser("validate", help="validate an existing release manifest")
    validate_parser.add_argument("--manifest", type=Path, required=True)
    validate_parser.add_argument("--artifacts-dir", type=Path)
    validate_parser.add_argument("--tag")
    validate_parser.add_argument("--commit")

    audit_parser = subparsers.add_parser(
        "audit-workflows", help="reject unpinned actions and container images"
    )
    audit_parser.add_argument("--root", type=Path, default=Path("."))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "validate-tag":
            validate_tag(args.tag)
            print(f"release tag is valid: {args.tag}")
        elif args.command == "verify-tag-commit":
            verify_tag_commit(args.tag, args.commit, args.repo_root, main_ref=args.main_ref)
            print(f"tag {args.tag} matches {args.commit} and is reachable from {args.main_ref}")
        elif args.command == "check-conflicts":
            conflicts = release_conflicts(
                args.tag,
                release_exists=args.release_exists,
                image_tags_exist=args.image_tags_exist,
            )
            if conflicts:
                for conflict in conflicts:
                    print(f"conflict: {conflict}", file=sys.stderr)
                return 1
            print(f"release {args.tag} is new; no conflicting release or image tags")
        elif args.command == "generate":
            manifest = build_manifest(_load_inputs(args.inputs), args.artifacts_dir)
            write_manifest(manifest, args.output)
            print(f"wrote release manifest: {args.output}")
        elif args.command == "validate":
            validate_manifest(
                load_manifest(args.manifest),
                artifacts_dir=args.artifacts_dir,
                expected_tag=args.tag,
                expected_commit=args.commit,
            )
            print(f"release manifest is valid: {args.manifest}")
        elif args.command == "audit-workflows":
            problems = audit_workflows(args.root)
            if problems:
                for problem in problems:
                    print(problem, file=sys.stderr)
                return 1
            print("workflows are pinned")
    except (IdentityError, ManifestError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
