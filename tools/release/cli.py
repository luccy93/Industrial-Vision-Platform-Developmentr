"""Command line entry point for V22/V23 release validation.

Usage examples::

    python -m tools.release.cli validate-tag --tag v1.2.3
    python -m tools.release.cli verify-tag-commit --tag v1.2.3 --commit <40-hex>
    python -m tools.release.cli check-release --repo <owner>/<repo> --tag v1.2.3
    python -m tools.release.cli generate --inputs inputs.json \\
        --artifacts-dir release-artifacts --output release-artifacts/release-manifest.json
    python -m tools.release.cli verify --manifest release-artifacts/release-manifest.json \\
        --artifacts-dir release-artifacts --tag v1.2.3 --commit <40-hex> \\
        --profile production --repo-root . --main-ref origin/main
    python -m tools.release.cli check-report --report release-verification.json \\
        --manifest release-manifest.json --require-production
    python -m tools.release.cli verify-deploy --manifest release-manifest.json \\
        --report release-verification.json --require-verified --running --check-logs \\
        --preflight-report deployment-preflight.json
    python -m tools.release.cli preflight --manifest release-manifest.json \\
        --repo-root . --previous-manifest previous-manifest.json \\
        --output deployment-preflight.json
    python -m tools.release.cli rehearse-rollback --manifest release-manifest.json \\
        --previous-manifest previous-manifest.json \\
        --target-report release-verification.json \\
        --previous-report previous-release-verification.json \\
        --smoke-api-url https://staging.example.com --smoke-username smoke \\
        --execute --evidence-dir rehearsal-evidence \\
        --output rollback-rehearsal.json
    python -m tools.release.cli gpu-qualify --manifest release-manifest.json \\
        --execute --output gpu-runtime.json
    python -m tools.release.cli rollback-plan --manifest previous-manifest.json \\
        --report previous-release-verification.json
    python -m tools.release.cli smoke --api-url https://ops.example.com/api \\
        --web-url https://ops.example.com --username smoke@example.com
    python -m tools.release.cli publication-report --events published-images.jsonl \\
        --tag v1.2.3 --repository <owner>/<repo>
    python -m tools.release.cli qualify-prerequisites --repo-root . \\
        --profile local_validation --scope artifact --tag v1.2.3 --commit <40-hex>
    python -m tools.release.cli qualify --manifest release-artifacts/release-manifest.json \\
        --artifacts-dir release-artifacts --profile production_qualification --scope full \\
        --verification-report release-artifacts/release-verification.json \\
        --publication-report release-artifacts/publication-report.json \\
        --deployment-report release-artifacts/deployment-report.json \\
        --rehearsal-report release-artifacts/rehearsal/rollback-rehearsal.json \\
        --gpu-report release-artifacts/gpu-runtime.json \\
        --tag v1.2.3 --commit <40-hex>
    python -m tools.release.cli check-qualification --report release-artifacts/release-qualification.json \\
        --manifest release-artifacts/release-manifest.json --require-production \\
        --verification-report release-artifacts/release-verification.json \\
        --publication-report release-artifacts/publication-report.json \\
        --deployment-report release-artifacts/deployment-report.json \\
        --rehearsal-report release-artifacts/rehearsal/rollback-rehearsal.json \\
        --gpu-report release-artifacts/gpu-runtime.json
    python -m tools.release.cli audit-workflows --root .

Every command exits non-zero on a policy violation. Smoke passwords are read
from an environment variable, never from the command line.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from tools.release.deployment import (
    DEFAULT_CPU_COMPOSE,
    DEFAULT_GPU_COMPOSE,
    DeploymentError,
    render_rollback_plan,
    verification_report_errors,
    verify_deployment,
)
from tools.release.gpu import (
    GpuError,
    qualify_gpu_runtime,
    render_gpu_summary,
    write_gpu_report,
)
from tools.release.identity import (
    REQUIRED_IMAGES,
    IdentityError,
    release_conflicts,
    validate_tag,
    verify_tag_commit,
)
from tools.release.manifest import (
    ManifestError,
    build_manifest,
    load_manifest,
    render_summary,
    validate_manifest,
    write_manifest,
)
from tools.release.preflight import (
    PreflightError,
    render_preflight_summary,
    run_preflight,
    write_preflight_report,
)
from tools.release.prerequisites import (
    PrerequisiteError,
    probe_prerequisites,
    render_prerequisites_summary,
)
from tools.release.publication import (
    PublicationError,
    build_publication_report,
    render_publication_summary,
    write_publication_report,
)
from tools.release.qualification import (
    QUALIFICATION_PROFILES,
    SCOPES,
    QualificationError,
    qualification_report_errors,
    qualify_release,
    render_qualification_summary,
    write_qualification_report,
)
from tools.release.registry import RegistryError, check_release_conflicts
from tools.release.rehearsal import (
    RehearsalError,
    render_rehearsal_summary,
    run_rollback_rehearsal,
    write_rehearsal_report,
)
from tools.release.smoke import (
    SmokeError,
    render_smoke_summary,
    run_smoke,
    write_smoke_report,
)
from tools.release.verification import (
    PROFILES,
    VerificationError,
    render_verification_summary,
    verify_release,
    write_verification_report,
)
from tools.release.workflows import audit_workflows


def _parse_bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"true", "1", "yes"}:
        return True
    if normalized in {"false", "0", "no"}:
        return False
    raise argparse.ArgumentTypeError(f"expected true or false, got {value!r}")


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ManifestError(f"could not read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ManifestError(f"{path} is not valid JSON: {exc}") from exc


def _load_inputs(path: Path) -> dict[str, Any]:
    payload = _load_json(path)
    if not isinstance(payload, dict):
        raise ManifestError("release inputs must be a JSON object")
    return payload


def _write_json(payload: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m tools.release.cli",
        description="Validate release identity, manifests, deployments, and workflow pinning.",
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

    release_parser = subparsers.add_parser(
        "check-release",
        help="fail closed unless GitHub proves the release tag and GHCR tags are new",
    )
    release_parser.add_argument("--repo", required=True)
    release_parser.add_argument("--tag", required=True)
    release_parser.add_argument("--images", default=",".join(REQUIRED_IMAGES))

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

    summary_parser = subparsers.add_parser(
        "summary", help="render the release-notes artifact/digest/verification section"
    )
    summary_parser.add_argument("--manifest", type=Path, required=True)

    verification_parser = subparsers.add_parser(
        "verify",
        help="independently verify a release manifest, evidence, registry digests, and attestations",
    )
    verification_parser.add_argument("--manifest", type=Path, required=True)
    verification_parser.add_argument("--artifacts-dir", type=Path)
    verification_parser.add_argument("--tag")
    verification_parser.add_argument("--commit")
    verification_parser.add_argument("--profile", choices=PROFILES, default="local")
    verification_parser.add_argument("--repo-root", type=Path, default=Path("."))
    verification_parser.add_argument("--main-ref", default="origin/main")
    verification_parser.add_argument("--output", type=Path)

    report_parser = subparsers.add_parser(
        "check-report", help="require a verification report to authorize the exact manifest"
    )
    report_parser.add_argument("--report", type=Path, required=True)
    report_parser.add_argument("--manifest", type=Path, required=True)
    report_parser.add_argument("--require-production", action="store_true")

    deploy_parser = subparsers.add_parser(
        "verify-deploy", help="verify digest-pinned Compose configuration and a running stack"
    )
    deploy_parser.add_argument("--manifest", type=Path, required=True)
    deploy_parser.add_argument("--report", type=Path)
    deploy_parser.add_argument("--preflight-report", type=Path)
    deploy_parser.add_argument("--require-verified", action="store_true")
    deploy_parser.add_argument("--check-logs", action="store_true")
    deploy_parser.add_argument("--logs-tail", type=int, default=500)
    deploy_parser.add_argument("--gpu", action="store_true")
    deploy_parser.add_argument("--project")
    deploy_parser.add_argument("--running", action="store_true")
    deploy_parser.add_argument("--compose", action="append", default=None)
    deploy_parser.add_argument("--tag")
    deploy_parser.add_argument("--commit")
    deploy_parser.add_argument("--output", type=Path)

    rollback_parser = subparsers.add_parser(
        "rollback-plan", help="render a digest-pinned rollback plan that preserves data"
    )
    rollback_parser.add_argument("--manifest", type=Path, required=True)
    rollback_parser.add_argument("--report", type=Path)
    rollback_parser.add_argument("--allow-unverified", action="store_true")
    rollback_parser.add_argument("--gpu", action="store_true")
    rollback_parser.add_argument("--backup-file", default="backup.sql")
    rollback_parser.add_argument("--current-manifest", type=Path)
    rollback_parser.add_argument("--tag")
    rollback_parser.add_argument("--commit")
    rollback_parser.add_argument("--output", type=Path)

    smoke_parser = subparsers.add_parser(
        "smoke", help="run post-deployment HTTP, auth, WebSocket, and header checks"
    )
    smoke_parser.add_argument("--api-url", required=True)
    smoke_parser.add_argument("--web-url")
    smoke_parser.add_argument("--ws-url")
    smoke_parser.add_argument("--username")
    smoke_parser.add_argument("--password-env", default="IVP_SMOKE_PASSWORD")
    smoke_parser.add_argument("--timeout", type=float, default=10.0)
    smoke_parser.add_argument("--insecure", action="store_true")
    smoke_parser.add_argument("--manifest", type=Path)
    smoke_parser.add_argument("--tag")
    smoke_parser.add_argument("--commit")
    smoke_parser.add_argument("--output", type=Path)

    preflight_parser = subparsers.add_parser(
        "preflight",
        help="prove Compose, migration, volume, and rollback safety before deployment",
    )
    preflight_parser.add_argument("--manifest", type=Path, required=True)
    preflight_parser.add_argument("--repo-root", type=Path, default=Path("."))
    preflight_parser.add_argument("--compose", action="append", default=None)
    preflight_parser.add_argument("--gpu", action="store_true")
    preflight_parser.add_argument("--project")
    preflight_parser.add_argument("--previous-manifest", type=Path)
    preflight_parser.add_argument("--tag")
    preflight_parser.add_argument("--commit")
    preflight_parser.add_argument("--previous-tag")
    preflight_parser.add_argument("--previous-commit")
    preflight_parser.add_argument("--output", type=Path)

    rehearsal_parser = subparsers.add_parser(
        "rehearse-rollback",
        help="execute and verify a digest-pinned rollback rehearsal",
    )
    rehearsal_parser.add_argument("--manifest", type=Path, required=True)
    rehearsal_parser.add_argument("--previous-manifest", type=Path, required=True)
    rehearsal_parser.add_argument("--target-report", type=Path)
    rehearsal_parser.add_argument("--previous-report", type=Path)
    rehearsal_parser.add_argument("--compose", action="append", default=None)
    rehearsal_parser.add_argument("--gpu", action="store_true")
    rehearsal_parser.add_argument("--project")
    rehearsal_parser.add_argument("--execute", action="store_true")
    rehearsal_parser.add_argument("--smoke-api-url")
    rehearsal_parser.add_argument("--smoke-web-url")
    rehearsal_parser.add_argument("--smoke-username")
    rehearsal_parser.add_argument("--smoke-password-env", default="IVP_SMOKE_PASSWORD")
    rehearsal_parser.add_argument("--smoke-timeout", type=float, default=10.0)
    rehearsal_parser.add_argument("--insecure", action="store_true")
    rehearsal_parser.add_argument("--evidence-dir", type=Path)
    rehearsal_parser.add_argument("--tag")
    rehearsal_parser.add_argument("--commit")
    rehearsal_parser.add_argument("--previous-tag")
    rehearsal_parser.add_argument("--previous-commit")
    rehearsal_parser.add_argument("--output", type=Path)

    gpu_parser = subparsers.add_parser(
        "gpu-qualify",
        help="prove the NVIDIA driver, Docker runtime, and GPU container access",
    )
    gpu_parser.add_argument("--manifest", type=Path, required=True)
    gpu_parser.add_argument("--execute", action="store_true")
    gpu_parser.add_argument("--skip-container", action="store_true")
    gpu_parser.add_argument("--tag")
    gpu_parser.add_argument("--commit")
    gpu_parser.add_argument("--output", type=Path)

    publication_parser = subparsers.add_parser(
        "publication-report", help="report complete, partial, or failed image publication"
    )
    publication_parser.add_argument("--events", type=Path, required=True)
    publication_parser.add_argument("--tag")
    publication_parser.add_argument("--repository")
    publication_parser.add_argument("--output", type=Path)
    publication_parser.add_argument("--fail-on-incomplete", action="store_true")

    publication_summary = subparsers.add_parser(
        "publication-summary", help="render a previously generated publication report"
    )
    publication_summary.add_argument("--report", type=Path, required=True)
    publication_summary.add_argument("--require-complete", action="store_true")

    prerequisites_parser = subparsers.add_parser(
        "qualify-prerequisites",
        help="probe live qualification prerequisites without printing secrets",
    )
    prerequisites_parser.add_argument("--repo-root", type=Path, default=Path("."))
    prerequisites_parser.add_argument("--profile", choices=QUALIFICATION_PROFILES, default="local_validation")
    prerequisites_parser.add_argument("--scope", choices=SCOPES, default="artifact")
    prerequisites_parser.add_argument("--tag")
    prerequisites_parser.add_argument("--commit")
    prerequisites_parser.add_argument("--repository")
    prerequisites_parser.add_argument("--artifacts-dir", type=Path)
    prerequisites_parser.add_argument("--verification-report", type=Path)
    prerequisites_parser.add_argument("--publication-report", type=Path)
    prerequisites_parser.add_argument("--deployment-report", type=Path)
    prerequisites_parser.add_argument("--rehearsal-report", type=Path)
    prerequisites_parser.add_argument("--gpu-report", type=Path)
    prerequisites_parser.add_argument("--main-ref", default="origin/main")
    prerequisites_parser.add_argument("--require-github", type=_parse_bool)
    prerequisites_parser.add_argument("--require-docker", type=_parse_bool)
    prerequisites_parser.add_argument("--require-gpu", action="store_true")
    prerequisites_parser.add_argument("--require-live-evidence", action="store_true")
    prerequisites_parser.add_argument("--production-authorized", action="store_true")
    prerequisites_parser.add_argument("--output", type=Path)

    qualify_parser = subparsers.add_parser(
        "qualify", help="qualify an exact release manifest and its live evidence"
    )
    qualify_parser.add_argument("--manifest", type=Path, required=True)
    qualify_parser.add_argument("--artifacts-dir", type=Path, required=True)
    qualify_parser.add_argument("--profile", choices=QUALIFICATION_PROFILES, required=True)
    qualify_parser.add_argument("--scope", choices=SCOPES, required=True)
    qualify_parser.add_argument("--verification-report", type=Path, required=True)
    qualify_parser.add_argument("--publication-report", type=Path)
    qualify_parser.add_argument("--deployment-report", type=Path)
    qualify_parser.add_argument("--rehearsal-report", type=Path)
    qualify_parser.add_argument("--gpu-report", type=Path)
    qualify_parser.add_argument("--tag")
    qualify_parser.add_argument("--commit")
    qualify_parser.add_argument("--repository")
    qualify_parser.add_argument("--repo-root", type=Path, default=Path("."))
    qualify_parser.add_argument("--main-ref", default="origin/main")
    qualify_parser.add_argument("--require-live-evidence", action="store_true")
    qualify_parser.add_argument("--require-gpu-runtime", action="store_true")
    qualify_parser.add_argument("--output", type=Path)

    qualification_gate = subparsers.add_parser(
        "check-qualification",
        help="require a qualification report to authorize the exact manifest",
    )
    qualification_gate.add_argument("--report", type=Path, required=True)
    qualification_gate.add_argument("--manifest", type=Path, required=True)
    qualification_gate.add_argument("--verification-report", type=Path)
    qualification_gate.add_argument("--publication-report", type=Path)
    qualification_gate.add_argument("--deployment-report", type=Path)
    qualification_gate.add_argument("--rehearsal-report", type=Path)
    qualification_gate.add_argument("--gpu-report", type=Path)
    qualification_gate.add_argument("--require-production", action="store_true")

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
        elif args.command == "check-release":
            images = [part.strip() for part in args.images.split(",") if part.strip()]
            unknown = sorted(set(images) - set(REQUIRED_IMAGES))
            if unknown:
                raise IdentityError(f"unknown release images: {', '.join(unknown)}")
            token = os.environ.get("GITHUB_TOKEN", "")
            if not token:
                raise RegistryError("GITHUB_TOKEN is required to verify release immutability")
            conflicts = check_release_conflicts(args.repo, args.tag, images, token)
            if conflicts:
                for conflict in conflicts:
                    print(f"conflict: {conflict}", file=sys.stderr)
                return 1
            print(f"release {args.tag} is new; no conflicting release or GHCR tags")
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
        elif args.command == "summary":
            sys.stdout.write(render_summary(load_manifest(args.manifest)))
        elif args.command == "verify":
            artifacts_dir = args.artifacts_dir or args.manifest.parent
            report = verify_release(
                args.manifest,
                artifacts_dir=artifacts_dir,
                profile=args.profile,
                expected_tag=args.tag,
                expected_commit=args.commit,
                repo_root=args.repo_root,
                main_ref=args.main_ref,
            )
            if args.output is not None:
                write_verification_report(report, args.output)
            sys.stdout.write(render_verification_summary(report))
            if not report["verified"]:
                return 1
        elif args.command == "check-report":
            manifest = load_manifest(args.manifest)
            report = _load_json(args.report)
            errors = verification_report_errors(
                report,
                manifest,
                manifest_path=args.manifest,
                require_production=args.require_production,
            )
            if errors:
                for error in errors:
                    print(f"error: {error}", file=sys.stderr)
                return 1
            print(f"verification report authorizes deployment: {args.report}")
        elif args.command == "verify-deploy":
            compose_files = (
                [Path(item) for item in args.compose]
                if args.compose
                else [Path(item) for item in (DEFAULT_GPU_COMPOSE if args.gpu else DEFAULT_CPU_COMPOSE)]
            )
            result = verify_deployment(
                args.manifest,
                compose_files=compose_files,
                gpu=args.gpu,
                project=args.project,
                running=args.running,
                report_path=args.report,
                require_verified=args.require_verified,
                preflight_report_path=args.preflight_report,
                check_logs=args.check_logs,
                logs_tail=args.logs_tail,
                expected_tag=args.tag,
                expected_commit=args.commit,
            )
            if args.output is not None:
                _write_json(result, args.output)
            print(f"deployment verification: {result['state']}")
            for check in result["checks"]:
                print(f"- {check['name']}: {check['state']} - {check['detail']}")
            if result["state"] != "PASS":
                return 1
        elif args.command == "rollback-plan":
            plan = render_rollback_plan(
                args.manifest,
                gpu=args.gpu,
                backup_file=args.backup_file,
                current_manifest_path=args.current_manifest,
                verification_report_path=args.report,
                allow_unverified=args.allow_unverified,
                expected_tag=args.tag,
                expected_commit=args.commit,
            )
            if args.output is not None:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(plan, encoding="utf-8", newline="\n")
                print(f"wrote rollback plan: {args.output}")
            else:
                sys.stdout.write(plan)
        elif args.command == "smoke":
            password = None
            if args.username:
                password = os.environ.get(args.password_env)
                if not password:
                    raise SmokeError(
                        f"set {args.password_env} to the smoke user's password; "
                        "passwords are never accepted on the command line"
                    )
            report = run_smoke(
                args.api_url,
                web_url=args.web_url,
                ws_url=args.ws_url,
                username=args.username,
                password=password,
                timeout=args.timeout,
                verify_tls=not args.insecure,
                manifest_path=args.manifest,
                expected_tag=args.tag,
                expected_commit=args.commit,
            )
            if args.output is not None:
                write_smoke_report(report, args.output)
            sys.stdout.write(render_smoke_summary(report))
            if not report["verified"]:
                return 1
        elif args.command == "publication-report":
            report = build_publication_report(
                args.events,
                tag=args.tag,
                source_repository=args.repository,
            )
            if args.output is not None:
                write_publication_report(report, args.output)
            sys.stdout.write(render_publication_summary(report))
            if args.fail_on_incomplete and not report["complete"]:
                return 1
        elif args.command == "publication-summary":
            report = _load_json(args.report)
            if not isinstance(report, dict):
                raise PublicationError("publication report must be a JSON object")
            sys.stdout.write(render_publication_summary(report))
            if args.require_complete and report.get("complete") is not True:
                return 1
        elif args.command == "qualify-prerequisites":
            report = probe_prerequisites(
                repo_root=args.repo_root,
                profile=args.profile,
                scope=args.scope,
                expected_tag=args.tag,
                expected_commit=args.commit,
                expected_repository=args.repository,
                artifacts_dir=args.artifacts_dir,
                verification_report=args.verification_report,
                publication_report=args.publication_report,
                deployment_report=args.deployment_report,
                rehearsal_report=args.rehearsal_report,
                gpu_report=args.gpu_report,
                main_ref=args.main_ref,
                require_github=args.require_github,
                require_docker=args.require_docker,
                require_gpu=args.require_gpu,
                require_live_evidence=args.require_live_evidence,
                production_authorized=args.production_authorized,
            )
            if args.output is not None:
                _write_json(report, args.output)
            sys.stdout.write(render_prerequisites_summary(report))
            if not report["ready"]:
                return 1
        elif args.command == "qualify":
            report = qualify_release(
                args.manifest,
                artifacts_dir=args.artifacts_dir,
                profile=args.profile,
                scope=args.scope,
                verification_report_path=args.verification_report,
                publication_report_path=args.publication_report,
                deployment_report_path=args.deployment_report,
                rehearsal_report_path=args.rehearsal_report,
                gpu_report_path=args.gpu_report,
                expected_tag=args.tag,
                expected_commit=args.commit,
                expected_repository=args.repository,
                repo_root=args.repo_root,
                main_ref=args.main_ref,
                require_live_evidence=args.require_live_evidence,
                require_gpu_runtime=args.require_gpu_runtime,
            )
            if args.output is not None:
                write_qualification_report(report, args.output)
            sys.stdout.write(render_qualification_summary(report))
            if not report["qualified"]:
                return 1
        elif args.command == "check-qualification":
            manifest = load_manifest(args.manifest)
            report = _load_json(args.report)
            errors = qualification_report_errors(
                report,
                manifest,
                manifest_path=args.manifest,
                require_production=args.require_production,
                verification_report_path=args.verification_report,
                publication_report_path=args.publication_report,
                deployment_report_path=args.deployment_report,
                rehearsal_report_path=args.rehearsal_report,
                gpu_report_path=args.gpu_report,
            )
            if errors:
                for error in errors:
                    print(f"error: {error}", file=sys.stderr)
                return 1
            print(f"qualification report authorizes deployment: {args.report}")
        elif args.command == "preflight":
            compose_files = (
                [Path(item) for item in args.compose]
                if args.compose
                else [Path(item) for item in (DEFAULT_GPU_COMPOSE if args.gpu else DEFAULT_CPU_COMPOSE)]
            )
            report = run_preflight(
                args.manifest,
                repo_root=args.repo_root,
                compose_files=compose_files,
                gpu=args.gpu,
                project=args.project,
                previous_manifest_path=args.previous_manifest,
                expected_tag=args.tag,
                expected_commit=args.commit,
                expected_previous_tag=args.previous_tag,
                expected_previous_commit=args.previous_commit,
            )
            if args.output is not None:
                write_preflight_report(report, args.output)
            sys.stdout.write(render_preflight_summary(report))
            if not report["verified"]:
                return 1
        elif args.command == "rehearse-rollback":
            if args.execute:
                if args.evidence_dir is None:
                    raise RehearsalError(
                        "--execute requires --evidence-dir so every rehearsal step is hash-verifiable"
                    )
                if args.output is None:
                    raise RehearsalError(
                        "--execute requires --output so the rehearsal report and its evidence are retained"
                    )
                if args.evidence_dir.resolve() != args.output.parent.resolve():
                    raise RehearsalError(
                        "--evidence-dir must be the directory that contains --output; "
                        "qualification resolves rehearsal evidence relative to the report"
                    )
            password = None
            if args.smoke_username:
                password = os.environ.get(args.smoke_password_env)
                if not password:
                    raise RehearsalError(
                        f"set {args.smoke_password_env} to the smoke user's password; "
                        "passwords are never accepted on the command line"
                    )
            compose_files = (
                [Path(item) for item in args.compose]
                if args.compose
                else [Path(item) for item in (DEFAULT_GPU_COMPOSE if args.gpu else DEFAULT_CPU_COMPOSE)]
            )
            report = run_rollback_rehearsal(
                args.manifest,
                args.previous_manifest,
                compose_files=compose_files,
                gpu=args.gpu,
                project=args.project,
                execute=args.execute,
                target_verification_report=args.target_report,
                previous_verification_report=args.previous_report,
                smoke_api_url=args.smoke_api_url,
                smoke_web_url=args.smoke_web_url,
                smoke_username=args.smoke_username,
                smoke_password=password,
                smoke_timeout=args.smoke_timeout,
                smoke_verify_tls=not args.insecure,
                expected_tag=args.tag,
                expected_commit=args.commit,
                expected_previous_tag=args.previous_tag,
                expected_previous_commit=args.previous_commit,
                evidence_dir=args.evidence_dir,
            )
            if args.output is not None:
                write_rehearsal_report(report, args.output)
            sys.stdout.write(render_rehearsal_summary(report))
            if not report["verified"]:
                return 1
        elif args.command == "gpu-qualify":
            report = qualify_gpu_runtime(
                args.manifest,
                execute=args.execute,
                run_container=not args.skip_container,
                expected_tag=args.tag,
                expected_commit=args.commit,
            )
            if args.output is not None:
                write_gpu_report(report, args.output)
            sys.stdout.write(render_gpu_summary(report))
            if not report["verified"]:
                return 1
        elif args.command == "audit-workflows":
            problems = audit_workflows(args.root)
            if problems:
                for problem in problems:
                    print(problem, file=sys.stderr)
                return 1
            print("workflows are pinned")
    except (
        DeploymentError,
        GpuError,
        IdentityError,
        ManifestError,
        PreflightError,
        PrerequisiteError,
        PublicationError,
        QualificationError,
        RehearsalError,
        RegistryError,
        SmokeError,
        VerificationError,
        OSError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
