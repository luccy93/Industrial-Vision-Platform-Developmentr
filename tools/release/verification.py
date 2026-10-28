"""Independent release verification and evidence-state reporting (V23).

The manifest records what the release workflow observed. Verification is a
separate step: it inspects the recorded evidence, classifies every result as
PASS, FAIL, NOT_RUN, UNAVAILABLE, or SIMULATED, and, in production mode,
queries GHCR and GitHub attestations instead of trusting the manifest alone.

Nothing in this module treats missing, placeholder, simulated, or externally
unavailable evidence as a pass. Production verification fails unless every
required check passes. A local-only run is never reported as production
verification.
"""

from __future__ import annotations

import base64
import json
import re
import shlex
import shutil
import subprocess
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from tools.release.identity import (
    DIGEST_PATTERN,
    REQUIRED_IMAGES,
    IdentityError,
    release_image_tags,
    validate_commit,
    validate_tag,
    verify_tag_commit,
)
from tools.release.manifest import (
    PROVENANCE_PREDICATE,
    SBOM_PREDICATE,
    ManifestError,
    load_manifest,
    manifest_errors,
    sha256_file,
    utc_now_iso,
)

VERIFICATION_SCHEMA_VERSION = 2
PROFILES = ("local", "production")
PASS = "PASS"
FAIL = "FAIL"
NOT_RUN = "NOT_RUN"
UNAVAILABLE = "UNAVAILABLE"
SIMULATED = "SIMULATED"
EVIDENCE_STATES = (PASS, FAIL, NOT_RUN, UNAVAILABLE, SIMULATED)

CHECK_FIELDS = ("name", "state", "required", "detail", "command")
SUBJECT_FIELDS = ("tag", "commit", "source_repository")
ARTIFACT_FIELDS = ("cpu", "gpu")
ARTIFACT_STATUS_FIELDS = ("state", "images", "runtime_state", "runtime_verified")
REPORT_FIELDS = (
    "schema_version",
    "profile",
    "generated_at",
    "manifest_sha256",
    "subject",
    "overall_state",
    "verified",
    "production_verified",
    "artifact_status",
    "checks",
    "limitations",
)

CPU_IMAGES = ("api", "web")
GPU_IMAGE = "api-gpu"
RELEASE_WORKFLOW = ".github/workflows/release.yml"

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
SEVERITY_COUNT = re.compile(r"\b(?:CRITICAL|HIGH)\s*:\s*[1-9][0-9]*", re.IGNORECASE)
SEVERITY_CELLS = {"CRITICAL", "HIGH"}
TRIVY_TABLE_MARKERS = ("Report Summary", "No vulnerabilities found")
SIMULATED_MARKERS = ("SIMULATED EVIDENCE", "PLACEHOLDER SCAN", "NOT A REAL SCAN")
REGISTRY_NOT_FOUND_MARKERS = ("manifest unknown", "no such manifest", "not found", "404")
REGISTRY_AUTH_MARKERS = ("unauthorized", "denied", "authentication required", "login")


class VerificationError(RuntimeError):
    """The requested verification could not be performed."""


CommandRunner = Callable[..., subprocess.CompletedProcess[str]]
IdentityVerifier = Callable[..., None]


def default_runner(
    args: Sequence[str],
    *,
    timeout: int = 180,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        capture_output=True,
        check=False,
        env=env,
        text=True,
        timeout=timeout,
    )


def _command_text(args: Sequence[str]) -> str:
    return " ".join(shlex.quote(str(part)) for part in args)


def _check(
    name: str,
    state: str,
    required: bool,
    detail: str,
    command: str | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "state": state,
        "required": required,
        "detail": detail,
        "command": command,
    }


def _plain_file_name(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and "/" not in value
        and "\\" not in value
        and value not in {".", ".."}
    )


def _is_placeholder_digest(value: Any) -> bool:
    """Reject syntactically valid but obviously fabricated digests."""
    if not isinstance(value, str) or DIGEST_PATTERN.fullmatch(value) is None:
        return False
    return len(set(value.split(":", 1)[1])) == 1


def _canonical(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def _artifact(artifacts_dir: Path, evidence: Any) -> tuple[Path | None, str]:
    if not isinstance(evidence, Mapping):
        return None, "evidence record is missing"
    path = evidence.get("path")
    digest = evidence.get("sha256")
    if not _plain_file_name(path):
        return None, "evidence path is not a plain file name"
    if not isinstance(digest, str) or DIGEST_PATTERN.fullmatch(digest) is None:
        return None, "evidence sha256 is invalid"
    candidate = artifacts_dir / path
    if not candidate.is_file():
        return None, f"evidence file does not exist: {path}"
    try:
        actual = sha256_file(candidate)
    except OSError as exc:
        return None, f"could not hash evidence {path}: {exc}"
    if actual != digest:
        return None, f"evidence hash mismatch for {path}: expected {digest}, got {actual}"
    return candidate, "evidence hash matches"


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _verify_sbom(
    name: str, image: Mapping[str, Any], artifacts_dir: Path
) -> tuple[dict[str, Any], Any | None]:
    label = f"sbom:{name}"
    path, detail = _artifact(artifacts_dir, image.get("sbom"))
    if path is None:
        return _check(label, FAIL, True, detail), None
    try:
        payload = _load_json(path)
    except (OSError, json.JSONDecodeError) as exc:
        return _check(label, FAIL, True, f"SBOM is not valid JSON: {exc}"), None
    if not isinstance(payload, Mapping):
        return _check(label, FAIL, True, "SBOM must be a JSON object"), None
    if payload.get("_simulation") is True or payload.get("_placeholder") is True:
        return (
            _check(label, SIMULATED, True, "SBOM is a simulation placeholder, not a generated SBOM"),
            None,
        )
    version = payload.get("spdxVersion")
    packages = payload.get("packages")
    if not isinstance(version, str) or not version.startswith("SPDX-"):
        return _check(label, FAIL, True, "SBOM is missing a valid spdxVersion"), None
    if not isinstance(packages, list) or not packages:
        return _check(label, FAIL, True, "SBOM contains no packages"), None
    return (
        _check(label, PASS, True, f"SPDX SBOM is valid and lists {len(packages)} packages"),
        payload,
    )


def _scan_text_state(text: str) -> tuple[str, str]:
    normalized = ANSI_ESCAPE.sub("", text)
    stripped = normalized.strip()
    if not stripped:
        return FAIL, "scan log is empty"
    upper = normalized.upper()
    if any(marker in upper for marker in SIMULATED_MARKERS):
        return SIMULATED, "scan log is a simulation placeholder, not a scanner result"
    if stripped.startswith(("{", "[")):
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError as exc:
            return FAIL, f"scan JSON is invalid: {exc}"
        if isinstance(payload, Mapping) and (
            payload.get("_simulation") is True or payload.get("_placeholder") is True
        ):
            return SIMULATED, "scan JSON is a simulation placeholder, not a scanner result"
        results = payload.get("Results") if isinstance(payload, Mapping) else payload
        if results is None:
            results = []
        if not isinstance(results, list):
            return FAIL, "scan JSON Results is not an array"
        findings = 0
        for result in results:
            if not isinstance(result, Mapping):
                continue
            vulnerabilities = result.get("Vulnerabilities") or []
            if not isinstance(vulnerabilities, list):
                continue
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, Mapping):
                    continue
                if str(vulnerability.get("Severity", "")).upper() in SEVERITY_CELLS:
                    findings += 1
        if findings:
            return FAIL, f"scan JSON contains {findings} CRITICAL/HIGH finding(s)"
        return PASS, "trivy JSON reports no CRITICAL/HIGH findings"
    if not any(marker in normalized for marker in TRIVY_TABLE_MARKERS):
        return FAIL, "scan log is not a recognized trivy report"
    if SEVERITY_COUNT.search(normalized):
        return FAIL, "trivy summary reports CRITICAL/HIGH findings"
    for line in normalized.splitlines():
        cells = {cell.strip().upper() for cell in re.split(r"[|\u2502]", line)}
        if cells & SEVERITY_CELLS:
            return FAIL, "trivy table contains a CRITICAL/HIGH severity row"
    return PASS, "trivy table reports zero CRITICAL/HIGH findings"


def _verify_scan(name: str, image: Mapping[str, Any], artifacts_dir: Path) -> dict[str, Any]:
    label = f"scan:{name}"
    path, detail = _artifact(artifacts_dir, (image.get("scan") or {}).get("log"))
    if path is None:
        return _check(label, FAIL, True, detail)
    try:
        state, scan_detail = _scan_text_state(path.read_text(encoding="utf-8"))
    except OSError as exc:
        return _check(label, FAIL, True, f"could not read scan log: {exc}")
    return _check(label, state, True, scan_detail)


def _bundle_objects(path: Path) -> list[Any]:
    text = path.read_text(encoding="utf-8")
    objects: list[Any] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        value = json.loads(line)
        if isinstance(value, list):
            objects.extend(value)
        else:
            objects.append(value)
    return objects


def _bundle_statement(objects: Sequence[Any]) -> tuple[Any | None, str]:
    for item in objects:
        if not isinstance(item, Mapping):
            continue
        envelope = item.get("dsseEnvelope")
        if not isinstance(envelope, Mapping):
            continue
        payload = envelope.get("payload")
        if not isinstance(payload, str) or not payload.strip():
            continue
        try:
            decoded = base64.b64decode(payload, validate=True)
            statement = json.loads(decoded.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(statement, Mapping):
            return statement, "DSSE payload decoded"
    return None, "attestation bundle has no decodable DSSE statement"


def _statement_binds_digest(statement: Mapping[str, Any], digest: str) -> bool:
    hex_digest = digest.split(":", 1)[1]
    subjects = statement.get("subject")
    if not isinstance(subjects, list):
        return False
    for subject in subjects:
        if not isinstance(subject, Mapping):
            continue
        subject_digest = subject.get("digest")
        if isinstance(subject_digest, Mapping) and subject_digest.get("sha256") == hex_digest:
            return True
    return False


def _predicate_matches(attested: Any, expected: Any) -> bool:
    if _canonical(attested) == _canonical(expected):
        return True
    if not isinstance(attested, Mapping) or not isinstance(expected, Mapping):
        return False
    # actions/attest records the SBOM document as the predicate. Compare the
    # SPDX identity and package inventory so formatting differences are safe
    # while a substituted SBOM is still rejected.
    return attested.get("spdxVersion") == expected.get("spdxVersion") and attested.get(
        "packages"
    ) == expected.get("packages")


def _verify_bundle(
    label: str,
    image: Mapping[str, Any],
    artifacts_dir: Path,
    field: str,
    *,
    digest: str,
    predicate: str,
    required: bool,
    expected_predicate: Any | None = None,
) -> dict[str, Any]:
    path, detail = _artifact(artifacts_dir, (image.get(field) or {}).get("evidence"))
    if path is None:
        return _check(label, FAIL, required, detail)
    try:
        objects = _bundle_objects(path)
    except (OSError, json.JSONDecodeError) as exc:
        return _check(label, FAIL, required, f"attestation bundle is not valid JSONL: {exc}")
    if not objects:
        return _check(label, FAIL, required, "attestation bundle is empty")
    if any(isinstance(item, Mapping) and item.get("_simulation") is True for item in objects):
        return _check(
            label,
            SIMULATED,
            required,
            "attestation bundle is a local simulation placeholder, not signed evidence",
        )
    envelope_present = any(
        isinstance(item, Mapping)
        and isinstance(item.get("dsseEnvelope"), Mapping)
        and isinstance(item.get("verificationMaterial"), Mapping)
        for item in objects
    )
    if not envelope_present:
        return _check(
            label,
            FAIL,
            required,
            "attestation bundle has no DSSE envelope or verification material",
        )
    statement, statement_detail = _bundle_statement(objects)
    if statement is None:
        return _check(label, FAIL, required, statement_detail)
    if statement.get("predicateType") != predicate:
        return _check(
            label,
            FAIL,
            required,
            f"bundle predicate {statement.get('predicateType')!r} does not match {predicate!r}",
        )
    if not _statement_binds_digest(statement, digest):
        return _check(label, FAIL, required, "bundle statement does not bind the image digest")
    if expected_predicate is not None and not _predicate_matches(
        statement.get("predicate"), expected_predicate
    ):
        return _check(label, FAIL, required, "bundle predicate does not match the local SBOM")
    return _check(label, PASS, required, "bundle statement binds the digest, predicate, and evidence hash")


def _classify_registry_failure(detail: str) -> str:
    lowered = detail.lower()
    if any(marker in lowered for marker in REGISTRY_NOT_FOUND_MARKERS):
        return FAIL
    if any(marker in lowered for marker in REGISTRY_AUTH_MARKERS):
        return UNAVAILABLE
    return UNAVAILABLE


def _registry_check(
    image: Mapping[str, Any],
    *,
    source_repository: str,
    tag: str,
    commit: str,
    runner: CommandRunner,
    which: Callable[[str], str | None],
    pull: bool = True,
) -> dict[str, Any]:
    name = str(image.get("name"))
    label = f"registry:{name}"
    if which("docker") is None:
        return _check(label, UNAVAILABLE, True, "docker is not installed; registry digest not checked")
    repository = image.get("repository")
    digest = image.get("digest")
    tags = image.get("tags")
    image_id = image.get("image_id")
    if not isinstance(repository, str) or not isinstance(digest, str) or not isinstance(tags, list):
        return _check(label, FAIL, True, "manifest image record is incomplete")
    if DIGEST_PATTERN.fullmatch(digest) is None:
        return _check(label, FAIL, True, "manifest image digest is invalid")
    if _is_placeholder_digest(digest):
        return _check(label, FAIL, True, "manifest image digest is a placeholder, not a real artifact")
    expected_repository = f"ghcr.io/{source_repository.lower()}/{name}"
    if repository != expected_repository:
        return _check(
            label,
            FAIL,
            True,
            f"repository {repository!r} is not the expected {expected_repository!r}",
        )
    if not tag or not commit:
        return _check(label, FAIL, True, "manifest tag and commit are required for registry verification")
    expected_tags = set(release_image_tags(tag, commit))
    if not all(isinstance(item, str) for item in tags) or set(tags) != expected_tags:
        return _check(
            label,
            FAIL,
            True,
            f"registry tags {tags!r} are not exactly {sorted(expected_tags)!r}",
        )
    references = [f"{repository}:{tag_value}" for tag_value in tags]
    references.append(f"{repository}@{digest}")
    commands: list[str] = []
    for reference in references:
        args = [
            "docker",
            "buildx",
            "imagetools",
            "inspect",
            "--format",
            "{{.Manifest.Digest}}",
            reference,
        ]
        command = _command_text(args)
        commands.append(command)
        try:
            result = runner(args, timeout=180)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return _check(label, UNAVAILABLE, True, f"registry query failed: {exc}", command)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "no output").strip()
            state = _classify_registry_failure(detail)
            return _check(
                label,
                state,
                True,
                f"could not resolve {reference}: {detail[:500]}",
                command,
            )
        observed = result.stdout.strip().splitlines()[-1].strip() if result.stdout.strip() else ""
        if DIGEST_PATTERN.fullmatch(observed) is None:
            return _check(label, FAIL, True, f"{reference} returned invalid digest {observed!r}", command)
        if observed != digest:
            return _check(
                label,
                FAIL,
                True,
                f"{reference} resolves to {observed}, manifest records {digest}",
                command,
            )
    if not pull:
        return _check(
            label,
            PASS,
            True,
            f"all {len(references)} references resolve to {digest}",
            " && ".join(commands),
        )
    pull_args = ["docker", "pull", f"{repository}@{digest}"]
    pull_command = _command_text(pull_args)
    commands.append(pull_command)
    try:
        pull_result = runner(pull_args, timeout=600)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _check(label, UNAVAILABLE, True, f"docker pull failed: {exc}", pull_command)
    if pull_result.returncode != 0:
        detail = (pull_result.stderr or pull_result.stdout or "no output").strip()
        state = _classify_registry_failure(detail)
        return _check(
            label,
            state,
            True,
            f"could not pull {repository}@{digest}: {detail[:500]}",
            pull_command,
        )
    inspect_args = ["docker", "image", "inspect", "--format", "{{.Id}}", f"{repository}@{digest}"]
    inspect_command = _command_text(inspect_args)
    commands.append(inspect_command)
    try:
        inspect_result = runner(inspect_args, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _check(label, UNAVAILABLE, True, f"docker inspect failed: {exc}", inspect_command)
    if inspect_result.returncode != 0:
        detail = (inspect_result.stderr or inspect_result.stdout or "no output").strip()
        return _check(
            label, FAIL, True, f"pulled image could not be inspected: {detail[:500]}", inspect_command
        )
    observed_id = inspect_result.stdout.strip()
    if not isinstance(image_id, str) or observed_id != image_id:
        return _check(
            label,
            FAIL,
            True,
            f"pulled image ID {observed_id} does not match manifest image_id {image_id!r}",
            inspect_command,
        )
    cleanup_args = ["docker", "image", "rm", f"{repository}@{digest}"]
    try:
        runner(cleanup_args, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        pass
    return _check(
        label,
        PASS,
        True,
        f"all {len(references)} references resolve to {digest} and the pulled image ID matches",
        " && ".join(commands),
    )


def _attestation_result(
    payload: Any,
    *,
    digest: str,
    predicate: str,
    expected_predicate: Any | None = None,
    require_predicate_match: bool = False,
) -> tuple[bool, str]:
    hex_digest = digest.split(":", 1)[1]
    items = payload if isinstance(payload, list) else [payload]
    saw_statement = False
    for item in items:
        if not isinstance(item, Mapping):
            continue
        result = item.get("verificationResult")
        if not isinstance(result, Mapping):
            continue
        signature = result.get("signature")
        certificate = signature.get("certificate") if isinstance(signature, Mapping) else None
        if not isinstance(certificate, Mapping):
            continue
        statement = result.get("statement")
        if not isinstance(statement, Mapping):
            continue
        if statement.get("predicateType") != predicate:
            continue
        saw_statement = True
        subjects = statement.get("subject")
        if not isinstance(subjects, list):
            continue
        matched = False
        for subject in subjects:
            if not isinstance(subject, Mapping):
                continue
            subject_digest = subject.get("digest")
            if isinstance(subject_digest, Mapping) and subject_digest.get("sha256") == hex_digest:
                matched = True
                break
        if not matched:
            continue
        if require_predicate_match:
            if expected_predicate is None:
                return False, "local SBOM is unavailable; the attested SBOM cannot be compared"
            if not _predicate_matches(statement.get("predicate"), expected_predicate):
                return False, "attested predicate does not match the local SBOM"
        return True, "GitHub attestation is signed, trusted, and bound to the image digest"
    if saw_statement:
        return False, "verification output does not bind the expected digest and predicate"
    return False, "verification output has no signed statement with the expected predicate"


def _attestation_command(
    *,
    repository: str,
    digest: str,
    source_repository: str,
    tag: str,
    commit: str,
    predicate: str,
    bundle: Path | None = None,
) -> list[str]:
    args = [
        "gh",
        "attestation",
        "verify",
        f"oci://{repository}@{digest}",
        "--repo",
        source_repository,
        "--signer-workflow",
        f"{source_repository}/{RELEASE_WORKFLOW}",
        "--source-digest",
        commit,
        "--source-ref",
        f"refs/tags/{tag}",
        "--deny-self-hosted-runners",
        "--predicate-type",
        predicate,
        "--format",
        "json",
    ]
    if bundle is not None:
        args.extend(["--bundle", str(bundle)])
    return args


def _attestation_check(
    label: str,
    image: Mapping[str, Any],
    *,
    source_repository: str,
    tag: str,
    commit: str,
    predicate: str,
    expected_predicate: Any | None,
    require_predicate_match: bool,
    runner: CommandRunner,
    which: Callable[[str], str | None],
) -> dict[str, Any]:
    if which("gh") is None:
        return _check(label, UNAVAILABLE, True, "GitHub CLI is not installed; attestation not checked")
    repository = image.get("repository")
    digest = image.get("digest")
    if not isinstance(repository, str) or not isinstance(digest, str):
        return _check(label, FAIL, True, "manifest image record is incomplete")
    if not source_repository or not tag or not commit:
        return _check(label, FAIL, True, "manifest identity is required for attestation verification")
    args = _attestation_command(
        repository=repository,
        digest=digest,
        source_repository=source_repository,
        tag=tag,
        commit=commit,
        predicate=predicate,
    )
    command = _command_text(args)
    try:
        result = runner(args, timeout=180)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _check(label, UNAVAILABLE, True, f"attestation verification failed: {exc}", command)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "no output").strip()
        return _check(label, FAIL, True, f"attestation was rejected: {detail[:500]}", command)
    output = result.stdout.strip()
    if not output:
        return _check(label, FAIL, True, "attestation verification returned no evidence", command)
    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        return _check(label, FAIL, True, "attestation verification output is malformed", command)
    ok, detail = _attestation_result(
        payload,
        digest=digest,
        predicate=predicate,
        expected_predicate=expected_predicate,
        require_predicate_match=require_predicate_match,
    )
    return _check(label, PASS if ok else FAIL, True, detail, command)


def _bundle_signature_check(
    label: str,
    image: Mapping[str, Any],
    artifacts_dir: Path,
    field: str,
    *,
    source_repository: str,
    tag: str,
    commit: str,
    predicate: str,
    expected_predicate: Any | None,
    require_predicate_match: bool,
    runner: CommandRunner,
    which: Callable[[str], str | None],
) -> dict[str, Any]:
    if which("gh") is None:
        return _check(label, UNAVAILABLE, True, "GitHub CLI is not installed; bundle not verified")
    path, detail = _artifact(artifacts_dir, (image.get(field) or {}).get("evidence"))
    if path is None:
        return _check(label, FAIL, True, detail)
    repository = image.get("repository")
    digest = image.get("digest")
    if not isinstance(repository, str) or not isinstance(digest, str):
        return _check(label, FAIL, True, "manifest image record is incomplete")
    if not source_repository or not tag or not commit:
        return _check(label, FAIL, True, "manifest identity is required for bundle verification")
    args = _attestation_command(
        repository=repository,
        digest=digest,
        source_repository=source_repository,
        tag=tag,
        commit=commit,
        predicate=predicate,
        bundle=path,
    )
    command = _command_text(args)
    try:
        result = runner(args, timeout=180)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _check(label, UNAVAILABLE, True, f"bundle verification failed: {exc}", command)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "no output").strip()
        return _check(label, FAIL, True, f"recorded bundle was rejected: {detail[:500]}", command)
    output = result.stdout.strip()
    if not output:
        return _check(label, FAIL, True, "bundle verification returned no evidence", command)
    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        return _check(label, FAIL, True, "bundle verification output is malformed", command)
    ok, detail = _attestation_result(
        payload,
        digest=digest,
        predicate=predicate,
        expected_predicate=expected_predicate,
        require_predicate_match=require_predicate_match,
    )
    return _check(label, PASS if ok else FAIL, True, detail, command)


def _image_map(manifest: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    images = manifest.get("images")
    if not isinstance(images, list):
        return {}
    result: dict[str, Mapping[str, Any]] = {}
    for image in images:
        if isinstance(image, Mapping) and isinstance(image.get("name"), str):
            result.setdefault(image["name"], image)
    return result


def _identity_check(
    manifest: Mapping[str, Any],
    *,
    profile: str,
    expected_tag: str | None,
    expected_commit: str | None,
) -> dict[str, Any]:
    required = profile == "production" or expected_tag is not None or expected_commit is not None
    if expected_tag is None or expected_commit is None:
        if required:
            return _check(
                "identity",
                FAIL,
                True,
                "production verification requires the expected tag and commit",
            )
        return _check(
            "identity",
            NOT_RUN,
            False,
            "no expected tag/commit supplied; manifest identity was not independently checked",
        )
    release = manifest.get("release")
    tag = release.get("tag") if isinstance(release, Mapping) else None
    commit = release.get("commit") if isinstance(release, Mapping) else None
    if tag != expected_tag:
        return _check("identity", FAIL, True, f"manifest tag {tag!r} does not match {expected_tag!r}")
    if commit != expected_commit:
        return _check(
            "identity",
            FAIL,
            True,
            f"manifest commit {commit!r} does not match {expected_commit!r}",
        )
    return _check("identity", PASS, True, f"manifest is bound to {expected_tag} at {expected_commit}")


def _source_identity_check(
    *,
    expected_tag: str | None,
    expected_commit: str | None,
    repo_root: Path | None,
    main_ref: str,
    profile: str,
    identity_verifier: IdentityVerifier,
) -> dict[str, Any]:
    required = profile == "production" or expected_tag is not None or expected_commit is not None
    label = "source-identity"
    if expected_tag is None or expected_commit is None:
        if required:
            return _check(label, FAIL, True, "source identity requires the expected tag and commit")
        return _check(label, NOT_RUN, False, "no expected tag/commit supplied")
    if repo_root is None:
        return _check(
            label,
            FAIL if required else NOT_RUN,
            required,
            "no repository checkout supplied; tag-to-commit and main-branch reachability were not verified",
        )
    try:
        identity_verifier(expected_tag, expected_commit, repo_root, main_ref=main_ref)
    except IdentityError as exc:
        return _check(label, FAIL, True, str(exc))
    except (OSError, subprocess.SubprocessError) as exc:
        return _check(label, UNAVAILABLE, required, f"git verification could not run: {exc}")
    return _check(
        label,
        PASS,
        required,
        f"tag {expected_tag} resolves to {expected_commit} and is reachable from {main_ref}",
    )


def _workflow_identity_check(manifest: Mapping[str, Any]) -> dict[str, Any]:
    build = manifest.get("build")
    release = manifest.get("release")
    workflow = build.get("workflow") if isinstance(build, Mapping) else None
    source_repository = release.get("source_repository") if isinstance(release, Mapping) else None
    run_url = release.get("workflow_run_url") if isinstance(release, Mapping) else None
    if workflow != RELEASE_WORKFLOW:
        return _check(
            "workflow-identity",
            FAIL,
            True,
            f"build.workflow {workflow!r} is not the release workflow {RELEASE_WORKFLOW!r}",
        )
    if not isinstance(source_repository, str) or not isinstance(run_url, str):
        return _check("workflow-identity", FAIL, True, "release repository and workflow run URL are missing")
    expected_prefix = f"https://github.com/{source_repository}/actions/runs/"
    if not run_url.startswith(expected_prefix):
        return _check(
            "workflow-identity",
            FAIL,
            True,
            "workflow run URL does not belong to the recorded source repository",
        )
    return _check(
        "workflow-identity",
        PASS,
        True,
        f"release was produced by {RELEASE_WORKFLOW} in {source_repository}",
    )


def _digest_check(name: str, image: Mapping[str, Any]) -> dict[str, Any]:
    label = f"digest:{name}"
    digest = image.get("digest")
    image_id = image.get("image_id")
    pulled_image_id = image.get("pulled_image_id")
    if not isinstance(digest, str) or DIGEST_PATTERN.fullmatch(digest) is None:
        return _check(label, FAIL, True, "image digest is missing or malformed")
    if _is_placeholder_digest(digest):
        return _check(label, FAIL, True, "image digest is a placeholder, not a real artifact")
    if not isinstance(image_id, str) or DIGEST_PATTERN.fullmatch(image_id) is None:
        return _check(label, FAIL, True, "image_id is missing or malformed")
    if not isinstance(pulled_image_id, str) or DIGEST_PATTERN.fullmatch(pulled_image_id) is None:
        return _check(label, FAIL, True, "pulled_image_id is missing or malformed")
    if _is_placeholder_digest(image_id) or _is_placeholder_digest(pulled_image_id):
        return _check(label, FAIL, True, "image ID is a placeholder, not a real artifact")
    if image_id != pulled_image_id:
        return _check(
            label,
            FAIL,
            True,
            "locally built and pulled image IDs differ; digest association is unproven",
        )
    return _check(label, PASS, True, f"immutable digest {digest} has a matching pull-by-digest image ID")


def _gpu_checks(manifest: Mapping[str, Any]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    images = _image_map(manifest)
    variants = manifest.get("variants")
    gpu = variants.get("gpu") if isinstance(variants, Mapping) else None
    published = gpu.get("published") is True if isinstance(gpu, Mapping) else False
    if GPU_IMAGE in images and published:
        checks.append(_check("gpu-artifact", PASS, True, "GPU image is present and marked published"))
    else:
        checks.append(_check("gpu-artifact", FAIL, True, "GPU image is missing or not marked published"))
    runtime_smoke = gpu.get("runtime_smoke") if isinstance(gpu, Mapping) else None
    reason = gpu.get("runtime_smoke_reason") if isinstance(gpu, Mapping) else None
    if runtime_smoke == "passed":
        checks.append(_check("gpu-runtime", PASS, False, "GPU runtime smoke recorded as passed"))
    elif runtime_smoke == "not_run":
        checks.append(
            _check(
                "gpu-runtime",
                NOT_RUN,
                False,
                f"GPU runtime smoke was not run: {reason or 'no reason recorded'}",
            )
        )
    else:
        checks.append(_check("gpu-runtime", FAIL, False, "GPU runtime smoke result is missing or invalid"))
    return checks


def _aggregate(checks: Sequence[Mapping[str, Any]]) -> str:
    states = {str(check.get("state")) for check in checks}
    required_states = {str(check.get("state")) for check in checks if check.get("required") is True}
    if FAIL in states:
        return FAIL
    if SIMULATED in states:
        return SIMULATED
    if UNAVAILABLE in required_states:
        return UNAVAILABLE
    if NOT_RUN in required_states:
        return NOT_RUN
    return PASS


def _artifact_status(checks: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    def image_state(name: str) -> str:
        relevant = [
            check
            for check in checks
            if check.get("required") is True and str(check.get("name", "")).endswith(f":{name}")
        ]
        return _aggregate(relevant) if relevant else FAIL

    cpu_images = {name: image_state(name) for name in CPU_IMAGES}
    gpu_images = {GPU_IMAGE: image_state(GPU_IMAGE)}
    gpu_runtime = next((check for check in checks if check.get("name") == "gpu-runtime"), None)
    gpu_runtime_state = str(gpu_runtime.get("state")) if gpu_runtime else FAIL
    return {
        "cpu": {
            "state": _aggregate(
                [
                    check
                    for check in checks
                    if check.get("required") is True
                    and any(str(check.get("name", "")).endswith(f":{name}") for name in CPU_IMAGES)
                ]
            ),
            "images": cpu_images,
            "runtime_state": NOT_RUN,
            "runtime_verified": False,
        },
        "gpu": {
            "state": _aggregate(
                [
                    check
                    for check in checks
                    if check.get("required") is True and str(check.get("name", "")).endswith(f":{GPU_IMAGE}")
                ]
            ),
            "images": gpu_images,
            "runtime_state": gpu_runtime_state,
            "runtime_verified": gpu_runtime_state == PASS,
        },
    }


def _subject(manifest: Mapping[str, Any]) -> dict[str, Any]:
    release = manifest.get("release")
    if not isinstance(release, Mapping):
        return {"tag": None, "commit": None, "source_repository": None}
    return {
        "tag": release.get("tag"),
        "commit": release.get("commit"),
        "source_repository": release.get("source_repository"),
    }


def verify_release(
    manifest_path: Path,
    *,
    artifacts_dir: Path,
    profile: str = "local",
    expected_tag: str | None = None,
    expected_commit: str | None = None,
    repo_root: Path | None = None,
    main_ref: str = "origin/main",
    runner: CommandRunner = default_runner,
    which: Callable[[str], str | None] = shutil.which,
    identity_verifier: IdentityVerifier = verify_tag_commit,
    now: Callable[[], str] = utc_now_iso,
    pull_registry: bool = True,
) -> dict[str, Any]:
    if profile not in PROFILES:
        raise VerificationError(f"unknown verification profile {profile!r}; expected one of {PROFILES}")
    if expected_tag is not None:
        try:
            validate_tag(expected_tag)
        except IdentityError as exc:
            raise VerificationError(str(exc)) from exc
    if expected_commit is not None:
        try:
            validate_commit(expected_commit)
        except IdentityError as exc:
            raise VerificationError(str(exc)) from exc
    if not manifest_path.is_file():
        raise VerificationError(f"manifest does not exist: {manifest_path}")
    if not artifacts_dir.is_dir():
        raise VerificationError(f"artifacts directory does not exist: {artifacts_dir}")
    try:
        manifest = load_manifest(manifest_path)
        manifest_sha = sha256_file(manifest_path)
    except (ManifestError, OSError) as exc:
        raise VerificationError(str(exc)) from exc

    checks: list[dict[str, Any]] = []
    checks.append(
        _identity_check(
            manifest,
            profile=profile,
            expected_tag=expected_tag,
            expected_commit=expected_commit,
        )
    )
    checks.append(
        _source_identity_check(
            expected_tag=expected_tag,
            expected_commit=expected_commit,
            repo_root=repo_root,
            main_ref=main_ref,
            profile=profile,
            identity_verifier=identity_verifier,
        )
    )
    checks.append(_workflow_identity_check(manifest))
    errors = manifest_errors(
        manifest,
        artifacts_dir=artifacts_dir,
        expected_tag=expected_tag,
        expected_commit=expected_commit,
    )
    if errors:
        checks.append(_check("manifest", FAIL, True, "; ".join(errors[:12])))
    else:
        checks.append(_check("manifest", PASS, True, "manifest and local evidence hashes are valid"))

    images = _image_map(manifest)
    release = manifest.get("release")
    source_repository = release.get("source_repository") if isinstance(release, Mapping) else None
    tag = release.get("tag") if isinstance(release, Mapping) else None
    commit = release.get("commit") if isinstance(release, Mapping) else None
    source_repository = source_repository if isinstance(source_repository, str) else ""
    tag = tag if isinstance(tag, str) else ""
    commit = commit if isinstance(commit, str) else ""

    for name in REQUIRED_IMAGES:
        image = images.get(name)
        if image is None:
            checks.append(_check(f"digest:{name}", FAIL, True, "image entry is missing"))
            checks.append(_check(f"sbom:{name}", FAIL, True, "image entry is missing"))
            checks.append(_check(f"scan:{name}", FAIL, True, "image entry is missing"))
            checks.append(
                _check(f"provenance-bundle:{name}", FAIL, profile == "production", "image entry is missing")
            )
            checks.append(
                _check(
                    f"sbom-attestation-bundle:{name}",
                    FAIL,
                    profile == "production",
                    "image entry is missing",
                )
            )
            continue
        checks.append(_digest_check(name, image))
        sbom_check, sbom_payload = _verify_sbom(name, image, artifacts_dir)
        checks.append(sbom_check)
        checks.append(_verify_scan(name, image, artifacts_dir))
        expected_sbom = sbom_payload if isinstance(sbom_payload, Mapping) else None
        checks.append(
            _verify_bundle(
                f"provenance-bundle:{name}",
                image,
                artifacts_dir,
                "provenance",
                digest=str(image.get("digest") or ""),
                predicate=PROVENANCE_PREDICATE,
                required=profile == "production",
            )
        )
        checks.append(
            _verify_bundle(
                f"sbom-attestation-bundle:{name}",
                image,
                artifacts_dir,
                "sbom_attestation",
                digest=str(image.get("digest") or ""),
                predicate=SBOM_PREDICATE,
                required=profile == "production",
                expected_predicate=expected_sbom,
            )
        )

    for name in REQUIRED_IMAGES:
        image = images.get(name)
        if profile == "production":
            if image is None:
                checks.append(_check(f"registry:{name}", FAIL, True, "image entry is missing"))
                checks.append(_check(f"provenance-attestation:{name}", FAIL, True, "image entry is missing"))
                checks.append(_check(f"sbom-attestation:{name}", FAIL, True, "image entry is missing"))
                checks.append(
                    _check(f"provenance-bundle-signature:{name}", FAIL, True, "image entry is missing")
                )
                checks.append(_check(f"sbom-bundle-signature:{name}", FAIL, True, "image entry is missing"))
                continue
            checks.append(
                _registry_check(
                    image,
                    source_repository=source_repository,
                    tag=tag,
                    commit=commit,
                    runner=runner,
                    which=which,
                    pull=pull_registry,
                )
            )
            sbom_payload: Any | None = None
            sbom_path, _ = _artifact(artifacts_dir, image.get("sbom"))
            if sbom_path is not None:
                try:
                    sbom_payload = _load_json(sbom_path)
                except (OSError, json.JSONDecodeError):
                    sbom_payload = None
            checks.append(
                _attestation_check(
                    f"provenance-attestation:{name}",
                    image,
                    source_repository=source_repository,
                    tag=tag,
                    commit=commit,
                    predicate=PROVENANCE_PREDICATE,
                    expected_predicate=None,
                    require_predicate_match=False,
                    runner=runner,
                    which=which,
                )
            )
            checks.append(
                _attestation_check(
                    f"sbom-attestation:{name}",
                    image,
                    source_repository=source_repository,
                    tag=tag,
                    commit=commit,
                    predicate=SBOM_PREDICATE,
                    expected_predicate=sbom_payload,
                    require_predicate_match=True,
                    runner=runner,
                    which=which,
                )
            )
            checks.append(
                _bundle_signature_check(
                    f"provenance-bundle-signature:{name}",
                    image,
                    artifacts_dir,
                    "provenance",
                    source_repository=source_repository,
                    tag=tag,
                    commit=commit,
                    predicate=PROVENANCE_PREDICATE,
                    expected_predicate=None,
                    require_predicate_match=False,
                    runner=runner,
                    which=which,
                )
            )
            checks.append(
                _bundle_signature_check(
                    f"sbom-bundle-signature:{name}",
                    image,
                    artifacts_dir,
                    "sbom_attestation",
                    source_repository=source_repository,
                    tag=tag,
                    commit=commit,
                    predicate=SBOM_PREDICATE,
                    expected_predicate=sbom_payload,
                    require_predicate_match=True,
                    runner=runner,
                    which=which,
                )
            )
        else:
            checks.append(
                _check(
                    f"registry:{name}",
                    NOT_RUN,
                    False,
                    "local profile: GHCR digest references were not queried",
                )
            )
            checks.append(
                _check(
                    f"provenance-attestation:{name}",
                    NOT_RUN,
                    False,
                    "local profile: GitHub attestation trust was not verified",
                )
            )
            checks.append(
                _check(
                    f"sbom-attestation:{name}",
                    NOT_RUN,
                    False,
                    "local profile: GitHub attestation trust was not verified",
                )
            )
            checks.append(
                _check(
                    f"provenance-bundle-signature:{name}",
                    NOT_RUN,
                    False,
                    "local profile: bundle signature was not cryptographically verified",
                )
            )
            checks.append(
                _check(
                    f"sbom-bundle-signature:{name}",
                    NOT_RUN,
                    False,
                    "local profile: bundle signature was not cryptographically verified",
                )
            )

    checks.extend(_gpu_checks(manifest))
    artifact_status = _artifact_status(checks)
    overall = _aggregate(checks)
    verified = overall == PASS and all(
        check.get("state") == PASS for check in checks if check.get("required") is True
    )
    limitations = [
        f"{check['name']}: {check['state']} - {check['detail']}"
        for check in checks
        if check.get("state") != PASS
    ]
    return {
        "schema_version": VERIFICATION_SCHEMA_VERSION,
        "profile": profile,
        "generated_at": now(),
        "manifest_sha256": manifest_sha,
        "subject": _subject(manifest),
        "overall_state": overall,
        "verified": verified,
        "production_verified": profile == "production" and verified,
        "artifact_status": artifact_status,
        "checks": checks,
        "limitations": limitations,
    }


def write_verification_report(report: Mapping[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def render_verification_summary(report: Mapping[str, Any]) -> str:
    lines = [
        f"Release verification: {report.get('overall_state')} "
        f"(profile={report.get('profile')}, verified={report.get('verified')})",
    ]
    subject = report.get("subject") or {}
    lines.append(
        f"Subject: {subject.get('tag')} at {subject.get('commit')} from {subject.get('source_repository')}"
    )
    artifact_status = report.get("artifact_status") or {}
    for variant in ARTIFACT_FIELDS:
        status = artifact_status.get(variant) or {}
        if not status:
            continue
        lines.append(
            f"{variant.upper()} artifacts: {status.get('state')} "
            f"(runtime={status.get('runtime_state')}, runtime_verified={status.get('runtime_verified')})"
        )
    for check in report.get("checks") or []:
        required = "required" if check.get("required") else "informational"
        lines.append(f"- {check.get('name')}: {check.get('state')} ({required}) - {check.get('detail')}")
    limitations = report.get("limitations") or []
    if limitations:
        lines.append("Limitations:")
        lines.extend(f"- {item}" for item in limitations)
    return "\n".join(lines) + "\n"
