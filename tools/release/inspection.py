"""Read-only external infrastructure inspection (V28).

Everything in this module is a GET, a read-only CLI inspection, or a local
file hash. Nothing creates, moves, deletes, publishes, deploys, dispatches, or
changes registry, IAM, DNS, firewall, database, volume, or host state.

The functions accept injected HTTP and command runners so the ordinary test
suite never contacts GitHub, GHCR, a Docker daemon, or a staging host.
"""

from __future__ import annotations

import json
import shlex
import subprocess
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

import httpx

from tools.release.identity import (
    DIGEST_PATTERN,
    REQUIRED_IMAGES,
    SOURCE_REPOSITORY_PATTERN,
    TAG_PATTERN,
)
from tools.release.manifest import utc_now_iso
from tools.release.verification import (
    FAIL,
    NOT_RUN,
    PASS,
    SIMULATED,
    UNAVAILABLE,
    CommandRunner,
    attestation_cli_support,
    default_runner,
    verify_attestation_evidence,
    verify_sbom_evidence,
    verify_scan_evidence,
)

GITHUB_API_ROOT = "https://api.github.com"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
DEFAULT_GITHUB_TIMEOUT = 15.0
DEFAULT_REGISTRY_TIMEOUT = 90.0
DEFAULT_ATTESTATION_TIMEOUT = 180.0
REGISTRY_NOT_FOUND_MARKERS = ("manifest unknown", "no such manifest", "not found", "404")
REGISTRY_AUTH_MARKERS = ("unauthorized", "denied", "authentication required", "login")

HttpGet = Callable[[str, Mapping[str, str], float], tuple[int, Any, str | None]]


def _check(
    name: str,
    category: str,
    state: str,
    required: bool,
    detail: str,
    *,
    mode: str = "live-read-only",
    command: str | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "category": category,
        "state": state,
        "required": required,
        "mode": mode,
        "detail": detail,
        "command": command,
    }


def _command_text(args: Sequence[str]) -> str:
    return " ".join(shlex.quote(str(part)) for part in args)


def _aggregate_states(states: Sequence[str]) -> str:
    values = set(states)
    if FAIL in values:
        return FAIL
    if SIMULATED in values:
        return SIMULATED
    if UNAVAILABLE in values:
        return UNAVAILABLE
    if NOT_RUN in values:
        return NOT_RUN
    return PASS


def _default_http_get(
    url: str,
    headers: Mapping[str, str],
    timeout: float,
) -> tuple[int, Any, str | None]:
    try:
        with httpx.Client(verify=True, follow_redirects=False, timeout=timeout) as client:
            response = client.get(url, headers=dict(headers))
            content = response.content
            if len(content) > MAX_RESPONSE_BYTES:
                return response.status_code, None, "response exceeded the safe size limit"
            try:
                payload = response.json()
            except ValueError:
                payload = None
            return response.status_code, payload, None
    except httpx.HTTPError as exc:
        return 0, None, f"request failed: {type(exc).__name__}"


def _github_headers(token: str | None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "industrial-vision-platform-v28-readiness",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _request_state(status: int, error: str | None) -> str:
    if error:
        return UNAVAILABLE
    if status == 404:
        return FAIL
    if status in {401, 403, 429}:
        return UNAVAILABLE
    if status >= 500:
        return UNAVAILABLE
    if status != 200:
        return UNAVAILABLE
    return PASS


def _subject(manifest: Mapping[str, Any]) -> tuple[str | None, str | None, str | None]:
    release = manifest.get("release")
    if not isinstance(release, Mapping):
        return None, None, None
    tag = release.get("tag")
    commit = release.get("commit")
    repository = release.get("source_repository")
    return (
        tag if isinstance(tag, str) else None,
        commit if isinstance(commit, str) else None,
        repository if isinstance(repository, str) else None,
    )


def _images(manifest: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for image in manifest.get("images") or []:
        if isinstance(image, Mapping) and isinstance(image.get("name"), str):
            result[str(image["name"])] = image
    return result


def _expected_asset_names(manifest: Mapping[str, Any]) -> list[str]:
    names = {"release-manifest.json"}
    for image in _images(manifest).values():
        sbom = image.get("sbom")
        if isinstance(sbom, Mapping) and isinstance(sbom.get("path"), str):
            names.add(str(sbom["path"]))
        scan = image.get("scan")
        if isinstance(scan, Mapping):
            log = scan.get("log")
            if isinstance(log, Mapping) and isinstance(log.get("path"), str):
                names.add(str(log["path"]))
        for key in ("provenance", "sbom_attestation"):
            attestation = image.get(key)
            if isinstance(attestation, Mapping):
                evidence = attestation.get("evidence")
                if isinstance(evidence, Mapping) and isinstance(evidence.get("path"), str):
                    names.add(str(evidence["path"]))
    return sorted(names)


def inspect_github_release(
    manifest: Mapping[str, Any],
    *,
    token: str | None = None,
    timeout: float = DEFAULT_GITHUB_TIMEOUT,
    http_get: HttpGet | None = None,
    now: Callable[[], str] = utc_now_iso,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Inspect an existing GitHub Release, tag, assets, and workflow run."""
    tag, commit, repository = _subject(manifest)
    checks: list[dict[str, Any]] = []
    observation: dict[str, Any] = {
        "source": "github-api",
        "observed_at": now(),
        "repository": repository,
        "tag": tag,
        "commit": commit,
        "requests": [],
        "tag_commit": None,
        "release": None,
        "assets": [],
        "workflow": None,
    }
    if (
        tag is None
        or commit is None
        or repository is None
        or TAG_PATTERN.fullmatch(tag) is None
        or SOURCE_REPOSITORY_PATTERN.fullmatch(repository) is None
    ):
        checks.append(
            _check(
                "github-tag-exists",
                "github-release",
                FAIL,
                True,
                "the manifest does not contain a stable tag, commit, and source repository",
            )
        )
        for name in (
            "github-tag-commit",
            "github-release-exists",
            "github-release-identity",
            "github-release-assets",
            "github-workflow-run",
        ):
            checks.append(_check(name, "github-release", NOT_RUN, True, "manifest identity is incomplete"))
        return checks, observation

    get = http_get or _default_http_get
    headers = _github_headers(token)

    def get_json(path: str) -> tuple[int, Any, str | None, str]:
        url = f"{GITHUB_API_ROOT}{path}"
        status, payload, error = get(url, headers, timeout)
        observation["requests"].append(
            {
                "url": url,
                "status": status,
                "state": _request_state(status, error),
                "error": error,
            }
        )
        return status, payload, error, url

    tag_ref_path = f"/repos/{repository}/git/ref/tags/{tag}"
    status, payload, error, url = get_json(tag_ref_path)
    state = _request_state(status, error)
    tag_commit: str | None = None
    if state == PASS and isinstance(payload, Mapping):
        tag_object = payload.get("object")
        if isinstance(tag_object, Mapping):
            object_type = tag_object.get("type")
            object_sha = tag_object.get("sha")
            if object_type == "commit" and isinstance(object_sha, str):
                tag_commit = object_sha
            elif object_type == "tag" and isinstance(object_sha, str):
                tag_status, tag_payload, tag_error, _ = get_json(f"/repos/{repository}/git/tags/{object_sha}")
                tag_state = _request_state(tag_status, tag_error)
                if tag_state == PASS and isinstance(tag_payload, Mapping):
                    peeled = tag_payload.get("object")
                    if (
                        isinstance(peeled, Mapping)
                        and peeled.get("type") == "commit"
                        and isinstance(peeled.get("sha"), str)
                    ):
                        tag_commit = str(peeled["sha"])
                    else:
                        state = FAIL
                else:
                    state = tag_state
            else:
                state = FAIL
    observation["tag_commit"] = tag_commit
    checks.append(
        _check(
            "github-tag-exists",
            "github-release",
            state,
            True,
            "stable release tag exists and resolves to a commit"
            if state == PASS
            else (
                f"stable release tag {tag} does not exist"
                if state == FAIL and status == 404
                else "stable release tag could not be inspected with read-only access"
            ),
            command=f"GET {url}",
        )
    )
    if tag_commit is None:
        checks.append(
            _check(
                "github-tag-commit",
                "github-release",
                UNAVAILABLE if state != FAIL else NOT_RUN,
                True,
                "the tag commit could not be resolved, so the source commit was not compared",
                command=f"GET {url}",
            )
        )
    else:
        matches = tag_commit == commit
        checks.append(
            _check(
                "github-tag-commit",
                "github-release",
                PASS if matches else FAIL,
                True,
                f"tag resolves to the manifest commit {commit}"
                if matches
                else f"tag resolves to {tag_commit}, manifest records {commit}",
                command=f"GET {url}",
            )
        )

    release_path = f"/repos/{repository}/releases/tags/{tag}"
    status, payload, error, url = get_json(release_path)
    state = _request_state(status, error)
    release: Mapping[str, Any] | None = payload if isinstance(payload, Mapping) else None
    if state == PASS and release is not None:
        draft = release.get("draft")
        prerelease = release.get("prerelease")
        tag_name = release.get("tag_name")
        if draft is True or prerelease is True:
            state = FAIL
        elif tag_name != tag:
            state = FAIL
        observation["release"] = {
            "id": release.get("id"),
            "tag_name": tag_name,
            "draft": draft,
            "prerelease": prerelease,
            "html_url": release.get("html_url"),
            "published_at": release.get("published_at"),
        }
    checks.append(
        _check(
            "github-release-exists",
            "github-release",
            state,
            True,
            f"GitHub Release {tag} exists and is published"
            if state == PASS
            else (
                f"no GitHub Release exists for tag {tag}"
                if state == FAIL and status == 404
                else "GitHub Release is missing, draft, prerelease, mis-tagged, or inaccessible"
            ),
            command=f"GET {url}",
        )
    )

    identity_problems: list[str] = []
    if release is not None:
        if release.get("tag_name") != tag:
            identity_problems.append("release tag does not match the manifest")
        html_url = release.get("html_url")
        expected_prefix = f"https://github.com/{repository}/releases/tag/"
        if not isinstance(html_url, str) or not html_url.startswith(expected_prefix):
            identity_problems.append("release URL does not identify the expected repository")
        if tag_commit is None:
            identity_problems.append("tag commit is unresolved")
        elif tag_commit != commit:
            identity_problems.append("release tag commit does not match the manifest commit")
    else:
        identity_problems.append("release metadata is unavailable")
    checks.append(
        _check(
            "github-release-identity",
            "github-release",
            FAIL if identity_problems else PASS,
            True,
            "; ".join(identity_problems)
            if identity_problems
            else "release repository, tag, and source commit match the manifest",
            command=f"GET {release_path}",
        )
    )

    expected_assets = _expected_asset_names(manifest)
    asset_problems: list[str] = []
    observed_assets: list[dict[str, Any]] = []
    if release is not None:
        raw_assets = release.get("assets")
        by_name: dict[str, Mapping[str, Any]] = {}
        if isinstance(raw_assets, list):
            for asset in raw_assets:
                if isinstance(asset, Mapping) and isinstance(asset.get("name"), str):
                    by_name[str(asset["name"])] = asset
        for name in expected_assets:
            asset = by_name.get(name)
            if asset is None:
                asset_problems.append(f"missing asset {name}")
                continue
            size = asset.get("size")
            state_value = asset.get("state")
            observed_assets.append(
                {
                    "name": name,
                    "size": size,
                    "state": state_value,
                    "digest": asset.get("digest"),
                }
            )
            if state_value != "uploaded":
                asset_problems.append(f"asset {name} is not uploaded")
            elif not isinstance(size, int) or size <= 0:
                asset_problems.append(f"asset {name} is empty")
    else:
        asset_problems.append("release assets are unavailable")
    observation["assets"] = observed_assets
    checks.append(
        _check(
            "github-release-assets",
            "github-release",
            FAIL if asset_problems else PASS,
            True,
            "; ".join(asset_problems[:10])
            if asset_problems
            else f"all {len(expected_assets)} required release assets are uploaded",
            command=f"GET {release_path}",
        )
    )

    release_meta = manifest.get("release")
    run_id = release_meta.get("workflow_run_id") if isinstance(release_meta, Mapping) else None
    run_attempt = release_meta.get("workflow_run_attempt") if isinstance(release_meta, Mapping) else None
    workflow_path = (
        manifest.get("build", {}).get("workflow") if isinstance(manifest.get("build"), Mapping) else None
    )
    if not isinstance(run_id, int) or run_id < 1:
        checks.append(
            _check(
                "github-workflow-run",
                "github-release",
                NOT_RUN,
                True,
                "the manifest does not record a workflow run id",
            )
        )
    else:
        status, payload, error, url = get_json(f"/repos/{repository}/actions/runs/{run_id}")
        state = _request_state(status, error)
        problems: list[str] = []
        run: Mapping[str, Any] | None = payload if isinstance(payload, Mapping) else None
        if state == PASS and run is not None:
            if run.get("head_sha") != commit:
                problems.append("workflow run head commit does not match the manifest")
            if workflow_path and run.get("path") != workflow_path:
                problems.append("workflow run path does not match the release workflow")
            if run.get("event") != "push":
                problems.append("workflow run event is not push")
            if run.get("status") != "completed":
                problems.append("workflow run is not completed")
            if run.get("conclusion") != "success":
                problems.append("workflow run did not succeed")
            if isinstance(run_attempt, int) and run.get("run_attempt") != run_attempt:
                problems.append("workflow run attempt does not match the manifest")
            observation["workflow"] = {
                "id": run_id,
                "head_sha": run.get("head_sha"),
                "path": run.get("path"),
                "event": run.get("event"),
                "status": run.get("status"),
                "conclusion": run.get("conclusion"),
                "run_attempt": run.get("run_attempt"),
            }
        else:
            problems.append("workflow run metadata is unavailable")
        checks.append(
            _check(
                "github-workflow-run",
                "github-release",
                FAIL if problems else PASS,
                True,
                "; ".join(problems)
                if problems
                else "workflow run identity and successful completion match the manifest",
                command=f"GET {url}",
            )
        )
    return checks, observation


def _classify_registry_failure(detail: str) -> str:
    lowered = detail.lower()
    if any(marker in lowered for marker in REGISTRY_NOT_FOUND_MARKERS):
        return FAIL
    if any(marker in lowered for marker in REGISTRY_AUTH_MARKERS):
        return UNAVAILABLE
    return UNAVAILABLE


def _run_command(
    runner: CommandRunner,
    args: Sequence[str],
    *,
    timeout: float,
) -> tuple[subprocess.CompletedProcess[str] | None, str | None]:
    try:
        return runner(list(args), timeout=timeout), None
    except subprocess.TimeoutExpired:
        return None, "timeout"
    except (OSError, subprocess.SubprocessError):
        return None, "execution_error"


def inspect_ghcr(
    manifest: Mapping[str, Any],
    *,
    runner: CommandRunner = default_runner,
    which: Callable[[str], str | None],
    timeout: float = DEFAULT_REGISTRY_TIMEOUT,
    now: Callable[[], str] = utc_now_iso,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Resolve immutable GHCR digests and platform metadata without pulling."""
    checks: list[dict[str, Any]] = []
    observation: dict[str, Any] = {
        "source": "docker-buildx-imagetools",
        "observed_at": now(),
        "images": {},
        "platforms": {},
    }
    if which("docker") is None:
        for name in (*REQUIRED_IMAGES, "ghcr-platform-metadata"):
            checks.append(
                _check(
                    f"ghcr-{name}" if name != "ghcr-platform-metadata" else name,
                    "registry",
                    UNAVAILABLE,
                    True,
                    "docker is not installed; GHCR manifests were not inspected",
                )
            )
        return checks, observation

    probe, failure = _run_command(runner, ["docker", "buildx", "version"], timeout=30)
    if failure is not None or probe is None or probe.returncode != 0:
        for name in (*REQUIRED_IMAGES, "ghcr-platform-metadata"):
            checks.append(
                _check(
                    f"ghcr-{name}" if name != "ghcr-platform-metadata" else name,
                    "registry",
                    UNAVAILABLE,
                    True,
                    "docker buildx is unavailable; GHCR manifests were not inspected",
                )
            )
        return checks, observation

    images = _images(manifest)
    for name in REQUIRED_IMAGES:
        label = f"ghcr-{name}"
        image = images.get(name)
        if image is None:
            checks.append(_check(label, "registry", FAIL, True, f"the manifest has no {name} image"))
            continue
        repository = image.get("repository")
        digest = image.get("digest")
        tags = image.get("tags")
        if (
            not isinstance(repository, str)
            or not isinstance(digest, str)
            or DIGEST_PATTERN.fullmatch(digest) is None
            or not isinstance(tags, list)
            or not all(isinstance(tag, str) for tag in tags)
        ):
            checks.append(
                _check(label, "registry", FAIL, True, f"the {name} manifest image record is incomplete")
            )
            continue
        references = [f"{repository}:{tag}" for tag in tags] + [f"{repository}@{digest}"]
        commands: list[str] = []
        problems: list[str] = []
        state = PASS
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
            result, failure = _run_command(runner, args, timeout=timeout)
            if failure is not None or result is None:
                state = UNAVAILABLE
                problems.append(f"{reference} could not be inspected ({failure or 'no result'})")
                break
            if result.returncode != 0:
                detail = (result.stderr or result.stdout or "no output").strip()
                state = _classify_registry_failure(detail)
                problems.append(f"{reference} failed: {detail[:300]}")
                break
            observed = result.stdout.strip().splitlines()[-1].strip() if result.stdout.strip() else ""
            if DIGEST_PATTERN.fullmatch(observed) is None:
                state = FAIL
                problems.append(f"{reference} returned invalid digest {observed!r}")
                break
            if observed != digest:
                state = FAIL
                problems.append(f"{reference} resolves to {observed}, manifest records {digest}")
                break
        observation["images"][name] = {
            "repository": repository,
            "digest": digest,
            "tags": list(tags),
            "references": references,
            "state": state,
            "problems": problems,
        }
        checks.append(
            _check(
                label,
                "registry",
                state,
                True,
                f"all {len(references)} references resolve to {digest}"
                if state == PASS
                else "; ".join(problems[:4]),
                command=" && ".join(commands),
            )
        )

    api = images.get("api")
    if api is None or not isinstance(api.get("repository"), str) or not isinstance(api.get("digest"), str):
        checks.append(
            _check(
                "ghcr-platform-metadata",
                "registry",
                NOT_RUN,
                True,
                "the api image reference is unavailable for platform inspection",
            )
        )
        return checks, observation
    args = [
        "docker",
        "buildx",
        "imagetools",
        "inspect",
        "--raw",
        f"{api['repository']}@{api['digest']}",
    ]
    command = _command_text(args)
    result, failure = _run_command(runner, args, timeout=timeout)
    if failure is not None or result is None or result.returncode != 0:
        detail = (
            (result.stderr or result.stdout or "no output").strip()
            if result is not None
            else (failure or "no result")
        )
        checks.append(
            _check(
                "ghcr-platform-metadata",
                "registry",
                UNAVAILABLE,
                True,
                f"platform metadata could not be inspected: {detail[:300]}",
                command=command,
            )
        )
    else:
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            checks.append(
                _check(
                    "ghcr-platform-metadata",
                    "registry",
                    FAIL,
                    True,
                    "the registry returned malformed platform metadata",
                    command=command,
                )
            )
        else:
            platforms: list[dict[str, Any]] = []
            manifests = payload.get("manifests") if isinstance(payload, Mapping) else None
            if isinstance(manifests, list):
                for item in manifests:
                    if isinstance(item, Mapping):
                        platform = item.get("platform")
                        if isinstance(platform, Mapping):
                            platforms.append(dict(platform))
            observation["platforms"]["api"] = platforms
            checks.append(
                _check(
                    "ghcr-platform-metadata",
                    "registry",
                    PASS,
                    True,
                    f"platform metadata lists {len(platforms)} platform manifest(s)"
                    if platforms
                    else "the api digest resolves to a single-platform manifest",
                    command=command,
                )
            )
    return checks, observation


def inspect_attestations(
    manifest: Mapping[str, Any],
    *,
    runner: CommandRunner = default_runner,
    which: Callable[[str], str | None],
    artifacts_dir: Path | None,
    timeout: float = DEFAULT_ATTESTATION_TIMEOUT,
    now: Callable[[], str] = utc_now_iso,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Verify genuine GitHub attestations without trusting local files alone."""
    checks: list[dict[str, Any]] = []
    observation: dict[str, Any] = {
        "source": "gh-attestation-verify",
        "observed_at": now(),
        "images": {},
        "sbom": {},
    }
    supported, detail = attestation_cli_support(runner=runner, which=which)
    checks.append(
        _check(
            "attestation-cli",
            "attestation",
            PASS if supported else UNAVAILABLE,
            True,
            detail,
            command="gh attestation verify --help",
        )
    )
    if not supported:
        for name in (*REQUIRED_IMAGES, "attestation-sbom"):
            checks.append(
                _check(
                    f"attestation-{name}" if name != "attestation-sbom" else name,
                    "attestation",
                    UNAVAILABLE,
                    True,
                    "the installed GitHub CLI cannot verify attestations",
                )
            )
        return checks, observation

    tag, commit, repository = _subject(manifest)
    images = _images(manifest)
    if tag is None or commit is None or repository is None:
        for name in (*REQUIRED_IMAGES, "attestation-sbom"):
            checks.append(
                _check(
                    f"attestation-{name}" if name != "attestation-sbom" else name,
                    "attestation",
                    NOT_RUN,
                    True,
                    "manifest identity is incomplete",
                )
            )
        return checks, observation

    sbom_checks: list[dict[str, Any]] = []
    for name in REQUIRED_IMAGES:
        label = f"attestation-{name}"
        image = images.get(name)
        if image is None:
            checks.append(_check(label, "attestation", FAIL, True, f"manifest has no {name} image"))
            continue
        provenance = image.get("provenance")
        predicate = provenance.get("predicate_type") if isinstance(provenance, Mapping) else None
        if not isinstance(predicate, str) or not predicate:
            checks.append(
                _check(label, "attestation", FAIL, True, f"{name} has no provenance predicate type")
            )
            continue
        result = verify_attestation_evidence(
            image,
            source_repository=repository,
            tag=tag,
            commit=commit,
            predicate=predicate,
            runner=runner,
            which=which,
            label=label,
        )
        checks.append(
            _check(
                label,
                "attestation",
                str(result.get("state")),
                True,
                str(result.get("detail")),
                command=result.get("command"),
            )
        )
        observation["images"][name] = {
            "predicate": predicate,
            "state": result.get("state"),
            "detail": result.get("detail"),
            "command": result.get("command"),
        }

        if artifacts_dir is None:
            sbom_checks.append(
                _check(
                    f"sbom-attestation:{name}",
                    "attestation",
                    UNAVAILABLE,
                    True,
                    "no local artifacts directory was supplied for SBOM attestation comparison",
                )
            )
            continue
        sbom_result, sbom_payload = verify_sbom_evidence(image, artifacts_dir)
        if sbom_payload is None:
            sbom_checks.append(
                _check(
                    f"sbom-attestation:{name}",
                    "attestation",
                    str(sbom_result.get("state")),
                    True,
                    f"local SBOM is unavailable: {sbom_result.get('detail')}",
                )
            )
            continue
        sbom_attestation = image.get("sbom_attestation")
        sbom_predicate = (
            sbom_attestation.get("predicate_type") if isinstance(sbom_attestation, Mapping) else None
        )
        if not isinstance(sbom_predicate, str) or not sbom_predicate:
            sbom_checks.append(
                _check(
                    f"sbom-attestation:{name}",
                    "attestation",
                    FAIL,
                    True,
                    f"{name} has no SBOM attestation predicate type",
                )
            )
            continue
        result = verify_attestation_evidence(
            image,
            source_repository=repository,
            tag=tag,
            commit=commit,
            predicate=sbom_predicate,
            expected_predicate=sbom_payload,
            require_predicate_match=True,
            runner=runner,
            which=which,
            label=f"sbom-attestation:{name}",
        )
        sbom_checks.append(
            _check(
                f"sbom-attestation:{name}",
                "attestation",
                str(result.get("state")),
                True,
                str(result.get("detail")),
                command=result.get("command"),
            )
        )
        observation["sbom"][name] = {
            "predicate": sbom_predicate,
            "state": result.get("state"),
            "detail": result.get("detail"),
            "command": result.get("command"),
        }

    if sbom_checks:
        state = _aggregate_states([str(item.get("state")) for item in sbom_checks])
        detail = (
            "all SBOM attestations are signed, trusted, and bound to the local SBOMs"
            if state == PASS
            else "; ".join(str(item.get("detail")) for item in sbom_checks)[:500]
        )
        checks.append(
            _check(
                "attestation-sbom",
                "attestation",
                state,
                True,
                detail,
                command=sbom_checks[0].get("command"),
            )
        )
    else:
        checks.append(
            _check(
                "attestation-sbom",
                "attestation",
                UNAVAILABLE,
                True,
                "SBOM attestations could not be inspected",
            )
        )
    return checks, observation


def inspect_artifacts(
    manifest: Mapping[str, Any],
    *,
    artifacts_dir: Path | None,
    now: Callable[[], str] = utc_now_iso,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Validate local SBOM and scan evidence without executing it."""
    observation: dict[str, Any] = {
        "source": "local-release-artifacts",
        "observed_at": now(),
        "artifacts_dir": str(artifacts_dir) if artifacts_dir is not None else None,
        "sbom": {},
        "scan": {},
    }
    if artifacts_dir is None:
        return (
            [
                _check(
                    "sbom-evidence",
                    "release",
                    UNAVAILABLE,
                    True,
                    "no local artifacts directory was supplied; SBOM content was not downloaded or executed",
                ),
                _check(
                    "scan-evidence",
                    "release",
                    UNAVAILABLE,
                    True,
                    "no local artifacts directory was supplied; scan content was not downloaded or executed",
                ),
            ],
            observation,
        )
    images = _images(manifest)
    sbom_checks: list[dict[str, Any]] = []
    scan_checks: list[dict[str, Any]] = []
    for name in REQUIRED_IMAGES:
        image = images.get(name)
        if image is None:
            sbom_checks.append(_check(f"sbom:{name}", "release", FAIL, True, f"manifest has no {name} image"))
            scan_checks.append(_check(f"scan:{name}", "release", FAIL, True, f"manifest has no {name} image"))
            continue
        sbom_result, _ = verify_sbom_evidence(image, artifacts_dir)
        scan_result = verify_scan_evidence(image, artifacts_dir)
        sbom_checks.append(sbom_result)
        scan_checks.append(scan_result)
        observation["sbom"][name] = {
            "state": sbom_result.get("state"),
            "detail": sbom_result.get("detail"),
        }
        observation["scan"][name] = {
            "state": scan_result.get("state"),
            "detail": scan_result.get("detail"),
        }
    sbom_state = _aggregate_states([str(item.get("state")) for item in sbom_checks])
    scan_state = _aggregate_states([str(item.get("state")) for item in scan_checks])
    return (
        [
            _check(
                "sbom-evidence",
                "release",
                sbom_state,
                True,
                "all three SPDX SBOMs are valid and hash-bound"
                if sbom_state == PASS
                else "; ".join(str(item.get("detail")) for item in sbom_checks)[:500],
                mode="local",
            ),
            _check(
                "scan-evidence",
                "release",
                scan_state,
                True,
                "all three scan logs are clean and hash-bound"
                if scan_state == PASS
                else "; ".join(str(item.get("detail")) for item in scan_checks)[:500],
                mode="local",
            ),
        ],
        observation,
    )
