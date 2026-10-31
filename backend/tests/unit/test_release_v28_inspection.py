"""V28 authorized, read-only infrastructure inspection tests.

These tests are fully offline: GitHub, GHCR, attestation, artifact, and network
behavior is supplied through deterministic fakes. Nothing here contacts a real
host, registry, release, or Docker daemon.
"""

from __future__ import annotations

import json
import ssl
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest

from backend.tests.unit.test_release_verification import (
    COMMIT,
    SOURCE_REPOSITORY,
    TAG,
    make_release,
)
from tools.release import connectivity, inspection
from tools.release.identity import REQUIRED_IMAGES
from tools.release.staging import (
    STAGING_TARGET_STATEMENT,
    staging_target_errors,
    staging_target_live_errors,
)
from tools.release.verification import FAIL, NOT_RUN, PASS, UNAVAILABLE

GENERATED_AT = "2026-10-31T00:00:00Z"
TOKEN_SENTINEL = "ghp_v28_inspection_sentinel_do_not_disclose"
FUTURE_CERT = "Dec 31 23:59:59 2030 GMT"


def _target(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": 1,
        "name": "staging-east-1",
        "environment": "staging",
        "release": {
            "tag": TAG,
            "commit": COMMIT,
            "source_repository": SOURCE_REPOSITORY,
        },
        "api_url": "https://api.staging.example.test",
        "web_url": "https://web.staging.example.test",
        "ws_url": "wss://ws.staging.example.test",
        "smoke_username": "smoke@example.test",
        "smoke_password_env": "IVP_SMOKE_PASSWORD",
        "compose_project": "ivp-staging",
        "compose_files": ["compose.release.yaml"],
        "gpu": False,
        "staging_statement": STAGING_TARGET_STATEMENT,
        "allowed_hostnames": [
            "api.staging.example.test",
            "web.staging.example.test",
            "ws.staging.example.test",
        ],
        "allow_private_network": False,
        "production_hostnames": ["api.example.com"],
    }
    payload.update(overrides)
    return payload


# ---------------------------------------------------------------------------
# Explicit staging target policy
# ---------------------------------------------------------------------------


def test_v28_target_accepts_explicit_staging_declaration() -> None:
    payload = _target()
    assert staging_target_errors(payload) == []
    assert staging_target_live_errors(payload) == []


def test_v28_target_requires_statement_before_live_checks() -> None:
    payload = _target()
    payload.pop("staging_statement")
    assert staging_target_errors(payload) == []
    problems = staging_target_live_errors(payload)
    assert any("staging_statement is required" in problem for problem in problems)


def test_v28_target_rejects_wrong_statement_text() -> None:
    payload = _target(staging_statement="This is staging, trust me.")
    assert any("staging_statement" in problem for problem in staging_target_errors(payload))


def test_v28_target_requires_allowed_hostnames_before_live_checks() -> None:
    payload = _target()
    payload.pop("allowed_hostnames")
    problems = staging_target_live_errors(payload)
    assert any("allowed_hostnames is required" in problem for problem in problems)


def test_v28_target_requires_production_hostnames_declaration() -> None:
    payload = _target()
    payload.pop("production_hostnames")
    problems = staging_target_live_errors(payload)
    assert any("production_hostnames must be declared" in problem for problem in problems)


def test_v28_target_rejects_hostname_outside_allowed_list() -> None:
    payload = _target(
        api_url="https://other.staging.example.test",
    )
    assert any("not listed in allowed_hostnames" in problem for problem in staging_target_errors(payload))


def test_v28_target_rejects_production_overlap() -> None:
    payload = _target(production_hostnames=["web.staging.example.test"])
    assert any("overlap" in problem for problem in staging_target_errors(payload))
    live_problems = staging_target_live_errors(payload)
    assert any("declared production hosts" in problem for problem in live_problems)


def test_v28_target_rejects_externally_supplied_production_host() -> None:
    problems = staging_target_live_errors(_target(), production_hosts=["api.staging.example.test"])
    assert any("declared production hosts" in problem for problem in problems)


def test_v28_target_rejects_private_hostname_unless_allowed() -> None:
    payload = _target(api_url="https://10.0.0.5")
    assert any("private or loopback" in problem for problem in staging_target_errors(payload))
    allowed = _target(
        api_url="https://10.0.0.5",
        allow_private_network=True,
        allowed_hostnames=["10.0.0.5", "web.staging.example.test", "ws.staging.example.test"],
    )
    assert staging_target_errors(allowed) == []


def test_v28_target_rejects_wildcard_hostname() -> None:
    payload = _target(allowed_hostnames=["*.staging.example.test"])
    assert any("wildcards" in problem for problem in staging_target_errors(payload))


def test_v28_target_rejects_hostname_that_is_a_url() -> None:
    payload = _target(allowed_hostnames=["https://api.staging.example.test"])
    assert any("bare hostname" in problem for problem in staging_target_errors(payload))


# ---------------------------------------------------------------------------
# GitHub release, tag, asset, and workflow inspection
# ---------------------------------------------------------------------------


def _expected_assets(manifest: dict[str, Any]) -> list[str]:
    names = {"release-manifest.json"}
    for image in manifest["images"]:
        names.add(image["sbom"]["path"])
        names.add(image["scan"]["log"]["path"])
        names.add(image["provenance"]["evidence"]["path"])
        names.add(image["sbom_attestation"]["evidence"]["path"])
    return sorted(names)


class _FakeGitHub:
    def __init__(
        self,
        manifest: dict[str, Any],
        *,
        tag: bool = True,
        tag_commit: str = COMMIT,
        release: bool = True,
        release_tag: str = TAG,
        release_url: str | None = None,
        assets: list[dict[str, Any]] | None = None,
        workflow: dict[str, Any] | None = None,
        unauthorized: bool = False,
    ) -> None:
        self.manifest = manifest
        self.tag = tag
        self.tag_commit = tag_commit
        self.release = release
        self.release_tag = release_tag
        self.release_url = release_url or (f"https://github.com/{SOURCE_REPOSITORY}/releases/tag/{TAG}")
        self.assets = assets
        self.workflow = workflow
        self.unauthorized = unauthorized
        self.requests: list[dict[str, Any]] = []

    def __call__(
        self,
        url: str,
        headers: dict[str, str],
        timeout: float,
    ) -> tuple[int, Any, str | None]:
        del timeout
        self.requests.append({"url": url, "headers": dict(headers)})
        if self.unauthorized:
            return 401, {"message": "Bad credentials"}, None
        path = url.removeprefix("https://api.github.com")
        if path == f"/repos/{SOURCE_REPOSITORY}/git/ref/tags/{TAG}":
            if not self.tag:
                return 404, {"message": "Not Found"}, None
            return 200, {"object": {"type": "commit", "sha": self.tag_commit}}, None
        if path == f"/repos/{SOURCE_REPOSITORY}/releases/tags/{TAG}":
            if not self.release:
                return 404, {"message": "Not Found"}, None
            assets = self.assets
            if assets is None:
                assets = [
                    {"name": name, "size": 128, "state": "uploaded", "digest": None}
                    for name in _expected_assets(self.manifest)
                ]
            return (
                200,
                {
                    "id": 99,
                    "tag_name": self.release_tag,
                    "draft": False,
                    "prerelease": False,
                    "html_url": self.release_url,
                    "published_at": "2026-10-30T00:00:00Z",
                    "assets": assets,
                },
                None,
            )
        if path == f"/repos/{SOURCE_REPOSITORY}/actions/runs/123":
            workflow = self.workflow or {
                "id": 123,
                "head_sha": COMMIT,
                "path": ".github/workflows/release.yml",
                "event": "push",
                "status": "completed",
                "conclusion": "success",
                "run_attempt": 1,
            }
            return 200, workflow, None
        return 404, {"message": "Not Found"}, None


def _github(
    tmp_path: Path,
    **overrides: Any,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    _, _, manifest = make_release(tmp_path)
    fake = _FakeGitHub(manifest, **overrides)
    checks, observation = inspection.inspect_github_release(
        manifest,
        token=TOKEN_SENTINEL,
        http_get=fake,
        now=lambda: GENERATED_AT,
    )
    return manifest, checks, observation


def _state(checks: list[dict[str, Any]], name: str) -> str:
    for check in checks:
        if check["name"] == name:
            return str(check["state"])
    raise AssertionError(f"no {name} check was produced")


def test_github_inspection_passes_with_complete_read_only_evidence(tmp_path: Path) -> None:
    _, checks, observation = _github(tmp_path)
    assert {check["name"] for check in checks} == {
        "github-tag-exists",
        "github-tag-commit",
        "github-release-exists",
        "github-release-identity",
        "github-release-assets",
        "github-workflow-run",
    }
    assert all(check["state"] == PASS for check in checks), checks
    assert all(check["mode"] == "live-read-only" for check in checks)
    assert observation["tag_commit"] == COMMIT
    assert observation["release"]["tag_name"] == TAG


def test_github_inspection_reports_missing_release_and_tag(tmp_path: Path) -> None:
    _, checks, _ = _github(tmp_path, tag=False, release=False)
    assert _state(checks, "github-tag-exists") == FAIL
    assert _state(checks, "github-tag-commit") == NOT_RUN
    assert _state(checks, "github-release-exists") == FAIL
    assert _state(checks, "github-release-identity") == FAIL
    assert _state(checks, "github-release-assets") == FAIL


def test_github_inspection_rejects_tag_commit_mismatch(tmp_path: Path) -> None:
    _, checks, _ = _github(tmp_path, tag_commit="b" * 40)
    assert _state(checks, "github-tag-commit") == FAIL
    assert _state(checks, "github-release-identity") == FAIL


def test_github_inspection_rejects_missing_release_assets(tmp_path: Path) -> None:
    _, checks, _ = _github(tmp_path, assets=[])
    assert _state(checks, "github-release-assets") == FAIL


def test_github_inspection_rejects_failed_workflow_run(tmp_path: Path) -> None:
    workflow = {
        "id": 123,
        "head_sha": COMMIT,
        "path": ".github/workflows/release.yml",
        "event": "push",
        "status": "completed",
        "conclusion": "failure",
        "run_attempt": 1,
    }
    _, checks, _ = _github(tmp_path, workflow=workflow)
    assert _state(checks, "github-workflow-run") == FAIL


def test_github_inspection_unauthorized_is_unavailable_not_pass(tmp_path: Path) -> None:
    _, checks, _ = _github(tmp_path, unauthorized=True)
    assert _state(checks, "github-tag-exists") == UNAVAILABLE
    assert _state(checks, "github-release-exists") == UNAVAILABLE
    assert all(check["state"] != PASS for check in checks)


def test_github_inspection_never_leaks_the_token(tmp_path: Path) -> None:
    _, _, manifest = make_release(tmp_path)
    fake = _FakeGitHub(manifest)
    checks, observation = inspection.inspect_github_release(
        manifest,
        token=TOKEN_SENTINEL,
        http_get=fake,
        now=lambda: GENERATED_AT,
    )
    rendered = json.dumps({"checks": checks, "observation": observation}, sort_keys=True)
    assert TOKEN_SENTINEL not in rendered
    assert "Authorization" not in rendered
    assert fake.requests
    assert all(
        request["headers"].get("Authorization") == f"Bearer {TOKEN_SENTINEL}" for request in fake.requests
    )


def test_github_inspection_without_identity_never_guesses(tmp_path: Path) -> None:
    _, _, manifest = make_release(tmp_path)
    manifest["release"]["tag"] = "not-a-release-tag"
    checks, _ = inspection.inspect_github_release(manifest, now=lambda: GENERATED_AT)
    assert _state(checks, "github-tag-exists") == FAIL
    assert all(check["state"] != PASS for check in checks)


# ---------------------------------------------------------------------------
# GHCR digest and platform inspection
# ---------------------------------------------------------------------------


def _registry_runner(
    manifest: dict[str, Any],
    *,
    override_digest: str | None = None,
    failure: str | None = None,
) -> Any:
    digests = {image["name"]: image["digest"] for image in manifest["images"]}

    def runner(args: Any, *, timeout: int = 180) -> subprocess.CompletedProcess[str]:
        del timeout
        if args[:3] == ["docker", "buildx", "version"]:
            return subprocess.CompletedProcess(args, 0, "github.com/docker/buildx v0.30.0\n", "")
        if args[:3] == ["docker", "buildx", "imagetools"] and "--raw" in args:
            payload = {
                "manifests": [
                    {"platform": {"os": "linux", "architecture": "amd64"}},
                ]
            }
            return subprocess.CompletedProcess(args, 0, json.dumps(payload), "")
        reference = args[-1]
        name = reference.rsplit("/", 1)[-1].split(":", 1)[0].split("@", 1)[0]
        digest = digests.get(name)
        if failure is not None:
            return subprocess.CompletedProcess(args, 1, "", failure)
        if override_digest is not None and name == "api":
            return subprocess.CompletedProcess(args, 0, override_digest + "\n", "")
        if digest is None:
            return subprocess.CompletedProcess(args, 1, "", "manifest unknown")
        return subprocess.CompletedProcess(args, 0, digest + "\n", "")

    return runner


def test_ghcr_inspection_unavailable_without_docker(tmp_path: Path) -> None:
    _, _, manifest = make_release(tmp_path)
    checks, _ = inspection.inspect_ghcr(
        manifest,
        runner=_registry_runner(manifest),
        which=lambda _: None,
        now=lambda: GENERATED_AT,
    )
    assert all(check["state"] == UNAVAILABLE for check in checks)
    assert {check["name"] for check in checks} == {
        "ghcr-api",
        "ghcr-web",
        "ghcr-api-gpu",
        "ghcr-platform-metadata",
    }


def test_ghcr_inspection_passes_with_matching_digests(tmp_path: Path) -> None:
    _, _, manifest = make_release(tmp_path)
    checks, observation = inspection.inspect_ghcr(
        manifest,
        runner=_registry_runner(manifest),
        which=lambda name: rf"C:\tools\{name}.exe",
        now=lambda: GENERATED_AT,
    )
    assert all(check["state"] == PASS for check in checks), checks
    assert set(observation["images"]) == set(REQUIRED_IMAGES)
    assert observation["platforms"]["api"][0]["architecture"] == "amd64"


def test_ghcr_inspection_fails_on_digest_mismatch(tmp_path: Path) -> None:
    _, _, manifest = make_release(tmp_path)
    checks, _ = inspection.inspect_ghcr(
        manifest,
        runner=_registry_runner(manifest, override_digest="sha256:" + "0" * 64),
        which=lambda name: rf"C:\tools\{name}.exe",
        now=lambda: GENERATED_AT,
    )
    assert _state(checks, "ghcr-api") == FAIL


def test_ghcr_inspection_auth_failure_is_unavailable(tmp_path: Path) -> None:
    _, _, manifest = make_release(tmp_path)
    checks, _ = inspection.inspect_ghcr(
        manifest,
        runner=_registry_runner(manifest, failure="unauthorized: authentication required"),
        which=lambda name: rf"C:\tools\{name}.exe",
        now=lambda: GENERATED_AT,
    )
    assert _state(checks, "ghcr-api") == UNAVAILABLE


# ---------------------------------------------------------------------------
# Attestation and local artifact evidence
# ---------------------------------------------------------------------------


def test_attestation_inspection_without_gh_is_unavailable(tmp_path: Path) -> None:
    _, artifacts, manifest = make_release(tmp_path)
    checks, _ = inspection.inspect_attestations(
        manifest,
        runner=_registry_runner(manifest),
        which=lambda _: None,
        artifacts_dir=artifacts,
        now=lambda: GENERATED_AT,
    )
    assert _state(checks, "attestation-cli") == UNAVAILABLE
    assert all(check["state"] == UNAVAILABLE for check in checks)


def test_artifact_inspection_requires_an_explicit_directory() -> None:
    manifest = {"images": []}
    checks, _ = inspection.inspect_artifacts(manifest, artifacts_dir=None, now=lambda: GENERATED_AT)
    assert {check["name"] for check in checks} == {"sbom-evidence", "scan-evidence"}
    assert all(check["state"] == UNAVAILABLE for check in checks)


def test_artifact_inspection_passes_with_clean_local_evidence(tmp_path: Path) -> None:
    _, artifacts, manifest = make_release(tmp_path)
    checks, observation = inspection.inspect_artifacts(
        manifest,
        artifacts_dir=artifacts,
        now=lambda: GENERATED_AT,
    )
    assert all(check["state"] == PASS for check in checks), checks
    assert set(observation["sbom"]) == set(REQUIRED_IMAGES)


# ---------------------------------------------------------------------------
# Bounded connectivity primitives
# ---------------------------------------------------------------------------


def test_connectivity_timeout_bounds_are_explicit() -> None:
    assert connectivity.validate_timeout(1) == 1.0
    assert connectivity.validate_timeout(60) == 60.0
    for value in (0, 0.5, 61, True, "10"):
        with pytest.raises(connectivity.ConnectivityError):
            connectivity.validate_timeout(value)  # type: ignore[arg-type]


def test_target_hosts_uses_only_explicit_target_hostnames() -> None:
    assert connectivity.target_hosts(_target()) == [
        ("api.staging.example.test", 443),
        ("web.staging.example.test", 443),
        ("ws.staging.example.test", 443),
    ]
    with pytest.raises(connectivity.ConnectivityError):
        connectivity.target_hosts({"api_url": "https://api.staging.example.test"})


def test_certificate_days_remaining_is_computed_from_not_after() -> None:
    cert = {"notAfter": FUTURE_CERT}
    days = connectivity.certificate_days_remaining(
        cert, now_epoch=ssl.cert_time_to_seconds(FUTURE_CERT) - 86400 * 30
    )
    assert days == pytest.approx(30.0)
    assert connectivity.certificate_days_remaining({}) is None
    assert connectivity.certificate_days_remaining({"notAfter": "nonsense"}) is None


class _FakeResponse:
    def __init__(self, status: int, payload: Any, headers: dict[str, str], text: str = "") -> None:
        self.status = status
        self.payload = payload
        self.headers = {key.lower(): value for key, value in headers.items()}
        self.text = text

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


def _healthy_probes() -> dict[str, Any]:
    headers = {
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "strict-origin-when-cross-origin",
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-permitted-cross-domain-policies": "none",
    }
    payloads = {
        "/live": {"status": "ok"},
        "/ready": {"ready": True},
        "/health": {"status": "ok"},
        "/": {"service": "industrial-vision-platform"},
    }

    def http_probe(url: str, *, timeout: float) -> _FakeResponse:
        del timeout
        path = urlsplit(url).path or "/"
        if "web.staging" in url:
            return _FakeResponse(
                200,
                None,
                headers,
                "<title>Industrial AI Vision Platform</title>",
            )
        return _FakeResponse(200, payloads.get(path, {}), headers)

    return {
        "dns_resolve": lambda host, port, *, timeout: ["192.0.2.10"],
        "tcp_probe": lambda host, port, *, timeout: None,
        "tls_probe": lambda host, port, *, timeout: {"notAfter": FUTURE_CERT},
        "http_probe": http_probe,
        "ws_probe": lambda url, *, timeout: (PASS, "WSS handshake succeeded"),
        "now_epoch": lambda: ssl.cert_time_to_seconds(FUTURE_CERT) - 86400 * 90,
        "now_iso": lambda: GENERATED_AT,
    }


def test_connectivity_checks_pass_with_healthy_bounded_probes() -> None:
    checks, observation = connectivity.connectivity_checks(_target(), **_healthy_probes())
    assert all(check["state"] == PASS for check in checks), checks
    assert observation["timeout_seconds"] == connectivity.DEFAULT_CONNECTIVITY_TIMEOUT
    assert observation["target"]["ports"] == [443]
    assert set(observation["dns"]) == {
        "api.staging.example.test",
        "web.staging.example.test",
        "ws.staging.example.test",
    }


def test_connectivity_checks_fail_closed_on_network_errors() -> None:
    def boom(*args: Any, **kwargs: Any) -> Any:
        raise OSError("network unreachable")

    checks, _ = connectivity.connectivity_checks(
        _target(),
        dns_resolve=boom,
        tcp_probe=boom,
        tls_probe=boom,
        http_probe=boom,
        ws_probe=lambda url, *, timeout: (FAIL, "WSS handshake failed"),
        now_epoch=lambda: 0.0,
        now_iso=lambda: GENERATED_AT,
    )
    required = [check for check in checks if check["required"] is True]
    assert required
    assert all(check["state"] != PASS for check in required), checks


def test_connectivity_rejects_expiring_certificates() -> None:
    probes = _healthy_probes()
    probes["tls_probe"] = lambda host, port, *, timeout: {"notAfter": FUTURE_CERT}
    probes["now_epoch"] = lambda: ssl.cert_time_to_seconds(FUTURE_CERT) - 86400 * 3
    checks, observation = connectivity.connectivity_checks(_target(), **probes)
    assert _state(checks, "tls-certificate") == FAIL
    assert observation["tls"]["api.staging.example.test"]["days_remaining"] == pytest.approx(3.0)


def test_websocket_unauthorized_close_code_is_reachable() -> None:
    class _Rejected(Exception):
        code = 4401

    def connect(url: str, timeout: float) -> Any:
        del url, timeout
        raise _Rejected("unauthorized")

    state, detail = connectivity.websocket_probe(
        "wss://ws.staging.example.test/ws/operations",
        ws_connect=connect,
    )
    assert state == PASS
    assert "4401" in detail


def test_connectivity_observation_never_contains_credentials() -> None:
    target = _target(
        api_url="https://api.staging.example.test",
        smoke_username="smoke@example.test",
    )
    _, observation = connectivity.connectivity_checks(target, **_healthy_probes())
    rendered = json.dumps(observation, sort_keys=True)
    assert "smoke@example.test" not in rendered
    assert "IVP_SMOKE_PASSWORD" not in rendered
