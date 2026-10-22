"""V22 fail-closed release/registry immutability checks (offline fake API)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from tools.release.identity import REQUIRED_IMAGES
from tools.release.manifest import build_manifest, render_summary
from tools.release.registry import (
    RegistryError,
    check_release_conflicts,
    registry_conflicts,
    release_exists,
)

TOKEN = "test-token"
REPOSITORY = "Octo/Repo"
TAG = "v1.2.3"

Route = tuple[int, Any] | Callable[[str], tuple[int, Any]]


def _fetch(routes: dict[str, Route]) -> tuple[Callable[[str, str], tuple[int, Any]], list[str]]:
    calls: list[str] = []

    def fetch(url: str, token: str) -> tuple[int, Any]:
        assert token == TOKEN
        calls.append(url)
        for fragment, response in routes.items():
            if fragment in url:
                return response(url) if callable(response) else response
        raise AssertionError(f"unexpected URL: {url}")

    return fetch, calls


def test_release_exists_distinguishes_absent_from_unverifiable() -> None:
    fetch, _ = _fetch({"/releases/tags/": (404, None)})
    assert release_exists(REPOSITORY, TAG, TOKEN, fetch=fetch) is False

    fetch, _ = _fetch({"/releases/tags/": (200, {"tag_name": TAG})})
    assert release_exists(REPOSITORY, TAG, TOKEN, fetch=fetch) is True

    fetch, _ = _fetch({"/releases/tags/": (403, None)})
    with pytest.raises(RegistryError, match="HTTP 403"):
        release_exists(REPOSITORY, TAG, TOKEN, fetch=fetch)


def test_new_release_has_no_conflicts() -> None:
    fetch, _ = _fetch({"/releases/tags/": (404, None), "/packages?": (200, [])})
    assert check_release_conflicts(REPOSITORY, TAG, REQUIRED_IMAGES, TOKEN, fetch=fetch) == []


def test_existing_release_is_a_conflict() -> None:
    fetch, _ = _fetch({"/releases/tags/": (200, {}), "/packages?": (200, [])})
    conflicts = check_release_conflicts(REPOSITORY, TAG, REQUIRED_IMAGES, TOKEN, fetch=fetch)
    assert len(conflicts) == 1
    assert "already exists" in conflicts[0]


def test_existing_registry_tag_is_a_conflict() -> None:
    fetch, calls = _fetch(
        {
            "/releases/tags/": (404, None),
            "/packages?": (200, [{"name": "repo/api"}]),
            "/packages/container/": (
                200,
                [{"metadata": {"container": {"tags": [TAG, "sha-aaaaaaa"]}}}],
            ),
        }
    )
    conflicts = registry_conflicts(REPOSITORY, TAG, REQUIRED_IMAGES, TOKEN, fetch=fetch)
    assert conflicts == ["ghcr.io/octo/repo/api:v1.2.3"]
    assert any("repo%2Fapi" in url for url in calls)


def test_other_version_tags_do_not_conflict() -> None:
    fetch, _ = _fetch(
        {
            "/packages?": (200, [{"name": "repo/api"}]),
            "/packages/container/": (200, [{"metadata": {"container": {"tags": ["v1.2.2"]}}}]),
        }
    )
    assert registry_conflicts(REPOSITORY, TAG, REQUIRED_IMAGES, TOKEN, fetch=fetch) == []


def test_missing_versions_endpoint_is_treated_as_absent() -> None:
    fetch, _ = _fetch(
        {
            "/packages?": (200, [{"name": "repo/api"}]),
            "/packages/container/": (404, None),
        }
    )
    assert registry_conflicts(REPOSITORY, TAG, REQUIRED_IMAGES, TOKEN, fetch=fetch) == []


def test_api_failure_blocks_publication() -> None:
    fetch, _ = _fetch({"/packages?": (403, None)})
    with pytest.raises(RegistryError, match="HTTP 403"):
        registry_conflicts(REPOSITORY, TAG, REQUIRED_IMAGES, TOKEN, fetch=fetch)


def test_summary_records_digests_and_verification_commands(tmp_path: Path) -> None:
    from backend.tests.unit.test_release_manifest import make_inputs

    inputs, artifacts = make_inputs(tmp_path)
    manifest = build_manifest(inputs, artifacts)
    summary = render_summary(manifest)

    assert "## Release artifacts" in summary
    assert "ghcr.io/octo/repo/api-gpu" in summary
    assert manifest["images"][0]["digest"] in summary
    assert "gh attestation verify oci://ghcr.io/octo/repo/api@" in summary
    assert "--predicate-type https://spdx.dev/Document" in summary
    assert "GPU runtime smoke: NOT RUN" in summary
    assert "docs/RELEASES.md" in summary
