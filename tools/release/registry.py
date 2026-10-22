"""GitHub release/registry immutability checks (V22).

Release tags and the artifacts they point at are immutable. Before building
anything, the release workflow asks GitHub whether a release or matching GHCR
tags already exist. Any API failure other than a definitive 404 raises: a
permission or network problem must block publication, not silently allow an
overwrite.

Standard library only, with an injectable fetcher for offline tests.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Sequence
from typing import Any

API_ROOT = "https://api.github.com"
PAGE_SIZE = 100
MAX_PAGES = 20

Fetcher = Callable[[str, str], tuple[int, Any]]


class RegistryError(RuntimeError):
    """GitHub could not prove that a release is new."""


def _default_fetch(url: str, token: str) -> tuple[int, Any]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "ivp-release-validator",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, None
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RegistryError(f"GitHub API request failed: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise RegistryError(f"GitHub API returned invalid JSON for {url}: {exc}") from exc


def release_exists(
    repository: str,
    tag: str,
    token: str,
    *,
    fetch: Fetcher = _default_fetch,
) -> bool:
    encoded_tag = urllib.parse.quote(tag, safe="")
    status, _ = fetch(f"{API_ROOT}/repos/{repository}/releases/tags/{encoded_tag}", token)
    if status == 200:
        return True
    if status == 404:
        return False
    raise RegistryError(f"could not verify existing release {tag}: GitHub API returned HTTP {status}")


def _paged(
    repository: str,
    path: str,
    token: str,
    fetch: Fetcher,
    *,
    label: str,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for page in range(1, MAX_PAGES + 1):
        separator = "&" if "?" in path else "?"
        url = f"{API_ROOT}{path}{separator}per_page={PAGE_SIZE}&page={page}"
        status, payload = fetch(url, token)
        if status == 404:
            return []
        if status != 200:
            raise RegistryError(
                f"could not inspect {label} for {repository}: GitHub API returned HTTP {status}"
            )
        if not isinstance(payload, list):
            raise RegistryError(f"GitHub API returned a non-list payload for {label}")
        items.extend(item for item in payload if isinstance(item, dict))
        if len(payload) < PAGE_SIZE:
            return items
    raise RegistryError(f"too many {label} pages for {repository}; refusing to guess")


def _package_names_for(image: str, repository: str, packages: Sequence[dict[str, Any]]) -> list[str]:
    repository_name = repository.split("/", 1)[1].lower()
    expected = {f"{repository_name}/{image}", image}
    names: list[str] = []
    for package in packages:
        name = package.get("name")
        if not isinstance(name, str):
            continue
        lowered = name.lower()
        if lowered in expected or lowered.endswith(f"/{image}"):
            names.append(name)
    return names


def registry_conflicts(
    repository: str,
    tag: str,
    images: Sequence[str],
    token: str,
    *,
    fetch: Fetcher = _default_fetch,
) -> list[str]:
    packages = _paged(
        repository,
        f"/repos/{repository}/packages?package_type=container",
        token,
        fetch,
        label="container packages",
    )
    conflicts: list[str] = []
    for image in images:
        for package_name in _package_names_for(image, repository, packages):
            encoded = urllib.parse.quote(package_name, safe="")
            versions = _paged(
                repository,
                f"/repos/{repository}/packages/container/{encoded}/versions",
                token,
                fetch,
                label=f"package versions for {package_name}",
            )
            for version in versions:
                metadata = version.get("metadata") or {}
                container = metadata.get("container") or {}
                tags = container.get("tags") or []
                if isinstance(tags, list) and tag in tags:
                    conflicts.append(f"ghcr.io/{repository.lower()}/{image}:{tag}")
    return sorted(set(conflicts))


def check_release_conflicts(
    repository: str,
    tag: str,
    images: Sequence[str],
    token: str,
    *,
    fetch: Fetcher = _default_fetch,
) -> list[str]:
    conflicts: list[str] = []
    if release_exists(repository, tag, token, fetch=fetch):
        conflicts.append(f"GitHub Release {tag} already exists; release tags are immutable")
    conflicts.extend(registry_conflicts(repository, tag, images, token, fetch=fetch))
    return conflicts
