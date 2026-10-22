"""Release identity rules for the tag-triggered release pipeline (V22).

This module is intentionally dependency-free (standard library only). The
release workflow validates the pushed tag before it installs any project
dependency, so importing third-party packages here would weaken the gate.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

#: Stable SemVer release tags only. Prereleases, build metadata, aliases,
#: leading zeros, and missing components are rejected by policy.
TAG_PATTERN = re.compile(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
SOURCE_REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")

#: Images that make up a stable release. GPU is a required deliverable:
#: a release that publishes CPU images without the verified GPU image would
#: advertise GPU support it cannot back.
REQUIRED_IMAGES = ("api", "web", "api-gpu")

SHORT_SHA_LENGTH = 7


class IdentityError(ValueError):
    """A release identity or immutability rule was violated."""


@dataclass(frozen=True)
class ReleaseVersion:
    major: int
    minor: int
    patch: int

    def __str__(self) -> str:
        return f"v{self.major}.{self.minor}.{self.patch}"


def parse_tag(tag: str) -> ReleaseVersion:
    """Parse a strict stable SemVer tag, or raise :class:`IdentityError`."""
    if not isinstance(tag, str):
        raise IdentityError("release tag must be a string")
    match = TAG_PATTERN.fullmatch(tag)
    if match is None:
        raise IdentityError(
            f"invalid release tag {tag!r}: expected vMAJOR.MINOR.PATCH with no prerelease, "
            "build metadata, leading zeros, or aliases"
        )
    return ReleaseVersion(*(int(part) for part in match.groups()))


def validate_tag(tag: str) -> str:
    """Return *tag* unchanged when it is a valid stable release tag."""
    parse_tag(tag)
    return tag


def validate_commit(commit: str) -> str:
    """Return *commit* when it is a full lowercase 40-character SHA."""
    if not isinstance(commit, str) or COMMIT_PATTERN.fullmatch(commit) is None:
        raise IdentityError(f"invalid commit SHA {commit!r}: expected 40 lowercase hex characters")
    return commit


def commit_short_sha(commit: str) -> str:
    return validate_commit(commit)[:SHORT_SHA_LENGTH]


def validate_digest(digest: str) -> str:
    """Return *digest* when it is a lowercase sha256 OCI digest."""
    if not isinstance(digest, str) or DIGEST_PATTERN.fullmatch(digest) is None:
        raise IdentityError(f"invalid image digest {digest!r}: expected sha256:<64 lowercase hex>")
    return digest


def validate_source_repository(repository: str) -> str:
    """Return *repository* when it looks like ``owner/name``."""
    if not isinstance(repository, str) or SOURCE_REPOSITORY_PATTERN.fullmatch(repository) is None:
        raise IdentityError(f"invalid source repository {repository!r}: expected owner/name")
    return repository


def image_repository(source_repository: str, image_name: str) -> str:
    """Return the canonical GHCR repository for a release image."""
    validate_source_repository(source_repository)
    if image_name not in REQUIRED_IMAGES:
        allowed = ", ".join(REQUIRED_IMAGES)
        raise IdentityError(f"unknown release image {image_name!r}: expected one of {allowed}")
    return f"ghcr.io/{source_repository.lower()}/{image_name}"


def release_image_tags(tag: str, commit: str) -> tuple[str, str]:
    """Return the immutable image tags published for a release commit.

    The version tag is the human-facing release reference; the short-SHA tag
    is the commit-addressed fallback. No mutable alias (``latest``) is
    published, so neither reference can silently move.
    """
    validate_tag(tag)
    return tag, f"sha-{commit_short_sha(commit)}"


def release_conflicts(tag: str, *, release_exists: bool, image_tags_exist: bool) -> list[str]:
    """Describe why a release must not proceed because it already exists.

    Release tags and their registry artifacts are immutable once published:
    a retry after a partial failure must use a new patch version instead of
    overwriting evidence for the failed attempt.
    """
    validate_tag(tag)
    conflicts: list[str] = []
    if release_exists:
        conflicts.append(f"a GitHub Release for {tag} already exists; published release tags are immutable")
    if image_tags_exist:
        conflicts.append(
            f"one or more registry tags for {tag} already exist; refusing to overwrite published artifacts"
        )
    return conflicts


def _git(repo_root: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), *args],
            capture_output=True,
            check=False,
            text=True,
        )
    except OSError as exc:  # pragma: no cover - git is a workflow prerequisite
        raise IdentityError(f"git is unavailable: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise IdentityError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout.strip()


def resolve_tag_commit(tag: str, repo_root: Path) -> str:
    """Resolve an annotated or lightweight tag to the commit it points at."""
    validate_tag(tag)
    return _git(repo_root, "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}")


def verify_tag_commit(tag: str, commit: str, repo_root: Path, *, main_ref: str = "origin/main") -> None:
    """Require the tag to point at *commit* and *commit* to be on the main line.

    This rejects both tag/commit mismatches and releases of commits that were
    never merged into the deployment branch under a misleading version label.
    """
    validate_tag(tag)
    validate_commit(commit)
    tag_commit = resolve_tag_commit(tag, repo_root)
    if tag_commit != commit:
        raise IdentityError(f"tag {tag} points at {tag_commit}, but this workflow runs for {commit}")
    _git(repo_root, "rev-parse", "--verify", f"{main_ref}^{{commit}}")
    result = subprocess.run(
        ["git", "-C", str(repo_root), "merge-base", "--is-ancestor", commit, main_ref],
        capture_output=True,
        check=False,
        text=True,
    )
    if result.returncode == 1:
        raise IdentityError(
            f"commit {commit} is not reachable from {main_ref}; release tags must point at an approved commit"
        )
    if result.returncode != 0:
        detail = result.stderr.strip() or f"exit {result.returncode}"
        raise IdentityError(f"could not verify reachability from {main_ref}: {detail}")
