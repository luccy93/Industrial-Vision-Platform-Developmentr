"""V22 release identity rules (offline; local git repositories only)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tools.release.identity import (
    IdentityError,
    image_repository,
    parse_tag,
    release_conflicts,
    release_image_tags,
    validate_commit,
    validate_digest,
    validate_source_repository,
    validate_tag,
    verify_tag_commit,
)

VALID_TAGS = ["v0.0.0", "v1.2.3", "v10.20.30"]

INVALID_TAGS = [
    "1.2.3",
    "v1",
    "v1.2",
    "v1.2.3.4",
    "v1.2.3-rc.1",
    "v1.2.3-alpha",
    "v1.2.3+build.5",
    "v01.2.3",
    "v1.02.3",
    "v1.2.03",
    "V1.2.3",
    "latest",
    "v1.2.x",
    " v1.2.3",
    "v1.2.3 ",
    "",
    "v-1.2.3",
]

COMMIT = "a" * 40
DIGEST = "sha256:" + "b" * 64


@pytest.mark.parametrize("tag", VALID_TAGS)
def test_valid_stable_tags_are_accepted(tag: str) -> None:
    assert validate_tag(tag) == tag


@pytest.mark.parametrize("tag", INVALID_TAGS)
def test_malformed_tags_are_rejected(tag: str) -> None:
    with pytest.raises(IdentityError):
        validate_tag(tag)


def test_parse_tag_components() -> None:
    parsed = parse_tag("v12.34.56")
    assert (parsed.major, parsed.minor, parsed.patch) == (12, 34, 56)
    assert str(parsed) == "v12.34.56"


def test_commit_validation() -> None:
    assert validate_commit(COMMIT) == COMMIT
    for value in ("A" * 40, "a" * 39, "a" * 41, "g" * 40, ""):
        with pytest.raises(IdentityError):
            validate_commit(value)


def test_digest_validation() -> None:
    assert validate_digest(DIGEST) == DIGEST
    for value in (
        "sha256:" + "B" * 64,
        "sha512:" + "b" * 64,
        "sha256:" + "b" * 63,
        "b" * 64,
        "",
    ):
        with pytest.raises(IdentityError):
            validate_digest(value)


def test_image_repository_is_canonical_ghcr_path() -> None:
    assert image_repository("Octo/Repo", "api") == "ghcr.io/octo/repo/api"
    assert image_repository("octo/repo", "api-gpu") == "ghcr.io/octo/repo/api-gpu"
    with pytest.raises(IdentityError):
        image_repository("octo/repo", "debug")
    with pytest.raises(IdentityError):
        validate_source_repository("not-a-repository")


def test_release_image_tags_are_immutable_references() -> None:
    assert release_image_tags("v1.2.3", COMMIT) == ("v1.2.3", "sha-aaaaaaa")


def test_release_conflicts() -> None:
    assert release_conflicts("v1.2.3", release_exists=False, image_tags_exist=False) == []
    release = release_conflicts("v1.2.3", release_exists=True, image_tags_exist=False)
    assert len(release) == 1 and "already exists" in release[0]
    images = release_conflicts("v1.2.3", release_exists=False, image_tags_exist=True)
    assert len(images) == 1 and "refusing to overwrite" in images[0]
    both = release_conflicts("v1.2.3", release_exists=True, image_tags_exist=True)
    assert len(both) == 2


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _repo(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "release-tests@example.test")
    _git(repo, "config", "user.name", "Release Tests")
    (repo / "file.txt").write_text("one\n", encoding="utf-8")
    _git(repo, "add", "file.txt")
    _git(repo, "commit", "-m", "one")
    _git(repo, "branch", "-M", "main")
    return repo, _git(repo, "rev-parse", "HEAD")


def test_verify_tag_commit_accepts_annotated_and_lightweight_tags(tmp_path: Path) -> None:
    repo, commit = _repo(tmp_path)
    _git(repo, "tag", "v1.0.0")
    _git(repo, "tag", "-a", "v1.0.1", "-m", "annotated")

    verify_tag_commit("v1.0.0", commit, repo, main_ref="main")
    verify_tag_commit("v1.0.1", commit, repo, main_ref="main")


def test_verify_tag_commit_rejects_mismatch(tmp_path: Path) -> None:
    repo, first = _repo(tmp_path)
    _git(repo, "tag", "v1.0.0")
    (repo / "file.txt").write_text("two\n", encoding="utf-8")
    _git(repo, "commit", "-am", "two")
    second = _git(repo, "rev-parse", "HEAD")

    with pytest.raises(IdentityError, match="points at"):
        verify_tag_commit("v1.0.0", second, repo, main_ref="main")
    assert first != second


def test_verify_tag_commit_rejects_unapproved_commit(tmp_path: Path) -> None:
    repo, _ = _repo(tmp_path)
    _git(repo, "checkout", "-b", "feature")
    (repo / "file.txt").write_text("feature\n", encoding="utf-8")
    _git(repo, "commit", "-am", "feature")
    feature_commit = _git(repo, "rev-parse", "HEAD")
    _git(repo, "tag", "v2.0.0")
    _git(repo, "checkout", "main")

    with pytest.raises(IdentityError, match="not reachable from main"):
        verify_tag_commit("v2.0.0", feature_commit, repo, main_ref="main")


def test_verify_tag_commit_rejects_unknown_tag_or_main_ref(tmp_path: Path) -> None:
    repo, commit = _repo(tmp_path)
    with pytest.raises(IdentityError):
        verify_tag_commit("v9.9.9", commit, repo, main_ref="main")

    _git(repo, "tag", "v1.0.0")
    with pytest.raises(IdentityError):
        verify_tag_commit("v1.0.0", commit, repo, main_ref="origin/main")
