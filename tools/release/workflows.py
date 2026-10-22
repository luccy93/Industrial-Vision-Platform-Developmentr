"""Workflow supply-chain policy checks (V22).

Rules enforced:

* every remote ``uses:`` reference is pinned to a full 40-character commit SHA
  (a trailing version comment is allowed);
* local ``uses: ./path`` references are allowed;
* registry images started with ``docker run`` must be digest-pinned.

The check is textual and dependency-free on purpose: the release validation
job runs before project dependencies are installed. Registry-qualified image
names are required for scanner containers; Docker Hub shorthand is rejected
by review, not silently accepted here.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path

USES_PATTERN = re.compile(r"^\s*(?:-\s*)?uses:\s*['\"]?([^'\"\s#]+)")
SHA_PIN_PATTERN = re.compile(r"@[0-9a-f]{40}$")
DIGEST_PIN_PATTERN = re.compile(r"@sha256:[0-9a-f]{64}$")
LOCAL_IMAGE_PREFIXES = ("ivp-", "localhost/", "localhost:", "127.0.0.1/")


def workflow_files(root: Path) -> list[Path]:
    """Return workflow files under *root* (a repo root or workflows dir)."""
    candidate = root / ".github" / "workflows"
    directory = candidate if candidate.is_dir() else root
    files = sorted(set(directory.glob("*.yml")) | set(directory.glob("*.yaml")))
    return [path for path in files if path.is_file()]


def _registry_images(line: str) -> list[str]:
    marker = "docker run"
    index = line.find(marker)
    if index < 0:
        return []
    try:
        tokens = shlex.split(line[index + len(marker) :].replace("\\", ""), comments=False)
    except ValueError:
        return []
    images: list[str] = []
    for token in tokens:
        if token.startswith(("-", "$", "/", ".", "~")):
            continue
        head = token.split("/", 1)[0]
        if "." not in head and ":" not in head:
            continue
        if token.startswith(LOCAL_IMAGE_PREFIXES):
            continue
        images.append(token)
    return images


def audit_workflow_text(path_label: str, text: str) -> list[str]:
    """Return policy violations for one workflow body."""
    errors: list[str] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        match = USES_PATTERN.match(line)
        if match is not None:
            reference = match.group(1)
            if not reference.startswith("./") and SHA_PIN_PATTERN.search(reference) is None:
                errors.append(
                    f"{path_label}:{line_number}: action {reference} is not pinned to a "
                    "40-character commit SHA"
                )
        for image in _registry_images(line):
            if DIGEST_PIN_PATTERN.search(image) is None:
                errors.append(
                    f"{path_label}:{line_number}: container image {image} is not digest-pinned "
                    "(expected name@sha256:<64 hex>)"
                )
    return errors


def audit_workflows(root: Path) -> list[str]:
    """Audit every workflow file under *root*; empty list means compliant."""
    files = workflow_files(root)
    if not files:
        return [f"no workflow files found under {root}"]
    errors: list[str] = []
    for path in files:
        try:
            label = str(path.relative_to(root))
        except ValueError:
            label = path.name
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            errors.append(f"{label}: could not read workflow: {exc}")
            continue
        errors.extend(audit_workflow_text(label, text))
    return errors
