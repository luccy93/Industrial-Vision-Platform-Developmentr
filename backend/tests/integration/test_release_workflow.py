"""V22 release supply-chain static validation.

Offline checks over the release/CI workflows and the digest-pinned Compose
overlays. They prove the policy is encoded in the repository, not that a real
release ran (no release tag is created by these tests).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from tools.release.workflows import audit_workflows

REPO_ROOT = Path(__file__).resolve().parents[3]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
SHA_PIN = re.compile(r"@[0-9a-f]{40}$")
IMAGES = ("api", "web", "api-gpu")


def _read(name: str) -> str:
    return (REPO_ROOT / name).read_text(encoding="utf-8")


def _workflow(name: str) -> dict[str, Any]:
    with open(WORKFLOWS / name, encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    return job.get("steps") or []


def _step_names(job: dict[str, Any]) -> list[str]:
    return [step.get("name", str(step.get("uses", ""))) for step in _steps(job)]


def _release_raw() -> str:
    return _read(".github/workflows/release.yml")


def test_release_triggers_only_on_version_tags() -> None:
    raw = _release_raw()
    trigger = raw.split("\njobs:", 1)[0]
    assert re.search(r"^on:\s*$", trigger, re.MULTILINE)
    assert re.search(r"^  push:\s*$", trigger, re.MULTILINE)
    assert re.search(r'^    tags: \["v\*"\]$', trigger, re.MULTILINE)
    assert "pull_request" not in trigger
    assert "workflow_dispatch" not in trigger
    assert "branches:" not in trigger
    assert re.search(r"^  cancel-in-progress: false$", raw, re.MULTILINE)


def test_release_permissions_are_least_privilege() -> None:
    config = _workflow("release.yml")
    assert config["permissions"] == {}
    jobs = config["jobs"]
    assert jobs["validate"]["permissions"] == {"contents": "read", "packages": "read"}
    assert jobs["gates"]["permissions"] == {"contents": "read"}
    assert jobs["publish"]["permissions"] == {
        "contents": "read",
        "packages": "write",
        "id-token": "write",
        "attestations": "write",
    }
    assert jobs["release"]["permissions"] == {"contents": "write"}
    assert jobs["gates"]["needs"] == "validate"
    assert jobs["publish"]["needs"] == "gates"
    assert jobs["release"]["needs"] == "publish"


def test_every_release_action_is_sha_pinned() -> None:
    config = _workflow("release.yml")
    references = [step["uses"] for job in config["jobs"].values() for step in _steps(job) if "uses" in step]
    assert references
    assert all(SHA_PIN.search(reference) for reference in references), references
    assert audit_workflows(REPO_ROOT) == []


def test_release_checks_tag_identity_before_building() -> None:
    config = _workflow("release.yml")
    validate = config["jobs"]["validate"]
    commands = "\n".join(step.get("run", "") for step in _steps(validate))
    assert "validate-tag" in commands
    assert "verify-tag-commit" in commands
    assert "--main-ref origin/main" in commands
    assert "check-release" in commands
    assert "GITHUB_TOKEN" in _release_raw()
    gates = "\n".join(step.get("run", "") for step in _steps(config["jobs"]["gates"]))
    assert "pytest backend/tests" in gates
    assert "ruff check backend tools" in gates


def test_release_pipeline_builds_scans_and_pushes_all_images() -> None:
    config = _workflow("release.yml")
    publish = config["jobs"]["publish"]
    names = _step_names(publish)
    build_at = names.index("Build release images")
    scan_at = names.index("Scan release images (blocking)")
    push_at = names.index("Publish images and prove digest association")
    sbom_at = names.index("Generate SPDX SBOMs from published digests")
    assert build_at < scan_at < push_at < sbom_at

    body = "\n".join(step.get("run", "") for step in _steps(publish))
    for image in IMAGES:
        assert f"ivp-{image}:release" in body
        assert f"{image}.spdx.json" in body
    assert "spdx-json" in body
    # Scans are blocking and happen before any push.
    assert "--exit-code 1" in body
    assert "--severity CRITICAL,HIGH" in body
    assert "--ignore-unfixed" in body
    # Digest association proof: registry digest, re-pull, image ID equality.
    assert "imagetools inspect" in body
    assert "docker pull" in body
    assert "PULLED_ID" in body and "LOCAL_ID" in body
    # No mutable alias is ever published.
    assert ":latest" not in body and "latest" not in body


def test_release_attests_provenance_and_sbom_for_each_image() -> None:
    config = _workflow("release.yml")
    publish = config["jobs"]["publish"]
    attest_steps = [step for step in _steps(publish) if step.get("uses", "").startswith("actions/attest@")]
    assert len(attest_steps) == 6
    assert sum("sbom-path" in step["with"] for step in attest_steps) == 3
    for step in attest_steps:
        assert step["with"]["push-to-registry"] is True
        assert step["with"]["create-storage-record"] is False
    body = "\n".join(step.get("run", "") for step in _steps(publish))
    assert "release-manifest.json" in body
    assert "tools.release.cli generate" in body
    assert "tools.release.cli validate" in body
    assert "gpu_runtime_smoke" in body and "not_run" in body
    assert "GPU infrastructure unavailable" in body


def test_release_publishes_verified_release_with_evidence() -> None:
    raw = _release_raw()
    config = _workflow("release.yml")
    release = config["jobs"]["release"]
    body = "\n".join(step.get("run", "") for step in _steps(release))
    assert "download-artifact" in " ".join(step.get("uses", "") for step in _steps(release))
    assert "gh release create" in body
    assert "--verify-tag" in body
    assert "release-manifest.json" in body
    assert "tools.release.cli summary" in body
    for image in IMAGES:
        assert f"{image}.spdx.json" in body
    # Triggering is a push tag; the workflow itself never creates or moves tags.
    assert "git tag" not in raw
    assert "git push" not in raw


def test_ci_workflow_cannot_publish_or_move_tags() -> None:
    raw = _read(".github/workflows/ci.yml")
    config = _workflow("ci.yml")
    for job in config["jobs"].values():
        permissions = job.get("permissions") or {}
        assert "write" not in str(permissions)
    assert "packages: write" not in raw
    assert "id-token: write" not in raw
    assert "contents: write" not in raw
    assert "gh release" not in raw
    assert "git tag" not in raw
    assert "git push" not in raw
    assert "docker push" not in raw
    assert "actions/attest" not in raw


def test_ci_runs_pinning_audit_and_validates_release_overlays() -> None:
    config = _workflow("ci.yml")
    security = "\n".join(step.get("run", "") for step in _steps(config["jobs"]["security"]))
    assert "audit-workflows --root ." in security
    deploy = "\n".join(step.get("run", "") for step in _steps(config["jobs"]["deploy"]))
    assert "compose.release.yaml" in deploy
    assert "compose.gpu.release.yaml" in deploy


def test_release_compose_overlays_remove_build_and_pin_images() -> None:
    class ResetLoader(yaml.SafeLoader):
        pass

    ResetLoader.add_constructor("!reset", lambda loader, node: None)

    for name, expected_images in (
        (
            "compose.release.yaml",
            ("IVP_API_IMAGE", "IVP_WEB_IMAGE"),
        ),
        (
            "compose.gpu.release.yaml",
            ("IVP_CPU_API_IMAGE", "IVP_GPU_API_IMAGE", "IVP_WEB_IMAGE"),
        ),
    ):
        with open(REPO_ROOT / name, encoding="utf-8") as handle:
            overlay = yaml.load(handle, Loader=ResetLoader)
        _assert_digest_only_overlay(overlay, expected_images)


def _assert_digest_only_overlay(overlay: dict[str, Any], expected_images: tuple[str, ...]) -> None:
    services = overlay["services"]
    assert services["migrate"]["build"] is None
    assert services["web"]["build"] is None
    for name in ("migrate", "api", "web"):
        image = services[name]["image"]
        assert any(variable in image for variable in expected_images), (name, image)
        assert "@sha256:" not in image  # provided at deploy time
        assert ":?set " in image  # absent digest fails, no silent fallback


def test_release_gpu_overlay_keeps_cuda_and_nvidia_reservation() -> None:
    class ResetLoader(yaml.SafeLoader):
        pass

    ResetLoader.add_constructor("!reset", lambda loader, node: None)
    with open(REPO_ROOT / "compose.gpu.release.yaml", encoding="utf-8") as handle:
        overlay = yaml.load(handle, Loader=ResetLoader)
    api = overlay["services"]["api"]
    assert api["environment"]["MODEL_DEVICE"] == "cuda"
    device = api["deploy"]["resources"]["reservations"]["devices"][0]
    assert device["driver"] == "nvidia"
    assert "gpu" in device["capabilities"]
    # Migration stays on the CPU digest.
    assert "IVP_CPU_API_IMAGE" in overlay["services"]["migrate"]["image"]
    raw = _read("compose.gpu.release.yaml")
    assert "Do NOT combine" in raw
