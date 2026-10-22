"""V22 workflow pinning audit and release CLI tests (offline)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tools.release.cli import main
from tools.release.workflows import audit_workflow_text, audit_workflows, workflow_files

PINNED = "11d5960a326750d5838078e36cf38b85af677262"
DIGEST = "sha256:" + "a" * 64


def test_pinned_actions_local_actions_and_digest_images_pass() -> None:
    text = (
        "steps:\n"
        f"  - uses: actions/checkout@{PINNED} # v4.4.0\n"
        "  - uses: ./local/action\n"
        f"  - run: docker run --rm ghcr.io/example/scanner@{DIGEST}\n"
    )
    assert audit_workflow_text("workflow.yml", text) == []


def test_unpinned_action_is_rejected() -> None:
    problems = audit_workflow_text("workflow.yml", "  - uses: actions/checkout@v4\n")
    assert len(problems) == 1
    assert "not pinned" in problems[0]
    assert "actions/checkout@v4" in problems[0]


def test_unpinned_container_image_is_rejected() -> None:
    problems = audit_workflow_text(
        "workflow.yml",
        "  - run: docker run --rm ghcr.io/example/scanner:1.2.3\n",
    )
    assert len(problems) == 1
    assert "not digest-pinned" in problems[0]


def test_locally_built_image_is_not_treated_as_a_registry_pull() -> None:
    assert audit_workflow_text("workflow.yml", "  - run: docker run --rm ivp-api:ci\n") == []


def test_continued_docker_run_is_still_audited() -> None:
    text = (
        "  - run: |\n      docker run --rm \\\n        ghcr.io/example/scanner:1.2.3 \\\n        scan /repo\n"
    )
    problems = audit_workflow_text("workflow.yml", text)
    assert len(problems) == 1
    assert "not digest-pinned" in problems[0]

    pinned = text.replace("ghcr.io/example/scanner:1.2.3", f"ghcr.io/example/scanner@{DIGEST}")
    assert audit_workflow_text("workflow.yml", pinned) == []


def test_volume_mounts_are_not_mistaken_for_images() -> None:
    text = (
        "  - run: |\n"
        "      docker run --rm -v trivy-cache:/root/.cache/trivy \\\n"
        f"        ghcr.io/example/scanner@{DIGEST} scan /repo\n"
    )
    assert audit_workflow_text("workflow.yml", text) == []


def test_workflow_files_accept_repo_root_or_workflows_directory(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    target = workflows / "ci.yml"
    target.write_text("name: ci\n", encoding="utf-8")

    assert workflow_files(tmp_path) == [target]
    assert workflow_files(workflows) == [target]


def test_audit_workflows_reports_missing_workflows(tmp_path: Path) -> None:
    problems = audit_workflows(tmp_path)
    assert len(problems) == 1
    assert "no workflow files found" in problems[0]


def test_cli_validate_tag(capsys: Any) -> None:
    assert main(["validate-tag", "--tag", "v1.2.3"]) == 0
    assert "valid" in capsys.readouterr().out
    assert main(["validate-tag", "--tag", "latest"]) == 1
    assert "error:" in capsys.readouterr().err


def test_cli_check_conflicts(capsys: Any) -> None:
    base = ["check-conflicts", "--tag", "v1.2.3"]
    assert main(base + ["--release-exists", "false", "--image-tags-exist", "false"]) == 0
    assert "no conflicting" in capsys.readouterr().out
    assert main(base + ["--release-exists", "true", "--image-tags-exist", "false"]) == 1
    assert "already exists" in capsys.readouterr().err


def test_cli_generate_and_validate_round_trip(tmp_path: Path, capsys: Any) -> None:
    from backend.tests.unit.test_release_manifest import make_inputs

    inputs, artifacts = make_inputs(tmp_path)
    inputs_path = tmp_path / "release-inputs.json"
    inputs_path.write_text(json.dumps(inputs), encoding="utf-8")
    output = artifacts / "release-manifest.json"

    assert (
        main(
            [
                "generate",
                "--inputs",
                str(inputs_path),
                "--artifacts-dir",
                str(artifacts),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert output.is_file()
    capsys.readouterr()

    assert (
        main(
            [
                "validate",
                "--manifest",
                str(output),
                "--artifacts-dir",
                str(artifacts),
                "--tag",
                "v1.2.3",
                "--commit",
                "a" * 40,
            ]
        )
        == 0
    )
    assert "valid" in capsys.readouterr().out

    output.write_text(
        output.read_text(encoding="utf-8").replace("v1.2.3", "v1.2.4"),
        encoding="utf-8",
    )
    assert (
        main(
            [
                "validate",
                "--manifest",
                str(output),
                "--artifacts-dir",
                str(artifacts),
                "--tag",
                "v1.2.3",
            ]
        )
        == 1
    )
    assert "invalid" in capsys.readouterr().err


def test_cli_audit_workflows(tmp_path: Path, capsys: Any) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "bad.yml").write_text("steps:\n  - uses: actions/checkout@v4\n", encoding="utf-8")

    assert main(["audit-workflows", "--root", str(tmp_path)]) == 1
    assert "not pinned" in capsys.readouterr().err

    (workflows / "bad.yml").write_text(f"steps:\n  - uses: actions/checkout@{PINNED}\n", encoding="utf-8")
    assert main(["audit-workflows", "--root", str(tmp_path)]) == 0
    assert "pinned" in capsys.readouterr().out
