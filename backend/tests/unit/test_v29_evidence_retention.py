"""V29 structured evidence retention tests.

The tests use synthetic sentinels only. They prove that evidence is sanitized
before it is written, that retained hashes describe the exact stored bytes, and
that malformed structured input is rejected instead of copied.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from backend.app.core.redaction import REDACTED, dump_sanitized_json, scan_text
from tools.release.evidence import write_evidence_report
from tools.release.manifest import sha256_file
from tools.release.readiness import _retain_evidence, _write_live_inspection, write_readiness_report

SENTINEL = "v29_evidence_sentinel_do_not_disclose"


def test_dump_sanitized_json_redacts_nested_values_and_preserves_metadata() -> None:
    payload = {
        "repository_id": "repo-1",
        "key_id": "key-1",
        "token_count": 3,
        "password_policy": "strong",
        "api_key_required": True,
        "public_key_fingerprint": "SHA256:abc",
        "nested": {
            "access_token": SENTINEL,
            "safe": "keep-me",
        },
        "items": [{"client_secret": SENTINEL + "_two", "name": "keep"}],
    }

    rendered = dump_sanitized_json(payload)
    cleaned = json.loads(rendered)

    assert SENTINEL not in rendered
    assert scan_text(rendered) == []
    assert cleaned["repository_id"] == "repo-1"
    assert cleaned["key_id"] == "key-1"
    assert cleaned["token_count"] == 3
    assert cleaned["password_policy"] == "strong"
    assert cleaned["api_key_required"] is True
    assert cleaned["public_key_fingerprint"] == "SHA256:abc"
    assert cleaned["nested"] == {"access_token": REDACTED, "safe": "keep-me"}
    assert cleaned["items"][0]["name"] == "keep"


def test_write_readiness_report_hashes_the_sanitized_bytes(tmp_path: Path) -> None:
    path = tmp_path / "readiness.json"
    digest = write_readiness_report(
        {
            "nested": {"api_key": SENTINEL},
            "token_count": 2,
            "safe": "keep",
        },
        path,
    )

    text = path.read_text(encoding="utf-8")
    assert SENTINEL not in text
    assert scan_text(text) == []
    assert json.loads(text)["nested"]["api_key"] == REDACTED
    assert digest == sha256_file(path)


def test_live_inspection_is_sanitized_before_its_hash_is_taken(tmp_path: Path) -> None:
    path = _write_live_inspection(
        tmp_path,
        {
            "mode": "live-read-only",
            "nested": {"client_secret": SENTINEL},
            "safe": "keep",
        },
    )

    text = path.read_text(encoding="utf-8")
    assert SENTINEL not in text
    assert scan_text(text) == []
    assert json.loads(text)["nested"]["client_secret"] == REDACTED
    assert sha256_file(path) == "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def test_evidence_report_writer_sanitizes_nested_events(tmp_path: Path) -> None:
    path = tmp_path / "evidence.json"
    write_evidence_report(
        {
            "events": [{"token": SENTINEL, "repository_id": "repo-1"}],
            "safe": "keep",
        },
        path,
    )

    text = path.read_text(encoding="utf-8")
    assert SENTINEL not in text
    assert scan_text(text) == []
    assert json.loads(text)["events"][0]["token"] == REDACTED
    assert json.loads(text)["events"][0]["repository_id"] == "repo-1"


def test_malformed_json_is_not_retained_or_copied(tmp_path: Path) -> None:
    source = tmp_path / "rollback.json"
    source.write_text('{"password": "' + SENTINEL + '"', encoding="utf-8")
    evidence: list[dict[str, object]] = []

    binding = _retain_evidence(
        source,
        tmp_path / "evidence",
        kind="rollback-evidence",
        state="PASS",
        evidence=evidence,
    )

    assert binding is None
    assert evidence == []
    assert not (tmp_path / "evidence").exists() or not any((tmp_path / "evidence").iterdir())


def test_secret_bearing_json_is_not_bound_and_gets_a_distinct_redacted_copy(
    tmp_path: Path,
) -> None:
    source = tmp_path / "rollback.json"
    source.write_text(
        json.dumps({"steps": [{"detail": f"password={SENTINEL}"}]}),
        encoding="utf-8",
    )
    original_digest = sha256_file(source)
    evidence: list[dict[str, object]] = []
    evidence_dir = tmp_path / "evidence"

    binding = _retain_evidence(
        source,
        evidence_dir,
        kind="rollback-evidence",
        state="PASS",
        evidence=evidence,
    )

    assert binding is None
    assert evidence == []
    copies = list(evidence_dir.glob("*-redacted.json"))
    assert len(copies) == 1
    redacted = copies[0]
    assert redacted.name != source.name
    assert "redacted" in redacted.name
    assert sha256_file(redacted) != original_digest
    assert SENTINEL not in redacted.read_text(encoding="utf-8")
    assert scan_text(redacted.read_text(encoding="utf-8")) == []


def test_secret_bearing_text_is_not_bound_and_gets_a_distinct_redacted_copy(
    tmp_path: Path,
) -> None:
    source = tmp_path / "backup.md"
    source.write_text("# Backup\npassword=" + SENTINEL + "\n", encoding="utf-8")
    original_digest = sha256_file(source)
    evidence: list[dict[str, object]] = []
    evidence_dir = tmp_path / "evidence"

    binding = _retain_evidence(
        source,
        evidence_dir,
        kind="backup-documentation",
        state="PASS",
        evidence=evidence,
    )

    assert binding is None
    assert evidence == []
    copies = list(evidence_dir.glob("*-redacted.md"))
    assert len(copies) == 1
    redacted = copies[0]
    assert sha256_file(redacted) != original_digest
    assert SENTINEL not in redacted.read_text(encoding="utf-8")
    assert scan_text(redacted.read_text(encoding="utf-8")) == []


def test_clean_json_keeps_its_original_bytes_and_hash(tmp_path: Path) -> None:
    source = tmp_path / "clean.json"
    source.write_text(
        json.dumps(
            {
                "repository_id": "repo-1",
                "token_count": 2,
                "nested": {"safe": "keep"},
            }
        ),
        encoding="utf-8",
    )
    original_digest = sha256_file(source)
    evidence: list[dict[str, object]] = []

    binding = _retain_evidence(
        source,
        tmp_path / "evidence",
        kind="release-manifest",
        state="PASS",
        evidence=evidence,
    )

    assert isinstance(binding, dict)
    assert binding["sha256"] == original_digest
    destination = tmp_path / "evidence" / str(binding["path"])
    assert destination.read_bytes() == source.read_bytes()
    assert sha256_file(destination) == original_digest
    assert evidence == [binding]
