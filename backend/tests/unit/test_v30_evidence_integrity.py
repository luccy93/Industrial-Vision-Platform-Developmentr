"""V30 evidence-integrity and tamper-detection tests.

Every evidence file, report, manifest, audit chain, and checkpoint used here is
synthetic and lives under pytest's temporary directory. The tests never contact
a registry, a release service, a network endpoint, or a real credential.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from backend.app.core.redaction import REDACTED
from tools.release.cli import main
from tools.release.evidence_verification import (
    EvidenceVerificationError,
    aggregate_outcome,
    extract_bound_evidence,
    load_integrity_manifest,
    render_verification_json,
    seal_report_evidence,
    verification_exit_code,
    verify_audit_file,
    verify_individual_evidence,
    verify_report,
    write_integrity_manifest,
)
from tools.release.integrity import (
    AUDIT_CHAIN_INVALID,
    AUDIT_EVENT_TYPES,
    AUDIT_OUTCOMES,
    EVIDENCE_CREATED,
    EVIDENCE_MISSING,
    EVIDENCE_MODIFIED,
    EVIDENCE_PATH_INVALID,
    EVIDENCE_REJECTED,
    EVIDENCE_REPLACED,
    EVIDENCE_VERIFIED,
    GENESIS_PREVIOUS_HASH,
    MANIFEST_BINDING_MISMATCH,
    AuditChainError,
    EvidencePathError,
    EvidenceRecord,
    IntegrityError,
    append_audit_event,
    build_audit_chain,
    build_audit_record,
    canonical_json_bytes,
    create_checkpoint,
    derive_event_id,
    normalize_timestamp,
    read_audit_chain,
    record_hash,
    resolve_evidence_path,
    validate_relative_path,
    verify_audit_chain,
    write_audit_chain,
    write_checkpoint,
)
from tools.release.manifest import sha256_file
from tools.release.verification import FAIL, NOT_RUN, PASS, UNAVAILABLE
from tools.verify_evidence import run as run_verify_evidence

REPO_ROOT = Path(__file__).resolve().parents[3]
SENTINEL = "v30_test_sentinel_do_not_disclose"


def _sha(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _write(path: Path, data: bytes | str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        path.write_text(data, encoding="utf-8", newline="\n")
    else:
        path.write_bytes(data)
    return path


def _evidence_report(entries: list[dict[str, Any]], **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": 1,
        "profile": "test",
        "generated_at": "2026-11-04T00:00:00Z",
        "evidence": entries,
    }
    payload.update(overrides)
    return payload


def _bound(path: str, data: bytes | str, **overrides: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "kind": "evidence",
        "path": path,
        "sha256": _sha(data),
        "state": PASS,
    }
    entry.update(overrides)
    return entry


def _write_report(path: Path, payload: dict[str, Any]) -> Path:
    return _write(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _seal(
    report_path: Path,
    evidence_root: Path,
    *,
    integrity_path: Path | None = None,
    audit_path: Path | None = None,
    **overrides: Any,
) -> dict[str, Any]:
    return seal_report_evidence(
        report_path,
        integrity_path=integrity_path or (report_path.parent / f"{report_path.stem}.integrity.json"),
        audit_path=audit_path or (report_path.parent / f"{report_path.stem}.audit.jsonl"),
        evidence_root=evidence_root,
        timestamp=overrides.pop("timestamp", "2026-11-04T00:00:00Z"),
        **overrides,
    )


def _sealed(
    tmp_path: Path,
    *,
    data: bytes = b'{"safe": "value"}\n',
) -> tuple[Path, Path, dict[str, Any]]:
    evidence_root = tmp_path / "evidence"
    _write(evidence_root / "target.json", data)
    report_path = _write_report(
        tmp_path / "report.json",
        _evidence_report([_bound("target.json", data, kind="target")]),
    )
    sealed = _seal(report_path, evidence_root)
    return report_path, evidence_root, sealed


def _record(tmp_path: Path) -> EvidenceRecord:
    data = b"evidence bytes\n"
    _write(tmp_path / "evidence" / "target.json", data)
    return EvidenceRecord(
        evidence_id="evidence:target",
        kind="target",
        path="target.json",
        sha256=_sha(data),
        size=len(data),
        created_at="2026-11-04T00:00:00Z",
    )


def _sample_chain(tmp_path: Path) -> list[dict[str, Any]]:
    evidence = _record(tmp_path)
    return build_audit_chain(
        [
            {
                "event_type": EVIDENCE_CREATED,
                "timestamp": "2026-11-04T00:00:00Z",
                "outcome": PASS,
                "evidence": evidence,
            },
            {
                "event_type": EVIDENCE_VERIFIED,
                "timestamp": "2026-11-04T00:00:01Z",
                "outcome": PASS,
                "evidence": evidence,
            },
            {
                "event_type": EVIDENCE_MODIFIED,
                "timestamp": "2026-11-04T00:00:02Z",
                "outcome": FAIL,
                "evidence_id": evidence.evidence_id,
            },
        ]
    )


def _check(result: Any, name: str) -> Any:
    matches = [check for check in result.checks if check.name == name]
    assert matches, f"verification did not emit check {name!r}"
    return matches[-1]


# ---------------------------------------------------------------------------
# Deterministic records, canonicalization, and path policy
# ---------------------------------------------------------------------------


def test_record_hash_and_event_id_are_deterministic(tmp_path: Path) -> None:
    evidence = _record(tmp_path)
    first = build_audit_record(
        sequence=0,
        event_type=EVIDENCE_CREATED,
        timestamp="2026-11-04T00:00:00Z",
        outcome=PASS,
        evidence=evidence,
    )
    second = build_audit_record(
        sequence=0,
        event_type=EVIDENCE_CREATED,
        timestamp="2026-11-04T00:00:00Z",
        outcome=PASS,
        evidence=evidence,
    )
    assert first == second
    assert first["event_id"] == derive_event_id(first)
    assert first["record_hash"] == record_hash(first)
    assert canonical_json_bytes(first).decode("utf-8").startswith("{")
    assert b"\n" not in canonical_json_bytes(first)


def test_record_hash_changes_when_payload_changes(tmp_path: Path) -> None:
    evidence = _record(tmp_path)
    first = build_audit_record(
        sequence=0,
        event_type=EVIDENCE_CREATED,
        timestamp="2026-11-04T00:00:00Z",
        outcome=PASS,
        evidence=evidence,
        details={"note": "first"},
    )
    second = build_audit_record(
        sequence=0,
        event_type=EVIDENCE_CREATED,
        timestamp="2026-11-04T00:00:00Z",
        outcome=PASS,
        evidence=evidence,
        details={"note": "second"},
    )
    assert first["event_id"] != second["event_id"]
    assert first["record_hash"] != second["record_hash"]


def test_canonical_json_is_sorted_compact_and_ascii() -> None:
    assert canonical_json_bytes({"b": 1, "a": "\u00e9"}) == b'{"a":"\\u00e9","b":1}'


def test_timestamp_normalization() -> None:
    assert normalize_timestamp("2026-11-04T01:02:03+01:00") == "2026-11-04T00:02:03Z"
    assert normalize_timestamp("2026-11-04T00:02:03.999Z") == "2026-11-04T00:02:03Z"
    assert normalize_timestamp("2026-11-04T00:02:03Z") == "2026-11-04T00:02:03Z"
    with pytest.raises(IntegrityError):
        normalize_timestamp("2026-11-04T00:02:03")
    with pytest.raises(IntegrityError):
        normalize_timestamp("not-a-timestamp")


@pytest.mark.parametrize(
    "path",
    ["a.json", "dir/a.json", "a-b_c.1.json", "evidence/target.json"],
)
def test_safe_relative_paths_are_accepted(path: str) -> None:
    assert validate_relative_path(path) == path


@pytest.mark.parametrize(
    "path",
    [
        "",
        ".",
        "..",
        "../escape.json",
        "a/../../b.json",
        "./a.json",
        "a/./b.json",
        "a//b.json",
        "/absolute.json",
        "C:/windows.json",
        "C:relative.json",
        "a\\b.json",
        "a:b.json",
        "a/",
        "con.txt",
        "dir/NUL.json",
        "a/ ",
        "a/b.",
        "a/\x00b",
    ],
)
def test_unsafe_relative_paths_are_rejected(path: str) -> None:
    with pytest.raises(EvidencePathError):
        validate_relative_path(path)


def test_resolve_evidence_path_rejects_escape(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    root.mkdir()
    outside = _write(tmp_path / "outside.txt", "outside\n")
    with pytest.raises(EvidencePathError):
        resolve_evidence_path(root, "../outside.txt")
    with pytest.raises(EvidencePathError):
        resolve_evidence_path(root, str(outside))
    assert resolve_evidence_path(root, "inside.txt") == (root / "inside.txt").resolve()


def test_symlink_below_root_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    root.mkdir()
    outside = _write(tmp_path / "outside.txt", "outside\n")
    link = root / "link.txt"
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError):
        pytest.skip("host does not permit synthetic symlink creation")
    with pytest.raises(EvidencePathError, match="symbolic link"):
        resolve_evidence_path(root, "link.txt")


def test_evidence_record_rejects_credential_metadata() -> None:
    with pytest.raises(IntegrityError):
        EvidenceRecord(
            evidence_id="evidence:target",
            kind="target",
            path=f"token={SENTINEL}.json",
            sha256="sha256:" + "a" * 64,
            size=1,
            created_at="2026-11-04T00:00:00Z",
        )


# ---------------------------------------------------------------------------
# Audit-chain construction, verification, append, and checkpointing
# ---------------------------------------------------------------------------


def test_audit_chain_supports_every_event_type(tmp_path: Path) -> None:
    evidence = _record(tmp_path)
    events: list[dict[str, Any]] = []
    for index, event_type in enumerate(AUDIT_EVENT_TYPES):
        timestamp = f"2026-11-04T00:00:{index:02d}Z"
        if event_type in (EVIDENCE_CREATED, EVIDENCE_VERIFIED):
            events.append(
                {
                    "event_type": event_type,
                    "timestamp": timestamp,
                    "outcome": PASS,
                    "evidence": evidence,
                }
            )
        elif event_type == AUDIT_CHAIN_INVALID:
            events.append(
                {
                    "event_type": event_type,
                    "timestamp": timestamp,
                    "outcome": FAIL,
                    "evidence_id": "audit:chain",
                }
            )
        else:
            events.append(
                {
                    "event_type": event_type,
                    "timestamp": timestamp,
                    "outcome": FAIL,
                    "evidence_id": evidence.evidence_id,
                }
            )
    records = build_audit_chain(events)
    assert len(records) == len(AUDIT_EVENT_TYPES)
    result = verify_audit_chain(records)
    assert result.outcome == PASS
    assert result.record_count == len(AUDIT_EVENT_TYPES)
    assert set(result.event_counts) == set(AUDIT_EVENT_TYPES)

    audit_path = tmp_path / "audit.jsonl"
    write_audit_chain(audit_path, records)
    assert verify_audit_chain(audit_path).outcome == PASS
    appended = append_audit_event(
        audit_path,
        event_type=EVIDENCE_VERIFIED,
        timestamp="2026-11-04T00:00:09Z",
        outcome=PASS,
        evidence=evidence,
        details={"actual_sha256": evidence.sha256},
    )
    assert appended["sequence"] == len(records)
    assert verify_audit_chain(audit_path).outcome == PASS

    checkpoint = create_checkpoint(audit_path)
    checkpoint_path = tmp_path / "checkpoint.json"
    write_checkpoint(checkpoint_path, checkpoint)
    anchored = verify_audit_chain(audit_path, checkpoint=checkpoint)
    assert anchored.outcome == PASS
    assert anchored.anchored is True
    assert anchored.record_count == len(records) + 1


def test_audit_chain_rejects_empty_and_malformed_records(tmp_path: Path) -> None:
    empty = verify_audit_chain([])
    assert empty.outcome == FAIL
    assert any("empty" in problem.detail for problem in empty.problems)

    audit_path = _write(tmp_path / "bad.jsonl", b"{}\n\n")
    with pytest.raises(AuditChainError):
        read_audit_chain(audit_path)

    audit_path = _write(tmp_path / "bad-utf8.jsonl", b"\xff\n")
    with pytest.raises(AuditChainError):
        read_audit_chain(audit_path)

    audit_path = _write(tmp_path / "array.jsonl", b"[]\n")
    with pytest.raises(AuditChainError):
        read_audit_chain(audit_path)


def test_audit_chain_detects_record_tampering(tmp_path: Path) -> None:
    chain = _sample_chain(tmp_path)
    assert verify_audit_chain(chain).outcome == PASS

    changed_details = [dict(record) for record in chain]
    changed_details[1]["details"] = {"tampered": True}
    changed_outcome = [dict(record) for record in chain]
    changed_outcome[1]["outcome"] = "SIMULATED"
    changed_outcome[1]["record_hash"] = record_hash(changed_outcome[1])
    changed_outcome[1]["event_id"] = derive_event_id(changed_outcome[1])
    changed_event = [dict(record) for record in chain]
    changed_event[1]["event_id"] = changed_event[0]["event_id"]
    changed_event[1]["record_hash"] = record_hash(changed_event[1])
    broken_link = [dict(record) for record in chain]
    broken_link[1]["previous_record_hash"] = GENESIS_PREVIOUS_HASH
    broken_link[1]["record_hash"] = record_hash(broken_link[1])
    broken_link[1]["event_id"] = derive_event_id(broken_link[1])
    non_canonical_time = [dict(record) for record in chain]
    non_canonical_time[1]["timestamp"] = "2026-11-04 00:00:01"
    non_canonical_time[1]["record_hash"] = record_hash(non_canonical_time[1])
    extra_field = [dict(record) for record in chain]
    extra_field[1]["unexpected"] = True
    extra_field[1]["record_hash"] = record_hash(extra_field[1])

    for records in (
        changed_details,
        changed_outcome,
        changed_event,
        broken_link,
        non_canonical_time,
        extra_field,
        list(reversed(chain)),
        chain[1:],
    ):
        result = verify_audit_chain(records)
        assert result.outcome == FAIL
        assert any(problem.code == AUDIT_CHAIN_INVALID for problem in result.problems)


def test_audit_chain_checkpoint_detects_truncation_extension_and_tampering(
    tmp_path: Path,
) -> None:
    chain = _sample_chain(tmp_path)
    checkpoint = create_checkpoint(chain)
    assert verify_audit_chain(chain, checkpoint=checkpoint).outcome == PASS

    truncated = chain[:-1]
    result = verify_audit_chain(truncated, checkpoint=checkpoint)
    assert result.outcome == FAIL
    assert any("ended before" in problem.detail for problem in result.problems)

    extension = build_audit_record(
        sequence=len(chain),
        event_type=EVIDENCE_VERIFIED,
        timestamp="2026-11-04T00:00:09Z",
        outcome=PASS,
        previous_record_hash=chain[-1]["record_hash"],
        evidence_id="evidence:target",
    )
    result = verify_audit_chain(chain + [extension], checkpoint=checkpoint)
    assert result.outcome == FAIL
    assert any("beyond" in problem.detail for problem in result.problems)

    tampered = [dict(record) for record in chain]
    tampered[-1]["details"] = {"changed": True}
    assert verify_audit_chain(tampered, checkpoint=checkpoint).outcome == FAIL


def test_checkpoint_provider_is_explicit(tmp_path: Path) -> None:
    chain = _sample_chain(tmp_path)
    checkpoint = create_checkpoint(chain)

    class _Provider:
        def __init__(self, payload: dict[str, Any] | None = None, error: str | None = None) -> None:
            self.payload = payload
            self.error = error

        def fetch(self) -> dict[str, Any]:
            if self.error is not None:
                raise RuntimeError(self.error)
            assert self.payload is not None
            return self.payload

    anchored = verify_audit_chain(chain, checkpoint_provider=_Provider(checkpoint))
    assert anchored.outcome == PASS
    assert anchored.anchored is True

    unavailable = verify_audit_chain(chain, checkpoint_provider=_Provider(error="unreachable"))
    assert unavailable.outcome == UNAVAILABLE

    both = verify_audit_chain(
        chain,
        checkpoint=checkpoint,
        checkpoint_provider=_Provider(checkpoint),
    )
    assert both.outcome == FAIL

    malformed = verify_audit_chain(
        chain,
        checkpoint_provider=_Provider({"schema_version": 1}),
    )
    assert malformed.outcome == UNAVAILABLE


def test_audit_outcomes_are_stable() -> None:
    assert set(AUDIT_OUTCOMES) == {PASS, FAIL, UNAVAILABLE, NOT_RUN}
    assert "SIMULATED" not in AUDIT_OUTCOMES
    with pytest.raises(IntegrityError):
        build_audit_record(
            sequence=0,
            event_type=EVIDENCE_VERIFIED,
            timestamp="2026-11-04T00:00:00Z",
            outcome="SIMULATED",
            evidence_id="evidence:target",
        )


# ---------------------------------------------------------------------------
# Report evidence verification
# ---------------------------------------------------------------------------


def test_valid_report_and_evidence_pass(tmp_path: Path) -> None:
    report_path, _, _ = _sealed(tmp_path)
    result = verify_report(report_path)
    assert result.outcome == PASS
    assert _check(result, "report-exists").outcome == PASS
    assert _check(result, "report-schema").outcome == PASS
    assert _check(result, "integrity-report-binding").outcome == PASS
    assert _check(result, "audit-chain").outcome == PASS
    assert _check(result, "integrity-audit-binding").outcome == PASS
    assert _check(result, "audit-events").outcome == PASS
    assert result.report is not None
    assert result.report["sha256"] == sha256_file(report_path)
    assert result.evidence and result.evidence[0]["outcome"] == PASS
    assert verification_exit_code(result.outcome) == 0
    assert result.to_dict()["mutation"]["performed"] is False


def test_verification_is_read_only(tmp_path: Path) -> None:
    report_path, evidence_root, sealed = _sealed(tmp_path)
    evidence_path = evidence_root / "target.json"
    paths = [
        report_path,
        evidence_path,
        Path(sealed["integrity_path"]),
        Path(sealed["audit_path"]),
    ]
    before = {path: sha256_file(path) for path in paths}
    verify_report(report_path)
    verify_audit_file(Path(sealed["audit_path"]))
    verify_individual_evidence(evidence_path, expected_sha256=sha256_file(evidence_path))
    after = {path: sha256_file(path) for path in paths}
    assert before == after


def test_missing_evidence_never_becomes_pass(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    report_path = _write_report(
        tmp_path / "report.json",
        _evidence_report([_bound("missing.json", b"missing")]),
    )
    result = verify_report(report_path, evidence_root=evidence_root)
    assert result.outcome == FAIL
    assert any(issue.event_type == EVIDENCE_MISSING for issue in result.issues)
    assert _check(result, "evidence:evidence:missing.json").outcome == FAIL
    assert verification_exit_code(result.outcome) == 1


@pytest.mark.parametrize(
    ("replacement", "expected_event"),
    [
        (b'{"safe": "VALUE"}\n', EVIDENCE_REPLACED),
        (b'{"safe": "value", "extra": true}\n', EVIDENCE_MODIFIED),
        (b"", EVIDENCE_MODIFIED),
    ],
)
def test_content_tampering_is_detected(
    tmp_path: Path,
    replacement: bytes,
    expected_event: str,
) -> None:
    report_path, evidence_root, _ = _sealed(tmp_path)
    _write(evidence_root / "target.json", replacement)
    result = verify_report(report_path)
    assert result.outcome == FAIL
    assert any(issue.event_type == expected_event for issue in result.issues)
    assert verification_exit_code(result.outcome) == 1


def test_replaced_evidence_with_same_size_is_not_pass(tmp_path: Path) -> None:
    report_path, evidence_root, _ = _sealed(tmp_path)
    _write(evidence_root / "target.json", b'{"safe": "other"}\n')
    result = verify_report(report_path)
    assert result.outcome == FAIL
    assert any(issue.event_type in (EVIDENCE_MODIFIED, EVIDENCE_REPLACED) for issue in result.issues)


def test_directory_evidence_is_rejected(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    (evidence_root / "target.json").mkdir(parents=True)
    report_path = _write_report(
        tmp_path / "report.json",
        _evidence_report([_bound("target.json", b"not-a-file")]),
    )
    result = verify_report(report_path, evidence_root=evidence_root)
    assert result.outcome == FAIL
    assert any(issue.event_type == EVIDENCE_REJECTED for issue in result.issues)


def test_missing_evidence_root_is_unavailable(tmp_path: Path) -> None:
    report_path = _write_report(
        tmp_path / "report.json",
        _evidence_report([_bound("target.json", b"target")]),
    )
    result = verify_report(report_path, evidence_root=tmp_path / "absent")
    assert result.outcome == UNAVAILABLE
    assert verification_exit_code(result.outcome) == 2


def test_report_tampering_breaks_sidecar_binding(tmp_path: Path) -> None:
    report_path, _, _ = _sealed(tmp_path)
    original = report_path.read_text(encoding="utf-8")
    _write(report_path, original + " ")
    result = verify_report(report_path)
    assert result.outcome == FAIL
    assert _check(result, "integrity-report-binding").outcome == FAIL


def test_expected_report_digest_mismatch_fails(tmp_path: Path) -> None:
    report_path, _, _ = _sealed(tmp_path)
    result = verify_report(
        report_path,
        expected_report_sha256="sha256:" + "a" * 64,
    )
    assert result.outcome == FAIL
    assert _check(result, "report-sha256").outcome == FAIL


def test_audit_tampering_is_detected(tmp_path: Path) -> None:
    report_path, _, sealed = _sealed(tmp_path)
    audit_path = Path(sealed["audit_path"])
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    record["outcome"] = FAIL
    lines[0] = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    _write(audit_path, "\n".join(lines) + "\n")

    result = verify_report(report_path)
    assert result.outcome == FAIL
    assert _check(result, "audit-chain").outcome == FAIL
    assert verify_audit_file(audit_path).outcome == FAIL
    assert verification_exit_code(result.outcome) == 1


def test_missing_audit_chain_is_unavailable(tmp_path: Path) -> None:
    report_path, _, sealed = _sealed(tmp_path)
    Path(sealed["audit_path"]).unlink()
    result = verify_report(report_path)
    assert result.outcome == UNAVAILABLE
    assert _check(result, "audit-chain").outcome == UNAVAILABLE
    assert verification_exit_code(result.outcome) == 2


def test_sidecar_audit_binding_mismatch_fails(tmp_path: Path) -> None:
    report_path, _, _ = _sealed(tmp_path)
    sidecar_path = tmp_path / "report.integrity.json"
    sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
    sidecar["audit"]["record_count"] += 1
    _write(sidecar_path, json.dumps(sidecar, indent=2, sort_keys=True) + "\n")
    result = verify_report(report_path)
    assert result.outcome == FAIL
    assert _check(result, "integrity-audit-binding").outcome == FAIL


# ---------------------------------------------------------------------------
# Path attacks, manifest binding, and compatibility
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "../outside.txt",
        "../../outside.txt",
        "/etc/passwd",
        "C:/Windows/win.ini",
        "a\\b.txt",
        "a/../../b.txt",
        "./target.json",
        "a/./target.json",
        "a//target.json",
        "con.txt",
    ],
)
def test_path_attacks_are_rejected_without_reading_outside_files(
    tmp_path: Path,
    path: str,
) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    outside = _write(tmp_path / "outside.txt", "outside\n")
    before = sha256_file(outside)
    report_path = _write_report(
        tmp_path / "report.json",
        _evidence_report([_bound(path, b"anything")]),
    )
    result = verify_report(report_path, evidence_root=evidence_root)
    assert result.outcome == FAIL
    assert any(issue.event_type == EVIDENCE_PATH_INVALID for issue in result.issues)
    assert sha256_file(outside) == before


def test_manifest_binding_pass_and_mismatch(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    data = b"evidence\n"
    _write(evidence_root / "target.json", data)
    release = {
        "tag": "v1.2.3",
        "commit": "a" * 40,
        "source_repository": "example/repo",
    }
    manifest = {"schema_version": 1, "release": release}
    manifest_path = _write(
        tmp_path / "manifest.json",
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    )
    report_path = _write_report(
        tmp_path / "report.json",
        _evidence_report(
            [_bound("target.json", data, kind="target")],
            schema_version=2,
            profile="production",
            manifest_sha256=sha256_file(manifest_path),
            subject=release,
        ),
    )
    result = verify_report(
        report_path,
        manifest_path=manifest_path,
        evidence_root=evidence_root,
    )
    assert result.outcome == PASS
    assert _check(result, "manifest-binding").outcome == PASS
    assert _check(result, "manifest-subject").outcome == PASS

    manifest["release"]["tag"] = "v1.2.4"
    _write(manifest_path, json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    result = verify_report(
        report_path,
        manifest_path=manifest_path,
        evidence_root=evidence_root,
    )
    assert result.outcome == FAIL
    assert any(issue.event_type == MANIFEST_BINDING_MISMATCH for issue in result.issues)


def test_manifest_subject_mismatch_fails(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    data = b"evidence\n"
    _write(evidence_root / "target.json", data)
    release = {
        "tag": "v1.2.3",
        "commit": "a" * 40,
        "source_repository": "example/repo",
    }
    manifest_path = _write(
        tmp_path / "manifest.json",
        json.dumps({"release": release}, indent=2, sort_keys=True) + "\n",
    )
    wrong_subject = dict(release)
    wrong_subject["tag"] = "v9.9.9"
    report_path = _write_report(
        tmp_path / "report.json",
        _evidence_report(
            [_bound("target.json", data)],
            manifest_sha256=sha256_file(manifest_path),
            subject=wrong_subject,
        ),
    )
    result = verify_report(
        report_path,
        manifest_path=manifest_path,
        evidence_root=evidence_root,
    )
    assert result.outcome == FAIL
    assert _check(result, "manifest-subject").outcome == FAIL


def test_missing_manifest_is_unavailable(tmp_path: Path) -> None:
    report_path, _, _ = _sealed(tmp_path)
    result = verify_report(report_path, manifest_path=tmp_path / "absent.json")
    assert result.outcome == UNAVAILABLE
    assert any(issue.event_type == MANIFEST_BINDING_MISMATCH for issue in result.issues)


def test_verification_without_sidecar_remains_backward_compatible(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    data = b"legacy evidence\n"
    _write(evidence_root / "target.json", data)
    report_path = _write_report(
        tmp_path / "legacy-report.json",
        _evidence_report([_bound("target.json", data)]),
    )
    result = verify_report(report_path, evidence_root=evidence_root)
    assert result.outcome == PASS
    assert _check(result, "integrity-manifest").outcome == NOT_RUN
    assert _check(result, "evidence:evidence:target.json").outcome == PASS


def test_readiness_bindings_use_readiness_evidence_directory(tmp_path: Path) -> None:
    evidence_root = tmp_path / "readiness-evidence"
    data = b"readiness target\n"
    _write(evidence_root / "target.json", data)
    report_path = _write_report(
        tmp_path / "staging-readiness.json",
        {
            "schema_version": 1,
            "profile": "staging_readiness",
            "bindings": {
                "target": {
                    "kind": "target",
                    "path": "target.json",
                    "sha256": _sha(data),
                    "state": PASS,
                }
            },
            "evidence": [],
        },
    )
    result = verify_report(report_path)
    assert result.outcome == PASS
    assert result.evidence and result.evidence[0]["outcome"] == PASS


def test_redacted_diagnostic_copy_is_rejected(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    data = b"diagnostic\n"
    _write(evidence_root / "target-redacted.json", data)
    report_path = _write_report(
        tmp_path / "report.json",
        _evidence_report([_bound("target-redacted.json", data)]),
    )
    result = verify_report(report_path, evidence_root=evidence_root)
    assert result.outcome == FAIL
    assert any(issue.event_type == EVIDENCE_REJECTED for issue in result.issues)


@pytest.mark.parametrize("state", [FAIL, UNAVAILABLE, NOT_RUN, "SIMULATED"])
def test_non_pass_binding_states_are_rejected(tmp_path: Path, state: str) -> None:
    evidence_root = tmp_path / "evidence"
    data = b"evidence\n"
    _write(evidence_root / "target.json", data)
    report_path = _write_report(
        tmp_path / "report.json",
        _evidence_report([_bound("target.json", data, state=state)]),
    )
    result = verify_report(report_path, evidence_root=evidence_root)
    assert result.outcome == FAIL
    assert any(issue.event_type == EVIDENCE_REJECTED for issue in result.issues)


def test_same_path_alias_is_allowed(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    data = b"alias evidence\n"
    _write(evidence_root / "target.json", data)
    entry = _bound("target.json", data, kind="target")
    report_path = _write_report(
        tmp_path / "report.json",
        _evidence_report([entry, dict(entry, kind="alias")]),
    )
    entries, conflicts = extract_bound_evidence(json.loads(report_path.read_text(encoding="utf-8")))
    assert not conflicts
    assert len(entries) == 1
    assert entries[0].aliases
    assert verify_report(report_path, evidence_root=evidence_root).outcome == PASS


def test_content_reuse_requires_explicit_authorization(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    data = b"reused evidence\n"
    _write(evidence_root / "one.json", data)
    _write(evidence_root / "two.json", data)
    report_path = _write_report(
        tmp_path / "report.json",
        _evidence_report([_bound("one.json", data), _bound("two.json", data)]),
    )
    result = verify_report(report_path, evidence_root=evidence_root)
    assert result.outcome == FAIL
    assert any(issue.event_type == EVIDENCE_REJECTED for issue in result.issues)

    sealed = _seal(
        report_path,
        evidence_root,
        authorized_reuse=[_sha(data)],
    )
    assert sealed["manifest"]["authorized_reuse"]
    assert verify_report(report_path).outcome == PASS


def test_audit_without_creation_event_fails_cross_check(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    data = b"evidence\n"
    _write(evidence_root / "target.json", data)
    report_path = _write_report(
        tmp_path / "report.json",
        _evidence_report([_bound("target.json", data)]),
    )
    audit_path = tmp_path / "audit.jsonl"
    record = build_audit_record(
        sequence=0,
        event_type=EVIDENCE_VERIFIED,
        timestamp="2026-11-04T00:00:00Z",
        outcome=PASS,
        evidence_id="evidence:target.json",
    )
    write_audit_chain(audit_path, [record])
    result = verify_report(
        report_path,
        evidence_root=evidence_root,
        audit_path=audit_path,
    )
    assert result.outcome == FAIL
    assert any("no EVIDENCE_CREATED" in issue.detail for issue in result.issues)


def test_appending_to_sealed_chain_makes_sidecar_stale(tmp_path: Path) -> None:
    report_path, _, sealed = _sealed(tmp_path)
    audit_path = Path(sealed["audit_path"])
    append_audit_event(
        audit_path,
        event_type=EVIDENCE_VERIFIED,
        timestamp="2026-11-04T00:00:09Z",
        outcome=PASS,
        evidence_id="evidence:target.json",
        details={"actual_sha256": sealed["manifest"]["evidence"][0]["sha256"]},
    )
    assert verify_audit_file(audit_path).outcome == PASS
    result = verify_report(report_path)
    assert result.outcome == FAIL
    assert _check(result, "integrity-audit-binding").outcome == FAIL


# ---------------------------------------------------------------------------
# Redaction regression and false-positive resistance
# ---------------------------------------------------------------------------


def test_audit_details_are_redacted_before_hashing() -> None:
    record = build_audit_record(
        sequence=0,
        event_type=EVIDENCE_VERIFIED,
        timestamp="2026-11-04T00:00:00Z",
        outcome=PASS,
        evidence_id="evidence:target",
        details={
            "password": SENTINEL,
            "nested": {"api_token": SENTINEL},
            "message": f"Authorization: Bearer {SENTINEL}",
        },
    )
    rendered = canonical_json_bytes(record).decode("utf-8")
    assert SENTINEL not in rendered
    assert REDACTED in rendered


def test_verification_json_does_not_leak_credential_shaped_paths(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    data = b"safe bytes\n"
    _write(evidence_root / f"token={SENTINEL}.txt", data)
    report_path = _write_report(
        tmp_path / "report.json",
        _evidence_report([_bound(f"token={SENTINEL}.txt", data)]),
    )
    result = verify_report(report_path, evidence_root=evidence_root)
    rendered = render_verification_json(result)
    assert SENTINEL not in rendered
    assert REDACTED in rendered


def test_sealing_rejects_credential_shaped_metadata(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    data = b"safe bytes\n"
    _write(evidence_root / f"token={SENTINEL}.txt", data)
    report_path = _write_report(
        tmp_path / "report.json",
        _evidence_report([_bound(f"token={SENTINEL}.txt", data)]),
    )
    sidecar = tmp_path / "report.integrity.json"
    audit = tmp_path / "report.audit.jsonl"
    with pytest.raises((EvidenceVerificationError, IntegrityError)):
        _seal(report_path, evidence_root, integrity_path=sidecar, audit_path=audit)
    assert not sidecar.exists()
    assert not audit.exists()


def test_integrity_manifest_writer_fails_closed_on_credentials(tmp_path: Path) -> None:
    manifest = {
        "schema_version": 1,
        "profile": "evidence_integrity",
        "generated_at": "2026-11-04T00:00:00Z",
        "report": {
            "path": "report.json",
            "sha256": "sha256:" + "a" * 64,
            "schema_version": 1,
            "profile": "test",
        },
        "parent_id": "report:sha256:" + "a" * 64,
        "evidence_root": ".",
        "evidence": [],
        "audit": {
            "path": "audit.jsonl",
            "sha256": "sha256:" + "b" * 64,
            "record_count": 1,
            "head": "sha256:" + "b" * 64,
            "checkpoint": None,
        },
        "authorized_reuse": [],
        "limitations": [f"token={SENTINEL}"],
    }
    output = tmp_path / "integrity.json"
    with pytest.raises(EvidenceVerificationError):
        write_integrity_manifest(output, manifest)
    assert not output.exists()


def test_seal_refuses_overwrite_and_preserves_inputs(tmp_path: Path) -> None:
    report_path, evidence_root, sealed = _sealed(tmp_path)
    report_before = sha256_file(report_path)
    evidence_before = sha256_file(evidence_root / "target.json")
    with pytest.raises(EvidenceVerificationError):
        _seal(report_path, evidence_root)
    assert sha256_file(report_path) == report_before
    assert sha256_file(evidence_root / "target.json") == evidence_before
    assert Path(sealed["integrity_path"]).is_file()
    assert Path(sealed["audit_path"]).is_file()


def test_seal_rejects_digest_mismatch_and_missing_evidence(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    data = b"real bytes\n"
    _write(evidence_root / "target.json", data)
    wrong = _bound("target.json", b"different bytes\n")
    report_path = _write_report(tmp_path / "wrong.json", _evidence_report([wrong]))
    with pytest.raises(EvidenceVerificationError):
        _seal(report_path, evidence_root)

    missing = _bound("missing.json", b"missing bytes\n")
    report_path = _write_report(tmp_path / "missing.json", _evidence_report([missing]))
    with pytest.raises(EvidenceVerificationError):
        _seal(report_path, evidence_root)


def test_seal_rejects_invalid_report_metadata_before_writing(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    data = b"real bytes\n"
    _write(evidence_root / "target.json", data)

    for name, overrides in (
        ("no-schema.json", {"schema_version": None}),
        ("bad-schema.json", {"schema_version": 0}),
        ("no-profile.json", {"profile": ""}),
    ):
        report_path = _write_report(
            tmp_path / name,
            _evidence_report([_bound("target.json", data)], **overrides),
        )
        sidecar = tmp_path / f"{report_path.stem}.integrity.json"
        audit = tmp_path / f"{report_path.stem}.audit.jsonl"
        with pytest.raises(EvidenceVerificationError):
            _seal(
                report_path,
                evidence_root,
                integrity_path=sidecar,
                audit_path=audit,
            )
        assert not sidecar.exists()
        assert not audit.exists()


def test_seal_rejects_a_report_without_evidence(tmp_path: Path) -> None:
    report_path = _write_report(tmp_path / "empty.json", _evidence_report([]))
    with pytest.raises(EvidenceVerificationError, match="no supported evidence"):
        _seal(report_path, tmp_path)
    assert not (tmp_path / "empty.integrity.json").exists()
    assert not (tmp_path / "empty.audit.jsonl").exists()


def test_aggregate_outcome_precedence() -> None:
    from tools.release.evidence_verification import VerificationCheck

    def check(outcome: str, required: bool = True) -> VerificationCheck:
        return VerificationCheck("x", outcome, required, "detail")

    assert aggregate_outcome([check(PASS), check(FAIL, required=False)]) == PASS
    assert aggregate_outcome([check(PASS), check(UNAVAILABLE)]) == UNAVAILABLE
    assert aggregate_outcome([check(NOT_RUN), check(UNAVAILABLE)]) == UNAVAILABLE
    assert aggregate_outcome([check(FAIL), check(UNAVAILABLE)]) == FAIL
    assert aggregate_outcome([check(NOT_RUN)]) == NOT_RUN
    assert aggregate_outcome([]) == NOT_RUN
    assert verification_exit_code(PASS) == 0
    assert verification_exit_code(FAIL) == 1
    assert verification_exit_code(UNAVAILABLE) == 2
    assert verification_exit_code(NOT_RUN) == 3
    assert verification_exit_code("UNKNOWN") == 4


# ---------------------------------------------------------------------------
# Sidecar schema and existing report-schema compatibility
# ---------------------------------------------------------------------------


def _integrity_schema() -> dict[str, Any]:
    return json.loads((REPO_ROOT / "release" / "evidence-integrity.schema.json").read_text(encoding="utf-8"))


def test_integrity_schema_is_valid_and_accepts_sealed_sidecar(tmp_path: Path) -> None:
    schema = _integrity_schema()
    Draft202012Validator.check_schema(schema)
    _, _, sealed = _sealed(tmp_path)
    sidecar = json.loads(Path(sealed["integrity_path"]).read_text(encoding="utf-8"))
    assert list(Draft202012Validator(schema).iter_errors(sidecar)) == []


def test_integrity_schema_rejects_malformed_sidecars(tmp_path: Path) -> None:
    schema = _integrity_schema()
    _, _, sealed = _sealed(tmp_path)
    sidecar = json.loads(Path(sealed["integrity_path"]).read_text(encoding="utf-8"))

    unknown = dict(sidecar)
    unknown["unexpected"] = True
    assert list(Draft202012Validator(schema).iter_errors(unknown))

    wrong_profile = dict(sidecar)
    wrong_profile["profile"] = "other"
    assert list(Draft202012Validator(schema).iter_errors(wrong_profile))

    traversal = json.loads(json.dumps(sidecar))
    traversal["evidence"][0]["path"] = "../escape.json"
    assert list(Draft202012Validator(schema).iter_errors(traversal))

    missing_evidence = dict(sidecar)
    missing_evidence["evidence"] = []
    assert list(Draft202012Validator(schema).iter_errors(missing_evidence))


def test_existing_report_schemas_are_unchanged() -> None:
    verification_schema = json.loads(
        (REPO_ROOT / "release" / "release-verification.schema.json").read_text(encoding="utf-8")
    )
    readiness_schema = json.loads(
        (REPO_ROOT / "release" / "staging-readiness.schema.json").read_text(encoding="utf-8")
    )
    assert verification_schema["properties"]["schema_version"]["const"] == 2
    assert readiness_schema["properties"]["schema_version"]["const"] == 1
    assert "evidence_integrity" not in json.dumps(verification_schema)
    assert "evidence_integrity" not in json.dumps(readiness_schema)
    assert "record_hash" not in json.dumps(verification_schema)
    assert "record_hash" not in json.dumps(readiness_schema)


def test_sidecar_loader_rejects_bad_bindings(tmp_path: Path) -> None:
    _, _, sealed = _sealed(tmp_path)
    sidecar_path = Path(sealed["integrity_path"])
    sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))

    wrong_parent = json.loads(json.dumps(sidecar))
    wrong_parent["evidence"][0]["parent_id"] = "report:sha256:" + "c" * 64
    bad_parent_path = _write(
        tmp_path / "bad-parent.integrity.json",
        json.dumps(wrong_parent, indent=2, sort_keys=True) + "\n",
    )
    with pytest.raises(EvidenceVerificationError):
        load_integrity_manifest(bad_parent_path)

    duplicate = json.loads(json.dumps(sidecar))
    duplicate["evidence"].append(dict(duplicate["evidence"][0]))
    duplicate_path = _write(
        tmp_path / "duplicate.integrity.json",
        json.dumps(duplicate, indent=2, sort_keys=True) + "\n",
    )
    with pytest.raises(EvidenceVerificationError):
        load_integrity_manifest(duplicate_path)

    bad_audit = json.loads(json.dumps(sidecar))
    bad_audit["audit"]["record_count"] = 0
    bad_audit_path = _write(
        tmp_path / "bad-audit.integrity.json",
        json.dumps(bad_audit, indent=2, sort_keys=True) + "\n",
    )
    with pytest.raises(EvidenceVerificationError):
        load_integrity_manifest(bad_audit_path)


# ---------------------------------------------------------------------------
# CLI behavior and exit codes
# ---------------------------------------------------------------------------


def test_cli_verify_evidence_exit_codes(tmp_path: Path, capsys: Any) -> None:
    report_path, evidence_root, _ = _sealed(tmp_path)
    assert main(["verify-evidence", "--report", str(report_path)]) == 0
    assert "PASS" in capsys.readouterr().out

    assert (
        main(
            [
                "verify-evidence",
                "--report",
                str(report_path),
                "--json",
            ]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["outcome"] == PASS

    _write(evidence_root / "target.json", b'{"safe": "other"}\n')
    assert main(["verify-evidence", "--report", str(report_path)]) == 1
    assert "FAIL" in capsys.readouterr().out

    assert main(["verify-evidence", "--report", str(tmp_path / "absent.json")]) == 2
    assert "UNAVAILABLE" in capsys.readouterr().out

    empty_report = _write_report(
        tmp_path / "empty.json",
        _evidence_report([]),
    )
    assert main(["verify-evidence", "--report", str(empty_report)]) == 3
    assert "NOT_RUN" in capsys.readouterr().out

    evidence_file = evidence_root / "target.json"
    assert (
        main(
            [
                "verify-evidence",
                "--evidence",
                str(evidence_file),
            ]
        )
        == 4
    )
    assert "--expected-sha256" in capsys.readouterr().err


def test_cli_individual_evidence_and_audit(tmp_path: Path, capsys: Any) -> None:
    evidence_file = _write(tmp_path / "evidence" / "target.json", b"evidence\n")
    digest = sha256_file(evidence_file)
    assert (
        main(
            [
                "verify-evidence",
                "--evidence",
                str(evidence_file),
                "--expected-sha256",
                digest,
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert (
        main(
            [
                "verify-evidence",
                "--evidence",
                str(evidence_file),
                "--expected-sha256",
                "sha256:" + "a" * 64,
            ]
        )
        == 1
    )
    capsys.readouterr()

    _, _, sealed = _sealed(tmp_path)
    audit_path = Path(sealed["audit_path"])
    assert main(["verify-audit", "--audit", str(audit_path)]) == 0
    capsys.readouterr()
    checkpoint_path = tmp_path / "checkpoint.json"
    assert (
        main(
            [
                "checkpoint-evidence",
                "--audit",
                str(audit_path),
                "--output",
                str(checkpoint_path),
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert (
        main(
            [
                "verify-audit",
                "--audit",
                str(audit_path),
                "--checkpoint",
                str(checkpoint_path),
            ]
        )
        == 0
    )
    capsys.readouterr()
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    record["outcome"] = FAIL
    lines[0] = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    _write(audit_path, "\n".join(lines) + "\n")
    assert main(["verify-audit", "--audit", str(audit_path)]) == 1
    assert "FAIL" in capsys.readouterr().out


def test_cli_seal_and_checkpoint_are_explicit(tmp_path: Path, capsys: Any) -> None:
    evidence_root = tmp_path / "evidence"
    data = b"sealed evidence\n"
    _write(evidence_root / "target.json", data)
    report_path = _write_report(
        tmp_path / "report.json",
        _evidence_report([_bound("target.json", data)]),
    )
    integrity_path = tmp_path / "report.integrity.json"
    audit_path = tmp_path / "report.audit.jsonl"
    args = [
        "seal-evidence",
        "--report",
        str(report_path),
        "--integrity",
        str(integrity_path),
        "--audit",
        str(audit_path),
        "--evidence-root",
        str(evidence_root),
    ]
    assert main(args) == 0
    assert "sealed evidence" in capsys.readouterr().out
    assert integrity_path.is_file()
    assert audit_path.is_file()
    assert main(args) == 1
    assert "refusing to overwrite" in capsys.readouterr().err

    checkpoint_path = tmp_path / "checkpoint.json"
    assert (
        main(
            [
                "checkpoint-evidence",
                "--audit",
                str(audit_path),
                "--output",
                str(checkpoint_path),
                "--source",
                "synthetic-test",
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert checkpoint_path.is_file()
    assert (
        main(
            [
                "verify-audit",
                "--audit",
                str(audit_path),
                "--checkpoint",
                str(checkpoint_path),
            ]
        )
        == 0
    )
    capsys.readouterr()


def test_thin_verify_entry_point(tmp_path: Path, capsys: Any) -> None:
    report_path, _, _ = _sealed(tmp_path)
    assert run_verify_evidence(["--report", str(report_path)]) == 0
    assert "PASS" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Additional adversarial coverage: readability, identifier conflicts,
# sidecar/report disagreement, symlinks, and audit incidents
# ---------------------------------------------------------------------------


def test_unreadable_evidence_is_unavailable(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    evidence_root = tmp_path / "evidence"
    data = b"unreadable evidence\n"
    _write(evidence_root / "target.json", data)
    report_path = _write_report(
        tmp_path / "report.json",
        _evidence_report([_bound("target.json", data)]),
    )

    def _raise_oserror(path: Path) -> Any:
        raise OSError("simulated read failure")

    monkeypatch.setattr(
        "tools.release.evidence_verification.hash_evidence_file",
        _raise_oserror,
    )
    result = verify_report(report_path, evidence_root=evidence_root)
    assert result.outcome == UNAVAILABLE
    check = _check(result, "evidence:evidence:target.json")
    assert check.outcome == UNAVAILABLE
    assert any(
        issue.event_type == EVIDENCE_REJECTED and issue.outcome == UNAVAILABLE for issue in result.issues
    )
    assert verification_exit_code(result.outcome) == 2


def test_evidence_root_that_is_a_file_is_unavailable(tmp_path: Path) -> None:
    data = b"evidence\n"
    report_path = _write_report(
        tmp_path / "report.json",
        _evidence_report([_bound("target.json", data)]),
    )
    root_file = _write(tmp_path / "not-a-directory", data)
    result = verify_report(report_path, evidence_root=root_file)
    assert result.outcome == UNAVAILABLE
    assert verification_exit_code(result.outcome) == 2


def test_identifier_reuse_for_different_evidence_is_a_conflict(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    _write(evidence_root / "one.json", b"one\n")
    _write(evidence_root / "two.json", b"two\n")
    report = _evidence_report(
        [
            _bound("one.json", b"one\n", evidence_id="evidence:shared"),
            _bound("two.json", b"two\n", evidence_id="evidence:shared"),
        ]
    )
    entries, conflicts = extract_bound_evidence(report)
    assert len(entries) == 1
    assert any("more than one path or digest" in conflict for conflict in conflicts)

    report_path = _write_report(tmp_path / "report.json", report)
    result = verify_report(report_path, evidence_root=evidence_root)
    assert result.outcome == FAIL
    assert _check(result, "report-evidence-conflict").outcome == FAIL
    assert any(issue.event_type == MANIFEST_BINDING_MISMATCH for issue in result.issues)


def test_same_path_bound_to_two_digests_is_a_conflict(tmp_path: Path) -> None:
    report = _evidence_report(
        [
            _bound("target.json", b"first\n"),
            _bound("target.json", b"second\n", kind="other"),
        ]
    )
    _, conflicts = extract_bound_evidence(report)
    assert any("bound to more than one digest" in conflict for conflict in conflicts)


def test_sidecar_evidence_not_referenced_by_report_fails_binding(tmp_path: Path) -> None:
    report_path, _, sealed = _sealed(tmp_path)
    sidecar_path = Path(sealed["integrity_path"])
    sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
    extra = dict(sidecar["evidence"][0])
    extra["evidence_id"] = "evidence:extra.json"
    extra["path"] = "extra.json"
    extra["sha256"] = "sha256:" + "b" * 64
    extra["size"] = 1
    sidecar["evidence"].append(extra)
    _write(sidecar_path, json.dumps(sidecar, indent=2, sort_keys=True) + "\n")

    result = verify_report(report_path)
    assert result.outcome == FAIL
    check = _check(result, "integrity-manifest-evidence:evidence:extra.json")
    assert check.outcome == FAIL
    assert any(issue.event_type == MANIFEST_BINDING_MISMATCH for issue in result.issues)


def test_symlink_evidence_in_report_is_rejected(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    outside = _write(tmp_path / "outside.txt", "outside bytes\n")
    link = evidence_root / "link.txt"
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError):
        pytest.skip("host does not permit synthetic symlink creation")

    before = sha256_file(outside)
    report_path = _write_report(
        tmp_path / "report.json",
        _evidence_report([_bound("link.txt", outside.read_bytes())]),
    )
    result = verify_report(report_path, evidence_root=evidence_root)
    assert result.outcome == FAIL
    assert any(issue.event_type == EVIDENCE_PATH_INVALID for issue in result.issues)
    assert sha256_file(outside) == before


def test_failed_verification_incident_fails_audit_verification(tmp_path: Path) -> None:
    evidence = _record(tmp_path)
    records = build_audit_chain(
        [
            {
                "event_type": EVIDENCE_CREATED,
                "timestamp": "2026-11-04T00:00:00Z",
                "outcome": PASS,
                "evidence": evidence,
            },
            {
                "event_type": EVIDENCE_VERIFIED,
                "timestamp": "2026-11-04T00:00:01Z",
                "outcome": FAIL,
                "evidence": evidence,
                "details": {"reason": "digest mismatch"},
            },
        ]
    )
    audit_path = tmp_path / "audit.jsonl"
    write_audit_chain(audit_path, records)
    assert verify_audit_chain(audit_path).outcome == PASS

    result = verify_audit_file(audit_path)
    assert result.outcome == FAIL
    assert _check(result, "audit-chain").outcome == PASS
    assert _check(result, "audit-incidents").outcome == FAIL
    assert any(issue.event_type == EVIDENCE_REJECTED for issue in result.issues)


def test_append_refuses_an_invalid_chain(tmp_path: Path) -> None:
    evidence = _record(tmp_path)
    audit_path = tmp_path / "audit.jsonl"
    record = build_audit_record(
        sequence=0,
        event_type=EVIDENCE_CREATED,
        timestamp="2026-11-04T00:00:00Z",
        outcome=PASS,
        evidence=evidence,
    )
    record["outcome"] = FAIL
    _write(
        audit_path,
        json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n",
    )
    with pytest.raises(AuditChainError, match="invalid audit chain"):
        append_audit_event(
            audit_path,
            event_type=EVIDENCE_VERIFIED,
            timestamp="2026-11-04T00:00:01Z",
            outcome=PASS,
            evidence=evidence,
        )


def test_individual_evidence_must_resolve_below_the_root(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    outside = _write(tmp_path / "outside.txt", "outside\n")
    result = verify_individual_evidence(
        outside,
        expected_sha256=sha256_file(outside),
        evidence_root=evidence_root,
    )
    assert result.outcome == FAIL
    assert any(issue.event_type == EVIDENCE_PATH_INVALID for issue in result.issues)
    assert verification_exit_code(result.outcome) == 1
