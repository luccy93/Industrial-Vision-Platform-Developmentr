"""V29 adversarial credential-protection tests.

Every value here is a synthetic sentinel. These tests exercise the central
redaction policy, the logging filter, structured evidence retention, and hash
integrity. They never contact a real service and never contain real secrets.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sys
from pathlib import Path

import pytest

from backend.app.core.logging import RedactingFilter
from backend.app.core.redaction import (
    REDACTED,
    RedactionError,
    contains_sensitive_material,
    dump_sanitized_json,
    is_sensitive_name,
    redact_structure,
    redact_text,
    sanitize_json_document,
    scan_text,
)
from tools.release.evidence import write_evidence_report
from tools.release.manifest import sha256_file
from tools.release.readiness import (
    _retain_evidence,
    _write_live_inspection,
    write_readiness_report,
)

SENTINEL = "v29_adversarial_sentinel_do_not_disclose"


def _assert_redacted(text: str) -> None:
    assert SENTINEL not in text
    assert REDACTED in text


@pytest.mark.parametrize(
    "text",
    [
        f"POSTGRES_PASSWORD={SENTINEL}",
        f"IVP_POSTGRES_PASSWORD={SENTINEL}",
        f"PROD_DATABASE_PASSWORD={SENTINEL}",
        f"SERVICE_API_TOKEN={SENTINEL}",
        f"GITHUB_APP_PRIVATE_KEY={SENTINEL}",
        f"export GITHUB_APP_PRIVATE_KEY={SENTINEL}",
        f"env:\n  IVP_POSTGRES_PASSWORD: {SENTINEL}",
        f"- SERVICE_API_TOKEN: {SENTINEL}",
        f"GHCR_TOKEN={SENTINEL}",
        f"CLIENT_SECRET={SENTINEL}",
    ],
)
def test_prefixed_environment_assignments_are_redacted(text: str) -> None:
    _assert_redacted(redact_text(text))
    assert contains_sensitive_material(text) is True


@pytest.mark.parametrize(
    "text",
    [
        '{"password": "' + SENTINEL + '"}',
        '{"nested": {"client_secret": "' + SENTINEL + '"}}',
        '{"items": [{"access_token": "' + SENTINEL + '"}]}',
        '{\\"password\\": \\"' + SENTINEL + '\\"}',
        'password = "' + SENTINEL + '"',
    ],
)
def test_quoted_json_and_escaped_json_values_are_redacted(text: str) -> None:
    _assert_redacted(redact_text(text))


@pytest.mark.parametrize(
    "text",
    [
        f"https://user:{SENTINEL}@example.test/path",
        f"https://user:p@{SENTINEL}@example.test/path",
        f"postgresql://ivp:{SENTINEL}@db.internal:5432/ivp",
        f"rtsp://admin:{SENTINEL}@10.0.0.5/stream",
        f"https://example.test/path?access_token={SENTINEL}&safe=1",
        f"https://example.test/path?auth={SENTINEL}",
        f"https://example.test/path?access_key={SENTINEL}",
        f"https://example.test/path?secret_key={SENTINEL}",
        f"https://example.test/path?credential={SENTINEL}",
    ],
)
def test_url_userinfo_and_query_credentials_are_redacted(text: str) -> None:
    _assert_redacted(redact_text(text))


@pytest.mark.parametrize(
    "text",
    [
        f"Authorization: Bearer {SENTINEL}",
        f"authorization: Basic {SENTINEL}",
        f"Proxy-Authorization: Digest {SENTINEL}",
        f"Cookie: session={SENTINEL}; theme=dark",
        f"Set-Cookie: session={SENTINEL}; Path=/",
        f"X-API-Key: {SENTINEL}",
        f"x-custom-token: {SENTINEL}",
        f"X_API_KEY: {SENTINEL}",
    ],
)
def test_authorization_cookie_and_custom_headers_are_redacted(text: str) -> None:
    _assert_redacted(redact_text(text))


def test_authorization_schemes_are_preserved() -> None:
    bearer = redact_text(f"Authorization: Bearer {SENTINEL}")
    basic = redact_text(f"Authorization: Basic {SENTINEL}")
    assert bearer == f"Authorization: Bearer {REDACTED}"
    assert basic == f"Authorization: Basic {REDACTED}"


@pytest.mark.parametrize(
    "text",
    [
        f"before\n-----BEGIN RSA PRIVATE KEY-----\n{SENTINEL}\n-----END RSA PRIVATE KEY-----\nafter",
        f"before\n-----BEGIN OPENSSH PRIVATE KEY-----\n{SENTINEL}\n-----END OPENSSH PRIVATE KEY-----\nafter",
        f"before\n-----BEGIN PRIVATE KEY-----\n{SENTINEL}",
    ],
)
def test_private_key_blocks_are_removed(text: str) -> None:
    redacted = redact_text(text)
    assert SENTINEL not in redacted
    assert "PRIVATE KEY" not in redacted
    assert "before" in redacted


def test_nested_structured_payload_is_sanitized_and_metadata_is_kept() -> None:
    payload = {
        "repository_id": "repo-1",
        "key_id": "key-1",
        "public_key_fingerprint": "SHA256:abc",
        "token_count": 3,
        "password_policy": "strong",
        "api_key_required": True,
        "deployment_id": "dep-1",
        "nested": {
            "access_token": SENTINEL,
            "safe": "keep-me",
            "url": f"https://example.test/path?token={SENTINEL}",
        },
        "events": [
            {"client_secret": SENTINEL + "_two", "name": "keep"},
            {"detail": f"password={SENTINEL}_three"},
        ],
    }

    cleaned = redact_structure(payload)
    rendered = json.dumps(cleaned, sort_keys=True)

    assert SENTINEL not in rendered
    assert cleaned["repository_id"] == "repo-1"
    assert cleaned["key_id"] == "key-1"
    assert cleaned["public_key_fingerprint"] == "SHA256:abc"
    assert cleaned["token_count"] == 3
    assert cleaned["password_policy"] == "strong"
    assert cleaned["api_key_required"] is True
    assert cleaned["deployment_id"] == "dep-1"
    assert cleaned["nested"]["safe"] == "keep-me"
    assert cleaned["events"][0]["name"] == "keep"
    assert scan_text(rendered) == []


@pytest.mark.parametrize(
    "text",
    [
        f"env:\n  POSTGRES_PASSWORD: {SENTINEL}\n  SAFE: keep",
        f"password: |\n  {SENTINEL}\n  second-line",
        f"- password: >-\n  {SENTINEL}",
        f"password:\n  {SENTINEL}",
    ],
)
def test_yaml_like_text_and_block_scalars_are_redacted(text: str) -> None:
    redacted = redact_text(text)
    _assert_redacted(redacted)
    assert "secret-assignment" in scan_text(text)


def test_yaml_safe_sibling_fields_are_preserved() -> None:
    redacted = redact_text(f"env:\n  POSTGRES_PASSWORD: {SENTINEL}\n  SAFE: keep")

    assert SENTINEL not in redacted
    assert "POSTGRES_PASSWORD: [REDACTED]" in redacted
    assert "SAFE: keep" in redacted


def test_log_message_args_and_structured_extras_are_redacted() -> None:
    record = logging.LogRecord(
        "test",
        logging.WARNING,
        __file__,
        1,
        "login token=%s",
        (SENTINEL,),
        None,
    )
    record.context = {"nested": {"access_token": SENTINEL, "safe": "keep"}}
    record.authorization_header = f"Bearer {SENTINEL}"

    RedactingFilter().filter(record)

    rendered = record.getMessage() + json.dumps(record.context, sort_keys=True)
    assert SENTINEL not in rendered
    assert record.context["nested"]["safe"] == "keep"
    assert SENTINEL not in getattr(record, "authorization_header")


def test_exception_traceback_is_redacted() -> None:
    try:
        raise RuntimeError(f"authentication failed token={SENTINEL}")
    except RuntimeError:
        record = logging.LogRecord(
            "test",
            logging.ERROR,
            __file__,
            1,
            "boom",
            (),
            sys.exc_info(),
        )

    RedactingFilter().filter(record)

    assert record.exc_text is not None
    assert SENTINEL not in record.exc_text
    assert REDACTED in record.exc_text


def test_preset_exception_text_is_redacted() -> None:
    record = logging.LogRecord("test", logging.ERROR, __file__, 1, "boom", (), None)
    record.exc_text = f"Traceback (most recent call last):\nRuntimeError: password={SENTINEL}"

    RedactingFilter().filter(record)

    assert record.exc_text is not None
    assert SENTINEL not in record.exc_text
    assert REDACTED in record.exc_text


@pytest.mark.parametrize(
    "text",
    [
        "repository_id=repo-1",
        "key_id=key-1",
        "public_key_fingerprint=SHA256:abc",
        "token_count=42",
        "password_policy=strong",
        "api_key_required=true",
        "deployment_id=dep-1",
        "release_id=rel-1",
        "smoke_password_env=IVP_SMOKE_PASSWORD",
        "authorization_header=X-Authorization",
        "private_key_id=key-1",
        "secret_name=prod-db",
        "https://deploy.user@example.test/path",
        "https://user.name@example.test/path",
        "gh attestation verify --source-digest " + "a" * 40,
        "authorization check completed for camera 3",
        "token_count: 42; password_policy: strong; api_key_required: true",
    ],
)
def test_non_secret_metadata_and_identifiers_are_not_redacted(text: str) -> None:
    assert redact_text(text) == text
    assert scan_text(text) == []


@pytest.mark.parametrize(
    "name",
    [
        "repository_id",
        "key_id",
        "public_key_fingerprint",
        "token_count",
        "password_policy",
        "api_key_required",
        "deployment_id",
        "release_id",
        "smoke_password_env",
        "authorization_header",
        "private_key_id",
        "secret_name",
    ],
)
def test_metadata_names_are_not_sensitive(name: str) -> None:
    assert is_sensitive_name(name) is False


def test_scan_results_never_echo_the_secret() -> None:
    findings = scan_text(f"POSTGRES_PASSWORD={SENTINEL}\nAuthorization: Bearer {SENTINEL}")
    assert "secret-assignment" in findings
    assert "authorization-header" in findings
    assert SENTINEL not in " ".join(findings)


def test_sanitize_json_document_fails_closed_on_invalid_json() -> None:
    with pytest.raises(RedactionError):
        sanitize_json_document('{"access_token": "' + SENTINEL)


def test_sanitize_json_document_returns_sanitized_bytes() -> None:
    payload = {"nested": {"api_key": SENTINEL}, "token_count": 1}
    cleaned, text = sanitize_json_document(json.dumps(payload))

    assert cleaned["nested"]["api_key"] == REDACTED
    assert cleaned["token_count"] == 1
    assert SENTINEL not in text
    assert text == dump_sanitized_json(payload)


def test_secret_bearing_json_is_not_bound_and_its_redacted_copy_has_a_new_hash(
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
    redacted_text = redacted.read_text(encoding="utf-8")
    redacted_digest = hashlib.sha256(redacted.read_bytes()).hexdigest()
    assert redacted.name == f"rollback-evidence-{redacted_digest[:12]}-redacted.json"
    assert sha256_file(redacted) == f"sha256:{redacted_digest}"
    assert sha256_file(redacted) != original_digest
    assert SENTINEL not in redacted_text
    assert scan_text(redacted_text) == []


def test_secret_bearing_text_is_not_bound_and_its_redacted_copy_has_a_new_hash(
    tmp_path: Path,
) -> None:
    source = tmp_path / "backup.md"
    source.write_text(f"# Backup\npassword={SENTINEL}\n", encoding="utf-8")
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
    redacted_text = redacted.read_text(encoding="utf-8")
    redacted_digest = hashlib.sha256(redacted.read_bytes()).hexdigest()
    assert redacted.name == f"backup-documentation-{redacted_digest[:12]}-redacted.md"
    assert sha256_file(redacted) != original_digest
    assert SENTINEL not in redacted_text
    assert scan_text(redacted_text) == []


def test_malformed_structured_evidence_fails_closed_without_retention(
    tmp_path: Path,
) -> None:
    source = tmp_path / "rollback.json"
    source.write_text('{"password": "' + SENTINEL, encoding="utf-8")
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
    assert not evidence_dir.exists() or not any(evidence_dir.iterdir())


def test_clean_structured_evidence_keeps_its_exact_bytes_and_hash(
    tmp_path: Path,
) -> None:
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
    evidence_dir = tmp_path / "evidence"

    binding = _retain_evidence(
        source,
        evidence_dir,
        kind="release-manifest",
        state="PASS",
        evidence=evidence,
    )

    assert isinstance(binding, dict)
    assert binding["sha256"] == original_digest
    assert evidence == [binding]
    destination = evidence_dir / str(binding["path"])
    assert destination.read_bytes() == source.read_bytes()
    assert sha256_file(destination) == original_digest


def test_readiness_report_hash_matches_the_sanitized_stored_bytes(
    tmp_path: Path,
) -> None:
    payload = {
        "nested": {"api_key": SENTINEL},
        "token_count": 2,
        "safe": "keep",
    }
    path = tmp_path / "readiness.json"
    digest = write_readiness_report(payload, path)
    stored = path.read_bytes()

    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    assert digest == sha256_file(path)
    assert digest == "sha256:" + hashlib.sha256(stored).hexdigest()
    assert digest != "sha256:" + hashlib.sha256(raw).hexdigest()
    text = stored.decode("utf-8")
    assert SENTINEL not in text
    assert scan_text(text) == []
    assert json.loads(text)["token_count"] == 2
    assert json.loads(text)["safe"] == "keep"


def test_live_inspection_hash_matches_the_sanitized_stored_bytes(
    tmp_path: Path,
) -> None:
    path = _write_live_inspection(
        tmp_path,
        {
            "mode": "live-read-only",
            "nested": {"client_secret": SENTINEL},
            "safe": "keep",
        },
    )
    stored = path.read_bytes()
    text = stored.decode("utf-8")

    assert SENTINEL not in text
    assert scan_text(text) == []
    assert sha256_file(path) == "sha256:" + hashlib.sha256(stored).hexdigest()
    assert json.loads(text)["nested"]["client_secret"] == REDACTED
    assert json.loads(text)["safe"] == "keep"


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
    assert json.loads(text)["safe"] == "keep"
