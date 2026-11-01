"""V29 central credential detection and redaction tests.

All values in this module are synthetic sentinels. They are not credentials and
must never be replaced with real secrets.
"""

from __future__ import annotations

import json
import logging

import pytest

from backend.app.core.logging import RedactingFilter
from backend.app.core.redaction import (
    REDACTED,
    RedactionError,
    contains_sensitive_material,
    is_sensitive_name,
    redact_structure,
    redact_text,
    sanitize_json_document,
    scan_text,
)

SENTINEL = "v29_synthetic_sentinel_do_not_disclose"


@pytest.mark.parametrize(
    "name",
    [
        "PASSWORD",
        "PASSWD",
        "POSTGRES_PASSWORD",
        "DATABASE_PASSWORD",
        "DB_PASSWORD",
        "REDIS_PASSWORD",
        "MYSQL_PASSWORD",
        "IVP_POSTGRES_PASSWORD",
        "PROD_DATABASE_PASSWORD",
        "API_TOKEN",
        "ACCESS_TOKEN",
        "REFRESH_TOKEN",
        "AUTH_TOKEN",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GHCR_TOKEN",
        "CR_PAT",
        "AWS_SECRET_ACCESS_KEY",
        "CLIENT_SECRET",
        "PRIVATE_KEY",
        "SIGNING_KEY",
        "WEBHOOK_SECRET",
        "SERVICE_API_TOKEN",
        "GITHUB_APP_PRIVATE_KEY",
        "PASSWORD_HASH",
    ],
)
def test_credential_bearing_names_are_sensitive(name: str) -> None:
    assert is_sensitive_name(name) is True


@pytest.mark.parametrize(
    "name",
    [
        "repository_id",
        "key_id",
        "public_key_fingerprint",
        "token_count",
        "password_policy",
        "api_key_required",
        "smoke_password_env",
        "authorization_header",
        "deployment_id",
        "private_key_id",
        "secret_name",
        "public_key",
    ],
)
def test_metadata_names_are_not_sensitive(name: str) -> None:
    assert is_sensitive_name(name) is False


@pytest.mark.parametrize(
    "text",
    [
        "PASSWORD=" + SENTINEL,
        "POSTGRES_PASSWORD=" + SENTINEL,
        "IVP_POSTGRES_PASSWORD=" + SENTINEL,
        "PROD_DATABASE_PASSWORD=" + SENTINEL,
        "SERVICE_API_TOKEN=" + SENTINEL,
        "GITHUB_APP_PRIVATE_KEY=" + SENTINEL,
        "password: " + SENTINEL,
        '"access_token": "' + SENTINEL + '"',
        "{'client_secret': '" + SENTINEL + "'}",
    ],
)
def test_assignment_forms_are_redacted(text: str) -> None:
    redacted = redact_text(text)
    assert SENTINEL not in redacted
    assert REDACTED in redacted


@pytest.mark.parametrize(
    "text",
    [
        "https://user:" + SENTINEL + "@example.test/path",
        "https://example.test/path?access_token=" + SENTINEL + "&safe=1",
        "postgresql://ivp:" + SENTINEL + "@db.internal:5432/ivp",
        "wss://example.test/socket?token=" + SENTINEL,
    ],
)
def test_url_credentials_are_redacted(text: str) -> None:
    redacted = redact_text(text)
    assert SENTINEL not in redacted
    assert REDACTED in redacted


@pytest.mark.parametrize(
    "text",
    [
        "Authorization: Bearer " + SENTINEL,
        "authorization: Basic " + SENTINEL,
        "Proxy-Authorization: Digest " + SENTINEL,
        "Cookie: session=" + SENTINEL,
        "Set-Cookie: session=" + SENTINEL + "; Path=/",
        "X-API-Key: " + SENTINEL,
        "x-custom-token: " + SENTINEL,
    ],
)
def test_header_credentials_are_redacted(text: str) -> None:
    redacted = redact_text(text)
    assert SENTINEL not in redacted
    assert REDACTED in redacted


def test_bearer_and_basic_scheme_names_are_preserved() -> None:
    bearer = redact_text("Authorization: Bearer " + SENTINEL)
    basic = redact_text("Authorization: Basic " + SENTINEL)
    assert "Bearer" in bearer
    assert "Basic" in basic


def test_private_key_block_is_removed_entirely() -> None:
    text = "before\n-----BEGIN RSA PRIVATE KEY-----\n" + SENTINEL + "\n-----END RSA PRIVATE KEY-----\nafter"
    redacted = redact_text(text)
    assert SENTINEL not in redacted
    assert "PRIVATE KEY" not in redacted
    assert "before" in redacted
    assert "after" in redacted


def test_nested_structure_preserves_non_secret_fields() -> None:
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
        "note": "password=" + SENTINEL + "_three",
    }

    cleaned = redact_structure(payload)
    rendered = json.dumps(cleaned, sort_keys=True)

    assert SENTINEL not in rendered
    assert cleaned["repository_id"] == "repo-1"
    assert cleaned["key_id"] == "key-1"
    assert cleaned["token_count"] == 3
    assert cleaned["password_policy"] == "strong"
    assert cleaned["api_key_required"] is True
    assert cleaned["public_key_fingerprint"] == "SHA256:abc"
    assert cleaned["nested"]["safe"] == "keep-me"
    assert cleaned["items"][0]["name"] == "keep"


def test_malformed_structured_evidence_fails_closed() -> None:
    with pytest.raises(RedactionError):
        sanitize_json_document('{"access_token": "' + SENTINEL)


def test_scan_text_reports_categories_without_values() -> None:
    findings = scan_text("POSTGRES_PASSWORD=" + SENTINEL + "\nAuthorization: Bearer " + SENTINEL)
    assert "secret-assignment" in findings
    assert "authorization-header" in findings
    assert SENTINEL not in " ".join(findings)


def test_redaction_markers_do_not_trigger_false_positives() -> None:
    assert scan_text('password="[REDACTED]"') == []
    assert scan_text("Authorization: Bearer [REDACTED]") == []
    assert contains_sensitive_material("token_count: 42; password_policy: strong") is False


def test_nested_logging_extra_is_redacted() -> None:
    record = logging.LogRecord("test", logging.WARNING, __file__, 1, "ok", (), None)
    record.context = {"access_token": SENTINEL, "safe": "keep"}

    RedactingFilter().filter(record)

    rendered = json.dumps(record.context, sort_keys=True)
    assert SENTINEL not in rendered
    assert record.context["safe"] == "keep"
