"""V20 log redaction — credentials never reach logs or tracebacks."""

from __future__ import annotations

import logging

from backend.app.core.logging import RedactingFilter, redact


def test_bearer_token_redacted() -> None:
    out = redact("authorization: Bearer abc.def.ghi")
    assert "abc.def.ghi" not in out
    assert "[REDACTED]" in out
    assert "Bearer" in out


def test_basic_and_digest_credentials_redacted() -> None:
    basic = redact("Authorization: Basic dXNlcjpwYXNzd29yZA==")
    assert "dXNlcjpwYXNzd29yZA==" not in basic
    assert "[REDACTED]" in basic
    digest = redact("Authorization: Digest username=admin, response=deadbeef")
    assert "deadbeef" not in digest
    assert "[REDACTED]" in digest


def test_benign_authorization_word_untouched() -> None:
    text = "authorization check completed for camera 3"
    assert redact(text) == text


def test_dsn_password_redacted() -> None:
    out = redact("postgresql+psycopg2://ivp:SuperSecret@db.internal:5432/industrial_vision")
    assert "SuperSecret" not in out
    assert "[REDACTED]" in out


def test_password_and_token_keywords_redacted() -> None:
    assert "hunter2" not in redact("password=hunter2")
    assert "abc123" not in redact("token: abc123")


def test_rtsp_credentials_redacted() -> None:
    out = redact("rtsp://admin:CameraPw@10.0.0.5/stream")
    assert "CameraPw" not in out


def _record(msg: str, args=None, exc_info=None, extra=None) -> logging.LogRecord:
    record = logging.LogRecord("test", logging.WARNING, __file__, 1, msg, args or (), exc_info)
    for key, value in (extra or {}).items():
        setattr(record, key, value)
    return record


def test_filter_redacts_message() -> None:
    record = _record("connecting with token=deadbeefcafe")
    RedactingFilter().filter(record)
    assert "deadbeefcafe" not in record.getMessage()


def test_filter_redacts_structured_extra() -> None:
    record = _record("ok", extra={"authorization_header": "Bearer top.secret.value"})
    RedactingFilter().filter(record)
    assert "top.secret.value" not in getattr(record, "authorization_header")


def test_filter_redacts_traceback() -> None:
    try:
        raise RuntimeError("auth failed for token=deadbeefcafe")
    except RuntimeError:
        record = _record("boom", exc_info=__import__("sys").exc_info())
    RedactingFilter().filter(record)
    assert record.exc_text is not None
    assert "deadbeefcafe" not in record.exc_text
    assert "[REDACTED]" in record.exc_text
