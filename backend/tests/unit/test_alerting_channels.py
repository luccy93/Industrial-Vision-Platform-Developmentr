"""Alerting channel contract tests — fakes, payloads, error mapping (V15)."""

from __future__ import annotations

import json

import pytest

from backend.app.alerting.channels import (
    ERROR_AUTH,
    ERROR_CLIENT,
    ERROR_CONNECTION,
    ERROR_RATE_LIMITED,
    ERROR_SERVER,
    ERROR_TIMEOUT,
    ChannelResult,
    FakeChannelAdapter,
    build_webhook_payload,
    categorize_http_error,
    categorize_smtp_error,
    payload_bytes,
    sign_webhook_payload,
)


def test_fake_adapter_records_and_scripts() -> None:
    fake = FakeChannelAdapter(
        name="smtp",
        results=[
            ChannelResult(delivered=False, retryable=True, error_category=ERROR_TIMEOUT),
            ChannelResult(delivered=True),
        ],
    )
    assert fake.is_configured() is True
    first = fake.send({"id": "n1"})
    assert first.delivered is False and first.retryable is True
    second = fake.send({"id": "n1"})
    assert second.delivered is True
    assert len(fake.calls) == 2
    fake.close()
    assert fake.closed is True


def test_fake_unconfigured() -> None:
    assert FakeChannelAdapter(configured=False).is_configured() is False


def test_webhook_payload_stable_keys() -> None:
    payload = build_webhook_payload(
        {
            "id": "n1",
            "rule_id": "r1",
            "source_event_id": "evt-9",
            "event_type": "incident_resolved",
            "severity": "HIGH",
            "priority": "P1",
            "camera_id": "cam-01",
            "incident_id": "i1",
            "title": "t",
            "message": "m",
            "created_at": "2026-01-01T00:00:00+00:00",
        }
    )
    assert payload["notification_id"] == "n1"
    assert payload["rule_id"] == "r1"
    assert payload["occurred_at"] == "2026-01-01T00:00:00+00:00"
    assert "password" not in json.dumps(payload).lower()
    assert "secret" not in json.dumps(payload).lower()


def test_webhook_signing() -> None:
    body = b'{"a":1}'
    assert sign_webhook_payload("", body) == ""
    first = sign_webhook_payload("s3cret", body)
    assert len(first) == 64
    assert sign_webhook_payload("s3cret", body) == first
    assert sign_webhook_payload("other", body) != first


def test_smtp_error_mapping_never_leaks() -> None:
    class FakeTimeout(Exception):
        pass

    FakeTimeout.__name__ = "SMTPTimeout"

    category, retryable = categorize_smtp_error(FakeTimeout("timed out after 10s"))
    assert (category, retryable) == (ERROR_TIMEOUT, True)

    class FakeAuth(Exception):
        pass

    FakeAuth.__name__ = "SMTPAuthenticationError"
    category, retryable = categorize_smtp_error(FakeAuth("535 bad password hunter2"))
    assert (category, retryable) == (ERROR_AUTH, False)
    assert "hunter2" not in category


def test_http_error_mapping() -> None:
    assert categorize_http_error(status=200) == ("", False)
    assert categorize_http_error(status=429) == (ERROR_RATE_LIMITED, True)
    assert categorize_http_error(status=503) == (ERROR_SERVER, True)
    assert categorize_http_error(status=404) == (ERROR_CLIENT, False)
    assert categorize_http_error(status=None) == ("unknown_error", True)
    code, retryable = categorize_http_error(status=None, timeout=True)
    assert (code, retryable) == (ERROR_TIMEOUT, True)
    code, retryable = categorize_http_error(status=None, connection=True)
    assert (code, retryable) == (ERROR_CONNECTION, True)


def test_payload_size_bound() -> None:
    assert payload_bytes({"a": 1}, max_bytes=1024).startswith(b'{"a":1}')
    with pytest.raises(ValueError):
        payload_bytes({"blob": "x" * 2000}, max_bytes=100)
