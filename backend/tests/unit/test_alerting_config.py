"""Alerting settings tests — safe defaults and startup validation (V15)."""

from __future__ import annotations

import pytest

from backend.app.core.config import AppEnv, Settings
from backend.app.core.exceptions import ConfigurationError


def _settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)  # type: ignore[call-arg]


def test_alerting_safe_defaults() -> None:
    settings = _settings()
    assert settings.alerting_enabled is False
    assert settings.alerting_eval_interval_seconds == 10.0
    assert settings.alerting_eval_batch_size == 200
    assert settings.alerting_delivery_batch_size == 50
    assert settings.alerting_delivery_timeout_seconds == 10.0
    assert settings.alerting_max_attempts == 8
    assert settings.alerting_retry_base_seconds == 30.0
    assert settings.alerting_max_payload_bytes == 65536
    assert settings.alerting_retention_days == 90
    assert settings.alerting_max_notifications_per_cycle == 500
    assert settings.alerting_smtp_host == ""
    assert settings.alerting_smtp_port == 587
    assert settings.alerting_smtp_tls_mode == "starttls"
    assert settings.alerting_smtp_password == ""
    assert settings.alerting_smtp_to == ""
    assert settings.alerting_webhook_urls == ""
    assert settings.alerting_webhook_secret == ""
    assert settings.alerting_webhook_allowlist == []
    assert settings.alerting_email_recipients == []
    assert settings.alerting_smtp_configured is False
    assert settings.alerting_webhook_configured is False


def test_smtp_tls_mode_allowlist() -> None:
    assert _settings(alerting_smtp_tls_mode="ssl").alerting_smtp_tls_mode == "ssl"
    assert _settings(alerting_smtp_tls_mode="none").alerting_smtp_tls_mode == "none"
    with pytest.raises(ConfigurationError):
        _settings(alerting_smtp_tls_mode="tls1.3").validate_startup()


def test_webhook_allowlist_parsing_and_cap() -> None:
    settings = _settings(alerting_webhook_urls="https://ops.example.com/hooks/a, http://10.0.0.9/hook")
    assert settings.alerting_webhook_allowlist == [
        "https://ops.example.com/hooks/a",
        "http://10.0.0.9/hook",
    ]
    assert settings.alerting_webhook_configured is True
    with pytest.raises(ConfigurationError):
        _settings(
            alerting_webhook_urls="https://a.example/x,https://b.example/x,https://c.example/x,"
            "https://d.example/x,https://e.example/x,https://f.example/x"
        ).validate_startup()


def test_webhook_rejects_non_http_urls_at_startup() -> None:
    settings = _settings(alerting_webhook_urls="ftp://files.example.com/hook")
    with pytest.raises(ValueError):
        settings.alerting_webhook_allowlist


def test_email_recipients_parsed_without_discovery() -> None:
    settings = _settings(alerting_smtp_to="ops@example.com,  oncall@example.com,not-an-address")
    assert settings.alerting_email_recipients == ["ops@example.com", "oncall@example.com"]
    assert _settings().alerting_email_recipients == []


def test_smtp_configured_gate() -> None:
    assert _settings().alerting_smtp_configured is False
    assert (
        _settings(
            alerting_smtp_host="smtp.example.com",
            alerting_smtp_from="ivp@example.com",
            alerting_smtp_to="ops@example.com",
        ).alerting_smtp_configured
        is True
    )
    assert (
        _settings(
            alerting_smtp_host="smtp.example.com",
            alerting_smtp_from="ivp@example.com",
        ).alerting_smtp_configured
        is False
    )


def test_production_env_still_constructible() -> None:
    # V16 production posture: explicit origins AND credentialed CORS
    # (browser sessions require both).
    settings = _settings(
        app_env=AppEnv.production,
        cors_allowed_origins=["https://ops.example.com"],
        cors_allow_credentials=True,
    )
    assert settings.alerting_enabled is False
    assert settings.validate_startup() is not None
