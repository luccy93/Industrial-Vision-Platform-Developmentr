"""V20 configuration hardening — strict production, permissive dev/test.

Complements ``test_hardening_config.py`` with the production-only rules
added in V20: PostgreSQL DSN with a non-default password, internal metrics
access, well-formed trusted proxies, origin shape validation, webhook scheme
validation with redaction, and secret-safe ``repr``.
"""

from __future__ import annotations

import pytest

from backend.app.core.config import AppEnv, Settings
from backend.app.core.exceptions import ConfigurationError

_STRONG_DSN = "postgresql+psycopg2://ivp:S3cure-Prod-Pass@db.internal:5432/industrial_vision"


def _settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)  # type: ignore[call-arg]


def _prod(**overrides) -> Settings:
    base: dict = {
        "app_env": AppEnv.production,
        "cors_allowed_origins": ["https://vision.example.com"],
        "cors_allow_credentials": True,
        "database_url": _STRONG_DSN,
    }
    base.update(overrides)
    return _settings(**base)


def test_production_accepts_hardened_configuration() -> None:
    assert _prod().validate_startup() != []


@pytest.mark.parametrize("weak", ["postgres", "password", "changeme", "admin", "test"])
def test_production_rejects_default_database_passwords(weak: str) -> None:
    dsn = f"postgresql+psycopg2://ivp:{weak}@db.internal:5432/industrial_vision"
    with pytest.raises(ConfigurationError):
        _prod(database_url=dsn).validate_startup()


def test_production_rejects_non_postgres_dialect() -> None:
    with pytest.raises(ConfigurationError):
        _prod(database_url="mysql://ivp:S3cure-Prod-Pass@db:3306/ivp").validate_startup()


def test_production_requires_internal_metrics_access() -> None:
    with pytest.raises(ConfigurationError):
        _prod(metrics_access="public").validate_startup()


def test_production_rejects_malformed_trusted_proxy() -> None:
    with pytest.raises(ConfigurationError):
        _prod(auth_trusted_proxies=["not-an-ip"]).validate_startup()


def test_production_accepts_ip_and_cidr_trusted_proxies() -> None:
    settings = _prod(auth_trusted_proxies=["10.0.0.0/8", "192.168.1.5", "::1"])
    assert settings.validate_startup() != []


@pytest.mark.parametrize(
    "origin",
    ["https://host/path", "https://user:pass@host", "https://host?q=1", "ftp://host"],
)
def test_origin_shape_validated_in_every_environment(origin: str) -> None:
    with pytest.raises(ConfigurationError):
        _settings(cors_allowed_origins=[origin]).validate_startup()


def test_webhook_allowlist_rejects_bad_scheme_without_leaking_path() -> None:
    settings = _settings(alerting_webhook_urls="ftp://hooks.example.com/secret-token-path")
    with pytest.raises(ConfigurationError) as excinfo:
        _ = settings.alerting_webhook_allowlist
    message = str(excinfo.value)
    assert "secret-token-path" not in message
    assert "ftp" in message


def test_webhook_allowlist_accepts_http_and_https() -> None:
    settings = _settings(alerting_webhook_urls="https://a.example.com/h,http://b.example.com/hook")
    assert settings.alerting_webhook_allowlist == [
        "https://a.example.com/h",
        "http://b.example.com/hook",
    ]


def test_secrets_are_excluded_from_repr() -> None:
    settings = _settings(
        database_url="postgresql+psycopg2://ivp:TopSecretPw@db:5432/ivp",
        redis_url="redis://:RedisSecret@cache:6379/0",
        alerting_smtp_password="SmtpSecret",
        alerting_webhook_secret="HookSecret",
    )
    text = repr(settings)
    for secret in ("TopSecretPw", "RedisSecret", "SmtpSecret", "HookSecret"):
        assert secret not in text


def test_dev_defaults_stay_permissive() -> None:
    # Wildcard origins without credentials remain valid outside production.
    settings = _settings()
    assert settings.validate_startup() != []
