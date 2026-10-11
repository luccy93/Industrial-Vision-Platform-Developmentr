"""Auth foundation tests — roles, passwords, sessions primitives (V16)."""

from datetime import UTC, datetime, timedelta

import pytest

from backend.app.auth.passwords import (
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    hash_password,
    needs_rehash,
    validate_password,
    verify_password,
)
from backend.app.auth.roles import Role, can, capabilities_for, normalize_role
from backend.app.auth.sessions import (
    digest_token,
    generate_token,
    hash_ip,
    normalize_email,
    session_is_live,
    tokens_equal,
    validate_email_shape,
)


def test_role_matrix_least_privilege() -> None:
    assert can(Role.ADMIN, "user_admin")
    assert can(Role.ADMIN, "admin_config")
    assert not can(Role.OPERATOR, "user_admin")
    assert not can(Role.OPERATOR, "admin_config")
    assert can(Role.OPERATOR, "incident_write")
    assert can(Role.OPERATOR, "camera_control")
    assert can(Role.OPERATOR, "notification_mute")
    assert not can(Role.VIEWER, "incident_write")
    assert not can(Role.VIEWER, "camera_control")
    assert can(Role.VIEWER, "read")
    assert can("operator", "incident_write")
    assert capabilities_for(Role.ADMIN) == frozenset(
        {"read", "incident_write", "camera_control", "notification_mute", "admin_config", "user_admin"}
    )


def test_normalize_role_rejects_unknown() -> None:
    with pytest.raises(ValueError):
        normalize_role("SUPERUSER")
    with pytest.raises(ValueError):
        normalize_role("")
    assert normalize_role(" admin ") is Role.ADMIN


def test_password_policy_boundaries() -> None:
    validate_password("a" * MIN_PASSWORD_LENGTH)
    validate_password("a" * MAX_PASSWORD_LENGTH)
    validate_password("correct horse battery staple 🌦️9")
    with pytest.raises(ValueError):
        validate_password("a" * (MIN_PASSWORD_LENGTH - 1))
    with pytest.raises(ValueError):
        # Never silently truncated: over-length is rejected.
        validate_password("a" * (MAX_PASSWORD_LENGTH + 1))
    with pytest.raises(ValueError):
        validate_password("passwordpassword")
    with pytest.raises(ValueError):
        validate_password("")
    with pytest.raises(ValueError):
        validate_password(None)


def test_password_hash_verify_roundtrip() -> None:
    stored = hash_password("Fixture-Auth-9-Voltage-Battery!")
    assert "Fixture-Auth" not in stored
    assert stored != hash_password("Fixture-Auth-9-Voltage-Battery!")
    assert verify_password(stored, "Fixture-Auth-9-Voltage-Battery!") is True
    assert verify_password(stored, "wrong-password-value") is False
    assert verify_password("not-a-hash", "whatever") is False
    assert needs_rehash(stored) is False


def test_session_token_primitives() -> None:
    first, second = generate_token(), generate_token()
    assert first != second
    assert len(first) >= 43  # 256-bit urlsafe
    assert digest_token(first) == digest_token(first)
    assert len(digest_token(first)) == 64
    assert first not in digest_token(first)
    assert tokens_equal(digest_token(first), digest_token(first)) is True
    assert tokens_equal(digest_token(first), digest_token(second)) is False


def test_email_normalization_and_shape() -> None:
    assert normalize_email("  Ops@Example.COM ") == "ops@example.com"
    validate_email_shape("ops@example.com")
    with pytest.raises(ValueError):
        normalize_email("   ")
    with pytest.raises(ValueError):
        validate_email_shape("not-an-email")
    assert hash_ip("127.0.0.1") != "127.0.0.1"
    assert hash_ip("127.0.0.1") == hash_ip("127.0.0.1")


def test_session_lifetime_logic() -> None:
    now = datetime.now(UTC)
    base = {
        "revoked_at": None,
        "expires_at": now + timedelta(hours=12),
        "created_at": now - timedelta(hours=1),
        "last_seen_at": now - timedelta(minutes=5),
        "idle_minutes": 15,
        "absolute_hours": 12,
    }
    assert session_is_live(now=now, **base) is True
    assert session_is_live(now=now, **{**base, "revoked_at": now}) is False
    assert session_is_live(now=now, **{**base, "expires_at": now}) is False
    assert (
        session_is_live(now=now, **{**base, "last_seen_at": now - timedelta(minutes=16)}) is False
    )
    assert (
        session_is_live(now=now, **{**base, "created_at": now - timedelta(hours=13)}) is False
    )
