"""Pytest fixtures — deterministic, hermetic, no external services."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from backend.app.auth.repository import AuthRepository
from backend.app.auth.roles import Role
from backend.app.auth.sessions import digest_token, generate_token, session_expiry
from backend.app.core.config import AppEnv, Settings
from backend.app.infrastructure.db import get_session_factory, init_db
from backend.app.main import create_app
from backend.tests.auth_client import AuthTestClient
from backend.tests.auth_helpers import TEST_PASSWORD

#: One Argon2id hash computed per test session and reused for every
#: fixture identity (same password, same stored string). Per-test hashing
#: would add minutes to the suite without testing anything new; real
#: hashing cost is covered by the dedicated auth tests.
_cached_fixture_hash: str | None = None


def _fixture_hash() -> str:
    global _cached_fixture_hash
    if _cached_fixture_hash is None:
        from backend.app.auth.passwords import hash_password

        _cached_fixture_hash = hash_password(TEST_PASSWORD)
    return _cached_fixture_hash


@pytest.fixture()
def test_settings(tmp_path) -> Settings:  # type: ignore[no-untyped-def]
    return Settings(
        app_name="industrial-vision-platform",
        app_env=AppEnv.testing,
        log_level="WARNING",
        api_host="127.0.0.1",
        api_port=8000,
        database_url=f"sqlite:///{tmp_path}/test.db",
        redis_url="redis://localhost:6379/15",
        gpu_enabled=False,
        model_device="cpu",
        model_confidence_threshold=0.5,
        websocket_enabled=True,
        target_processing_fps=10.0,
        frame_skip=0,
        buffer_size=8,
        _env_file=None,  # type: ignore[call-arg]
    )


@pytest.fixture()
def client(test_settings: Settings) -> TestClient:
    """App client authenticated as ADMIN (V16).

    Existing business-logic tests run with an administrator identity so
    they keep asserting behavior, not auth plumbing: the session cookie
    is set and the CSRF header defaults are installed. Dedicated V16
    tests cover unauthenticated/forbidden paths and the inventory.
    """
    init_db(test_settings.database_url)
    app = create_app(test_settings)
    now = datetime.now(UTC)
    repo = AuthRepository(get_session_factory(str(test_settings.database_url)))
    admin = repo.create_user(
        email="admin@example.com",
        password_hash=_fixture_hash(),
        role=Role.ADMIN,
        now=now,
    )
    raw_token, raw_csrf = generate_token(), generate_token()
    expires_at, _ = session_expiry(
        now,
        idle_minutes=int(test_settings.auth_session_idle_minutes),
        absolute_hours=int(test_settings.auth_session_absolute_hours),
    )
    info = repo.create_session(
        user_id=admin.id,
        token_digest=digest_token(raw_token),
        csrf_digest=digest_token(raw_csrf),
        created_at=now,
        authenticated_at=now,
        expires_at=expires_at,
    )
    assert info.id
    authed = AuthTestClient(app)
    # NOTE: this httpx/TestClient combo only sends jar cookies set with
    # an empty domain (verified by probe); response Set-Cookie
    # persistence works normally for real logins in the V16 tests.
    authed.cookies.set(str(test_settings.auth_session_cookie_name), raw_token, domain="", path="/")
    authed.headers[str(test_settings.auth_csrf_header)] = raw_csrf
    return authed
