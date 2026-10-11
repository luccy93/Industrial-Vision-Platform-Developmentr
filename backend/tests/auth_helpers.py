"""Shared authentication test helpers (V16).

Deterministic, offline: file-backed SQLite + real repository + real
Argon2id hashing. No live services. Passwords below are fixtures only.
"""

from __future__ import annotations

from datetime import UTC, datetime

from backend.app.auth.passwords import hash_password
from backend.app.auth.repository import AuthRepository, AuthUser
from backend.app.auth.roles import Role
from backend.app.infrastructure.db import get_session_factory

#: Fixture password satisfying the V16 policy (15-128 chars, not blocklisted).
TEST_PASSWORD = "Fixture-Auth-9-Voltage-Battery!"
TEST_PASSWORD_OTHER = "Second-Fixture-7-Copper-Circuit@"


def make_auth_repo(database_url: str) -> AuthRepository:
    return AuthRepository(get_session_factory(database_url))


def create_test_user(
    repo: AuthRepository,
    email: str,
    *,
    password: str = TEST_PASSWORD,
    role: Role = Role.VIEWER,
    is_active: bool = True,
    must_change_password: bool = False,
) -> tuple[AuthUser, str]:
    user = repo.create_user(
        email=email,
        password_hash=hash_password(password),
        role=role,
        is_active=is_active,
        must_change_password=must_change_password,
        now=datetime.now(UTC),
    )
    return user, password


def authenticate_client(test_client, database_url: str, email: str = "admin@example.com"):  # type: ignore[no-untyped-def]
    """Log a bespoke TestClient in as ADMIN against its app's database.

    For tests that build their own app/client instead of using the
    shared ``client`` fixture (e.g. restart/warmup tests that seed the
    database before ``create_app``). Mutates and returns the client.
    """
    repo = AuthRepository(get_session_factory(database_url))
    create_test_user(repo, email, role=Role.ADMIN)
    res = test_client.post("/api/v1/auth/login", json={"email": email, "password": TEST_PASSWORD})
    assert res.status_code == 200, res.text
    test_client.headers["X-CSRF-Token"] = res.json()["csrf_token"]
    return test_client
