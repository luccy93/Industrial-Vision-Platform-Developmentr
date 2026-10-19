"""Auth repository tests — users, guards, sessions, tickets (V16)."""

from datetime import UTC, datetime, timedelta

import pytest

from backend.app.auth.repository import (
    AuthRepository,
    BootstrapExistsError,
    LastAdminError,
    UserExistsError,
    UserNotFoundError,
)
from backend.app.auth.roles import Role
from backend.app.auth.sessions import digest_token, generate_token
from backend.app.infrastructure.db import get_session_factory, init_db
from backend.tests.auth_helpers import TEST_PASSWORD, create_test_user


def _repo(tmp_path) -> AuthRepository:  # type: ignore[no-untyped-def]
    url = f"sqlite:///{tmp_path}/auth.db"
    init_db(url)
    return AuthRepository(get_session_factory(url))


def test_case_normalized_user_uniqueness(tmp_path) -> None:  # type: ignore[no-untyped-def]
    repo = _repo(tmp_path)
    create_test_user(repo, "ops@example.com")
    with pytest.raises(UserExistsError):
        # Normalized form collides; the DB unique constraint is the backstop.
        repo.create_user(
            email="ops@example.com",
            password_hash="x" * 60,
            role=Role.VIEWER,
            now=datetime.now(UTC),
        )


def test_bootstrap_first_admin_and_refuse_second(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from backend.app.auth.passwords import hash_password

    repo = _repo(tmp_path)
    assert repo.has_active_admin() is False
    admin = repo.bootstrap_admin(
        email="root@example.com",
        password_hash=hash_password(TEST_PASSWORD),
        now=datetime.now(UTC),
    )
    assert admin.role is Role.ADMIN
    assert repo.has_active_admin() is True
    with pytest.raises(BootstrapExistsError):
        repo.bootstrap_admin(
            email="second@example.com",
            password_hash=hash_password(TEST_PASSWORD),
            now=datetime.now(UTC),
        )


def test_last_admin_demote_and_deactivate_guarded(tmp_path) -> None:  # type: ignore[no-untyped-def]
    repo = _repo(tmp_path)
    admin, _ = create_test_user(repo, "a1@example.com", role=Role.ADMIN)
    with pytest.raises(LastAdminError):
        repo.set_user_role(user_id=admin.id, role=Role.VIEWER)
    with pytest.raises(LastAdminError):
        repo.set_user_active(user_id=admin.id, is_active=False)
    # A second admin releases the guard.
    other, _ = create_test_user(repo, "a2@example.com", role=Role.ADMIN)
    demoted = repo.set_user_role(user_id=admin.id, role=Role.OPERATOR)
    assert demoted.role is Role.OPERATOR
    with pytest.raises(LastAdminError):
        repo.set_user_active(user_id=other.id, is_active=False)
    with pytest.raises(UserNotFoundError):
        repo.set_user_role(user_id="missing", role=Role.VIEWER)


def test_deactivation_revokes_sessions(tmp_path) -> None:  # type: ignore[no-untyped-def]
    repo = _repo(tmp_path)
    admin, _ = create_test_user(repo, "root@example.com", role=Role.ADMIN)
    user, _ = create_test_user(repo, "op@example.com", role=Role.OPERATOR)
    now = datetime.now(UTC)
    raw_session_token = generate_token()
    repo.create_session(
        user_id=user.id,
        token_digest=digest_token(raw_session_token),
        csrf_digest=digest_token(generate_token()),
        created_at=now,
        authenticated_at=now,
        expires_at=now + timedelta(hours=12),
    )
    repo.set_user_active(user_id=user.id, is_active=False)
    info = repo.get_session_by_digest(digest_token(raw_session_token))
    assert info is not None and info.revoked_at is not None
    assert repo.has_active_admin() is True
    assert admin.is_active is True


def test_session_revocation_and_ticket_single_use(tmp_path) -> None:  # type: ignore[no-untyped-def]
    repo = _repo(tmp_path)
    user, _ = create_test_user(repo, "op@example.com", role=Role.OPERATOR)
    now = datetime.now(UTC)
    raw, csrf = generate_token(), generate_token()
    info = repo.create_session(
        user_id=user.id,
        token_digest=digest_token(raw),
        csrf_digest=digest_token(csrf),
        created_at=now,
        authenticated_at=now,
        expires_at=now + timedelta(hours=12),
    )
    assert repo.get_session_by_digest(digest_token(raw)) is not None
    repo.revoke_session(session_id=info.id, now=now)
    revoked = repo.get_session_by_digest(digest_token(raw))
    assert revoked is not None and revoked.revoked_at is not None

    ticket_raw = generate_token()
    repo.issue_ticket(
        user_id=user.id,
        session_id=info.id,
        digest=digest_token(ticket_raw),
        scope="operations",
        created_at=now,
        expires_at=now + timedelta(seconds=30),
    )
    claimed = repo.consume_ticket(digest=digest_token(ticket_raw), now=now)
    assert claimed is not None and claimed["scope"] == "operations"
    assert repo.consume_ticket(digest=digest_token(ticket_raw), now=now) is None
    assert repo.consume_ticket(digest="0" * 64, now=now) is None
    expired_raw = generate_token()
    repo.issue_ticket(
        user_id=user.id,
        session_id=info.id,
        digest=digest_token(expired_raw),
        scope="operations",
        created_at=now - timedelta(minutes=5),
        expires_at=now - timedelta(seconds=1),
    )
    assert repo.consume_ticket(digest=digest_token(expired_raw), now=now) is None


def test_throttle_counters_and_audit(tmp_path) -> None:  # type: ignore[no-untyped-def]
    repo = _repo(tmp_path)
    now = datetime.now(UTC)
    for _ in range(3):
        repo.record_attempt(email_normalized="op@example.com", ip_hash="ip1", succeeded=False, now=now)
    repo.record_attempt(email_normalized="op@example.com", ip_hash="ip1", succeeded=True, now=now)
    account, ip_wide = repo.count_recent_failures(
        email_normalized="op@example.com", ip_hash="ip1", since=now - timedelta(minutes=15)
    )
    assert (account, ip_wide) == (3, 3)
    repo.audit(actor_user_id=None, target_user_id=None, action="bootstrap_admin", detail="ok", now=now)
    pruned = repo.prune_expired_sessions(now=now + timedelta(days=1))
    assert pruned == 0
