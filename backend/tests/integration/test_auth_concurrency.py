"""Auth concurrency invariants — last admin, single-use tickets (V16)."""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from typing import Any

from backend.app.auth.repository import AuthRepository, LastAdminError
from backend.app.auth.roles import Role
from backend.app.auth.sessions import digest_token, generate_token
from backend.app.infrastructure.db import get_session_factory, init_db
from backend.tests.auth_helpers import create_test_user


def _repo(tmp_path: Any) -> AuthRepository:  # type: ignore[no-untyped-def]
    url = f"sqlite:///{tmp_path}/race.db"
    init_db(url)
    return AuthRepository(get_session_factory(url))


def test_concurrent_last_admin_demotion_exactly_one_wins(tmp_path: Any) -> None:  # type: ignore[no-untyped-def]
    repo = _repo(tmp_path)
    admin_a, _ = create_test_user(repo, "a@example.com", role=Role.ADMIN)
    admin_b, _ = create_test_user(repo, "b@example.com", role=Role.ADMIN)
    outcomes: dict[str, str] = {}

    def demote(user_id: str, key: str) -> None:
        try:
            repo.set_user_role(user_id=user_id, role=Role.VIEWER)
            outcomes[key] = "demoted"
        except LastAdminError:
            outcomes[key] = "guarded"

    threads = [
        threading.Thread(target=demote, args=(admin_a.id, "a")),
        threading.Thread(target=demote, args=(admin_b.id, "b")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert sorted(outcomes.values()) == ["demoted", "guarded"]
    remaining = [u for u in repo.list_users()[0] if u.role is Role.ADMIN and u.is_active]
    assert len(remaining) == 1


def test_concurrent_ticket_consume_exactly_one_wins(tmp_path: Any) -> None:  # type: ignore[no-untyped-def]
    repo = _repo(tmp_path)
    user, _ = create_test_user(repo, "op@example.com", role=Role.OPERATOR)
    now = datetime.now(UTC)
    session = repo.create_session(
        user_id=user.id,
        token_digest=digest_token(generate_token()),
        csrf_digest=digest_token(generate_token()),
        created_at=now,
        authenticated_at=now,
        expires_at=now + timedelta(hours=12),
    )
    raw = generate_token()
    repo.issue_ticket(
        user_id=user.id,
        session_id=session.id,
        digest=digest_token(raw),
        scope="operations",
        created_at=now,
        expires_at=now + timedelta(seconds=30),
    )
    wins: list[bool] = []
    lock = threading.Lock()

    def consume() -> None:
        claimed = repo.consume_ticket(digest=digest_token(raw), now=datetime.now(UTC))
        with lock:
            wins.append(claimed is not None)

    threads = [threading.Thread(target=consume) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert wins.count(True) == 1
    assert wins.count(False) == 7
