"""Auth API tests — login, sessions, CSRF, passwords, throttle (V16)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi.testclient import TestClient

from backend.app.auth.repository import AuthRepository
from backend.app.auth.roles import Role
from backend.app.auth.sessions import digest_token, generate_token
from backend.app.core.config import AppEnv, Settings
from backend.app.infrastructure.db import get_session_factory, init_db
from backend.app.main import create_app
from backend.tests.auth_helpers import TEST_PASSWORD, create_test_user


def _repo(client: Any) -> AuthRepository:
    url = str(client.app.state.settings.database_url)
    return AuthRepository(get_session_factory(url))


def _login(client: Any, email: str, password: str) -> Any:
    return client.post("/api/v1/auth/login", json={"email": email, "password": password})


def test_login_success_sets_cookie_and_csrf(client: Any) -> None:
    repo = _repo(client)
    create_test_user(repo, "op@example.com", role=Role.OPERATOR)
    plain = TestClient(client.app)
    res = _login(plain, "op@example.com", TEST_PASSWORD)
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["user"]["email"] == "op@example.com"
    assert body["user"]["role"] == "OPERATOR"
    assert body["must_change_password"] is False
    assert body["csrf_token"]
    assert body["session_expires_at"]
    assert "password_hash" not in body["user"]
    assert "token_digest" not in body["user"]
    set_cookie = res.headers.get("set-cookie", "")
    assert "ivp_session=" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "samesite=lax" in set_cookie.lower()
    assert "Path=/" in set_cookie
    # Session cookie authenticates follow-up requests on the same client.
    me = plain.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert me.json()["user"]["email"] == "op@example.com"


def test_login_failures_are_generic(client: Any) -> None:
    repo = _repo(client)
    create_test_user(repo, "op@example.com", role=Role.OPERATOR)
    plain = TestClient(client.app)
    for email, password in [
        ("op@example.com", "wrong-password-value"),
        ("missing@example.com", TEST_PASSWORD),
        ("not-an-email", TEST_PASSWORD),
    ]:
        res = _login(plain, email, password)
        assert res.status_code == 401, res.text
        assert res.json()["error"]["code"] == "invalid_credentials"
        assert res.json()["error"]["message"] == "Invalid email or password."
        assert "set-cookie" not in res.headers


def test_inactive_account_rejected_with_generic_error(client: Any) -> None:
    repo = _repo(client)
    create_test_user(repo, "off@example.com", role=Role.VIEWER, is_active=False)
    plain = TestClient(client.app)
    res = _login(plain, "off@example.com", TEST_PASSWORD)
    assert res.status_code == 401
    assert res.json()["error"]["code"] == "invalid_credentials"


def test_logout_revokes_and_clears(client: Any) -> None:
    repo = _repo(client)
    create_test_user(repo, "op@example.com", role=Role.OPERATOR)
    plain = TestClient(client.app)
    login = _login(plain, "op@example.com", TEST_PASSWORD)
    csrf = login.json()["csrf_token"]
    out = plain.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf})
    assert out.status_code == 200
    assert out.json() == {"ok": True}
    # Session is dead even though the client still holds the cookie.
    me = plain.get("/api/v1/auth/me")
    assert me.status_code == 401
    # Idempotent: logging out again still clears and succeeds.
    again = plain.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf})
    assert again.status_code == 200


def test_me_requires_valid_session(client: Any) -> None:
    plain = TestClient(client.app)
    assert plain.get("/api/v1/auth/me").status_code == 401


def test_csrf_rotation_and_enforcement(client: Any) -> None:
    repo = _repo(client)
    create_test_user(repo, "op@example.com", role=Role.OPERATOR)
    plain = TestClient(client.app)
    csrf = _login(plain, "op@example.com", TEST_PASSWORD).json()["csrf_token"]
    rotated = plain.post("/api/v1/auth/csrf", headers={"X-CSRF-Token": csrf})
    assert rotated.status_code == 200
    fresh = rotated.json()["csrf_token"]
    assert fresh and fresh != csrf
    # Old CSRF no longer accepted on a protected mutation.
    bad = plain.post(
        "/api/v1/auth/change-password",
        headers={"X-CSRF-Token": csrf},
        json={"current_password": TEST_PASSWORD, "new_password": TEST_PASSWORD + "X"},
    )
    assert bad.status_code == 403
    # Missing CSRF is rejected too.
    missing = plain.post(
        "/api/v1/auth/change-password",
        json={"current_password": TEST_PASSWORD, "new_password": TEST_PASSWORD + "X"},
    )
    assert missing.status_code == 403


def test_change_password_flow(client: Any) -> None:
    from backend.app.auth.sessions import digest_token as _digest
    from backend.app.auth.sessions import generate_token as _token

    repo = _repo(client)
    user, _ = create_test_user(repo, "op@example.com", role=Role.OPERATOR)
    plain = TestClient(client.app)
    csrf = _login(plain, "op@example.com", TEST_PASSWORD).json()["csrf_token"]
    headers = {"X-CSRF-Token": csrf}
    wrong = plain.post(
        "/api/v1/auth/change-password",
        headers=headers,
        json={"current_password": "wrong-password-value", "new_password": "New-Valid-Password-9-Zulu!"},
    )
    assert wrong.status_code == 422
    weak = plain.post(
        "/api/v1/auth/change-password",
        headers=headers,
        json={"current_password": TEST_PASSWORD, "new_password": "short"},
    )
    assert weak.status_code == 422
    ok = plain.post(
        "/api/v1/auth/change-password",
        headers=headers,
        json={"current_password": TEST_PASSWORD, "new_password": "New-Valid-Password-9-Zulu!"},
    )
    assert ok.status_code == 200, ok.text
    # Old password is dead; new password works; current session survives.
    stale = TestClient(client.app)
    assert _login(stale, "op@example.com", TEST_PASSWORD).status_code == 401
    assert plain.get("/api/v1/auth/me").status_code == 200
    # Password change invalidates *other* sessions: mint one directly
    # (no login, so no rotation noise) and confirm it dies at change.
    from datetime import timedelta as _delta

    csrf2 = _login(plain, "op@example.com", "New-Valid-Password-9-Zulu!").json()["csrf_token"]
    other2_raw = _token()
    repo.create_session(
        user_id=user.id,
        token_digest=_digest(other2_raw),
        csrf_digest=_digest(_token()),
        created_at=datetime.now(UTC),
        authenticated_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + _delta(hours=12),
    )
    other2 = TestClient(client.app)
    other2.cookies.set("ivp_session", other2_raw, domain="", path="/")
    assert other2.get("/api/v1/auth/me").status_code == 200
    again = plain.post(
        "/api/v1/auth/change-password",
        headers={"X-CSRF-Token": csrf2},
        json={
            "current_password": "New-Valid-Password-9-Zulu!",
            "new_password": "Another-Valid-Password-4-Yankee!",
        },
    )
    assert again.status_code == 200, again.text
    assert other2.get("/api/v1/auth/me").status_code == 401
    assert plain.get("/api/v1/auth/me").status_code == 200
    assert repo.get_user_by_id(user.id) is not None


def test_forced_password_change_gate(client: Any) -> None:
    repo = _repo(client)
    create_test_user(repo, "new@example.com", role=Role.VIEWER, must_change_password=True)
    plain = TestClient(client.app)
    body = _login(plain, "new@example.com", TEST_PASSWORD).json()
    assert body["must_change_password"] is True
    assert plain.get("/api/v1/auth/me").status_code == 200
    blocked = plain.get("/api/v1/incidents")
    assert blocked.status_code == 403
    assert blocked.json()["error"]["code"] == "password_change_required"
    csrf = body["csrf_token"]
    changed = plain.post(
        "/api/v1/auth/change-password",
        headers={"X-CSRF-Token": csrf},
        json={"current_password": TEST_PASSWORD, "new_password": "Fresh-Valid-Password-6-Xray!"},
    )
    assert changed.status_code == 200, changed.text
    assert plain.get("/api/v1/incidents").status_code == 200


def test_account_throttle_escalates_without_lockout(client: Any) -> None:
    repo = _repo(client)
    create_test_user(repo, "op@example.com", role=Role.OPERATOR)
    plain = TestClient(client.app)
    codes = [_login(plain, "op@example.com", "wrong-password-value").status_code for _ in range(6)]
    assert codes[:5] == [401] * 5
    assert codes[5] == 429
    throttled = _login(plain, "op@example.com", "wrong-password-value")
    assert throttled.status_code == 429
    assert "Retry-After" in throttled.headers
    # Even the correct password is delayed while the throttle holds.
    assert _login(plain, "op@example.com", TEST_PASSWORD).status_code == 429


def test_no_public_registration(client: Any) -> None:
    plain = TestClient(client.app)
    for method, path in [
        ("post", "/api/v1/auth/register"),
        ("post", "/api/v1/auth/signup"),
        ("post", "/api/v1/auth/users"),
    ]:
        res = getattr(plain, method)(path, json={"email": "x@example.com", "password": TEST_PASSWORD})
        # No route (404) or auth required (401) — never a created user.
        assert res.status_code in (401, 404, 405), (method, path, res.status_code)


def test_session_expiry_enforced(client: Any) -> None:
    repo = _repo(client)
    user, _ = create_test_user(repo, "op@example.com", role=Role.OPERATOR)
    now = datetime.now(UTC)
    raw = generate_token()
    # Expired absolute lifetime.
    repo.create_session(
        user_id=user.id,
        token_digest=digest_token(raw),
        csrf_digest=digest_token(generate_token()),
        created_at=now - timedelta(hours=13),
        authenticated_at=now - timedelta(hours=13),
        expires_at=now - timedelta(hours=1),
    )
    aged = TestClient(client.app)
    aged.cookies.set("ivp_session", raw, domain="", path="/")
    assert aged.get("/api/v1/auth/me").status_code == 401
    # Idle timeout exceeded.
    raw2 = generate_token()
    repo.create_session(
        user_id=user.id,
        token_digest=digest_token(raw2),
        csrf_digest=digest_token(generate_token()),
        created_at=now - timedelta(minutes=30),
        authenticated_at=now - timedelta(minutes=30),
        expires_at=now + timedelta(hours=11),
    )
    idle = TestClient(client.app)
    idle.cookies.set("ivp_session", raw2, domain="", path="/")
    assert idle.get("/api/v1/auth/me").status_code == 401


def test_origin_policy(client: Any, test_settings: Any) -> None:
    """Disallowed cross-origin state changes are rejected (403)."""
    strict = Settings(
        app_env=AppEnv.testing,
        database_url=str(test_settings.database_url),
        cors_allowed_origins=["https://ops.example.com"],
        cors_allow_credentials=True,
        _env_file=None,  # type: ignore[call-arg]
    )
    init_db(str(strict.database_url))
    app = create_app(strict)
    repo = AuthRepository(get_session_factory(str(strict.database_url)))
    create_test_user(repo, "op@example.com", role=Role.OPERATOR, password=TEST_PASSWORD)
    evil = TestClient(app)
    denied = evil.post(
        "/api/v1/auth/login",
        headers={"origin": "https://evil.example.com"},
        json={"email": "op@example.com", "password": TEST_PASSWORD},
    )
    assert denied.status_code == 403
    allowed = evil.post(
        "/api/v1/auth/login",
        headers={"origin": "https://ops.example.com"},
        json={"email": "op@example.com", "password": TEST_PASSWORD},
    )
    assert allowed.status_code == 200, allowed.text


def test_bootstrap_cli_first_and_refuse_second(
    client: Any, tmp_path: Any, monkeypatch: Any, capsys: Any
) -> None:
    from backend.app.auth import bootstrap as bootstrap_mod

    url = f"sqlite:///{tmp_path}/boot.db"
    from backend.app.infrastructure.db import init_db as _init

    _init(url)
    settings = client.app.state.settings.model_copy(update={"database_url": url})
    monkeypatch.setattr(bootstrap_mod, "get_settings", lambda: settings)
    monkeypatch.setattr("getpass.getpass", lambda prompt="": "Bootstrap-Admin-9-Zulu-Key!")
    assert bootstrap_mod.main(["--email", "root@example.com"]) == 0
    out = capsys.readouterr().out
    assert "root@example.com" in out
    assert "Bootstrap-Admin-9-Zulu-Key!" not in out
    assert bootstrap_mod.main(["--email", "second@example.com"]) == 1
    err = capsys.readouterr().err
    assert "already exists" in err
    assert "Bootstrap-Admin-9-Zulu-Key!" not in err + out
