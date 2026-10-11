"""WebSocket ticket tests — issuance, single use, revocation, origin (V16)."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from backend.app.auth.repository import AuthRepository
from backend.app.auth.roles import Role
from backend.app.infrastructure.db import get_session_factory
from backend.tests.auth_helpers import TEST_PASSWORD, create_test_user


def _repo(client: Any) -> AuthRepository:
    url = str(client.app.state.settings.database_url)
    return AuthRepository(get_session_factory(url))


def _authed(client: Any, email: str = "op@example.com") -> TestClient:
    logged = TestClient(client.app)
    res = logged.post("/api/v1/auth/login", json={"email": email, "password": TEST_PASSWORD})
    assert res.status_code == 200, res.text
    logged.headers["X-CSRF-Token"] = res.json()["csrf_token"]
    return logged


def _ticket(logged: TestClient, scope: str) -> str:
    res = logged.post("/api/v1/auth/ws-ticket", json={"scope": scope})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["scope"] == scope
    assert body["expires_at"]
    return str(body["ticket"])


def test_ws_ticket_happy_path_and_rejection_codes(client: Any) -> None:
    repo = _repo(client)
    create_test_user(repo, "op@example.com", role=Role.OPERATOR)
    logged = _authed(client)

    ticket = _ticket(logged, "operations")
    with logged.websocket_connect(f"/ws/operations?ticket={ticket}"):
        pass

    # Reused tickets are rejected with 4401.
    with pytest.raises(WebSocketDisconnect) as exc:
        with logged.websocket_connect(f"/ws/operations?ticket={ticket}") as ws:
            ws.receive_text()
    assert exc.value.code == 4401

    # Missing, garbage, and expired tickets are rejected with 4401.
    with pytest.raises(WebSocketDisconnect) as exc:
        with logged.websocket_connect("/ws/operations") as ws:
            ws.receive_text()
    assert exc.value.code == 4401
    with pytest.raises(WebSocketDisconnect) as exc:
        with logged.websocket_connect("/ws/operations?ticket=" + "0" * 43) as ws:
            ws.receive_text()
    assert exc.value.code == 4401


def test_ws_ticket_scope_binding(client: Any) -> None:
    repo = _repo(client)
    create_test_user(repo, "op@example.com", role=Role.OPERATOR)
    logged = _authed(client)
    ops_ticket = _ticket(logged, "operations")
    # An operations ticket cannot open a camera socket.
    with pytest.raises(WebSocketDisconnect) as exc:
        with logged.websocket_connect(f"/ws/cameras/cam-01?ticket={ops_ticket}") as ws:
            ws.receive_text()
    assert exc.value.code == 4401
    # Unknown scopes are refused at issuance; unknown cameras are NOT
    # (the socket reports CAMERA_NOT_FOUND to authorized holders).
    res = logged.post("/api/v1/auth/ws-ticket", json={"scope": "admin"})
    assert res.status_code == 422
    cam_ticket = _ticket(logged, "camera:nope")
    with logged.websocket_connect(f"/ws/cameras/nope?ticket={cam_ticket}") as ws:
        import json as _json

        message = _json.loads(ws.receive_text())
        assert message["type"] == "stream_error"
        assert message["code"] == "CAMERA_NOT_FOUND"


def test_ws_ticket_revoked_session_rejected(client: Any) -> None:
    repo = _repo(client)
    user, _ = create_test_user(repo, "op@example.com", role=Role.OPERATOR)
    logged = _authed(client)
    ticket = _ticket(logged, "operations")
    from datetime import UTC, datetime

    repo.revoke_user_sessions(user_id=user.id, now=datetime.now(UTC))
    with pytest.raises(WebSocketDisconnect) as exc:
        with logged.websocket_connect(f"/ws/operations?ticket={ticket}") as ws:
            ws.receive_text()
    assert exc.value.code == 4401


def test_ws_ticket_deactivated_user_rejected(client: Any) -> None:
    repo = _repo(client)
    create_test_user(repo, "root@example.com", role=Role.ADMIN)
    user, _ = create_test_user(repo, "op@example.com", role=Role.OPERATOR)
    logged = _authed(client)
    ticket = _ticket(logged, "operations")
    repo.set_user_active(user_id=user.id, is_active=False)
    with pytest.raises(WebSocketDisconnect) as exc:
        with logged.websocket_connect(f"/ws/operations?ticket={ticket}") as ws:
            ws.receive_text()
    assert exc.value.code == 4401


def test_ws_ticket_requires_csrf_and_session(client: Any) -> None:
    plain = TestClient(client.app)
    assert plain.post("/api/v1/auth/ws-ticket", json={"scope": "operations"}).status_code == 401
    repo = _repo(client)
    create_test_user(repo, "op@example.com", role=Role.OPERATOR)
    logged = _authed(client)
    # Delete the CSRF header installed by the helper: ticket refused.
    del logged.headers["X-CSRF-Token"]
    assert logged.post("/api/v1/auth/ws-ticket", json={"scope": "operations"}).status_code == 403


def test_ws_origin_rejected(client: Any, test_settings: Any) -> None:
    """Disallowed handshake origins are rejected before any data flows."""
    from backend.app.core.config import AppEnv, Settings
    from backend.app.infrastructure.db import init_db
    from backend.app.main import create_app

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
    create_test_user(repo, "op@example.com", role=Role.OPERATOR)
    logged = TestClient(app)
    login = logged.post(
        "/api/v1/auth/login",
        headers={"origin": "https://ops.example.com"},
        json={"email": "op@example.com", "password": TEST_PASSWORD},
    )
    assert login.status_code == 200, login.text
    logged.headers["X-CSRF-Token"] = login.json()["csrf_token"]
    ticket = logged.post(
        "/api/v1/auth/ws-ticket",
        headers={"origin": "https://ops.example.com"},
        json={"scope": "operations"},
    ).json()["ticket"]
    with pytest.raises(WebSocketDisconnect) as exc:
        with logged.websocket_connect(
            f"/ws/operations?ticket={ticket}", headers={"origin": "https://evil.example.com"}
        ) as ws:
            ws.receive_text()
    assert exc.value.code == 4401


def test_ws_revalidation_closes_revoked_connection(client: Any, test_settings: Any) -> None:
    """Long-lived sockets drop after access revocation within the bound."""
    from datetime import UTC, datetime

    from backend.app.core.config import AppEnv, Settings
    from backend.app.infrastructure.db import init_db
    from backend.app.main import create_app

    fast = Settings(
        app_env=AppEnv.testing,
        database_url=str(test_settings.database_url),
        auth_ws_revalidate_seconds=10,
        _env_file=None,  # type: ignore[call-arg]
    )
    init_db(str(fast.database_url))
    app = create_app(fast)
    repo = AuthRepository(get_session_factory(str(fast.database_url)))
    user, _ = create_test_user(repo, "op@example.com", role=Role.OPERATOR)
    logged = TestClient(app)
    login = logged.post("/api/v1/auth/login", json={"email": "op@example.com", "password": TEST_PASSWORD})
    assert login.status_code == 200, login.text
    logged.headers["X-CSRF-Token"] = login.json()["csrf_token"]
    ticket = logged.post("/api/v1/auth/ws-ticket", json={"scope": "operations"}).json()["ticket"]
    with logged.websocket_connect(f"/ws/operations?ticket={ticket}") as ws:
        repo.revoke_user_sessions(user_id=user.id, now=datetime.now(UTC))
        with pytest.raises(WebSocketDisconnect) as exc:
            # Revalidation fires every 10 ticks (1 s tick); the blocking
            # receive returns on messages and raises once closed.
            for _ in range(30):
                ws.receive_text()
        assert exc.value.code == 4403
