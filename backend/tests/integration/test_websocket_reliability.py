"""WebSocket reliability tests (V19).

Complements ``test_ws_manager.py`` (unit-level backpressure/priority) and
``test_auth_ws.py`` (ticket auth) with integration-level lifecycle checks:
authorized clients connect and disconnect cleanly and the manager's tracked
connection count returns to baseline (no leaked connections).

The shared ``client`` fixture is an ``AuthTestClient`` that transparently
attaches a fresh single-use ticket, so negative auth cases use a plain
``TestClient`` over the same app instance.
"""

from __future__ import annotations

import time
from typing import Any

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect


def _ticket(client: Any, scope: str = "operations") -> str:
    res = client.post("/api/v1/auth/ws-ticket", json={"scope": scope})
    assert res.status_code == 200, res.text
    return str(res.json()["ticket"])


def _active(client: Any) -> int:
    return int(client.app.state.ws_manager.metrics()["active_connections"])


def _wait_active(client: Any, expected: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _active(client) == expected:
            return True
        time.sleep(0.05)
    return _active(client) == expected


def test_operations_ws_rejects_without_ticket_and_leaves_no_connection(client: Any) -> None:
    baseline = _active(client)
    plain = TestClient(client.app)
    with pytest.raises(WebSocketDisconnect) as exc:
        with plain.websocket_connect("/ws/operations") as ws:
            ws.receive_text()
    assert exc.value.code == 4401
    # A rejected socket must never be tracked.
    assert _active(client) == baseline


def test_operations_ws_multiclient_lifecycle_and_cleanup(client: Any) -> None:
    assert _active(client) == 0
    with (
        client.websocket_connect("/ws/operations"),
        client.websocket_connect("/ws/operations"),
        client.websocket_connect("/ws/operations"),
    ):
        assert _wait_active(client, 3)
    # Exiting the contexts disconnects every socket: no leaks.
    assert _wait_active(client, 0)


def test_operations_ws_ticket_is_single_use(client: Any) -> None:
    plain = TestClient(client.app)
    ticket = _ticket(client)
    with plain.websocket_connect(f"/ws/operations?ticket={ticket}"):
        pass
    with pytest.raises(WebSocketDisconnect) as exc:
        with plain.websocket_connect(f"/ws/operations?ticket={ticket}") as ws:
            ws.receive_text()
    assert exc.value.code == 4401
    assert _wait_active(client, 0)
