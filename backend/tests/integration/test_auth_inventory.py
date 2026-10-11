"""Route security inventory — fails on unclassified endpoints (V16).

Every registered HTTP route must either be explicitly public or carry
one of the shared authorization dependencies. WebSocket routes must be
ticket-gated. Adding a business endpoint without a policy breaks this
test by design.
"""

from __future__ import annotations

from typing import Any

from fastapi.routing import APIRoute

#: Exactly these paths are intentionally public (V11 probes + root/docs +
#: the authentication-establishment login call).
PUBLIC_PATHS = frozenset(
    {
        "/",
        "/docs",
        "/openapi.json",
        "/health",
        "/live",
        "/ready",
        "/api/v1/health",
        "/api/v1/auth/login",
    }
)

#: WebSocket routes gated by single-use tickets (not Depends-based).
WS_PATHS = frozenset({"/ws/operations", "/ws/cameras/{camera_id}"})

#: Session-authenticated auth endpoints that resolve the principal
#: in-handler (cookie session + CSRF) rather than via route Depends.
#: Classified here explicitly so the inventory stays exact.
SESSION_AUTHENTICATED_PATHS = frozenset(
    {
        "/api/v1/auth/logout",
        "/api/v1/auth/me",
        "/api/v1/auth/csrf",
        "/api/v1/auth/change-password",
        "/api/v1/auth/ws-ticket",
    }
)

#: Dependency function names produced by require_capability_dep and the
#: shared singletons in auth.dependencies.
KNOWN_AUTH_DEPS = frozenset(
    {
        "_require_read",
        "_require_incident_write",
        "_require_camera_control",
        "_require_notification_mute",
        "_require_admin_config",
        "_require_user_admin",
        "_dependency",
    }
)


def _route_dep_names(route: Any) -> set[str]:
    names: set[str] = set()
    for dep in getattr(route, "dependencies", []) or []:
        call = getattr(dep, "call", None) or getattr(dep, "dependency", None)
        name = getattr(call, "__name__", "")
        if name:
            names.add(str(name))
    return names


def _iter_routes(routes: Any) -> Any:
    """Recurse through nested included routers (FastAPI nests includes)."""
    for route in routes:
        if type(route).__name__ == "_IncludedRouter":
            yield from _iter_routes(route.original_router.routes)
        else:
            yield route


def test_every_http_route_is_classified(client: Any) -> None:
    unclassified: list[str] = []
    for route in _iter_routes(client.app.routes):
        if not isinstance(route, APIRoute):
            continue
        path = str(route.path)
        methods = sorted(getattr(route, "methods", set()) or set())
        if path in PUBLIC_PATHS or path in SESSION_AUTHENTICATED_PATHS:
            continue
        if path.startswith("/docs") or path.startswith("/redoc") or path.startswith("/openapi"):
            continue
        deps = _route_dep_names(route)
        if not (deps & KNOWN_AUTH_DEPS):
            unclassified.append(f"{','.join(methods)} {path} (deps={sorted(deps)})")
    assert not unclassified, f"unclassified business routes: {unclassified}"


def test_public_paths_stay_open_and_guarded_paths_reject_anon(client: Any) -> None:
    from fastapi.testclient import TestClient

    plain = TestClient(client.app)
    assert plain.get("/live").status_code == 200
    assert plain.get("/ready").status_code in (200, 503)
    assert plain.get("/health").status_code == 200
    assert plain.get("/api/v1/health").status_code == 200
    assert plain.get("/api/v1/operations/summary").status_code == 401
    assert plain.get("/api/v1/incidents").status_code == 401
    assert plain.get("/api/v1/cameras").status_code == 401
    assert plain.get("/api/v1/analytics/summary").status_code == 401
    assert plain.get("/api/v1/alerting/status").status_code == 401
    assert plain.get("/api/v1/auth/me").status_code == 401
    assert plain.get("/api/v1/auth/users").status_code == 401


def test_websocket_routes_are_ticket_gated(client: Any) -> None:
    import pytest
    from fastapi.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect

    plain = TestClient(client.app)
    paths = {str(route.path) for route in _iter_routes(client.app.routes)}
    for expected in WS_PATHS:
        assert expected in paths, f"missing WS route: {expected}"
    with pytest.raises(WebSocketDisconnect) as exc:
        with plain.websocket_connect("/ws/operations") as ws:
            ws.receive_text()  # Surfaces the 4401 close.
    assert exc.value.code == 4401
