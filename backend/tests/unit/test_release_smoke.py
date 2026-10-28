"""V23 post-deployment smoke checks (HTTP, auth, WebSocket, headers)."""

from __future__ import annotations

import json
from typing import Any

import httpx

from tools.release.smoke import (
    FAIL,
    NOT_RUN,
    PASS,
    run_smoke,
)

API = "http://api.test"
WEB = "http://web.test"
USER = "smoke@example.com"
PASSWORD = "correct-horse-battery-staple"
CSRF = "csrf-token-value"


def _headers() -> dict[str, str]:
    return {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "X-Permitted-Cross-Domain-Policies": "none",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    }


def _handler(*, invalid_accepts: bool = False, web_headers: dict[str, str] | None = None) -> Any:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.url.host == "web.test":
            headers = _headers() if web_headers is None else web_headers
            return httpx.Response(200, text="<html></html>", headers=headers)
        if path == "/live":
            return httpx.Response(200, json={"status": "ok"}, headers=_headers())
        if path == "/ready":
            return httpx.Response(200, json={"ready": True, "status": "ready"}, headers=_headers())
        if path == "/api/v1/auth/login":
            body = json.loads(request.content)
            if body["email"].startswith("smoke-invalid"):
                if invalid_accepts:
                    return httpx.Response(
                        200,
                        json={"user": {"email": body["email"]}, "csrf_token": CSRF},
                        headers={"set-cookie": "ivp_session=bad; Path=/"},
                    )
                return httpx.Response(
                    401,
                    json={"detail": {"code": "invalid_credentials", "message": "Invalid email or password."}},
                    headers=_headers(),
                )
            if body["email"] == USER and body["password"] == PASSWORD:
                return httpx.Response(
                    200,
                    json={"user": {"email": USER}, "csrf_token": CSRF},
                    headers={"set-cookie": "ivp_session=good; Path=/; HttpOnly"},
                )
            return httpx.Response(401, json={"detail": {"code": "invalid_credentials"}})
        if path == "/api/v1/auth/me":
            if "ivp_session=good" in request.headers.get("cookie", ""):
                return httpx.Response(200, json={"user": {"email": USER}}, headers=_headers())
            return httpx.Response(401, json={"detail": {"code": "unauthenticated"}})
        if path == "/api/v1/auth/ws-ticket":
            if request.headers.get("x-csrf-token") != CSRF:
                return httpx.Response(403, json={"detail": {"code": "csrf"}})
            return httpx.Response(200, json={"ticket": "ticket-value", "scope": "operations"})
        return httpx.Response(404, json={"detail": "not found"})

    return handler


class _Closed(Exception):
    def __init__(self, code: int) -> None:
        super().__init__(f"closed {code}")
        self.code = code


class _Socket:
    def __init__(self, close_code: int | None = None) -> None:
        self.close_code = close_code

    def recv(self, timeout: float) -> str:
        del timeout
        if self.close_code is not None:
            raise _Closed(self.close_code)
        raise TimeoutError

    def __enter__(self) -> _Socket:
        return self

    def __exit__(self, *args: Any) -> None:
        del args


def _ws(*, unauthorized_stays_open: bool = False, authenticated_closes: bool = False) -> Any:
    def connect(url: str, timeout: float) -> _Socket:
        del timeout
        if "ticket=" in url:
            return _Socket(4403 if authenticated_closes else None)
        return _Socket(None if unauthorized_stays_open else 4401)

    return connect


def _run(**kwargs: Any) -> dict[str, Any]:
    options: dict[str, Any] = {
        "web_url": WEB,
        "username": USER,
        "password": PASSWORD,
        "transport": httpx.MockTransport(_handler()),
        "ws_connect": _ws(),
        "now": lambda: "2026-10-23T00:00:00Z",
    }
    options.update(kwargs)
    return run_smoke(API, **options)


def test_smoke_passes_with_authenticated_deployment() -> None:
    report = _run()
    assert report["overall_state"] == PASS
    assert report["verified"] is True
    checks = {check["name"]: check for check in report["checks"]}
    for name in (
        "api-live",
        "api-ready",
        "api-headers",
        "auth-invalid-credentials",
        "auth-login",
        "ws-ticket",
        "ws-unauthorized",
        "ws-authenticated",
        "web-headers",
    ):
        assert checks[name]["state"] == PASS, (name, checks[name])
    assert report["limitations"] == []


def test_missing_credentials_are_not_run_not_success() -> None:
    report = _run(username=None, password=None)
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["auth-login"]["state"] == NOT_RUN
    assert checks["auth-login"]["required"] is True
    assert checks["ws-authenticated"]["state"] == NOT_RUN
    assert report["overall_state"] == NOT_RUN
    assert report["verified"] is False


def test_invalid_credentials_being_accepted_fails() -> None:
    report = _run(transport=httpx.MockTransport(_handler(invalid_accepts=True)))
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["auth-invalid-credentials"]["state"] == FAIL
    assert report["overall_state"] == FAIL
    assert report["verified"] is False


def test_unauthorized_websocket_staying_open_fails() -> None:
    report = _run(ws_connect=_ws(unauthorized_stays_open=True))
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["ws-unauthorized"]["state"] == FAIL
    assert "stayed open" in checks["ws-unauthorized"]["detail"]
    assert report["overall_state"] == FAIL


def test_authenticated_websocket_being_forbidden_fails() -> None:
    report = _run(ws_connect=_ws(authenticated_closes=True))
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["ws-authenticated"]["state"] == FAIL
    assert report["overall_state"] == FAIL


def test_missing_web_security_header_fails() -> None:
    headers = _headers()
    del headers["X-Frame-Options"]
    report = _run(transport=httpx.MockTransport(_handler(web_headers=headers)))
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["web-headers"]["state"] == FAIL
    assert "x-frame-options" in checks["web-headers"]["detail"]


def test_missing_web_url_is_not_run_not_success() -> None:
    report = _run(web_url=None)
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["web-headers"]["state"] == NOT_RUN
    assert checks["web-headers"]["required"] is True
    assert report["overall_state"] == NOT_RUN


def test_not_ready_deployment_fails() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/ready":
            return httpx.Response(
                503,
                json={"ready": False, "readiness": {"failing": ["database"]}},
                headers=_headers(),
            )
        return _handler()(request)

    report = _run(transport=httpx.MockTransport(handler))
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["api-ready"]["state"] == FAIL
    assert "database" in checks["api-ready"]["detail"]
    assert report["overall_state"] == FAIL


def test_password_is_not_written_to_report() -> None:
    report = _run()
    assert PASSWORD not in json.dumps(report)
