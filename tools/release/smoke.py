"""Post-deployment smoke checks for a digest-pinned release (V23).

The smoke tool is deliberately independent of the release workflow. It talks to
a running deployment over HTTP and WebSocket and reports PASS, FAIL, NOT_RUN, or
UNAVAILABLE. Missing credentials are reported as NOT_RUN, never as success; an
unauthenticated WebSocket that stays open is a hard failure.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from tools.release.manifest import (
    ManifestError,
    load_manifest,
    manifest_errors,
    sha256_file,
    utc_now_iso,
)
from tools.release.verification import FAIL, NOT_RUN, PASS, UNAVAILABLE

SMOKE_SCHEMA_VERSION = 1
API_HEADER_RULES = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
}
WEB_HEADER_RULES = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "x-permitted-cross-domain-policies": "none",
}
CSRF_HEADER = "X-CSRF-Token"
SESSION_COOKIE = "ivp_session"
UNAUTHORIZED_WS_CODE = 4401


class SmokeError(RuntimeError):
    """The smoke run could not be configured."""


def _check(name: str, state: str, required: bool, detail: str, command: str | None = None) -> dict[str, Any]:
    return {
        "name": name,
        "state": state,
        "required": required,
        "detail": detail,
        "command": command,
    }


def _aggregate(checks: list[Mapping[str, Any]]) -> str:
    states = {check.get("state") for check in checks}
    required = {check.get("state") for check in checks if check.get("required") is True}
    if FAIL in states:
        return FAIL
    if UNAVAILABLE in required:
        return UNAVAILABLE
    if NOT_RUN in required:
        return NOT_RUN
    return PASS


def _api_url(base: str, path: str) -> str:
    return base.rstrip("/") + path


def _subject(manifest: Mapping[str, Any]) -> dict[str, Any]:
    release = manifest.get("release")
    if not isinstance(release, Mapping):
        return {"tag": None, "commit": None, "source_repository": None}
    return {
        "tag": release.get("tag"),
        "commit": release.get("commit"),
        "source_repository": release.get("source_repository"),
    }


def _websocket_base(api_url: str, explicit: str | None) -> str:
    if explicit:
        return explicit.rstrip("/")
    parts = urlsplit(api_url)
    scheme = "wss" if parts.scheme == "https" else "ws"
    return urlunsplit((scheme, parts.netloc, parts.path.rstrip("/"), "", ""))


def _default_ws_connect(url: str, timeout: float) -> Any:
    try:
        from websockets.sync.client import connect
    except ImportError as exc:  # pragma: no cover - depends on the host install
        raise SmokeError(
            "the websockets package is required for WebSocket smoke checks; "
            "install backend/requirements-dev.txt"
        ) from exc
    return connect(url, open_timeout=timeout, close_timeout=timeout)


def _json_body(response: httpx.Response) -> Any:
    try:
        return response.json()
    except (ValueError, json.JSONDecodeError):
        return None


def _headers_check(
    name: str,
    response: httpx.Response,
    rules: Mapping[str, str],
    *,
    required: bool,
    csp_marker: str | None = None,
    forbid_header: str | None = None,
) -> dict[str, Any]:
    problems: list[str] = []
    headers = {key.lower(): value for key, value in response.headers.items()}
    for header, expected in rules.items():
        observed = headers.get(header)
        if observed is None:
            problems.append(f"missing {header}")
        elif expected and observed != expected:
            problems.append(f"{header} is {observed!r}, expected {expected!r}")
    if csp_marker is not None:
        csp = headers.get("content-security-policy") or headers.get("content-security-policy-report-only")
        if csp is None:
            problems.append("missing Content-Security-Policy")
        elif csp_marker not in csp:
            problems.append(f"Content-Security-Policy does not contain {csp_marker!r}")
    if forbid_header is not None and forbid_header.lower() in headers:
        problems.append(f"{forbid_header} must not be exposed")
    if problems:
        return _check(name, FAIL, required, "; ".join(problems))
    return _check(name, PASS, required, "security headers are present and correct")


def _login(
    client: httpx.Client,
    api_url: str,
    *,
    email: str,
    password: str,
) -> httpx.Response:
    return client.post(_api_url(api_url, "/api/v1/auth/login"), json={"email": email, "password": password})


def _invalid_auth_check(client: httpx.Client, api_url: str) -> dict[str, Any]:
    email = f"smoke-invalid-{uuid.uuid4().hex}@example.invalid"
    password = f"invalid-{uuid.uuid4().hex}"
    try:
        response = _login(client, api_url, email=email, password=password)
    except httpx.HTTPError as exc:
        return _check("auth-invalid-credentials", FAIL, True, f"login request failed: {exc}")
    if response.status_code == 429:
        return _check(
            "auth-invalid-credentials",
            FAIL,
            True,
            "login was throttled before invalid-credential rejection could be verified",
        )
    if response.status_code != 401:
        return _check(
            "auth-invalid-credentials",
            FAIL,
            True,
            f"invalid credentials returned HTTP {response.status_code}, expected 401",
        )
    payload = _json_body(response)
    detail = payload.get("detail") if isinstance(payload, Mapping) else None
    code = detail.get("code") if isinstance(detail, Mapping) else None
    if code != "invalid_credentials":
        return _check(
            "auth-invalid-credentials",
            FAIL,
            True,
            f"invalid login did not return the generic invalid_credentials code (got {code!r})",
        )
    cookies = {cookie.name for cookie in client.cookies.jar}
    if SESSION_COOKIE in cookies:
        return _check(
            "auth-invalid-credentials",
            FAIL,
            True,
            "invalid credentials created a session cookie",
        )
    return _check(
        "auth-invalid-credentials",
        PASS,
        True,
        "invalid credentials are rejected with the generic error and no session",
    )


def _positive_auth_check(
    client: httpx.Client,
    api_url: str,
    *,
    username: str,
    password: str,
) -> tuple[dict[str, Any], str | None]:
    try:
        response = _login(client, api_url, email=username, password=password)
    except httpx.HTTPError as exc:
        return _check("auth-login", FAIL, True, f"login request failed: {exc}"), None
    if response.status_code != 200:
        return (
            _check(
                "auth-login",
                FAIL,
                True,
                f"valid credentials returned HTTP {response.status_code}, expected 200",
            ),
            None,
        )
    payload = _json_body(response)
    if not isinstance(payload, Mapping):
        return _check("auth-login", FAIL, True, "login response is not a JSON object"), None
    user = payload.get("user")
    csrf = payload.get("csrf_token")
    if not isinstance(user, Mapping) or not isinstance(csrf, str) or not csrf:
        return _check("auth-login", FAIL, True, "login response is missing user or csrf_token"), None
    cookies = {cookie.name for cookie in client.cookies.jar}
    if SESSION_COOKIE not in cookies:
        return _check("auth-login", FAIL, True, "login did not set the session cookie"), None
    try:
        me = client.get(_api_url(api_url, "/api/v1/auth/me"))
    except httpx.HTTPError as exc:
        return _check("auth-login", FAIL, True, f"authenticated /me request failed: {exc}"), None
    if me.status_code != 200:
        return (
            _check("auth-login", FAIL, True, f"authenticated /me returned HTTP {me.status_code}"),
            None,
        )
    me_payload = _json_body(me)
    me_user = me_payload.get("user") if isinstance(me_payload, Mapping) else None
    if not isinstance(me_user, Mapping) or me_user.get("email") != user.get("email"):
        return _check("auth-login", FAIL, True, "authenticated /me did not return the login user"), None
    return (
        _check("auth-login", PASS, True, "valid credentials create a session and authenticate /me"),
        csrf,
    )


def _ticket(
    client: httpx.Client,
    api_url: str,
    *,
    csrf: str,
) -> tuple[str | None, dict[str, Any]]:
    try:
        response = client.post(
            _api_url(api_url, "/api/v1/auth/ws-ticket"),
            json={"scope": "operations"},
            headers={CSRF_HEADER: csrf},
        )
    except httpx.HTTPError as exc:
        return None, _check("ws-ticket", FAIL, True, f"ticket request failed: {exc}")
    if response.status_code != 200:
        return None, _check(
            "ws-ticket",
            FAIL,
            True,
            f"ticket request returned HTTP {response.status_code}, expected 200",
        )
    payload = _json_body(response)
    ticket = payload.get("ticket") if isinstance(payload, Mapping) else None
    if not isinstance(ticket, str) or not ticket:
        return None, _check("ws-ticket", FAIL, True, "ticket response is missing a ticket")
    return ticket, _check("ws-ticket", PASS, True, "a single-use operations ticket was issued")


def _ws_result(
    name: str,
    *,
    expect_close_code: int | None,
    url: str,
    ws_connect: Callable[[str, float], Any],
    timeout: float,
) -> dict[str, Any]:
    try:
        with ws_connect(url, timeout) as socket:
            try:
                socket.recv(timeout=timeout)
            except TimeoutError:
                if expect_close_code is not None:
                    return _check(
                        name,
                        FAIL,
                        True,
                        f"WebSocket stayed open instead of closing with code {expect_close_code}",
                    )
                return _check(name, PASS, True, "authenticated WebSocket remained open")
            except Exception as exc:  # ConnectionClosed and transport errors
                code = getattr(exc, "code", None)
                if expect_close_code is not None and code == expect_close_code:
                    return _check(
                        name,
                        PASS,
                        True,
                        f"WebSocket was closed with the expected code {code}",
                    )
                if expect_close_code is not None:
                    return _check(
                        name,
                        FAIL,
                        True,
                        f"WebSocket closed with code {code!r}, expected {expect_close_code}",
                    )
                return _check(
                    name,
                    FAIL,
                    True,
                    f"authenticated WebSocket closed unexpectedly with code {code!r}",
                )
            else:
                if expect_close_code is not None:
                    return _check(
                        name,
                        FAIL,
                        True,
                        "unauthenticated WebSocket returned application data",
                    )
                return _check(name, PASS, True, "authenticated WebSocket returned application data")
    except SmokeError as exc:
        return _check(name, UNAVAILABLE, True, str(exc))
    except Exception as exc:
        return _check(name, FAIL, True, f"WebSocket connection failed: {exc}")


def run_smoke(
    api_url: str,
    *,
    web_url: str | None = None,
    ws_url: str | None = None,
    username: str | None = None,
    password: str | None = None,
    timeout: float = 10.0,
    verify_tls: bool = True,
    manifest_path: Path | None = None,
    expected_tag: str | None = None,
    expected_commit: str | None = None,
    transport: httpx.BaseTransport | None = None,
    ws_connect: Callable[[str, float], Any] | None = None,
    now: Callable[[], str] = utc_now_iso,
) -> dict[str, Any]:
    if not api_url.strip():
        raise SmokeError("api_url is required")
    if username is not None and password is None:
        raise SmokeError("a password is required when a smoke username is supplied")
    manifest_sha: str | None = None
    subject: dict[str, Any] | None = None
    if manifest_path is not None:
        try:
            manifest = load_manifest(manifest_path)
        except ManifestError as exc:
            raise SmokeError(str(exc)) from exc
        errors = manifest_errors(
            manifest,
            expected_tag=expected_tag,
            expected_commit=expected_commit,
        )
        if errors:
            raise SmokeError("manifest is invalid:\n- " + "\n- ".join(errors))
        try:
            manifest_sha = sha256_file(manifest_path)
        except OSError as exc:
            raise SmokeError(f"could not hash manifest {manifest_path}: {exc}") from exc
        subject = _subject(manifest)
    checks: list[dict[str, Any]] = []
    client = httpx.Client(
        timeout=timeout,
        verify=verify_tls,
        transport=transport,
        follow_redirects=False,
    )
    try:
        try:
            live = client.get(_api_url(api_url, "/live"))
        except httpx.HTTPError as exc:
            live = None
            checks.append(_check("api-live", FAIL, True, f"GET /live failed: {exc}"))
        if live is not None:
            if live.status_code != 200:
                checks.append(_check("api-live", FAIL, True, f"GET /live returned HTTP {live.status_code}"))
            else:
                payload = _json_body(live)
                if not isinstance(payload, Mapping) or payload.get("status") != "ok":
                    checks.append(_check("api-live", FAIL, True, "GET /live did not return status=ok"))
                else:
                    checks.append(_check("api-live", PASS, True, "GET /live reports the process is alive"))
            checks.append(
                _headers_check(
                    "api-headers",
                    live,
                    API_HEADER_RULES,
                    required=True,
                    csp_marker="default-src 'none'",
                )
            )

        try:
            ready = client.get(_api_url(api_url, "/ready"))
        except httpx.HTTPError as exc:
            checks.append(_check("api-ready", FAIL, True, f"GET /ready failed: {exc}"))
        else:
            payload = _json_body(ready)
            if ready.status_code != 200:
                failing = (
                    payload.get("readiness", {}).get("failing")
                    if isinstance(payload, Mapping) and isinstance(payload.get("readiness"), Mapping)
                    else None
                )
                checks.append(
                    _check(
                        "api-ready",
                        FAIL,
                        True,
                        f"GET /ready returned HTTP {ready.status_code}; failing checks: {failing}",
                    )
                )
            elif not isinstance(payload, Mapping) or payload.get("ready") is not True:
                checks.append(_check("api-ready", FAIL, True, "GET /ready did not report ready=true"))
            else:
                checks.append(_check("api-ready", PASS, True, "GET /ready reports the deployment is ready"))

        checks.append(_invalid_auth_check(client, api_url))
        csrf: str | None = None
        if username is not None and password is not None:
            login_check, csrf = _positive_auth_check(client, api_url, username=username, password=password)
            checks.append(login_check)
        else:
            checks.append(
                _check(
                    "auth-login",
                    NOT_RUN,
                    True,
                    "no smoke username/password supplied; positive authentication was not tested",
                )
            )

        ws_connect = ws_connect or _default_ws_connect
        ws_base = _websocket_base(api_url, ws_url)
        checks.append(
            _ws_result(
                "ws-unauthorized",
                expect_close_code=UNAUTHORIZED_WS_CODE,
                url=f"{ws_base}/ws/operations",
                ws_connect=ws_connect,
                timeout=timeout,
            )
        )

        if csrf is not None:
            ticket, ticket_check = _ticket(client, api_url, csrf=csrf)
            checks.append(ticket_check)
            if ticket is not None:
                checks.append(
                    _ws_result(
                        "ws-authenticated",
                        expect_close_code=None,
                        url=f"{ws_base}/ws/operations?ticket={ticket}",
                        ws_connect=ws_connect,
                        timeout=timeout,
                    )
                )
            else:
                checks.append(
                    _check(
                        "ws-authenticated",
                        NOT_RUN,
                        True,
                        "no ticket was issued; authenticated WebSocket was not tested",
                    )
                )
        else:
            checks.append(
                _check(
                    "ws-authenticated",
                    NOT_RUN,
                    True,
                    "no authenticated session; authenticated WebSocket was not tested",
                )
            )

        if web_url:
            try:
                web = client.get(web_url)
            except httpx.HTTPError as exc:
                checks.append(_check("web-headers", FAIL, True, f"GET web root failed: {exc}"))
            else:
                if web.status_code != 200:
                    checks.append(
                        _check("web-headers", FAIL, True, f"GET web root returned HTTP {web.status_code}")
                    )
                else:
                    checks.append(
                        _headers_check(
                            "web-headers",
                            web,
                            WEB_HEADER_RULES,
                            required=True,
                            csp_marker="frame-ancestors 'none'",
                            forbid_header="x-powered-by",
                        )
                    )
        else:
            checks.append(
                _check(
                    "web-headers",
                    NOT_RUN,
                    True,
                    "no web URL supplied; frontend security headers were not tested",
                )
            )
    finally:
        client.close()

    overall = _aggregate(checks)
    verified = overall == PASS and all(
        check.get("state") == PASS for check in checks if check.get("required") is True
    )
    limitations = [
        f"{check['name']}: {check['state']} - {check['detail']}"
        for check in checks
        if check.get("state") != PASS
    ]
    return {
        "schema_version": SMOKE_SCHEMA_VERSION,
        "generated_at": now(),
        "manifest_sha256": manifest_sha,
        "subject": subject,
        "targets": {"api": api_url, "web": web_url, "websocket": ws_base},
        "overall_state": overall,
        "verified": verified,
        "checks": checks,
        "limitations": limitations,
    }


def write_smoke_report(report: Mapping[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def render_smoke_summary(report: Mapping[str, Any]) -> str:
    lines = [
        f"Deployment smoke: {report.get('overall_state')} (verified={report.get('verified')})",
    ]
    for check in report.get("checks") or []:
        required = "required" if check.get("required") else "informational"
        lines.append(f"- {check.get('name')}: {check.get('state')} ({required}) - {check.get('detail')}")
    limitations = report.get("limitations") or []
    if limitations:
        lines.append("Limitations:")
        lines.extend(f"- {item}" for item in limitations)
    return "\n".join(lines) + "\n"
