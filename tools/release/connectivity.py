"""Bounded, read-only connectivity probes for V28 readiness.

Every probe has an explicit timeout, validates certificates and hostnames, and
only contacts hostnames that the caller has already authorized. Nothing in this
module scans ports, follows redirects, mutates remote state, or stores response
bodies, cookies, or credentials.
"""

from __future__ import annotations

import socket
import ssl
import threading
import time
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from tools.release.verification import FAIL, PASS, UNAVAILABLE

CONNECTIVITY_SCHEMA_VERSION = 1
DEFAULT_CONNECTIVITY_TIMEOUT = 10.0
MIN_CONNECTIVITY_TIMEOUT = 1.0
MAX_CONNECTIVITY_TIMEOUT = 60.0
CERTIFICATE_MIN_VALIDITY_DAYS = 14
MAX_HTTP_BODY_BYTES = 2 * 1024 * 1024
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
SERVICE_NAME = "industrial-vision-platform"
WEB_IDENTITY_MARKER = "industrial ai vision platform"
UNAUTHORIZED_WS_CODES = frozenset({4401, 4403})


class ConnectivityError(RuntimeError):
    """A connectivity probe is misconfigured or cannot be executed."""


def _check(
    name: str,
    state: str,
    required: bool,
    detail: str,
    *,
    command: str | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "category": "connectivity",
        "state": state,
        "required": required,
        "mode": "live-read-only",
        "detail": detail,
        "command": command,
    }


def _bounded_call(function: Callable[[], Any], timeout: float, label: str) -> Any:
    """Run *function* in a daemon thread and fail closed after *timeout*."""
    result: dict[str, Any] = {}

    def run() -> None:
        try:
            result["value"] = function()
        except Exception as exc:  # noqa: BLE001 - the error is re-raised in the caller
            result["error"] = exc

    thread = threading.Thread(target=run, name=f"v28-{label}", daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        raise TimeoutError(f"{label} exceeded the {timeout:g}s timeout")
    error = result.get("error")
    if error is not None:
        raise error
    return result.get("value")


def validate_timeout(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConnectivityError("connectivity timeout must be a number")
    timeout = float(value)
    if not MIN_CONNECTIVITY_TIMEOUT <= timeout <= MAX_CONNECTIVITY_TIMEOUT:
        raise ConnectivityError(
            f"connectivity timeout must be between {MIN_CONNECTIVITY_TIMEOUT:g} "
            f"and {MAX_CONNECTIVITY_TIMEOUT:g} seconds"
        )
    return timeout


def target_hosts(target: Mapping[str, Any]) -> list[tuple[str, int]]:
    """Return the exact host/port pairs named by the target URLs."""
    pairs: set[tuple[str, int]] = set()
    for field in ("api_url", "web_url", "ws_url"):
        value = target.get(field)
        if not isinstance(value, str):
            raise ConnectivityError(f"target {field} is missing")
        parts = urlsplit(value)
        host = parts.hostname
        if not host:
            raise ConnectivityError(f"target {field} has no hostname")
        port = parts.port or 443
        pairs.add((host.lower(), port))
    return sorted(pairs)


def resolve_hostname(
    host: str,
    port: int = 443,
    *,
    timeout: float = DEFAULT_CONNECTIVITY_TIMEOUT,
) -> list[str]:
    timeout = validate_timeout(timeout)

    def resolve() -> list[str]:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        return sorted({str(info[4][0]) for info in infos})

    return list(_bounded_call(resolve, timeout, f"dns-{host}"))


def tcp_connect(host: str, port: int, *, timeout: float = DEFAULT_CONNECTIVITY_TIMEOUT) -> None:
    timeout = validate_timeout(timeout)

    def connect() -> None:
        with socket.create_connection((host, port), timeout=timeout):
            return None

    _bounded_call(connect, timeout, f"tcp-{host}-{port}")


def tls_certificate(
    host: str,
    port: int = 443,
    *,
    timeout: float = DEFAULT_CONNECTIVITY_TIMEOUT,
) -> dict[str, Any]:
    """Perform a verified TLS handshake and return certificate metadata only."""
    timeout = validate_timeout(timeout)
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    def probe() -> dict[str, Any]:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
                if not isinstance(cert, dict):
                    raise ConnectivityError("the server returned no peer certificate")
                return dict(cert)

    return dict(_bounded_call(probe, timeout, f"tls-{host}-{port}"))


def certificate_days_remaining(cert: Mapping[str, Any], *, now_epoch: float | None = None) -> float | None:
    not_after = cert.get("notAfter")
    if not isinstance(not_after, str):
        return None
    try:
        expires = ssl.cert_time_to_seconds(not_after)
    except ValueError:
        return None
    current = time.time() if now_epoch is None else now_epoch
    return (expires - current) / 86400.0


class HttpResponse:
    """A deliberately small response record with no cookies or body storage."""

    def __init__(
        self,
        status: int,
        headers: Mapping[str, str],
        text: str,
        payload: Any,
    ) -> None:
        self.status = status
        self.headers = {str(key).lower(): str(value) for key, value in headers.items()}
        self.text = text
        self.payload = payload

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


def http_get(
    url: str,
    *,
    timeout: float = DEFAULT_CONNECTIVITY_TIMEOUT,
    headers: Mapping[str, str] | None = None,
) -> HttpResponse:
    timeout = validate_timeout(timeout)
    request_headers = {
        "Accept": "application/json, text/html;q=0.9",
        "User-Agent": "industrial-vision-platform-v28-readiness",
    }
    request_headers.update(headers or {})

    def fetch() -> HttpResponse:
        with httpx.Client(verify=True, follow_redirects=False, timeout=timeout) as client:
            response = client.get(url, headers=request_headers)
            content = response.content
            if len(content) > MAX_HTTP_BODY_BYTES:
                raise ConnectivityError(f"response from {url} exceeded the {MAX_HTTP_BODY_BYTES} byte limit")
            try:
                payload = response.json()
            except ValueError:
                payload = None
            return HttpResponse(
                response.status_code,
                response.headers,
                response.text[:65536],
                payload,
            )

    return _bounded_call(fetch, timeout, f"http-{url}")


def _default_ws_connect(url: str, timeout: float) -> Any:
    try:
        from websockets.sync.client import connect
    except ImportError as exc:  # pragma: no cover - depends on the host install
        raise ConnectivityError(
            "the websockets package is required for WSS checks; install backend/requirements-dev.txt"
        ) from exc
    return connect(url, open_timeout=timeout, close_timeout=timeout)


def websocket_probe(
    url: str,
    *,
    timeout: float = DEFAULT_CONNECTIVITY_TIMEOUT,
    ws_connect: Callable[[str, float], Any] | None = None,
) -> tuple[str, str]:
    """Return ``(state, detail)`` for a WSS handshake.

    A server that completes the TLS/WebSocket handshake and then rejects an
    unauthenticated connection with 4401/4403 is reachable and behaves
    correctly; that is a PASS for connectivity, not an authentication test.
    """
    timeout = validate_timeout(timeout)
    connector = ws_connect or _default_ws_connect
    try:
        connection = connector(url, timeout)
    except ConnectivityError as exc:
        return UNAVAILABLE, str(exc)
    except Exception as exc:  # noqa: BLE001 - websockets exposes several exception types
        code = getattr(exc, "code", None)
        if code in UNAUTHORIZED_WS_CODES:
            return PASS, f"WSS handshake succeeded and unauthenticated access was rejected with {code}"
        return FAIL, f"WSS handshake failed: {type(exc).__name__}"
    try:
        connection.close()
    except Exception:  # noqa: BLE001 - closing is best effort
        pass
    return PASS, "WSS handshake succeeded"


def _api_url(base: str, path: str) -> str:
    return base.rstrip("/") + path


def _websocket_url(base: str) -> str:
    parts = urlsplit(base)
    path = parts.path.rstrip("/")
    if not path.endswith("/ws/operations"):
        path = f"{path}/ws/operations" if path else "/ws/operations"
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def _json_status(response: HttpResponse) -> str | None:
    payload = response.payload
    if not isinstance(payload, Mapping):
        return None
    status = payload.get("status")
    return str(status) if isinstance(status, str) else None


def _headers_problems(response: HttpResponse, rules: Mapping[str, str], *, web: bool) -> list[str]:
    problems: list[str] = []
    for header, expected in rules.items():
        observed = response.header(header)
        if observed is None:
            problems.append(f"missing {header}")
        elif observed != expected:
            problems.append(f"{header} is {observed!r}, expected {expected!r}")
    if response.header("strict-transport-security") is None:
        problems.append("missing Strict-Transport-Security")
    csp = response.header("content-security-policy") or response.header("content-security-policy-report-only")
    if csp is None:
        problems.append("missing Content-Security-Policy")
    elif web and "frame-ancestors 'none'" not in csp:
        problems.append("Content-Security-Policy does not contain frame-ancestors 'none'")
    if response.header("x-powered-by") is not None:
        problems.append("x-powered-by must not be exposed")
    return problems


def connectivity_checks(
    target: Mapping[str, Any],
    *,
    timeout: float = DEFAULT_CONNECTIVITY_TIMEOUT,
    execute_live: bool = True,
    dns_resolve: Callable[..., list[str]] = resolve_hostname,
    tcp_probe: Callable[..., None] = tcp_connect,
    tls_probe: Callable[..., Mapping[str, Any]] = tls_certificate,
    http_probe: Callable[..., HttpResponse] = http_get,
    ws_probe: Callable[..., tuple[str, str]] = websocket_probe,
    now_epoch: Callable[[], float] = time.time,
    now_iso: Callable[[], str] | None = None,
    check_service_identity: bool = True,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Run bounded probes against the exact target URLs."""
    timeout = validate_timeout(timeout)
    pairs = target_hosts(target)
    api_url = str(target["api_url"])
    web_url = str(target["web_url"])
    ws_url = _websocket_url(str(target["ws_url"]))
    observation: dict[str, Any] = {
        "schema_version": CONNECTIVITY_SCHEMA_VERSION,
        "source": "bounded-network-probes",
        "observed_at": now_iso()
        if now_iso is not None
        else time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "timeout_seconds": timeout,
        "target": {
            "name": target.get("name"),
            "hosts": [host for host, _ in pairs],
            "ports": sorted({port for _, port in pairs}),
        },
        "dns": {},
        "tls": {},
        "http": {},
        "websocket": None,
        "limitations": [],
    }
    checks: list[dict[str, Any]] = []

    dns_problems: list[str] = []
    for host, port in pairs:
        try:
            addresses = dns_resolve(host, port, timeout=timeout)
        except Exception as exc:  # noqa: BLE001 - probe failures are evidence
            observation["dns"][host] = {"error": type(exc).__name__}
            dns_problems.append(f"{host} did not resolve ({type(exc).__name__})")
            continue
        observation["dns"][host] = {"addresses": addresses}
        if not addresses:
            dns_problems.append(f"{host} resolved to no addresses")
    checks.append(
        _check(
            "dns-resolution",
            FAIL if dns_problems else PASS,
            True,
            "; ".join(dns_problems[:8])
            if dns_problems
            else f"resolved {len(pairs)} authorized host/port pair(s)",
            command="getaddrinfo " + ", ".join(f"{host}:{port}" for host, port in pairs),
        )
    )

    tcp_problems: list[str] = []
    for host, port in pairs:
        try:
            tcp_probe(host, port, timeout=timeout)
        except Exception as exc:  # noqa: BLE001 - probe failures are evidence
            tcp_problems.append(f"{host}:{port} refused or timed out ({type(exc).__name__})")
    checks.append(
        _check(
            "tcp-connectivity",
            FAIL if tcp_problems else PASS,
            True,
            "; ".join(tcp_problems[:8])
            if tcp_problems
            else f"TCP connect succeeded for {len(pairs)} authorized host/port pair(s)",
            command="tcp connect " + ", ".join(f"{host}:{port}" for host, port in pairs),
        )
    )

    tls_problems: list[str] = []
    expiries: list[float] = []
    for host, port in pairs:
        try:
            cert = tls_probe(host, port, timeout=timeout)
        except ssl.SSLCertVerificationError as exc:
            tls_problems.append(f"{host}:{port} certificate verification failed: {exc.reason or 'invalid'}")
            observation["tls"][host] = {"error": "certificate_verification_failed"}
            continue
        except Exception as exc:  # noqa: BLE001 - probe failures are evidence
            tls_problems.append(f"{host}:{port} TLS handshake failed ({type(exc).__name__})")
            observation["tls"][host] = {"error": type(exc).__name__}
            continue
        days = certificate_days_remaining(cert, now_epoch=now_epoch())
        observation["tls"][host] = {
            "subject": cert.get("subject"),
            "issuer": cert.get("issuer"),
            "not_after": cert.get("notAfter"),
            "days_remaining": round(days, 2) if days is not None else None,
        }
        if days is None:
            tls_problems.append(f"{host}:{port} certificate has no valid notAfter value")
        elif days < CERTIFICATE_MIN_VALIDITY_DAYS:
            tls_problems.append(
                f"{host}:{port} certificate expires in {days:.1f} days "
                f"(minimum {CERTIFICATE_MIN_VALIDITY_DAYS})"
            )
        else:
            expiries.append(days)
    checks.append(
        _check(
            "tls-certificate",
            FAIL if tls_problems else PASS,
            True,
            "; ".join(tls_problems[:8])
            if tls_problems
            else f"certificates verify and hostnames match; earliest expiry in {min(expiries):.1f} days",
            command="TLS handshake " + ", ".join(f"{host}:{port}" for host, port in pairs),
        )
    )

    def get(url: str) -> HttpResponse:
        response = http_probe(url, timeout=timeout)
        observation["http"][url] = {
            "status": response.status,
            "content_type": response.header("content-type"),
            "security_headers": {
                key: response.header(key)
                for key in (
                    "strict-transport-security",
                    "x-content-type-options",
                    "x-frame-options",
                    "referrer-policy",
                    "content-security-policy",
                    "x-permitted-cross-domain-policies",
                )
            },
        }
        return response

    live_url = _api_url(api_url, "/live")
    try:
        live = get(live_url)
    except Exception as exc:  # noqa: BLE001 - probe failures are evidence
        checks.append(
            _check(
                "https-live",
                FAIL,
                True,
                f"GET /live failed ({type(exc).__name__})",
                command=f"GET {live_url}",
            )
        )
        live = None
    else:
        problems: list[str] = []
        if live.status != 200:
            problems.append(f"HTTP {live.status}")
        if _json_status(live) != "ok":
            problems.append("body did not report status=ok")
        checks.append(
            _check(
                "https-live",
                FAIL if problems else PASS,
                True,
                "; ".join(problems) if problems else "GET /live reports status=ok",
                command=f"GET {live_url}",
            )
        )

    ready_url = _api_url(api_url, "/ready")
    try:
        ready = get(ready_url)
    except Exception as exc:  # noqa: BLE001 - probe failures are evidence
        checks.append(
            _check(
                "https-ready",
                FAIL,
                True,
                f"GET /ready failed ({type(exc).__name__})",
                command=f"GET {ready_url}",
            )
        )
    else:
        problems = []
        if ready.status != 200:
            problems.append(f"HTTP {ready.status}")
        if not isinstance(ready.payload, Mapping) or ready.payload.get("ready") is not True:
            problems.append("body did not report ready=true")
        checks.append(
            _check(
                "https-ready",
                FAIL if problems else PASS,
                True,
                "; ".join(problems) if problems else "GET /ready reports ready=true",
                command=f"GET {ready_url}",
            )
        )

    health_url = _api_url(api_url, "/health")
    try:
        health = get(health_url)
    except Exception as exc:  # noqa: BLE001 - probe failures are evidence
        checks.append(
            _check(
                "https-health",
                FAIL,
                True,
                f"GET /health failed ({type(exc).__name__})",
                command=f"GET {health_url}",
            )
        )
    else:
        problems = []
        if health.status != 200:
            problems.append(f"HTTP {health.status}")
        if _json_status(health) != "ok":
            problems.append("body did not report status=ok")
        checks.append(
            _check(
                "https-health",
                FAIL if problems else PASS,
                True,
                "; ".join(problems) if problems else "GET /health reports status=ok",
                command=f"GET {health_url}",
            )
        )

    header_problems: list[str] = []
    if live is not None:
        header_problems.extend(_headers_problems(live, API_HEADER_RULES, web=False))
    else:
        header_problems.append("API security headers could not be inspected")
    try:
        web = get(web_url)
    except Exception as exc:  # noqa: BLE001 - probe failures are evidence
        header_problems.append(f"GET web root failed ({type(exc).__name__})")
        web = None
    else:
        if web.status != 200:
            header_problems.append(f"GET web root returned HTTP {web.status}")
        else:
            header_problems.extend(_headers_problems(web, WEB_HEADER_RULES, web=True))
    checks.append(
        _check(
            "https-security-headers",
            FAIL if header_problems else PASS,
            True,
            "; ".join(header_problems[:8])
            if header_problems
            else "API and web security headers are present and correct",
            command=f"GET {live_url}; GET {web_url}",
        )
    )

    state, detail = ws_probe(ws_url, timeout=timeout)
    observation["websocket"] = {"url": ws_url, "state": state, "detail": detail}
    checks.append(_check("wss-connectivity", state, True, detail, command=f"WSS {ws_url}"))

    if check_service_identity:
        identity_problems: list[str] = []
        root_url = _api_url(api_url, "/")
        try:
            root = get(root_url)
        except Exception as exc:  # noqa: BLE001 - probe failures are evidence
            identity_problems.append(f"GET API root failed ({type(exc).__name__})")
        else:
            payload = root.payload
            if root.status != 200:
                identity_problems.append(f"GET API root returned HTTP {root.status}")
            elif not isinstance(payload, Mapping) or payload.get("service") != SERVICE_NAME:
                identity_problems.append("API root did not identify the expected service")
        if web is None:
            identity_problems.append("web root could not be inspected")
        elif WEB_IDENTITY_MARKER not in web.text.lower():
            identity_problems.append("web root did not contain the expected product marker")
        checks.append(
            _check(
                "service-identity",
                FAIL if identity_problems else PASS,
                False,
                "; ".join(identity_problems[:8])
                if identity_problems
                else "API and web roots identify the expected product",
                command=f"GET {root_url}; GET {web_url}",
            )
        )

    observation["limitations"] = [
        "Connectivity proves reachability and protocol behavior only; it does not "
        "authenticate a smoke user or prove production qualification.",
        "Only host/port pairs named by the explicit target were contacted.",
    ]
    return checks, observation
