"""Authenticated test client (V16).

``AuthTestClient`` behaves exactly like ``TestClient`` except
``websocket_connect`` transparently attaches a fresh single-use ticket
for the fixture identity — existing WS tests keep their assertions
about envelopes/queues/dedup without one edit per call site.

Negative auth cases (missing/invalid/expired/reused tickets) use a
plain ``TestClient`` directly. Auth coverage itself lives in the
dedicated V16 security tests plus the route-inventory regression test.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fastapi.testclient import TestClient


def _scope_for_ws_url(url: str) -> str:
    path = urlsplit(url).path
    if path.rstrip("/").endswith("/ws/operations"):
        return "operations"
    marker = "/ws/cameras/"
    if marker in path:
        camera_id = path.split(marker, 1)[1].split("/", 1)[0].split("?", 1)[0]
        return f"camera:{camera_id}"
    raise RuntimeError(f"AuthTestClient cannot derive a ticket scope for {url!r}")


class AuthTestClient(TestClient):
    """TestClient that upgrades WS connects with a one-time ticket."""

    def websocket_connect(  # type: ignore[no-untyped-def]
        self, url: str, *args: Any, **kwargs: Any
    ):
        scope = _scope_for_ws_url(url)
        issued = self.post("/api/v1/auth/ws-ticket", json={"scope": scope})
        if issued.status_code != 200:
            raise RuntimeError(
                f"AuthTestClient ticket issuance failed ({issued.status_code}): {issued.text}"
            )
        ticket = str(issued.json().get("ticket", ""))
        if not ticket:
            raise RuntimeError("AuthTestClient ticket issuance returned no ticket.")
        parts = urlsplit(url)
        query = dict(parse_qsl(parts.query))
        query["ticket"] = ticket
        authed = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))
        return super().websocket_connect(authed, *args, **kwargs)
