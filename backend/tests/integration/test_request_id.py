"""Request-ID tests — generated, supplied, bounded, retained on errors."""

from __future__ import annotations

import re

from fastapi.testclient import TestClient

from backend.app.core.request_context import REQUEST_ID_MAX_LENGTH, sanitize_request_id

HEX12 = re.compile(r"^[0-9a-f]{12}$")


def test_generated_request_id(client: TestClient) -> None:
    res = client.get("/health")
    assert res.status_code == 200
    request_id = res.headers.get("X-Request-ID", "")
    assert HEX12.match(request_id), request_id


def test_supplied_request_id_echoed(client: TestClient) -> None:
    res = client.get("/health", headers={"X-Request-ID": "ops-trace-42"})
    assert res.status_code == 200
    assert res.headers.get("X-Request-ID") == "ops-trace-42"


def test_oversized_request_id_regenerated(client: TestClient) -> None:
    res = client.get("/health", headers={"X-Request-ID": "x" * (REQUEST_ID_MAX_LENGTH + 1)})
    assert res.status_code == 200
    echoed = res.headers.get("X-Request-ID", "")
    assert echoed != "x" * (REQUEST_ID_MAX_LENGTH + 1)
    assert HEX12.match(echoed)


def test_malformed_request_id_regenerated(client: TestClient) -> None:
    res = client.get("/health", headers={"X-Request-ID": "bad\nid\x00here"})
    assert res.status_code == 200
    assert HEX12.match(res.headers.get("X-Request-ID", ""))


def test_error_response_retains_request_id(client: TestClient) -> None:
    res = client.get("/api/v1/incidents/does-not-exist", headers={"X-Request-ID": "trace-9"})
    assert res.status_code == 404
    assert res.headers.get("X-Request-ID") == "trace-9"
    body = res.json()
    assert body["error"]["request_id"] == "trace-9"


def test_error_response_generated_id_consistent(client: TestClient) -> None:
    res = client.get("/api/v1/incidents/does-not-exist")
    assert res.status_code == 404
    header_id = res.headers.get("X-Request-ID", "")
    assert res.json()["error"]["request_id"] == header_id


def test_sanitize_request_id_unit() -> None:
    assert sanitize_request_id("abc") == "abc"
    assert sanitize_request_id("  abc  ") == "abc"
    assert sanitize_request_id("") != ""
    assert sanitize_request_id(None) != ""
    assert sanitize_request_id(123) != ""
    assert sanitize_request_id("x" * 200) != "x" * 200
    assert sanitize_request_id("ok-id_1.2") == "ok-id_1.2"
