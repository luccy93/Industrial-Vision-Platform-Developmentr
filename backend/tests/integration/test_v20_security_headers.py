"""V20 HTTP security headers — baseline on every response, CSP scoping."""

from __future__ import annotations

from fastapi.testclient import TestClient

_BASELINE = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "x-permitted-cross-domain-policies": "none",
}


def test_health_carries_baseline_security_headers(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    for header, expected in _BASELINE.items():
        assert response.headers.get(header) == expected
    assert "camera=()" in response.headers.get("permissions-policy", "")
    assert response.headers.get("content-security-policy") == (
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    )


def test_docs_skip_restrictive_csp(client: TestClient) -> None:
    response = client.get("/openapi.json")
    assert response.status_code == 200
    assert "content-security-policy" not in response.headers
    # Baseline headers still apply to docs.
    assert response.headers.get("x-content-type-options") == "nosniff"


def test_no_hsts_outside_production(client: TestClient) -> None:
    response = client.get("/health")
    assert "strict-transport-security" not in response.headers
