"""CORS behavior tests — explicit origins, safe defaults."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_wildcard_origin_allowed_by_default(client: TestClient) -> None:
    res = client.get("/health", headers={"Origin": "http://localhost:3000"})
    assert res.status_code == 200
    assert res.headers.get("access-control-allow-origin") == "*"


def test_request_id_exposed_to_browsers(client: TestClient) -> None:
    res = client.get("/health", headers={"Origin": "http://localhost:3000"})
    exposed = res.headers.get("access-control-expose-headers", "")
    assert "X-Request-ID" in exposed


def test_explicit_origins_echo(client: TestClient) -> None:
    import tempfile

    from backend.app.core.config import AppEnv, Settings
    from backend.app.infrastructure.db import init_db
    from backend.app.main import create_app

    tmp = tempfile.mkdtemp().replace("\\", "/")
    settings = Settings(
        app_env=AppEnv.testing,
        database_url=f"sqlite:///{tmp}/cors.db",
        cors_allowed_origins=["https://ops.example.com"],
        cors_allow_credentials=False,
        _env_file=None,  # type: ignore[call-arg]
    )
    init_db(settings.database_url)
    scoped = TestClient(create_app(settings))
    res = scoped.get("/health", headers={"Origin": "https://ops.example.com"})
    assert res.status_code == 200
    assert res.headers.get("access-control-allow-origin") == "https://ops.example.com"
    res = scoped.get("/health", headers={"Origin": "https://evil.example.com"})
    assert "access-control-allow-origin" not in res.headers
