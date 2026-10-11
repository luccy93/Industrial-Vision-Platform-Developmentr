"""RBAC matrix tests — every sensitive API family (V16).

Unauthenticated → 401. Authenticated without the capability → 403.
Authorized roles succeed with valid inputs. Mass-assignment via
unsupported fields fails.
"""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from backend.app.auth.repository import AuthRepository
from backend.app.auth.roles import Role
from backend.app.infrastructure.db import get_session_factory
from backend.tests.auth_helpers import TEST_PASSWORD, create_test_user


def _repo(client: Any) -> AuthRepository:
    url = str(client.app.state.settings.database_url)
    return AuthRepository(get_session_factory(url))


def _clients(client: Any) -> dict[str, TestClient]:
    """Return fresh plain clients logged in as each role."""
    repo = _repo(client)
    create_test_user(repo, "admin2@example.com", role=Role.ADMIN)
    create_test_user(repo, "operator@example.com", role=Role.OPERATOR)
    create_test_user(repo, "viewer@example.com", role=Role.VIEWER)
    out: dict[str, TestClient] = {"anon": TestClient(client.app)}
    for name, email in [
        ("admin", "admin2@example.com"),
        ("operator", "operator@example.com"),
        ("viewer", "viewer@example.com"),
    ]:
        logged = TestClient(client.app)
        res = logged.post(
            "/api/v1/auth/login", json={"email": email, "password": TEST_PASSWORD}
        )
        assert res.status_code == 200, (name, res.text)
        logged.headers["X-CSRF-Token"] = res.json()["csrf_token"]
        out[name] = logged
    return out


def test_reads_open_to_all_roles_denied_anon(client: Any) -> None:
    parties = _clients(client)
    assert parties["anon"].get("/api/v1/operations/summary").status_code == 401
    for name in ("admin", "operator", "viewer"):
        res = parties[name].get("/api/v1/operations/summary")
        assert res.status_code == 200, (name, res.text)
    assert parties["viewer"].get("/api/v1/incidents").status_code == 200
    assert parties["viewer"].get("/api/v1/analytics/summary").status_code == 200
    assert parties["viewer"].get("/api/v1/alerting/rules").status_code == 200
    assert parties["viewer"].get("/api/v1/alerting/notifications").status_code == 200


def test_incident_lifecycle_operator_allowed_viewer_denied(client: Any) -> None:
    parties = _clients(client)
    payload = {"title": "RBAC probe", "description": "matrix check", "priority": "P2"}
    assert (
        parties["anon"].post("/api/v1/incidents", json=payload).status_code == 401
    )
    denied = parties["viewer"].post("/api/v1/incidents", json=payload)
    assert denied.status_code == 403, denied.text
    created = parties["operator"].post("/api/v1/incidents", json=payload)
    assert created.status_code == 201, created.text
    incident_id = created.json()["incident"]["id"]
    ack = parties["operator"].post(f"/api/v1/incidents/{incident_id}/acknowledge", json={})
    assert ack.status_code in (200, 409), ack.text
    viewer_ack = parties["viewer"].post(f"/api/v1/incidents/{incident_id}/acknowledge", json={})
    assert viewer_ack.status_code == 403


def test_camera_controls_operator_config_admin_only(client: Any, tmp_path: Any) -> None:
    from backend.tests.helpers import write_sample_video

    parties = _clients(client)
    video = write_sample_video(str(tmp_path / "rbac.mp4"), frames=30)
    camera = {"camera_id": "cam-rbac", "name": "RBAC cam", "source": video}
    assert parties["operator"].post("/api/v1/cameras", json=camera).status_code == 403
    made = parties["admin"].post("/api/v1/cameras", json=camera)
    assert made.status_code == 201, made.text
    assert parties["viewer"].post("/api/v1/cameras/cam-rbac/start").status_code == 403
    started = parties["operator"].post("/api/v1/cameras/cam-rbac/start")
    assert started.status_code == 200, started.text
    stopped = parties["operator"].post("/api/v1/cameras/cam-rbac/stop")
    assert stopped.status_code == 200, stopped.text
    assert stopped.json()["state"] == "STOPPED"
    assert parties["operator"].delete("/api/v1/cameras/cam-rbac").status_code == 403


def test_zones_and_suppression_admin_only(client: Any) -> None:
    parties = _clients(client)
    zone = {
        "zone_id": "z-rbac",
        "name": "RBAC zone",
        "polygon": [{"x": 0.1, "y": 0.1}, {"x": 0.4, "y": 0.1}, {"x": 0.4, "y": 0.4}],
    }
    res = parties["operator"].post("/api/v1/cameras/cam-01/zones", json=zone)
    assert res.status_code == 403, res.text
    assert parties["anon"].post("/api/v1/cameras/cam-01/zones", json=zone).status_code == 401
    suppress = parties["operator"].post(
        "/api/v1/cameras/cam-01/safety/suppress/evt-1", json={}
    )
    assert suppress.status_code == 403, suppress.text


def test_alert_rules_admin_mute_operator(client: Any) -> None:
    parties = _clients(client)
    rule = {"name": "RBAC rule", "channels": ["in_app"]}
    assert parties["operator"].post("/api/v1/alerting/rules", json=rule).status_code == 403
    made = parties["admin"].post("/api/v1/alerting/rules", json=rule)
    assert made.status_code == 201, made.text
    # Seed a notification through the repository for the mute probe.
    from backend.app.alerting.repository import AlertRepository

    alerts = AlertRepository(get_session_factory(str(client.app.state.settings.database_url)))
    created = alerts.create_notification(
        rule_id=made.json()["id"],
        source_event_id="evt-rbac",
        title="t",
        message="m",
        severity="HIGH",
    )
    assert created is not None
    mute_denied = parties["viewer"].post(
        f"/api/v1/alerting/notifications/{created.id}/mute", json={"minutes": 30}
    )
    assert mute_denied.status_code == 403
    muted = parties["operator"].post(
        f"/api/v1/alerting/notifications/{created.id}/mute", json={"minutes": 30}
    )
    assert muted.status_code == 200, muted.text
    assert muted.json()["muted_until"] is not None
    over = parties["operator"].post(
        f"/api/v1/alerting/notifications/{created.id}/mute", json={"minutes": 10000}
    )
    assert over.status_code == 422


def test_user_admin_locked_down_and_mass_assignment_rejected(client: Any) -> None:
    parties = _clients(client)
    assert parties["anon"].get("/api/v1/auth/users").status_code == 401
    assert parties["viewer"].get("/api/v1/auth/users").status_code == 403
    assert parties["operator"].post(
        "/api/v1/auth/users",
        json={"email": "x@example.com", "password": TEST_PASSWORD, "role": "VIEWER"},
    ).status_code == 403
    listed = parties["admin"].get("/api/v1/auth/users")
    assert listed.status_code == 200 and listed.json()["total"] >= 3
    # Unsupported fields (hashes, ids, timestamps) are rejected, not stored.
    forged = parties["admin"].post(
        "/api/v1/auth/users",
        json={
            "email": "forged@example.com",
            "password": TEST_PASSWORD,
            "role": "VIEWER",
            "password_hash": "argon2$injected",
            "is_active": True,
        },
    )
    assert forged.status_code == 422, forged.text
    target = listed.json()["users"][0]["id"]
    patched = parties["admin"].patch(
        f"/api/v1/auth/users/{target}", json={"password_hash": "argon2$injected"}
    )
    assert patched.status_code == 422, patched.text


def test_step_up_recent_auth_required(client: Any) -> None:
    """Aged sessions cannot perform sensitive admin operations."""
    from datetime import UTC, datetime, timedelta

    from backend.app.auth.sessions import digest_token, generate_token

    repo = _repo(client)
    admin, _ = create_test_user(repo, "aged@example.com", role=Role.ADMIN)
    now = datetime.now(UTC)
    raw = generate_token()
    # Live session (recent activity) but stale authentication (>10 min).
    info = repo.create_session(
        user_id=admin.id,
        token_digest=digest_token(raw),
        csrf_digest=digest_token(generate_token()),
        created_at=now - timedelta(minutes=5),
        authenticated_at=now - timedelta(minutes=30),
        expires_at=now + timedelta(hours=11),
    )
    csrf = generate_token()
    repo.rotate_session_csrf(session_id=info.id, csrf_digest=digest_token(csrf))
    aged = TestClient(client.app)
    aged.cookies.set("ivp_session", raw, domain="", path="/")
    aged.headers["X-CSRF-Token"] = csrf
    assert aged.get("/api/v1/auth/me").status_code == 200
    assert aged.get("/api/v1/auth/users").status_code == 200  # read: no step-up
    res = aged.post(
        "/api/v1/auth/users",
        json={"email": "late@example.com", "password": TEST_PASSWORD, "role": "VIEWER"},
    )
    assert res.status_code == 403
    assert res.json()["error"]["code"] == "recent_auth_required"
