"""WebSocket ticket authorization (V16).

Browser WebSocket APIs cannot attach authorization headers, so an
authenticated, CSRF-protected REST call mints a short-lived single-use
ticket passed as ``?ticket=``. Tickets are consumed atomically (exactly
once across workers), bound to session + user + scope, and useless as
REST credentials. Raw ticket values are never logged.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import WebSocket

from backend.app.auth.repository import AuthRepository
from backend.app.auth.roles import can
from backend.app.auth.sessions import digest_token, session_is_live

#: Application WebSocket close codes (4000–4999 range).
WS_CLOSE_UNAUTHORIZED = 4401
WS_CLOSE_FORBIDDEN = 4403

OPERATIONS_SCOPE = "operations"


def camera_scope(camera_id: str) -> str:
    return f"camera:{camera_id}"


def extract_ticket(websocket: WebSocket) -> str | None:
    """Read the one-time ticket from the query string (never logged)."""
    try:
        raw = websocket.query_params.get("ticket", "")
    except Exception:
        return None
    ticket = str(raw or "").strip()
    return ticket or None


def ws_origin_allowed(websocket: WebSocket, allowed_origins: list[str] | None) -> bool:
    """Validate the WS handshake Origin against the credentialed allowlist."""
    try:
        origin = websocket.headers.get("origin", "")
    except Exception:
        return True
    if not str(origin or "").strip():
        return True  # Non-browser client; ticket auth still applies.
    origins = [str(o).strip() for o in (allowed_origins or []) if str(o).strip()]
    if "*" in origins:
        return True  # Dev default; documented, never with credentials+prod.
    return str(origin).strip() in origins


def authorize_ticket(
    repository: AuthRepository,
    *,
    raw_ticket: str,
    scope: str,
    now: datetime,
    idle_minutes: int,
    absolute_hours: int,
) -> dict[str, Any] | None:
    """Consume the ticket and validate session + user + scope, or None."""
    claimed = repository.consume_ticket(digest=digest_token(raw_ticket), now=now)
    if claimed is None or claimed["scope"] != scope:
        return None
    session = repository.get_session(claimed["session_id"])
    if session is None:
        return None
    user = repository.get_user_by_id(claimed["user_id"])
    if user is None or not user.is_active:
        return None
    live = session_is_live(
        now=now,
        revoked_at=session.revoked_at,
        expires_at=session.expires_at,
        created_at=session.created_at,
        last_seen_at=session.last_seen_at,
        idle_minutes=idle_minutes,
        absolute_hours=absolute_hours,
    )
    if not live:
        return None
    if not can(user.role, "read"):
        return None
    return {"user": user, "session_id": session.id, "scope": scope}


def revalidate_connection(
    repository: AuthRepository,
    *,
    user_id: str,
    session_id: str,
    now: datetime,
    idle_minutes: int,
    absolute_hours: int,
) -> bool:
    """Bounded revalidation for long-lived connections after revocation."""
    session = repository.get_session(session_id)
    if session is None or session.user_id != user_id:
        return False
    user = repository.get_user_by_id(user_id)
    if user is None or not user.is_active:
        return False
    return session_is_live(
        now=now,
        revoked_at=session.revoked_at,
        expires_at=session.expires_at,
        created_at=session.created_at,
        last_seen_at=session.last_seen_at,
        idle_minutes=idle_minutes,
        absolute_hours=absolute_hours,
    )
