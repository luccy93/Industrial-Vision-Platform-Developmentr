"""Shared authorization dependencies — backend enforcement (V16).

One policy, one code path: every protected router resolves the current
principal here. ``401`` = missing/invalid authentication, ``403`` =
authenticated but lacking permission. Frontend checks are never
consulted.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import HTTPException, Request

from backend.app.auth.repository import AuthRepository, AuthUser
from backend.app.auth.roles import can
from backend.app.auth.sessions import digest_token, session_is_live, tokens_equal

SESSION_COOKIE_NAME = "ivp_session"

#: Paths that remain usable while ``must_change_password`` is set.
PASSWORD_CHANGE_ALLOWLIST = frozenset(
    {
        "/api/v1/auth/me",
        "/api/v1/auth/change-password",
        "/api/v1/auth/logout",
        "/api/v1/auth/csrf",
    }
)


@dataclass
class Principal:
    """Authenticated request identity resolved from the session cookie."""

    user: AuthUser
    session_id: str
    authenticated_at: datetime


def unauthenticated(detail: str = "Authentication required.") -> HTTPException:
    return HTTPException(status_code=401, detail=detail)


def forbidden(detail: str = "Insufficient permissions.") -> HTTPException:
    return HTTPException(status_code=403, detail=detail)


def extract_session_token(request: Request, cookie_name: str = SESSION_COOKIE_NAME) -> str | None:
    raw = request.cookies.get(cookie_name)
    if not raw or not raw.strip():
        return None
    return raw.strip()


def resolve_principal(
    request: Request,
    repository: AuthRepository,
    *,
    cookie_name: str = SESSION_COOKIE_NAME,
    idle_minutes: int,
    absolute_hours: int,
    now: datetime | None = None,
) -> Principal:
    """Validate the session cookie → active user, or raise ``401``.

    Every failure mode (missing/unknown/expired/idle/revoked session,
    inactive user) yields the same generic ``401`` so callers cannot
    probe account state.
    """
    moment = now or datetime.now(UTC)
    raw = extract_session_token(request, cookie_name)
    if raw is None:
        raise unauthenticated()
    session = repository.get_session_by_digest(digest_token(raw))
    if session is None:
        raise unauthenticated()
    user = repository.get_user_by_id(session.user_id)
    if user is None or not user.is_active:
        raise unauthenticated()
    live = session_is_live(
        now=moment,
        revoked_at=session.revoked_at,
        expires_at=session.expires_at,
        created_at=session.created_at,
        last_seen_at=session.last_seen_at,
        idle_minutes=idle_minutes,
        absolute_hours=absolute_hours,
    )
    if not live:
        raise unauthenticated()
    authenticated_at = session.authenticated_at
    if authenticated_at.tzinfo is None:
        authenticated_at = authenticated_at.replace(tzinfo=UTC)
    return Principal(user=user, session_id=session.id, authenticated_at=authenticated_at)


def check_capability(principal: Principal, capability: str) -> None:
    """Raise ``403`` unless the principal's role grants ``capability``."""
    if not can(principal.user.role, capability):
        raise forbidden()


def check_password_change_gate(principal: Principal, path: str) -> None:
    """Block forced-change users everywhere except the allowlist (``403``)."""
    if principal.user.must_change_password and path not in PASSWORD_CHANGE_ALLOWLIST:
        raise HTTPException(
            status_code=403,
            detail={"code": "password_change_required", "message": "Password change required."},
        )


def check_recent_auth(principal: Principal, *, within_minutes: int, now: datetime | None = None) -> None:
    """Step-up: sensitive ops need authentication within ``within_minutes``."""
    from datetime import timedelta

    moment = now or datetime.now(UTC)
    if moment - principal.authenticated_at > timedelta(minutes=within_minutes):
        raise HTTPException(
            status_code=403,
            detail={"code": "recent_auth_required", "message": "Recent authentication required."},
        )


def check_csrf(request: Request, expected_digest: str, header_name: str, raw_value: str | None) -> None:
    """Validate the session-bound CSRF header with constant-time compare."""
    _ = header_name
    if not raw_value or not tokens_equal(digest_token(raw_value), expected_digest):
        raise forbidden("Invalid CSRF token.")
