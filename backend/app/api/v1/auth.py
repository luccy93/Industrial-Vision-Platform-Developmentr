"""Authentication, sessions, users, WebSocket tickets (V16).

Contracts:

- ``POST /api/v1/auth/login`` — validates credentials (generic failures),
  throttles abuse, rotates sessions, sets the ``HttpOnly`` cookie, and
  returns the minimal user summary + CSRF token + expiry metadata.
- ``POST /api/v1/auth/logout`` — revokes the session, clears the cookie.
- ``GET /api/v1/auth/me`` — minimal identity or ``401``.
- ``POST /api/v1/auth/csrf`` — rotates the session CSRF token.
- ``POST /api/v1/auth/change-password`` — current-password check, policy
  enforcement, other sessions invalidated per documented policy.
- ``POST /api/v1/auth/ws-ticket`` — single-use ticket for WS upgrades.
- ``/api/v1/auth/users*`` — administrator-only identity management with
  recent-auth step-up and last-admin protection.

No public registration exists; the first administrator is created via
the documented bootstrap command. Passwords, hashes, digests, raw
tokens, and tickets never appear in responses or logs.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

from backend.app.auth.cookies import clear_session_cookie, set_session_cookie
from backend.app.auth.dependencies import (
    Principal,
    check_csrf,
    check_recent_auth,
    enforce_allowed_origin,
    get_request_auth_repository,
    require_user_admin,
    resolve_request_principal,
)
from backend.app.auth.passwords import (
    PasswordPolicyError,
    hash_password,
    verify_password,
)
from backend.app.auth.rate_limit import login_throttle, resolve_client_ip
from backend.app.auth.repository import (
    AuthRepository,
    LastAdminError,
    UserExistsError,
    UserNotFoundError,
)
from backend.app.auth.roles import normalize_role
from backend.app.auth.sessions import (
    digest_token,
    generate_token,
    hash_ip,
    normalize_email,
    session_expiry,
    validate_email_shape,
)

router = APIRouter(tags=["auth"])

GENERIC_LOGIN_FAILURE = "Invalid email or password."


class LoginRequest(BaseModel):
    model_config = {"extra": "forbid"}

    email: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1, max_length=1024)


class ChangePasswordRequest(BaseModel):
    model_config = {"extra": "forbid"}

    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=1, max_length=1024)


class WsTicketRequest(BaseModel):
    model_config = {"extra": "forbid"}

    scope: str = Field(min_length=1, max_length=128)


class UserCreateRequest(BaseModel):
    model_config = {"extra": "forbid"}

    email: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1, max_length=1024)
    role: str = Field(default="VIEWER", max_length=16)


class UserPatchRequest(BaseModel):
    model_config = {"extra": "forbid"}

    role: str | None = Field(default=None, max_length=16)
    is_active: bool | None = None
    must_change_password: bool | None = None


def _settings(request: Request) -> Any:
    return request.app.state.settings


def _principal(request: Request) -> Principal:
    return resolve_request_principal(request)


def _auth_repo(request: Request) -> AuthRepository:
    return get_request_auth_repository(request)


def _check_csrf(request: Request, principal: Principal, repo: AuthRepository) -> None:
    settings = _settings(request)
    header = str(settings.auth_csrf_header)
    expected = repo.get_session_csrf_digest(principal.session_id)
    if expected is None:
        raise HTTPException(status_code=401, detail="Authentication required.")
    check_csrf(request, expected, header, request.headers.get(header))


def _session_expires_at(repo: AuthRepository, session_id: str) -> str | None:
    info = repo.get_session(session_id)
    if info is None:
        return None
    expires = info.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    return expires.isoformat()


def _login_failure() -> HTTPException:
    return HTTPException(
        status_code=401,
        detail={"code": "invalid_credentials", "message": GENERIC_LOGIN_FAILURE},
    )


@router.post("/api/v1/auth/login")
def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    repo: AuthRepository = Depends(_auth_repo),
) -> dict[str, Any]:
    settings = _settings(request)
    enforce_allowed_origin(request, list(settings.cors_allowed_origins or []))
    now = datetime.now(UTC)
    try:
        normalized = normalize_email(body.email)
        validate_email_shape(normalized)
        shape_ok = True
    except ValueError:
        normalized, shape_ok = "", False
    ip = resolve_client_ip(request, list(settings.auth_trusted_proxies or []))
    allowed, retry_after = login_throttle(repo, settings, email_normalized=normalized, ip=ip, now=now)
    if not allowed:
        return _throttled(retry_after)
    user = repo.get_user_by_email(normalized) if shape_ok else None
    stored_hash = repo.get_password_hash(user.id) if user else None
    valid = bool(user and user.is_active and stored_hash and verify_password(stored_hash, body.password))
    repo.record_attempt(
        email_normalized=normalized or "invalid",
        ip_hash=hash_ip(ip),
        succeeded=valid,
        now=now,
    )
    if not valid:
        raise _login_failure()
    assert user is not None
    # Strict rotation: prior sessions are revoked at authentication time.
    repo.revoke_user_sessions(user_id=user.id, now=now)
    raw_token, raw_csrf = generate_token(), generate_token()
    expires_at, _ = session_expiry(
        now,
        idle_minutes=int(settings.auth_session_idle_minutes),
        absolute_hours=int(settings.auth_session_absolute_hours),
    )
    info = repo.create_session(
        user_id=user.id,
        token_digest=digest_token(raw_token),
        csrf_digest=digest_token(raw_csrf),
        created_at=now,
        authenticated_at=now,
        expires_at=expires_at,
    )
    repo.record_login(user_id=user.id, now=now)
    repo.prune_expired_sessions(now=now)
    repo.prune_attempts(before=now - timedelta(hours=24))
    repo.audit(
        actor_user_id=user.id,
        target_user_id=user.id,
        action="login.success",
        detail="",
        now=now,
    )
    set_session_cookie(response, raw_token, settings)
    refreshed = repo.get_user_by_id(user.id)
    return {
        "user": (refreshed or user).public_dict(),
        "csrf_token": raw_csrf,
        "session_expires_at": _session_expires_at(repo, info.id),
        "must_change_password": bool((refreshed or user).must_change_password),
    }


def _throttled(retry_after: int) -> Any:
    raise HTTPException(
        status_code=429,
        detail={"code": "too_many_attempts", "message": "Too many login attempts. Try again later."},
        headers={"Retry-After": str(max(1, retry_after))},
    )


@router.post("/api/v1/auth/logout")
def logout(
    request: Request,
    response: Response,
    repo: AuthRepository = Depends(_auth_repo),
) -> dict[str, Any]:
    settings = _settings(request)
    now = datetime.now(UTC)
    try:
        principal = resolve_request_principal(request)
    except HTTPException:
        clear_session_cookie(response, settings)
        return {"ok": True}
    repo.revoke_session(session_id=principal.session_id, now=now)
    repo.audit(
        actor_user_id=principal.user.id,
        target_user_id=principal.user.id,
        action="logout",
        detail="",
        now=now,
    )
    clear_session_cookie(response, settings)
    return {"ok": True}


@router.get("/api/v1/auth/me")
def me(
    request: Request,
    repo: AuthRepository = Depends(_auth_repo),
) -> dict[str, Any]:
    principal = _principal(request)
    return {
        "user": principal.user.public_dict(),
        "session_expires_at": _session_expires_at(repo, principal.session_id),
    }


@router.post("/api/v1/auth/csrf")
def rotate_csrf(
    request: Request,
    repo: AuthRepository = Depends(_auth_repo),
) -> dict[str, Any]:
    settings = _settings(request)
    enforce_allowed_origin(request, list(settings.cors_allowed_origins or []))
    principal = _principal(request)
    raw_csrf = generate_token()
    repo.rotate_session_csrf(session_id=principal.session_id, csrf_digest=digest_token(raw_csrf))
    return {"csrf_token": raw_csrf}


@router.post("/api/v1/auth/change-password")
def change_password(
    body: ChangePasswordRequest,
    request: Request,
    repo: AuthRepository = Depends(_auth_repo),
) -> dict[str, Any]:
    settings = _settings(request)
    enforce_allowed_origin(request, list(settings.cors_allowed_origins or []))
    principal = _principal(request)
    _check_csrf(request, principal, repo)
    now = datetime.now(UTC)
    stored_hash = repo.get_password_hash(principal.user.id)
    if not stored_hash or not verify_password(stored_hash, body.current_password):
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_current_password", "message": "Current password is incorrect."},
        )
    try:
        new_hash = hash_password(body.new_password)
    except PasswordPolicyError as exc:
        raise HTTPException(status_code=422, detail={"code": exc.code, "message": str(exc)}) from None
    # Documented policy: other sessions are invalidated; the current one
    # survives and is re-stamped as freshly authenticated.
    repo.set_password_hash(
        user_id=principal.user.id,
        password_hash=new_hash,
        must_change_password=False,
        revoke_others=False,
        now=now,
    )
    repo.revoke_user_sessions(user_id=principal.user.id, now=now, except_session_id=principal.session_id)
    repo.refresh_session_auth(session_id=principal.session_id, now=now)
    repo.audit(
        actor_user_id=principal.user.id,
        target_user_id=principal.user.id,
        action="password.change",
        detail="",
        now=now,
    )
    return {"ok": True, "must_change_password": False}


@router.post("/api/v1/auth/ws-ticket")
def issue_ws_ticket(
    body: WsTicketRequest,
    request: Request,
    repo: AuthRepository = Depends(_auth_repo),
) -> dict[str, Any]:
    from backend.app.auth.ws import OPERATIONS_SCOPE, camera_scope

    settings = _settings(request)
    enforce_allowed_origin(request, list(settings.cors_allowed_origins or []))
    principal = _principal(request)
    _check_csrf(request, principal, repo)
    scope = body.scope.strip()
    if scope == OPERATIONS_SCOPE:
        pass
    elif scope.startswith("camera:"):
        camera_id = scope[len("camera:") :].strip()
        if not camera_id:
            raise HTTPException(
                status_code=422,
                detail={"code": "validation_error", "message": "Camera scope requires an id."},
            )
        # Existence is NOT checked here: the socket itself reports
        # CAMERA_NOT_FOUND to authorized holders (preserved V02 contract).
        # Issuance still requires a valid session + CSRF + read role.
        scope = camera_scope(camera_id)
    else:
        raise HTTPException(
            status_code=422,
            detail={"code": "validation_error", "message": "Unknown ticket scope."},
        )
    now = datetime.now(UTC)
    raw_ticket = generate_token()
    repo.issue_ticket(
        user_id=principal.user.id,
        session_id=principal.session_id,
        digest=digest_token(raw_ticket),
        scope=scope,
        created_at=now,
        expires_at=now + timedelta(seconds=int(settings.auth_ws_ticket_ttl_seconds)),
    )
    repo.prune_tickets(now=now)
    return {
        "ticket": raw_ticket,
        "scope": scope,
        "expires_at": (now + timedelta(seconds=int(settings.auth_ws_ticket_ttl_seconds))).isoformat(),
    }


@router.get("/api/v1/auth/users", dependencies=[require_user_admin])
def list_users(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    repo: AuthRepository = Depends(_auth_repo),
) -> dict[str, Any]:
    items, total = repo.list_users(page=page, page_size=page_size)
    return {
        "users": [item.public_dict() for item in items],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.post("/api/v1/auth/users", dependencies=[require_user_admin], status_code=201)
def create_user(
    body: UserCreateRequest,
    request: Request,
    repo: AuthRepository = Depends(_auth_repo),
) -> dict[str, Any]:
    settings = _settings(request)
    enforce_allowed_origin(request, list(settings.cors_allowed_origins or []))
    principal = _principal(request)
    _check_csrf(request, principal, repo)
    check_recent_auth(principal, within_minutes=int(settings.auth_recent_auth_minutes))
    try:
        normalized = normalize_email(body.email)
        validate_email_shape(normalized)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail={"code": "validation_error", "message": "Email address is invalid."},
        ) from None
    try:
        role = normalize_role(body.role)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail={"code": "validation_error", "message": "Unknown role."},
        ) from None
    try:
        new_hash = hash_password(body.password)
    except PasswordPolicyError as exc:
        raise HTTPException(status_code=422, detail={"code": exc.code, "message": str(exc)}) from None
    try:
        created = repo.create_user(
            email=normalized,
            password_hash=new_hash,
            role=role,
            must_change_password=True,
            now=datetime.now(UTC),
        )
    except UserExistsError:
        raise HTTPException(
            status_code=409,
            detail={"code": "conflict", "message": "User already exists."},
        ) from None
    repo.audit(
        actor_user_id=principal.user.id,
        target_user_id=created.id,
        action="user.create",
        detail=f"role={role.value}",
        now=datetime.now(UTC),
    )
    return {"user": created.public_dict()}


@router.get("/api/v1/auth/users/{user_id}", dependencies=[require_user_admin])
def get_user(
    user_id: str,
    request: Request,
    repo: AuthRepository = Depends(_auth_repo),
) -> dict[str, Any]:
    found = repo.get_user_by_id(user_id)
    if found is None:
        raise HTTPException(status_code=404, detail=f"user not found: {user_id}")
    return {"user": found.public_dict()}


@router.patch("/api/v1/auth/users/{user_id}", dependencies=[require_user_admin])
def patch_user(
    user_id: str,
    body: UserPatchRequest,
    request: Request,
    repo: AuthRepository = Depends(_auth_repo),
) -> dict[str, Any]:
    settings = _settings(request)
    enforce_allowed_origin(request, list(settings.cors_allowed_origins or []))
    principal = _principal(request)
    _check_csrf(request, principal, repo)
    check_recent_auth(principal, within_minutes=int(settings.auth_recent_auth_minutes))
    now = datetime.now(UTC)
    try:
        updated: Any = None
        if body.role is not None:
            try:
                role = normalize_role(body.role)
            except ValueError:
                raise HTTPException(
                    status_code=422,
                    detail={"code": "validation_error", "message": "Unknown role."},
                ) from None
            updated = repo.set_user_role(user_id=user_id, role=role, now=now)
            repo.audit(
                actor_user_id=principal.user.id,
                target_user_id=user_id,
                action="user.role",
                detail=f"role={role.value}",
                now=now,
            )
        if body.is_active is not None:
            updated = repo.set_user_active(user_id=user_id, is_active=body.is_active, now=now)
            repo.audit(
                actor_user_id=principal.user.id,
                target_user_id=user_id,
                action="user.deactivate" if not body.is_active else "user.reactivate",
                detail="",
                now=now,
            )
        if body.must_change_password is not None:
            updated = repo.set_must_change_password(user_id=user_id, value=body.must_change_password)
            reset_action = (
                "user.force_password_reset" if body.must_change_password else "user.clear_password_reset"
            )
            repo.audit(
                actor_user_id=principal.user.id,
                target_user_id=user_id,
                action=reset_action,
                detail="",
                now=now,
            )
        if updated is None:
            found = repo.get_user_by_id(user_id)
            if found is None:
                raise HTTPException(status_code=404, detail=f"user not found: {user_id}")
            return {"user": found.public_dict()}
        return {"user": updated.public_dict()}
    except LastAdminError as exc:
        raise HTTPException(status_code=409, detail={"code": "last_admin", "message": str(exc)}) from None
    except UserNotFoundError:
        raise HTTPException(status_code=404, detail=f"user not found: {user_id}") from None


@router.post("/api/v1/auth/users/{user_id}/revoke-sessions", dependencies=[require_user_admin])
def revoke_user_sessions(
    user_id: str,
    request: Request,
    repo: AuthRepository = Depends(_auth_repo),
) -> dict[str, Any]:
    settings = _settings(request)
    enforce_allowed_origin(request, list(settings.cors_allowed_origins or []))
    principal = _principal(request)
    _check_csrf(request, principal, repo)
    check_recent_auth(principal, within_minutes=int(settings.auth_recent_auth_minutes))
    if repo.get_user_by_id(user_id) is None:
        raise HTTPException(status_code=404, detail=f"user not found: {user_id}")
    count = repo.revoke_user_sessions(user_id=user_id, now=datetime.now(UTC))
    repo.audit(
        actor_user_id=principal.user.id,
        target_user_id=user_id,
        action="session.revoke_others",
        detail=f"revoked={count}",
        now=datetime.now(UTC),
    )
    return {"ok": True, "revoked": count}
