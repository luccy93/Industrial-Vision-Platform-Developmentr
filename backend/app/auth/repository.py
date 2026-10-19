"""Auth persistence — users, sessions, tickets, throttle, audit (V16).

Conventions follow ``alerting/repository.py``: one injected session
factory, per-method sessions, atomic multi-row commits, reads never
mutate. Invariants that must hold under concurrency (last-admin
protection, single-use tickets) use single-statement conditional
``UPDATE`` guards so they are atomic on PostgreSQL and SQLite alike —
no ``SELECT FOR UPDATE`` dialect branching.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast

from sqlalchemy import delete, func, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.auth.roles import Role, normalize_role
from backend.app.models.auth_orm import (
    AuthAuditORM,
    LoginAttemptORM,
    UserORM,
    UserSessionORM,
    WebSocketTicketORM,
)


class UserExistsError(ValueError):
    pass


class UserNotFoundError(ValueError):
    pass


class LastAdminError(ValueError):
    """Refusing to remove the final active administrator."""


class BootstrapExistsError(ValueError):
    """An active administrator already exists; bootstrap refused."""


class SessionNotFoundError(ValueError):
    pass


@dataclass
class AuthUser:
    id: str
    email: str
    role: Role
    is_active: bool
    must_change_password: bool
    created_at: datetime
    updated_at: datetime
    last_login_at: datetime | None

    def public_dict(self) -> dict[str, object]:
        """Minimal identity safe for API responses (no hashes/tokens)."""
        return {
            "id": self.id,
            "email": self.email,
            "role": self.role.value,
            "is_active": self.is_active,
            "must_change_password": self.must_change_password,
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
        }


@dataclass
class AuthSessionInfo:
    id: str
    user_id: str
    created_at: datetime
    authenticated_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    revoked_at: datetime | None


def _aware(value: datetime) -> datetime:
    """Attach UTC to naive SQLite reads (storage is always UTC)."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def _affected(result: object) -> int:
    """Rows touched by a DML statement (CursorResult per repo convention)."""
    return int(cast(CursorResult, result).rowcount or 0)


def _user_to_domain(row: UserORM) -> AuthUser:
    return AuthUser(
        id=row.id,
        email=row.email,
        role=normalize_role(row.role),
        is_active=bool(row.is_active),
        must_change_password=bool(row.must_change_password),
        created_at=_aware(row.created_at),
        updated_at=_aware(row.updated_at),
        last_login_at=_aware(row.last_login_at) if row.last_login_at else None,
    )


def _session_to_info(row: UserSessionORM) -> AuthSessionInfo:
    return AuthSessionInfo(
        id=row.id,
        user_id=row.user_id,
        created_at=_aware(row.created_at),
        authenticated_at=_aware(row.authenticated_at),
        last_seen_at=_aware(row.last_seen_at),
        expires_at=_aware(row.expires_at),
        revoked_at=_aware(row.revoked_at) if row.revoked_at else None,
    )


class AuthRepository:
    """Persistence boundary for identity, sessions, tickets, throttle."""

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._sessions = session_factory

    # -- users ---------------------------------------------------------

    def create_user(
        self,
        *,
        email: str,
        password_hash: str,
        role: Role | str,
        is_active: bool = True,
        must_change_password: bool = False,
        now: datetime | None = None,
    ) -> AuthUser:
        parsed_role = normalize_role(role)
        moment = now or datetime.now(UTC)
        with self._sessions() as session:
            row = UserORM(
                id=str(uuid.uuid4()),
                email=email,
                password_hash=password_hash,
                role=parsed_role.value,
                is_active=is_active,
                must_change_password=must_change_password,
                created_at=moment,
                updated_at=moment,
            )
            session.add(row)
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                raise UserExistsError(f"user already exists: {email}") from None
            session.refresh(row)
            return _user_to_domain(row)

    def get_user_by_email(self, email: str) -> AuthUser | None:
        with self._sessions() as session:
            row = session.scalar(select(UserORM).where(UserORM.email == email))
            return _user_to_domain(row) if row else None

    def get_user_by_id(self, user_id: str) -> AuthUser | None:
        with self._sessions() as session:
            row = session.get(UserORM, user_id)
            return _user_to_domain(row) if row else None

    def get_password_hash(self, user_id: str) -> str | None:
        """Return the stored hash for verification (never serialized)."""
        with self._sessions() as session:
            row = session.get(UserORM, user_id)
            return str(row.password_hash) if row else None

    def list_users(self, *, page: int = 1, page_size: int = 50) -> tuple[list[AuthUser], int]:
        page = max(1, page)
        page_size = min(max(1, page_size), 200)
        with self._sessions() as session:
            total = session.scalar(select(func.count()).select_from(UserORM)) or 0
            rows = session.scalars(
                select(UserORM)
                .order_by(UserORM.created_at, UserORM.id)
                .offset((page - 1) * page_size)
                .limit(page_size)
            ).all()
            return [_user_to_domain(row) for row in rows], int(total)

    def has_active_admin(self) -> bool:
        with self._sessions() as session:
            count = session.scalar(
                select(func.count())
                .select_from(UserORM)
                .where(UserORM.role == Role.ADMIN.value, UserORM.is_active.is_(True))
            )
            return bool(count)

    def set_user_role(self, *, user_id: str, role: Role | str, now: datetime | None = None) -> AuthUser:
        """Change role; demoting/deactivating paths guard the last admin.

        The guard is a single conditional UPDATE so concurrent requests
        cannot jointly remove the final active administrator.
        """
        parsed_role = normalize_role(role)
        moment = now or datetime.now(UTC)
        with self._sessions() as session:
            if parsed_role != Role.ADMIN:
                guarded = (
                    update(UserORM)
                    .where(
                        UserORM.id == user_id,
                        UserORM.role == Role.ADMIN.value,
                        UserORM.is_active.is_(True),
                    )
                    .where(
                        select(func.count())
                        .select_from(UserORM)
                        .where(
                            UserORM.role == Role.ADMIN.value,
                            UserORM.is_active.is_(True),
                            UserORM.id != user_id,
                        )
                        .scalar_subquery()
                        > 0
                    )
                    .values(role=parsed_role.value, updated_at=moment)
                )
                result = session.execute(guarded)
                if _affected(result):
                    session.execute(
                        update(UserSessionORM)
                        .where(
                            UserSessionORM.user_id == user_id,
                            UserSessionORM.revoked_at.is_(None),
                        )
                        .values(revoked_at=moment)
                    )
                    session.commit()
                    row = session.get(UserORM, user_id)
                    return _user_to_domain(row)  # type: ignore[arg-type]
                existing = session.get(UserORM, user_id)
                if existing is None:
                    raise UserNotFoundError(f"user not found: {user_id}")
                if existing.role == Role.ADMIN.value and bool(existing.is_active):
                    raise LastAdminError("cannot demote the last active administrator.")
                # Non-admin role change or no-op: plain update.
                existing.role = parsed_role.value
                existing.updated_at = moment
                session.commit()
                session.refresh(existing)
                return _user_to_domain(existing)
            row = session.get(UserORM, user_id)
            if row is None:
                raise UserNotFoundError(f"user not found: {user_id}")
            row.role = parsed_role.value
            row.updated_at = moment
            session.commit()
            session.refresh(row)
            return _user_to_domain(row)

    def set_user_active(self, *, user_id: str, is_active: bool, now: datetime | None = None) -> AuthUser:
        moment = now or datetime.now(UTC)
        with self._sessions() as session:
            if not is_active:
                guarded = (
                    update(UserORM)
                    .where(
                        UserORM.id == user_id,
                        UserORM.role == Role.ADMIN.value,
                        UserORM.is_active.is_(True),
                    )
                    .where(
                        select(func.count())
                        .select_from(UserORM)
                        .where(
                            UserORM.role == Role.ADMIN.value,
                            UserORM.is_active.is_(True),
                            UserORM.id != user_id,
                        )
                        .scalar_subquery()
                        > 0
                    )
                    .values(is_active=False, updated_at=moment)
                )
                result = session.execute(guarded)
                if _affected(result):
                    session.execute(
                        update(UserSessionORM)
                        .where(
                            UserSessionORM.user_id == user_id,
                            UserSessionORM.revoked_at.is_(None),
                        )
                        .values(revoked_at=moment)
                    )
                    session.commit()
                    row = session.get(UserORM, user_id)
                    return _user_to_domain(row)  # type: ignore[arg-type]
                existing = session.get(UserORM, user_id)
                if existing is None:
                    raise UserNotFoundError(f"user not found: {user_id}")
                if existing.role == Role.ADMIN.value and bool(existing.is_active):
                    raise LastAdminError("cannot deactivate the last active administrator.")
                existing.is_active = False
                existing.updated_at = moment
                session.execute(
                    update(UserSessionORM)
                    .where(
                        UserSessionORM.user_id == user_id,
                        UserSessionORM.revoked_at.is_(None),
                    )
                    .values(revoked_at=moment)
                )
                session.commit()
                session.refresh(existing)
                return _user_to_domain(existing)
            row = session.get(UserORM, user_id)
            if row is None:
                raise UserNotFoundError(f"user not found: {user_id}")
            row.is_active = True
            row.updated_at = moment
            session.commit()
            session.refresh(row)
            return _user_to_domain(row)

    def set_password_hash(
        self,
        *,
        user_id: str,
        password_hash: str,
        must_change_password: bool = False,
        revoke_others: bool = True,
        now: datetime | None = None,
    ) -> AuthUser:
        moment = now or datetime.now(UTC)
        with self._sessions() as session:
            row = session.get(UserORM, user_id)
            if row is None:
                raise UserNotFoundError(f"user not found: {user_id}")
            row.password_hash = password_hash
            row.must_change_password = must_change_password
            row.updated_at = moment
            if revoke_others:
                session.execute(
                    update(UserSessionORM)
                    .where(
                        UserSessionORM.user_id == user_id,
                        UserSessionORM.revoked_at.is_(None),
                    )
                    .values(revoked_at=moment)
                )
            session.commit()
            session.refresh(row)
            return _user_to_domain(row)

    def set_must_change_password(self, *, user_id: str, value: bool) -> AuthUser:
        with self._sessions() as session:
            row = session.get(UserORM, user_id)
            if row is None:
                raise UserNotFoundError(f"user not found: {user_id}")
            row.must_change_password = value
            row.updated_at = datetime.now(UTC)
            session.commit()
            session.refresh(row)
            return _user_to_domain(row)

    def record_login(self, *, user_id: str, now: datetime) -> None:
        with self._sessions() as session:
            row = session.get(UserORM, user_id)
            if row is None:
                return
            row.last_login_at = now
            session.commit()

    def bootstrap_admin(self, *, email: str, password_hash: str, now: datetime) -> AuthUser:
        """One-time first-admin creation; refuses when an admin exists."""
        with self._sessions() as session:
            existing = session.scalar(
                select(func.count())
                .select_from(UserORM)
                .where(UserORM.role == Role.ADMIN.value, UserORM.is_active.is_(True))
            )
            if existing:
                raise BootstrapExistsError("an active administrator already exists.")
            row = UserORM(
                id=str(uuid.uuid4()),
                email=email,
                password_hash=password_hash,
                role=Role.ADMIN.value,
                is_active=True,
                must_change_password=False,
                created_at=now,
                updated_at=now,
            )
            try:
                session.add(row)
                session.commit()
            except IntegrityError:
                session.rollback()
                raise UserExistsError(f"user already exists: {email}") from None
            session.refresh(row)
            return _user_to_domain(row)

    # -- sessions --------------------------------------------------------

    def create_session(
        self,
        *,
        user_id: str,
        token_digest: str,
        csrf_digest: str,
        created_at: datetime,
        authenticated_at: datetime,
        expires_at: datetime,
    ) -> AuthSessionInfo:
        with self._sessions() as session:
            row = UserSessionORM(
                id=str(uuid.uuid4()),
                user_id=user_id,
                token_digest=token_digest,
                csrf_digest=csrf_digest,
                created_at=created_at,
                authenticated_at=authenticated_at,
                last_seen_at=created_at,
                expires_at=expires_at,
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return _session_to_info(row)

    def get_session_by_digest(self, token_digest: str) -> AuthSessionInfo | None:
        with self._sessions() as session:
            row = session.scalar(select(UserSessionORM).where(UserSessionORM.token_digest == token_digest))
            return _session_to_info(row) if row else None

    def get_session(self, session_id: str) -> AuthSessionInfo | None:
        with self._sessions() as session:
            row = session.get(UserSessionORM, session_id)
            return _session_to_info(row) if row else None

    def refresh_session_auth(self, *, session_id: str, now: datetime) -> None:
        """Mark explicit re-authentication (login / password change)."""
        with self._sessions() as session:
            row = session.get(UserSessionORM, session_id)
            if row is None:
                raise SessionNotFoundError(f"session not found: {session_id}")
            row.authenticated_at = now
            row.last_seen_at = now
            session.commit()

    def get_session_csrf_digest(self, session_id: str) -> str | None:
        with self._sessions() as session:
            row = session.get(UserSessionORM, session_id)
            return str(row.csrf_digest) if row else None

    def touch_session(self, *, session_id: str, now: datetime, min_interval_seconds: int = 300) -> None:
        """Refresh activity timestamp, throttled — never per-frame writes."""
        with self._sessions() as session:
            row = session.get(UserSessionORM, session_id)
            if row is None or row.revoked_at is not None:
                return
            last_seen = _aware(row.last_seen_at)
            if (now - last_seen).total_seconds() < min_interval_seconds:
                return
            row.last_seen_at = now
            session.commit()

    def rotate_session_csrf(self, *, session_id: str, csrf_digest: str) -> None:
        with self._sessions() as session:
            row = session.get(UserSessionORM, session_id)
            if row is None:
                raise SessionNotFoundError(f"session not found: {session_id}")
            row.csrf_digest = csrf_digest
            session.commit()

    def revoke_session(self, *, session_id: str, now: datetime) -> None:
        with self._sessions() as session:
            session.execute(
                update(UserSessionORM)
                .where(UserSessionORM.id == session_id, UserSessionORM.revoked_at.is_(None))
                .values(revoked_at=now)
            )
            session.commit()

    def revoke_user_sessions(
        self, *, user_id: str, now: datetime, except_session_id: str | None = None
    ) -> int:
        with self._sessions() as session:
            stmt = (
                update(UserSessionORM)
                .where(UserSessionORM.user_id == user_id, UserSessionORM.revoked_at.is_(None))
                .values(revoked_at=now)
            )
            if except_session_id:
                stmt = stmt.where(UserSessionORM.id != except_session_id)
            result = session.execute(stmt)
            session.commit()
            return _affected(result)

    def prune_expired_sessions(self, *, now: datetime, limit: int = 500) -> int:
        """Bounded cleanup of stale sessions (safe periodic maintenance)."""
        with self._sessions() as session:
            ids = session.scalars(
                select(UserSessionORM.id)
                .where(UserSessionORM.expires_at <= now)
                .order_by(UserSessionORM.expires_at)
                .limit(max(1, limit))
            ).all()
            if not ids:
                return 0
            result = session.execute(delete(UserSessionORM).where(UserSessionORM.id.in_(ids)))
            session.commit()
            return _affected(result)

    # -- websocket tickets -----------------------------------------------

    def issue_ticket(
        self,
        *,
        user_id: str,
        session_id: str,
        digest: str,
        scope: str,
        created_at: datetime,
        expires_at: datetime,
    ) -> str:
        with self._sessions() as session:
            row = WebSocketTicketORM(
                id=str(uuid.uuid4()),
                digest=digest,
                user_id=user_id,
                session_id=session_id,
                scope=scope,
                created_at=created_at,
                expires_at=expires_at,
            )
            session.add(row)
            session.commit()
            return str(row.id)

    def consume_ticket(self, *, digest: str, now: datetime) -> dict[str, str] | None:
        """Atomically consume a ticket exactly once; None when unusable."""
        with self._sessions() as session:
            claimed = session.execute(
                update(WebSocketTicketORM)
                .where(
                    WebSocketTicketORM.digest == digest,
                    WebSocketTicketORM.consumed_at.is_(None),
                    WebSocketTicketORM.expires_at > now,
                )
                .values(consumed_at=now)
            )
            if not _affected(claimed):
                return None
            row = session.scalar(select(WebSocketTicketORM).where(WebSocketTicketORM.digest == digest))
            session.commit()
            if row is None:
                return None
            return {
                "id": str(row.id),
                "user_id": str(row.user_id),
                "session_id": str(row.session_id),
                "scope": str(row.scope),
            }

    def prune_tickets(self, *, now: datetime, limit: int = 500) -> int:
        with self._sessions() as session:
            ids = session.scalars(
                select(WebSocketTicketORM.id)
                .where(WebSocketTicketORM.expires_at <= now)
                .order_by(WebSocketTicketORM.expires_at)
                .limit(max(1, limit))
            ).all()
            if not ids:
                return 0
            result = session.execute(delete(WebSocketTicketORM).where(WebSocketTicketORM.id.in_(ids)))
            session.commit()
            return _affected(result)

    # -- throttle + audit --------------------------------------------------

    def record_attempt(self, *, email_normalized: str, ip_hash: str, succeeded: bool, now: datetime) -> None:
        with self._sessions() as session:
            session.add(
                LoginAttemptORM(
                    id=str(uuid.uuid4()),
                    email_normalized=email_normalized,
                    ip_hash=ip_hash,
                    succeeded=succeeded,
                    attempted_at=now,
                )
            )
            session.commit()

    def count_recent_failures(
        self, *, email_normalized: str, ip_hash: str, since: datetime
    ) -> tuple[int, int]:
        """Return (account_failures, ip_failures) inside the window."""
        with self._sessions() as session:
            account = (
                session.scalar(
                    select(func.count())
                    .select_from(LoginAttemptORM)
                    .where(
                        LoginAttemptORM.email_normalized == email_normalized,
                        LoginAttemptORM.succeeded.is_(False),
                        LoginAttemptORM.attempted_at >= since,
                    )
                )
                or 0
            )
            ip_wide = (
                session.scalar(
                    select(func.count())
                    .select_from(LoginAttemptORM)
                    .where(
                        LoginAttemptORM.ip_hash == ip_hash,
                        LoginAttemptORM.succeeded.is_(False),
                        LoginAttemptORM.attempted_at >= since,
                    )
                )
                or 0
            )
            return int(account), int(ip_wide)

    def latest_failure_at(
        self,
        *,
        email_normalized: str | None,
        ip_hash: str | None,
        since: datetime,
    ) -> datetime | None:
        """Most recent failed attempt in scope (for escalating delays)."""
        with self._sessions() as session:
            stmt = select(func.max(LoginAttemptORM.attempted_at)).where(
                LoginAttemptORM.succeeded.is_(False),
                LoginAttemptORM.attempted_at >= since,
            )
            if email_normalized:
                stmt = stmt.where(LoginAttemptORM.email_normalized == email_normalized)
            if ip_hash:
                stmt = stmt.where(LoginAttemptORM.ip_hash == ip_hash)
            value = session.scalar(stmt)
            return _aware(value) if value is not None else None

    def prune_attempts(self, *, before: datetime, limit: int = 1000) -> int:
        with self._sessions() as session:
            ids = session.scalars(
                select(LoginAttemptORM.id)
                .where(LoginAttemptORM.attempted_at < before)
                .order_by(LoginAttemptORM.attempted_at)
                .limit(max(1, limit))
            ).all()
            if not ids:
                return 0
            result = session.execute(delete(LoginAttemptORM).where(LoginAttemptORM.id.in_(ids)))
            session.commit()
            return _affected(result)

    def audit(
        self,
        *,
        actor_user_id: str | None,
        target_user_id: str | None,
        action: str,
        detail: str = "",
        now: datetime | None = None,
    ) -> None:
        """Append a sanitized audit record; callers must pre-sanitize."""
        moment = now or datetime.now(UTC)
        with self._sessions() as session:
            session.add(
                AuthAuditORM(
                    id=str(uuid.uuid4()),
                    actor_user_id=actor_user_id,
                    target_user_id=target_user_id,
                    action=action,
                    detail=detail[:1024],
                    created_at=moment,
                )
            )
            session.commit()
