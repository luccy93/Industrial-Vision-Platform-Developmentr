"""Opaque session/CSRF token primitives (V16).

Tokens are cryptographically random (256-bit); only SHA-256 digests are
persisted. Raw values travel in the ``HttpOnly`` cookie (sessions) or a
single-use query value (tickets) and are never logged or stored.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from datetime import datetime, timedelta

TOKEN_BYTES = 32  # 256-bit opaque tokens
DIGEST_BYTES = 32  # SHA-256 hex digests are 64 chars

_EMAIL_RE = re.compile(r"^[^@\s]{1,255}@[^@\s]{1,255}\.[^@\s]{1,255}$")
MAX_EMAIL_LENGTH = 320


def generate_token() -> str:
    """Return a fresh 256-bit opaque token, URL-safe encoded."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def digest_token(raw: str) -> str:
    """Return the SHA-256 hex digest of a raw token (what is stored)."""
    return hashlib.sha256(raw.encode()).hexdigest()


def tokens_equal(left: str, right: str) -> bool:
    """Constant-time comparison for digests/CSRF values."""
    try:
        return hmac.compare_digest(str(left), str(right))
    except TypeError:
        return False


def normalize_email(value: object) -> str:
    """Strip + lowercase a login identifier; raises ``ValueError`` if blank."""
    normalized = str(value or "").strip().lower()
    if not normalized:
        raise ValueError("email is required.")
    return normalized


def validate_email_shape(normalized: str) -> None:
    """Basic shape check on an already-normalized identifier."""
    if len(normalized) > MAX_EMAIL_LENGTH or _EMAIL_RE.match(normalized) is None:
        raise ValueError("email address is invalid.")


def hash_ip(value: str) -> str:
    """One-way truncated hash of a client IP for abuse accounting.

    Raw client IPs are not retained; only this digest is stored with
    login attempts. Not a secret — just abuse-bucket keying.
    """
    return hashlib.sha256(f"ivp-ip:{value}".encode()).hexdigest()[:32]


def session_expiry(now: datetime, idle_minutes: int, absolute_hours: int) -> tuple[datetime, datetime]:
    """Return ``(expires_at, last_seen_at)`` for a fresh session."""
    return now + timedelta(hours=absolute_hours), now


def session_is_live(
    *,
    now: datetime,
    revoked_at: datetime | None,
    expires_at: datetime,
    created_at: datetime,
    last_seen_at: datetime,
    idle_minutes: int,
    absolute_hours: int,
) -> bool:
    """Pure lifetime check: revocation, absolute cap, then idle window."""
    if revoked_at is not None:
        return False
    if now >= expires_at:
        return False
    if now - created_at >= timedelta(hours=absolute_hours):
        return False
    if now - last_seen_at >= timedelta(minutes=idle_minutes):
        return False
    return True
