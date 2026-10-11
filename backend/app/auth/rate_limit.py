"""Login throttling — DB-backed sliding windows (V16).

Counters live in ``login_attempts`` so limits hold across backend
workers and restarts (in-memory buckets would not). Only failures are
recorded, keeping write volume bounded; rows are pruned by retention.

- Per account: ``auth_login_account_max_attempts`` failures inside
  ``auth_login_account_window_minutes`` trigger escalating delays
  (1, 2, 4, … minutes) capped at ``auth_login_max_delay_minutes``.
- Per IP: ``auth_login_ip_max_attempts`` failures inside
  ``auth_login_ip_window_minutes`` deny until the window slides past.
- No permanent lockout: attackers cannot deny service by locking victims.

Client IP: the direct peer, unless the peer is an explicitly configured
trusted proxy — then the first ``X-Forwarded-For`` entry. Arbitrary
forwarded values are never trusted. Raw IPs are hashed before storage.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import Request

from backend.app.auth.repository import AuthRepository
from backend.app.auth.sessions import hash_ip


def resolve_client_ip(request: Request, trusted_proxies: list[str] | None) -> str:
    peer = request.client.host if request.client else "unknown"
    proxies = [str(p).strip() for p in (trusted_proxies or []) if str(p).strip()]
    if not proxies or peer not in proxies:
        return peer
    forwarded = str(request.headers.get("x-forwarded-for", "") or "")
    first = forwarded.split(",")[0].strip()
    return first or peer


def login_throttle(
    repository: AuthRepository,
    settings: object,
    *,
    email_normalized: str,
    ip: str,
    now: datetime,
) -> tuple[bool, int]:
    """Return ``(allowed, retry_after_seconds)`` for a login attempt."""
    account_window = timedelta(minutes=int(getattr(settings, "auth_login_account_window_minutes", 15)))
    ip_window = timedelta(minutes=int(getattr(settings, "auth_login_ip_window_minutes", 15)))
    account_max = int(getattr(settings, "auth_login_account_max_attempts", 5))
    ip_max = int(getattr(settings, "auth_login_ip_max_attempts", 30))
    delay_cap = int(getattr(settings, "auth_login_max_delay_minutes", 15))
    ip_digest = hash_ip(ip)

    ip_failures = repository.count_recent_failures(
        email_normalized="", ip_hash=ip_digest, since=now - ip_window
    )[1]
    if ip_failures >= ip_max:
        latest = repository.latest_failure_at(
            email_normalized=None, ip_hash=ip_digest, since=now - ip_window
        )
        retry = _remaining(latest, now, ip_window) if latest else int(ip_window.total_seconds())
        return False, retry

    account_failures = repository.count_recent_failures(
        email_normalized=email_normalized, ip_hash="", since=now - account_window
    )[0]
    if account_failures >= account_max:
        over = account_failures - account_max + 1
        delay = timedelta(minutes=min(2 ** (over - 1), delay_cap))
        latest = repository.latest_failure_at(
            email_normalized=email_normalized, ip_hash=None, since=now - account_window
        )
        retry = _remaining(latest, now, delay) if latest else int(delay.total_seconds())
        return False, retry
    return True, 0


def _remaining(latest: datetime | None, now: datetime, span: timedelta) -> int:
    if latest is None:
        return 0
    if latest.tzinfo is None:
        from datetime import UTC

        latest = latest.replace(tzinfo=UTC)
    remaining = (latest + span - now).total_seconds()
    return max(0, int(remaining))
