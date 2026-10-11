"""Session cookie helpers (V16).

``HttpOnly`` always; ``SameSite`` from config (Lax default); ``Secure``
in production (explicit override forbidden from weakening production).
``Path=/`` so the browser also presents the cookie to the Next.js
server layer for DAL verification behind a same-origin deployment;
state-changing requests are still gated by the CSRF header.
"""

from __future__ import annotations

from typing import Literal

from fastapi import Response

SameSiteValue = Literal["lax", "strict", "none"]


def _samesite(settings: object) -> SameSiteValue:
    value = str(getattr(settings, "auth_cookie_samesite", "Lax")).lower()
    if value not in ("lax", "strict"):
        # Config validation rejects anything else; fail closed here.
        return "lax"
    return value  # type: ignore[return-value]


def cookie_is_secure(settings: object) -> bool:
    override = getattr(settings, "auth_cookie_secure", None)
    if override is not None:
        return bool(override)
    return bool(getattr(settings, "is_production", False))


def set_session_cookie(response: Response, raw_token: str, settings: object) -> None:
    max_age = int(getattr(settings, "auth_session_absolute_hours", 12)) * 3600
    response.set_cookie(
        key=str(getattr(settings, "auth_session_cookie_name", "ivp_session")),
        value=raw_token,
        max_age=max_age,
        httponly=True,
        secure=cookie_is_secure(settings),
        samesite=_samesite(settings),
        path="/",
    )


def clear_session_cookie(response: Response, settings: object) -> None:
    response.delete_cookie(
        key=str(getattr(settings, "auth_session_cookie_name", "ivp_session")),
        path="/",
        samesite=_samesite(settings),
        secure=cookie_is_secure(settings),
    )
