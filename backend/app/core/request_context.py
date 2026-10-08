"""Lightweight request context + request-ID helpers (V11, §14–§15).

Every request carries a bounded request ID: an inbound ``X-Request-ID``
is honored when it is sane, otherwise a fresh one is generated. IDs are
never trusted blindly — over-long or non-printable values are replaced.

The active :class:`RequestContext` is available to logging via a
context variable. No authentication identity lives here (V16 owns that).
"""

from __future__ import annotations

import re
import uuid
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from backend.app.domain.common import utcnow

REQUEST_ID_HEADER = "X-Request-ID"
REQUEST_ID_MAX_LENGTH = 128

_PRINTABLE_ASCII = re.compile(r"^[\x20-\x7e]+$")


def generate_request_id() -> str:
    """Generate a fresh 12-hex-char request ID (existing convention)."""
    return uuid.uuid4().hex[:12]


def sanitize_request_id(value: Any) -> str:
    """Return a safe request ID: honor sane inbound values, else generate.

    Rules: must be a string, 1–128 chars, printable ASCII. Anything else
    (missing, over-long, malformed, non-string) yields a fresh ID.
    """
    if not isinstance(value, str):
        return generate_request_id()
    cleaned = value.strip()
    if not cleaned or len(cleaned) > REQUEST_ID_MAX_LENGTH:
        return generate_request_id()
    if not _PRINTABLE_ASCII.match(cleaned):
        return generate_request_id()
    return cleaned


@dataclass
class RequestContext:
    """Per-request observability context (§15)."""

    request_id: str
    timestamp: datetime = field(default_factory=utcnow)
    method: str = ""
    path: str = ""

    def to_log_fields(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "method": self.method,
            "path": self.path,
        }


_current_context: ContextVar[RequestContext | None] = ContextVar("ivp_request_context", default=None)


def get_request_context() -> RequestContext | None:
    """Return the active request context, if any."""
    return _current_context.get()


def set_request_context(context: RequestContext | None) -> Any:
    """Install a request context; returns the reset token."""
    return _current_context.set(context)


def reset_request_context(token: Any) -> None:
    """Restore the previous request context."""
    _current_context.reset(token)
