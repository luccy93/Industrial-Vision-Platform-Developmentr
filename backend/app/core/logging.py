"""Structured application logging with secret redaction."""

from __future__ import annotations

import logging
import re
from typing import Any

_SENSITIVE_PATTERNS = (
    re.compile(r"(?i)(password\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(api[_-]?key\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(token\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(secret\s*[:=]\s*)\S+"),
)


def redact(text: str) -> str:
    redacted = text
    for pattern in _SENSITIVE_PATTERNS:
        redacted = pattern.sub(r"\1[REDACTED]", redacted)
    return redacted


class RedactingFormatter(logging.Formatter):
    """Formatter that redacts common secret patterns from messages."""

    def format(self, record: logging.LogRecord) -> str:
        original = super().format(record)
        try:
            return redact(original)
        except Exception:
            return original


def configure_logging(level: str = "INFO") -> logging.Logger:
    """Configure root logging once; return the app logger."""
    root = logging.getLogger()
    if getattr(root, "_ivp_configured", False):
        return logging.getLogger("industrial-vision")

    handler = logging.StreamHandler()
    formatter = RedactingFormatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    handler.setFormatter(formatter)
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root._ivp_configured = True  # type: ignore[attr-defined]
    return logging.getLogger("industrial-vision")


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
