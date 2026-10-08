"""Structured application logging with secret redaction."""

from __future__ import annotations

import logging
import re

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


def log_api_error(
    logger: logging.Logger,
    *,
    request_id: str,
    method: str,
    path: str,
    status: int,
    latency_ms: float,
    code: str = "",
    message: str = "",
) -> None:
    """Structured API-error line (§16): request_id/method/path/status/latency."""
    logger.warning(
        "api_error request_id=%s method=%s path=%s status=%s latency_ms=%.2f code=%s message=%s",
        request_id,
        method,
        path,
        status,
        max(0.0, float(latency_ms)),
        code,
        redact(str(message))[:512],
    )


def log_worker_error(
    logger: logging.Logger,
    *,
    worker: str,
    component: str,
    error_type: str,
    message: str = "",
    camera_id: str | None = None,
) -> None:
    """Structured background-worker error line (§16). Never logs payloads."""
    logger.warning(
        "worker_error worker=%s component=%s error_type=%s camera_id=%s message=%s",
        worker,
        component,
        error_type,
        camera_id or "-",
        redact(str(message))[:512],
    )
