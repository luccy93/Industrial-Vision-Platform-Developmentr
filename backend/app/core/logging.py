"""Structured logging with secret redaction (V18).

JSON in production, text in dev/test. Redacts common secret patterns from
every emitted record. Request/correlation context is pulled from a
contextvar so log lines carry request_id, route template, status, etc.
"""

from __future__ import annotations

import logging
import re
from contextvars import ContextVar
from typing import Any

from pythonjsonlogger.json import JsonFormatter

_SENSITIVE_PATTERNS = (
    re.compile(r"(?i)(password\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(passwd\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(api[_-]?key\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(token\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(secret\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(authorization\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(cookie\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(csrf\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(ws[_-]?ticket\s*[:=]\s*)\S+"),
    # DSNs with credentials
    re.compile(r"(?i)(://[^/\s:]+:)[^@\s]+(@)"),
    # RTSP URLs with credentials
    re.compile(r"(?i)(rtsp://[^/\s:]+:)[^@\s]+(@)"),
)


def redact(text: str) -> str:
    redacted = text
    for pattern in _SENSITIVE_PATTERNS:
        redacted = pattern.sub(r"\1[REDACTED]\2" if pattern.groups >= 2 else r"\1[REDACTED]", redacted)
    return redacted


# Context carried alongside the request. Set by middleware.
_LOG_CONTEXT: ContextVar[dict[str, Any]] = ContextVar("ivp_log_context", default={})


def set_log_context(ctx: dict[str, Any]) -> Any:
    return _LOG_CONTEXT.set(ctx)


def reset_log_context(token: Any) -> None:
    _LOG_CONTEXT.reset(token)


def get_log_context() -> dict[str, Any]:
    return dict(_LOG_CONTEXT.get() or {})


class RedactingFilter(logging.Filter):
    """Inject context fields and redact sensitive substrings in every record."""

    def filter(self, record: logging.LogRecord) -> bool:
        ctx = get_log_context()
        for key, value in ctx.items():
            if not hasattr(record, key):
                setattr(record, key, value)
        # Redact message
        try:
            if isinstance(record.msg, str):
                record.msg = redact(record.msg)
        except Exception:
            pass
        # Redact args
        try:
            if record.args:
                if isinstance(record.args, dict):
                    record.args = {
                        k: (redact(str(v)) if isinstance(v, str) else v) for k, v in record.args.items()
                    }
                elif isinstance(record.args, tuple):
                    record.args = tuple(redact(str(a)) if isinstance(a, str) else a for a in record.args)
        except Exception:
            pass
        return True


class _TextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        original = super().format(record)
        try:
            return redact(original)
        except Exception:
            return original


def configure_logging(
    level: str = "INFO",
    fmt: str = "text",
    service: str = "industrial-vision-platform",
    environment: str = "development",
) -> logging.Logger:
    """Configure root logging once; return the app logger."""
    root = logging.getLogger()
    if getattr(root, "_ivp_configured", False):
        # Update level only.
        root.setLevel(getattr(logging, str(level).upper(), logging.INFO))
        return logging.getLogger("industrial-vision")

    handler = logging.StreamHandler()
    if fmt == "json":
        formatter = JsonFormatter(
            fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
            rename_fields={"asctime": "timestamp", "levelname": "level", "name": "logger"},
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    else:
        formatter = _TextFormatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    handler.setFormatter(formatter)
    handler.addFilter(RedactingFilter())
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, str(level).upper(), logging.INFO))
    root._ivp_configured = True  # type: ignore[attr-defined]
    # Stash service/env for filter enrichment via a global default context.
    _LOG_CONTEXT.set({"service": service, "environment": environment})
    return logging.getLogger("industrial-vision")


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def log_api_error(logger, *, request_id, method, path, status, latency_ms, code="", message=""):
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


def log_worker_error(logger, *, worker, component, error_type, message="", camera_id=None):
    logger.warning(
        "worker_error worker=%s component=%s error_type=%s camera_id=%s message=%s",
        worker,
        component,
        error_type,
        camera_id or "-",
        redact(str(message))[:512],
    )
