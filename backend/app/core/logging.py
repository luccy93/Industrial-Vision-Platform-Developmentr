"""Structured logging with secret redaction (V18).

JSON in production, text in dev/test. Redacts common secret patterns from
every emitted record. Request/correlation context is pulled from a
contextvar so log lines carry request_id, route template, status, etc.
"""

from __future__ import annotations

import logging
from contextvars import ContextVar
from typing import Any

from pythonjsonlogger.json import JsonFormatter

from backend.app.core.redaction import redact_structure, redact_text

#: Structured record attributes that are never treated as free-form extras.
_STRUCTURAL_RECORD_ATTRS = frozenset(
    {"msg", "args", "exc_info", "exc_text", "stack_info", "message", "asctime"}
)


def redact(text: str) -> str:
    """Redact credentials from free-form log text using the V29 policy."""
    return redact_text(text)


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
        # Redact args, including nested structured values, before touching the
        # message template. Redacting a template such as ``token=%s`` would
        # consume the placeholder and make ``record.getMessage()`` raise.
        try:
            if record.args:
                if isinstance(record.args, dict):
                    record.args = redact_structure(record.args)
                elif isinstance(record.args, tuple):
                    record.args = tuple(redact_structure(arg) for arg in record.args)
                else:
                    record.args = redact_structure(record.args)
        except Exception:
            pass
        # Redact the message. When arguments are present, format first and
        # store the sanitized final message so the original placeholders are
        # never lost and the redacted values are used exactly once.
        try:
            if isinstance(record.msg, str):
                if record.args:
                    try:
                        message = record.getMessage()
                    except Exception:
                        message = record.msg
                    else:
                        record.args = ()
                    record.msg = redact(message)
                else:
                    record.msg = redact(record.msg)
            elif isinstance(record.msg, (dict, list, tuple)):
                record.msg = redact_structure(record.msg)
        except Exception:
            pass
        # Redact exception tracebacks. Setting `exc_text` (and leaving
        # `exc_info`) makes both the text and JSON formatters reuse the
        # redacted stack rather than formatting the raw one. A pre-set
        # `exc_text` (for example from an upstream handler or a custom
        # formatter) is sanitized too; otherwise a raw traceback could bypass
        # the filter entirely.
        try:
            if record.exc_info and not record.exc_text:
                record.exc_text = logging.Formatter().formatException(record.exc_info)
            if record.exc_text:
                record.exc_text = redact(record.exc_text)
        except Exception:
            pass
        try:
            if record.stack_info:
                record.stack_info = redact(record.stack_info)
        except Exception:
            pass
        # Redact free-form structured extras (attributes set via
        # `logger.info(..., extra={...})` or the log context).
        try:
            for key, value in list(record.__dict__.items()):
                if key in _STRUCTURAL_RECORD_ATTRS:
                    continue
                if isinstance(value, str):
                    cleaned = redact(value)
                    if cleaned != value:
                        setattr(record, key, cleaned)
                elif isinstance(value, (dict, list, tuple)):
                    setattr(record, key, redact_structure(value))
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
