"""Application exception hierarchy + stable HTTP error envelope."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

# ----------------------------------------------------------------------
# Centralized error-code registry (§13). New infrastructure errors use
# UPPER_SNAKE codes. Domain codes keep their established lowercase values
# (notably V10 `invalid_transition` / `invalid_state`) for backward
# compatibility — never renamed, never silently changed.
# ----------------------------------------------------------------------
ERROR_CODES: dict[str, dict[str, Any]] = {
    "VALIDATION_ERROR": {"status_code": 422, "message": "Request validation failed."},
    "NOT_FOUND": {"status_code": 404, "message": "Resource not found."},
    "CONFLICT": {"status_code": 409, "message": "Conflicting state."},
    "INVALID_STATE": {"status_code": 409, "message": "Operation not allowed in the current state."},
    "INVALID_TRANSITION": {"status_code": 409, "message": "Lifecycle transition not allowed."},
    "DEPENDENCY_UNAVAILABLE": {"status_code": 503, "message": "A required dependency is unavailable."},
    "SERVICE_NOT_READY": {"status_code": 503, "message": "Service is not ready to serve traffic."},
    "TIMEOUT": {"status_code": 504, "message": "An internal operation timed out."},
    "INTERNAL_ERROR": {"status_code": 500, "message": "An unexpected error occurred."},
    # Established domain codes (frozen for compatibility):
    "invalid_transition": {"status_code": 409, "message": "Lifecycle transition not allowed."},
    "invalid_state": {"status_code": 409, "message": "Operation not allowed in the current state."},
    "not_found": {"status_code": 404, "message": "Resource not found."},
    "http_error": {"status_code": 500, "message": "An unexpected error occurred."},
    "validation_error": {"status_code": 422, "message": "Request validation failed."},
    "internal_error": {"status_code": 500, "message": "An unexpected error occurred."},
}


class ErrorDetail(BaseModel):
    """Structured per-error details (free-form, JSON-safe)."""

    model_config = {"extra": "allow"}

    code: str = Field(min_length=1, max_length=128)
    message: str = Field(default="", max_length=4096)


class APIError(BaseModel):
    """The inner `error` object of the envelope (§12)."""

    model_config = {"extra": "allow"}

    code: str = Field(min_length=1, max_length=128)
    message: str = Field(default="", max_length=4096)
    details: dict[str, Any] | None = None
    request_id: str = Field(min_length=1, max_length=128)


class ErrorEnvelope(BaseModel):
    """Stable API error shape: {"error": {...}} (§12).

    Documents the wire contract; rendering stays in `error_envelope()`
    so the V01–V10 byte shape (notably: `details` omitted when empty)
    is preserved exactly.
    """

    model_config = {"extra": "allow"}

    error: APIError


class AppError(Exception):
    """Base typed application error."""

    code: str = "internal_error"
    message: str = "An unexpected error occurred."
    status_code: int = 500

    def __init__(
        self,
        message: str | None = None,
        *,
        code: str | None = None,
        status_code: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message or self.message)
        if message:
            self.message = message
        if code:
            self.code = code
        if status_code:
            self.status_code = status_code
        self.details = details or {}


class ConfigurationError(AppError):
    code = "configuration_error"
    message = "Invalid application configuration."
    status_code = 500


class ValidationError(AppError):
    code = "validation_error"
    message = "Request validation failed."
    status_code = 422


class CameraError(AppError):
    code = "camera_error"
    message = "Camera operation failed."
    status_code = 502


class StreamError(AppError):
    code = "stream_error"
    message = "Video stream operation failed."
    status_code = 502


class InferenceError(AppError):
    code = "inference_error"
    message = "AI inference failed."
    status_code = 502


class StorageError(AppError):
    code = "storage_error"
    message = "Storage operation failed."
    status_code = 503


class ServiceUnavailableError(AppError):
    code = "service_unavailable"
    message = "A required service is unavailable."
    status_code = 503


# ----------------------------------------------------------------------
# Domain exceptions (§18). Business logic raises these instead of bare
# ValueError / try/except Exception; the central handler maps them to
# HTTP responses consistently. Subclasses carry explicit wire codes so
# established domain codes are never silently changed.
# ----------------------------------------------------------------------
class DomainError(AppError):
    """Base for typed domain failures (mapped centrally to HTTP)."""


class ValidationDomainError(DomainError):
    code = "validation_error"
    message = "Domain validation failed."
    status_code = 422


class NotFoundDomainError(DomainError):
    code = "not_found"
    message = "Resource not found."
    status_code = 404


class ConflictDomainError(DomainError):
    code = "http_error"
    message = "Conflicting state."
    status_code = 409


class InvalidStateDomainError(DomainError):
    code = "invalid_state"
    message = "Operation not allowed in the current state."
    status_code = 409


class DependencyUnavailableError(DomainError):
    code = "service_not_ready"
    message = "A required dependency is unavailable."
    status_code = 503


class ServiceNotReadyError(DomainError):
    code = "service_not_ready"
    message = "Service is not ready to serve traffic."
    status_code = 503


def http_status_for_code(code: str) -> int:
    """Look up the canonical HTTP status for a registry code (§13)."""
    entry = ERROR_CODES.get(str(code))
    if entry is None:
        return 500
    try:
        return int(entry.get("status_code", 500))
    except (TypeError, ValueError):
        return 500


def error_envelope(
    code: str, message: str, request_id: str, details: dict[str, Any] | None = None
) -> dict[str, Any]:
    body: dict[str, Any] = {"error": {"code": code, "message": message, "request_id": request_id}}
    if details:
        body["error"]["details"] = details
    return body


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _handle_app_error(request: Request, exc: AppError) -> JSONResponse:
        request_id = getattr(request.state, "request_id", None) or uuid.uuid4().hex[:12]
        return JSONResponse(
            status_code=exc.status_code,
            content=error_envelope(exc.code, exc.message, request_id, exc.details or None),
        )

    @app.exception_handler(RequestValidationError)
    async def _handle_validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        request_id = getattr(request.state, "request_id", None) or uuid.uuid4().hex[:12]
        # Model-level validators embed the raw exception in `ctx`, which is
        # not JSON-serializable — stringify fallbacks without changing
        # serializable values.
        import json

        details = json.loads(json.dumps({"errors": exc.errors()}, default=str))
        return JSONResponse(
            status_code=422,
            content=error_envelope("validation_error", "Request validation failed.", request_id, details),
        )

    @app.exception_handler(StarletteHTTPException)
    async def _handle_http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        request_id = getattr(request.state, "request_id", None) or uuid.uuid4().hex[:12]
        detail = exc.detail
        if isinstance(detail, dict):
            # Structured details (e.g. invalid_transition) are preserved
            # verbatim under `details` instead of being stringified.
            code = "not_found" if exc.status_code == 404 else str(detail.get("code") or "http_error")
            message = str(detail.get("message") or detail)
            return JSONResponse(
                status_code=exc.status_code,
                content=error_envelope(code, message, request_id, detail),
            )
        code = "not_found" if exc.status_code == 404 else "http_error"
        return JSONResponse(
            status_code=exc.status_code,
            content=error_envelope(code, str(detail), request_id),
        )

    @app.exception_handler(Exception)
    async def _handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
        request_id = getattr(request.state, "request_id", None) or uuid.uuid4().hex[:12]
        # Never leak internals in production responses.
        return JSONResponse(
            status_code=500,
            content=error_envelope("internal_error", "An unexpected error occurred.", request_id),
        )
