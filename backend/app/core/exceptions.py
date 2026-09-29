"""Application exception hierarchy + stable HTTP error envelope."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException


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
        return JSONResponse(
            status_code=422,
            content=error_envelope(
                "validation_error", "Request validation failed.", request_id, {"errors": exc.errors()}
            ),
        )

    @app.exception_handler(StarletteHTTPException)
    async def _handle_http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        request_id = getattr(request.state, "request_id", None) or uuid.uuid4().hex[:12]
        code = "not_found" if exc.status_code == 404 else "http_error"
        return JSONResponse(
            status_code=exc.status_code,
            content=error_envelope(code, str(exc.detail), request_id),
        )

    @app.exception_handler(Exception)
    async def _handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
        request_id = getattr(request.state, "request_id", None) or uuid.uuid4().hex[:12]
        # Never leak internals in production responses.
        return JSONResponse(
            status_code=500,
            content=error_envelope("internal_error", "An unexpected error occurred.", request_id),
        )
