"""Error envelope + taxonomy tests — stable shape, frozen V10 codes."""

from __future__ import annotations

from backend.app.core.exceptions import (
    ERROR_CODES,
    APIError,
    ConflictDomainError,
    DependencyUnavailableError,
    DomainError,
    ErrorEnvelope,
    InvalidStateDomainError,
    NotFoundDomainError,
    ServiceNotReadyError,
    ValidationDomainError,
    error_envelope,
    http_status_for_code,
)


def test_envelope_shape_matches_wire_contract() -> None:
    body = error_envelope("not_found", "incident not found", "abc123")
    assert body == {"error": {"code": "not_found", "message": "incident not found", "request_id": "abc123"}}
    assert "details" not in body["error"]


def test_envelope_details_only_when_truthy() -> None:
    with_details = error_envelope("invalid_transition", "nope", "abc123", {"code": "x"})
    assert with_details["error"]["details"] == {"code": "x"}
    empty_details = error_envelope("http_error", "nope", "abc123", {})
    assert "details" not in empty_details["error"]


def test_envelope_models_validate_wire_payloads() -> None:
    raw = {
        "error": {
            "code": "invalid_transition",
            "message": "Cannot transition OPEN -> CLOSED",
            "request_id": "abc123",
            "details": {"current_status": "OPEN", "attempted_status": "CLOSED"},
        }
    }
    parsed = ErrorEnvelope.model_validate(raw)
    assert isinstance(parsed.error, APIError)
    assert parsed.error.code == "invalid_transition"
    assert parsed.error.details is not None
    assert parsed.error.details["current_status"] == "OPEN"


def test_v10_codes_frozen_in_registry() -> None:
    assert ERROR_CODES["invalid_transition"]["status_code"] == 409
    assert ERROR_CODES["invalid_state"]["status_code"] == 409
    assert ERROR_CODES["not_found"]["status_code"] == 404
    assert ERROR_CODES["validation_error"]["status_code"] == 422
    assert ERROR_CODES["internal_error"]["status_code"] == 500


def test_new_taxonomy_codes() -> None:
    assert ERROR_CODES["VALIDATION_ERROR"]["status_code"] == 422
    assert ERROR_CODES["NOT_FOUND"]["status_code"] == 404
    assert ERROR_CODES["CONFLICT"]["status_code"] == 409
    assert ERROR_CODES["INVALID_STATE"]["status_code"] == 409
    assert ERROR_CODES["INVALID_TRANSITION"]["status_code"] == 409
    assert ERROR_CODES["DEPENDENCY_UNAVAILABLE"]["status_code"] == 503
    assert ERROR_CODES["SERVICE_NOT_READY"]["status_code"] == 503
    assert ERROR_CODES["TIMEOUT"]["status_code"] == 504
    assert ERROR_CODES["INTERNAL_ERROR"]["status_code"] == 500


def test_domain_error_mapping() -> None:
    assert issubclass(ValidationDomainError, DomainError)
    assert ValidationDomainError("bad").status_code == 422
    assert NotFoundDomainError("gone").status_code == 404
    assert ConflictDomainError("clash").status_code == 409
    assert InvalidStateDomainError("closed").status_code == 409
    assert InvalidStateDomainError("closed").code == "invalid_state"
    assert DependencyUnavailableError("db").status_code == 503
    assert DependencyUnavailableError("db").code == "service_not_ready"
    assert ServiceNotReadyError("draining").status_code == 503


def test_http_status_for_code() -> None:
    assert http_status_for_code("SERVICE_NOT_READY") == 503
    assert http_status_for_code("invalid_transition") == 409
    assert http_status_for_code("no_such_code") == 500
