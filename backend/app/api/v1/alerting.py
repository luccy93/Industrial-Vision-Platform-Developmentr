"""Alerting operations API — rules, notifications, deliveries (V15).

Operator-facing management over durable alerting state. No authentication
exists on this platform (V16 owns it): these endpoints must not be exposed
to untrusted networks. No credentials ever appear in responses.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from starlette.exceptions import HTTPException

from backend.app.alerting.repository import (
    DeliveryNotFoundError,
    NotificationNotFoundError,
)
from backend.app.alerting.schemas import AlertChannel, SuppressionScope
from backend.app.infrastructure.db import get_db, get_session_factory

router = APIRouter(tags=["alerting"])

V16_WARNING = (
    "Alerting APIs have no authentication; do not expose them to untrusted "
    "networks until the V16 security volume lands."
)


def get_alert_repository(request: Request, session: Session = Depends(get_db)) -> Any:
    from backend.app.alerting.repository import AlertRepository as _AlertRepository

    factory = getattr(request.app.state, "session_factory", None)
    if factory is None:
        factory = get_session_factory(str(session.get_bind().url))  # type: ignore[union-attr]
    return _AlertRepository(factory)


def _alert_error(exc: Exception) -> HTTPException:
    from backend.app.alerting.repository import AlertRuleNotFoundError

    if isinstance(exc, AlertRuleNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, (NotificationNotFoundError, DeliveryNotFoundError)):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ValueError):
        return HTTPException(status_code=422, detail=str(exc))
    raise exc


def _parse_list(values: list[str]) -> list[str]:
    items: list[str] = []
    for value in values:
        items.extend(part.strip() for part in str(value).split(",") if part.strip())
    return items


class RuleCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=1024)
    enabled: bool = True
    domains: list[str] = Field(default_factory=list)
    event_types: list[str] = Field(default_factory=list)
    min_severity: str | None = None
    min_priority: str | None = None
    camera_ids: list[str] = Field(default_factory=list)
    incident_statuses: list[str] = Field(default_factory=list)
    channels: list[str] = Field(min_length=1)
    cooldown_seconds: int = Field(default=0, ge=0, le=86400)
    suppression_scope: str = "RULE"


class RulePatchRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=4096)
    enabled: bool | None = None
    domains: list[str] | None = None
    event_types: list[str] | None = None
    min_severity: str | None = None
    min_priority: str | None = None
    camera_ids: list[str] | None = None
    incident_statuses: list[str] | None = None
    channels: list[str] | None = None
    cooldown_seconds: int | None = Field(default=None, ge=0, le=86400)
    suppression_scope: str | None = None


def _rule_to_response(rule: Any) -> dict[str, Any]:
    return {
        "id": str(rule.id),
        "name": rule.name,
        "description": rule.description,
        "enabled": rule.enabled,
        "domains": list(rule.domains),
        "event_types": list(rule.event_types),
        "min_severity": rule.min_severity,
        "min_priority": rule.min_priority,
        "camera_ids": list(rule.camera_ids),
        "incident_statuses": list(rule.incident_statuses),
        "channels": [c.value if hasattr(c, "value") else str(c) for c in rule.channels],
        "cooldown_seconds": rule.cooldown_seconds,
        "suppression_scope": (
            rule.suppression_scope.value
            if hasattr(rule.suppression_scope, "value")
            else str(rule.suppression_scope)
        ),
        "trigger_count": rule.trigger_count,
        "suppressed_count": rule.suppressed_count,
        "last_triggered_at": rule.last_triggered_at.isoformat() if rule.last_triggered_at else None,
        "created_at": rule.created_at.isoformat() if rule.created_at else None,
        "updated_at": rule.updated_at.isoformat() if rule.updated_at else None,
    }


def _notification_to_response(item: Any) -> dict[str, Any]:
    return {
        "id": str(item.id),
        "rule_id": str(item.rule_id),
        "source_event_id": item.source_event_id,
        "source_domain": item.source_domain,
        "event_type": item.event_type,
        "camera_id": item.camera_id,
        "incident_id": item.incident_id,
        "title": item.title,
        "message": item.message,
        "severity": item.severity,
        "priority": item.priority,
        "context": dict(item.context or {}),
        "created_at": item.created_at.isoformat() if item.created_at else None,
    }


def _delivery_to_response(item: Any) -> dict[str, Any]:
    return {
        "id": str(item.id),
        "notification_id": str(item.notification_id),
        "channel": item.channel.value if hasattr(item.channel, "value") else str(item.channel),
        "destination": item.destination,
        "status": item.status.value if hasattr(item.status, "value") else str(item.status),
        "attempts": item.attempts,
        "next_retry_at": item.next_retry_at.isoformat() if item.next_retry_at else None,
        "last_attempt_at": item.last_attempt_at.isoformat() if item.last_attempt_at else None,
        "delivered_at": item.delivered_at.isoformat() if item.delivered_at else None,
        "last_error": item.last_error,
        "created_at": item.created_at.isoformat() if item.created_at else None,
    }


@router.get("/api/v1/alerting/status", summary="Alerting status")
def alerting_status(request: Request, repository: Any = Depends(get_alert_repository)) -> dict[str, Any]:
    """Engine state, channel availability, and delivery counters."""
    settings = getattr(request.app.state, "settings", None)
    enabled = bool(getattr(settings, "alerting_enabled", False)) if settings is not None else False
    evaluator = getattr(request.app.state, "alerting_evaluator", None)
    delivery_worker = getattr(request.app.state, "alerting_delivery", None)

    def _snapshot(worker: Any) -> dict[str, Any] | None:
        if worker is None:
            return None
        try:
            snapshot = worker.health()
            return {
                "state": snapshot.state.value if hasattr(snapshot.state, "value") else str(snapshot.state),
                "last_heartbeat": snapshot.last_heartbeat.isoformat() if snapshot.last_heartbeat else None,
                "restart_count": snapshot.restart_count,
                "last_error": snapshot.last_error,
            }
        except Exception:
            return {"state": "UNKNOWN"}

    channels: dict[str, Any] = {"in_app": {"available": True}}
    smtp_configured = False
    webhook_configured: list[str] = []
    if settings is not None:
        try:
            smtp_configured = bool(settings.alerting_smtp_configured)
        except Exception:
            smtp_configured = False
        try:
            webhook_configured = list(settings.alerting_webhook_allowlist)
        except Exception:
            webhook_configured = []
    channels["email"] = {"available": smtp_configured}
    channels["webhook"] = {"available": len(webhook_configured) > 0, "destinations": len(webhook_configured)}
    counts: dict[str, int] = {}
    try:
        counts = repository.delivery_counts()
    except Exception:
        counts = {}
    return {
        "enabled": enabled,
        "evaluator": _snapshot(evaluator),
        "delivery_worker": _snapshot(delivery_worker),
        "channels": channels,
        "deliveries": counts,
        "security_note": V16_WARNING,
    }


@router.get("/api/v1/alerting/rules", summary="List alert rules")
def list_rules(
    enabled: bool | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    repository: Any = Depends(get_alert_repository),
) -> dict[str, Any]:
    rules, total = repository.list_rules(enabled=enabled, page=page, page_size=page_size)
    return {
        "rules": [_rule_to_response(rule) for rule in rules],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.post("/api/v1/alerting/rules", summary="Create alert rule", status_code=201)
def create_rule(
    payload: RuleCreateRequest, repository: Any = Depends(get_alert_repository)
) -> dict[str, Any]:
    try:
        channels = [AlertChannel(str(channel).strip().lower()) for channel in payload.channels]
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"unknown alert channel: {exc}") from exc
    scope = SuppressionScope.RULE
    if payload.suppression_scope:
        try:
            scope = SuppressionScope(str(payload.suppression_scope).strip().upper())
        except ValueError as exc:
            raise HTTPException(
                status_code=422, detail=f"unknown suppression scope: {payload.suppression_scope!r}"
            ) from exc
    try:
        rule = repository.create_rule(
            name=payload.name,
            description=payload.description,
            enabled=payload.enabled,
            domains=payload.domains,
            event_types=payload.event_types,
            min_severity=payload.min_severity,
            min_priority=payload.min_priority,
            camera_ids=payload.camera_ids,
            incident_statuses=payload.incident_statuses,
            channels=channels,
            cooldown_seconds=payload.cooldown_seconds,
            suppression_scope=scope,
        )
    except Exception as exc:
        raise _alert_error(exc)
    return _rule_to_response(rule)


@router.get("/api/v1/alerting/rules/{rule_id}", summary="Get alert rule")
def get_rule(rule_id: str, repository: Any = Depends(get_alert_repository)) -> dict[str, Any]:
    rule = repository.get_rule(rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail=f"alert rule not found: {rule_id}")
    return _rule_to_response(rule)


@router.patch("/api/v1/alerting/rules/{rule_id}", summary="Update alert rule")
def patch_rule(
    rule_id: str, payload: RulePatchRequest, repository: Any = Depends(get_alert_repository)
) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    if payload.name is not None:
        fields["name"] = payload.name
    if payload.description is not None:
        fields["description"] = payload.description
    if payload.enabled is not None:
        fields["enabled"] = payload.enabled
    if payload.domains is not None:
        fields["domains"] = payload.domains
    if payload.event_types is not None:
        fields["event_types"] = payload.event_types
    if payload.min_severity is not None:
        fields["min_severity"] = payload.min_severity
    if payload.min_priority is not None:
        fields["min_priority"] = payload.min_priority
    if payload.camera_ids is not None:
        fields["camera_ids"] = payload.camera_ids
    if payload.incident_statuses is not None:
        fields["incident_statuses"] = payload.incident_statuses
    if payload.channels is not None:
        try:
            fields["channels"] = [AlertChannel(str(c).strip().lower()) for c in payload.channels]
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=f"unknown alert channel: {exc}") from exc
    if payload.cooldown_seconds is not None:
        fields["cooldown_seconds"] = payload.cooldown_seconds
    if payload.suppression_scope is not None:
        try:
            fields["suppression_scope"] = SuppressionScope(str(payload.suppression_scope).strip().upper())
        except ValueError as exc:
            raise HTTPException(
                status_code=422, detail=f"unknown suppression scope: {payload.suppression_scope!r}"
            ) from exc
    try:
        rule = repository.update_rule(rule_id, **fields)
    except Exception as exc:
        raise _alert_error(exc)
    if rule is None:
        raise HTTPException(status_code=404, detail=f"alert rule not found: {rule_id}")
    return _rule_to_response(rule)


@router.get("/api/v1/alerting/notifications", summary="List notifications")
def list_notifications(
    rule_id: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    domain: str | None = Query(default=None),
    camera_id: str | None = Query(default=None),
    incident_id: str | None = Query(default=None),
    created_from: datetime | None = Query(default=None),
    created_to: datetime | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    repository: Any = Depends(get_alert_repository),
) -> dict[str, Any]:
    items, total = repository.list_notifications(
        rule_id=rule_id,
        severity=severity,
        domain=domain,
        camera_id=camera_id,
        incident_id=incident_id,
        created_from=created_from,
        created_to=created_to,
        page=page,
        page_size=page_size,
    )
    return {
        "notifications": [_notification_to_response(item) for item in items],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/api/v1/alerting/notifications/{notification_id}", summary="Get notification")
def get_notification(
    notification_id: str, request: Request, repository: Any = Depends(get_alert_repository)
) -> dict[str, Any]:
    item = repository.get_notification(notification_id)
    if item is None:
        raise HTTPException(status_code=404, detail=f"notification not found: {notification_id}")
    deliveries, _ = repository.list_deliveries(notification_id=str(item.id))
    return {
        **_notification_to_response(item),
        "deliveries": [_delivery_to_response(delivery) for delivery in deliveries],
    }


@router.get("/api/v1/alerting/deliveries", summary="List deliveries")
def list_deliveries(
    notification_id: str | None = Query(default=None),
    channel: str | None = Query(default=None),
    status: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    repository: Any = Depends(get_alert_repository),
) -> dict[str, Any]:
    if channel is not None and channel not in ("in_app", "email", "webhook"):
        raise HTTPException(status_code=422, detail=f"unknown channel: {channel!r}")
    if status is not None and status not in ("pending", "sent", "failed"):
        raise HTTPException(status_code=422, detail=f"unknown delivery status: {status!r}")
    items, total = repository.list_deliveries(
        notification_id=notification_id,
        channel=channel,
        status=status,
        page=page,
        page_size=page_size,
    )
    return {
        "deliveries": [_delivery_to_response(item) for item in items],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.post("/api/v1/alerting/deliveries/{delivery_id}/retry", summary="Retry delivery")
def retry_delivery(delivery_id: str, repository: Any = Depends(get_alert_repository)) -> dict[str, Any]:
    """Requeue one failed delivery (idempotent; pending/sent are no-ops)."""
    delivery = repository.get_delivery(delivery_id)
    if delivery is None:
        raise HTTPException(status_code=404, detail=f"delivery not found: {delivery_id}")
    status = delivery.status.value if hasattr(delivery.status, "value") else str(delivery.status)
    if status == "sent":
        return {**_delivery_to_response(delivery), "retried": False}
    if status == "pending":
        return {**_delivery_to_response(delivery), "retried": False}
    updated = repository.mark_delivery(str(delivery.id), status="pending", next_retry_at=None)
    if updated is None:
        raise HTTPException(status_code=404, detail=f"delivery not found: {delivery_id}")
    return {**_delivery_to_response(updated), "retried": True}


__all__ = [
    "RuleCreateRequest",
    "RulePatchRequest",
    "get_alert_repository",
    "router",
]
