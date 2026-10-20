"""V20 metrics wiring — reliability emitters and alert/metric consistency."""

from __future__ import annotations

import re
from pathlib import Path

import yaml
from prometheus_client import REGISTRY, Counter, Histogram

import backend.app.core.metrics as metrics
from backend.app.core.metrics import (
    mark_start,
    record_db_error,
    record_notification_delivery,
    record_outbox_processed,
    record_redis_error,
    record_worker_failure,
    record_worker_heartbeat,
    refresh_uptime,
)

_SERVICE = "test-service"


def _value(name: str, labels: dict[str, str]) -> float:
    sample = REGISTRY.get_sample_value(name, labels)
    return sample or 0.0


def test_worker_heartbeat_sets_timestamp() -> None:
    before = _value(
        "ivp_worker_last_success_timestamp_seconds",
        {"service": _SERVICE, "worker": "hb-probe"},
    )
    record_worker_heartbeat("hb-probe", service=_SERVICE)
    after = _value(
        "ivp_worker_last_success_timestamp_seconds",
        {"service": _SERVICE, "worker": "hb-probe"},
    )
    assert after >= before
    assert after > 0


def test_worker_failure_increments_bounded_category() -> None:
    labels = {"service": _SERVICE, "worker": "w1", "error_category": "timeout"}
    before = _value("ivp_worker_failures_total", labels)
    record_worker_failure("w1", "timeout", service=_SERVICE)
    assert _value("ivp_worker_failures_total", labels) == before + 1


def test_worker_failure_empty_category_falls_back() -> None:
    labels = {"service": _SERVICE, "worker": "w2", "error_category": "unknown"}
    before = _value("ivp_worker_failures_total", labels)
    record_worker_failure("w2", "", service=_SERVICE)
    assert _value("ivp_worker_failures_total", labels) == before + 1


def test_outbox_and_notification_and_error_counters() -> None:
    outbox = {"service": _SERVICE, "outcome": "dead"}
    before = _value("ivp_outbox_processed_total", outbox)
    record_outbox_processed("dead", service=_SERVICE)
    assert _value("ivp_outbox_processed_total", outbox) == before + 1

    notif = {"service": _SERVICE, "channel": "email", "outcome": "terminal"}
    before = _value("ivp_notification_delivery_total", notif)
    record_notification_delivery("email", "terminal", service=_SERVICE)
    assert _value("ivp_notification_delivery_total", notif) == before + 1

    redis = {"service": _SERVICE, "operation": "ping"}
    before = _value("ivp_redis_errors_total", redis)
    record_redis_error("ping", service=_SERVICE)
    assert _value("ivp_redis_errors_total", redis) == before + 1

    db = {"service": _SERVICE, "operation": "session"}
    before = _value("ivp_db_errors_total", db)
    record_db_error("session", service=_SERVICE)
    assert _value("ivp_db_errors_total", db) == before + 1


def test_mark_start_and_refresh_uptime() -> None:
    mark_start(1_000_000.0)
    assert _value("ivp_app_start_time_seconds", {}) == 1_000_000.0
    refresh_uptime()
    assert _value("ivp_app_uptime_seconds", {}) >= 0.0


def _registered_metric_names() -> set[str]:
    allowed: set[str] = set()
    for value in vars(metrics).values():
        name = getattr(value, "_name", None)
        if not name:
            continue
        allowed.add(name)
        if isinstance(value, Histogram):
            allowed |= {f"{name}_bucket", f"{name}_count", f"{name}_sum"}
        if isinstance(value, Counter):
            allowed.add(f"{name}_total")
    return allowed


def _alert_metric_references() -> set[str]:
    alerts_path = Path(__file__).resolve().parents[3] / "monitoring" / "prometheus" / "alerts.yml"
    document = yaml.safe_load(alerts_path.read_text(encoding="utf-8"))
    referenced: set[str] = set()
    for group in document.get("groups", []):
        for rule in group.get("rules", []):
            referenced |= set(re.findall(r"\b(ivp_[a-z0-9_]+)\b", str(rule.get("expr", ""))))
    return referenced


def test_every_alert_metric_exists() -> None:
    referenced = _alert_metric_references()
    assert referenced, "alerts.yml must reference at least one ivp_ metric"
    missing = referenced - _registered_metric_names()
    assert not missing, f"alerts reference unregistered metrics: {sorted(missing)}"
