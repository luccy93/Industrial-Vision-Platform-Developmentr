"""Prometheus metrics for the Industrial Vision Platform (V18).

Bounded label sets only: route templates, methods, status classes, service.
Never user/camera/incident IDs, raw URLs, IPs or exception messages.
"""

from __future__ import annotations

import time

from prometheus_client import CONTENT_TYPE_LATEST, REGISTRY, Counter, Gauge, Histogram, Info, generate_latest

SERVICE_LABEL = "service"

#: Process start (unix seconds) for the uptime gauge. Set by ``mark_start``
#: when the app is created; falls back to module import time.
_PROCESS_START = time.time()

http_requests_total = Counter(
    "ivp_http_requests_total",
    "Total HTTP requests by route template, method and status class.",
    ["service", "method", "route", "status_class"],
)

http_request_duration_seconds = Histogram(
    "ivp_http_request_duration_seconds",
    "HTTP request duration by route template and method.",
    ["service", "method", "route"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

http_requests_in_flight = Gauge(
    "ivp_http_requests_in_flight",
    "HTTP requests currently in flight.",
    ["service", "method"],
)

http_errors_total = Counter(
    "ivp_http_errors_total",
    "HTTP error responses by route template and status class.",
    ["service", "route", "status_class"],
)

app_info = Info("ivp_app", "Application build/environment info.")
app_start_time = Gauge("ivp_app_start_time_seconds", "Process start time (unix seconds).")
app_uptime_seconds = Gauge("ivp_app_uptime_seconds", "Application uptime in seconds.")

# Domain metrics (bounded).
camera_connection_attempts_total = Counter(
    "ivp_camera_connection_attempts_total",
    "Camera connection attempts by outcome.",
    ["service", "outcome"],
)

camera_connected = Gauge(
    "ivp_cameras_connected",
    "Number of cameras currently in an authoritative connected state.",
    ["service"],
)

inference_requests_total = Counter(
    "ivp_inference_requests_total",
    "Inference requests by outcome.",
    ["service", "outcome"],
)

inference_duration_seconds = Histogram(
    "ivp_inference_duration_seconds",
    "Inference duration.",
    ["service"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

outbox_processed_total = Counter(
    "ivp_outbox_processed_total",
    "Durable outbox events processed by outcome.",
    ["service", "outcome"],
)

notification_delivery_total = Counter(
    "ivp_notification_delivery_total",
    "Notification delivery attempts by channel and outcome.",
    ["service", "channel", "outcome"],
)

worker_last_success_timestamp = Gauge(
    "ivp_worker_last_success_timestamp_seconds",
    "Unix timestamp of last successful worker cycle.",
    ["service", "worker"],
)

worker_failures_total = Counter(
    "ivp_worker_failures_total",
    "Worker failures by worker and error category.",
    ["service", "worker", "error_category"],
)

redis_errors_total = Counter(
    "ivp_redis_errors_total",
    "Redis operation errors by operation.",
    ["service", "operation"],
)

db_errors_total = Counter(
    "ivp_db_errors_total",
    "Database errors by operation.",
    ["service", "operation"],
)

# V33 continuous integrity auditing (bounded labels only).
integrity_audit_runs_total = Counter(
    "ivp_integrity_audit_runs_total",
    "Continuous integrity audit runs by trigger and terminal status.",
    ["service", "trigger", "status"],
)

integrity_audit_duration_seconds = Histogram(
    "ivp_integrity_audit_duration_seconds",
    "Continuous integrity audit duration by trigger.",
    ["service", "trigger"],
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 300.0),
)

integrity_findings_total = Counter(
    "ivp_integrity_findings_total",
    "Sanitized integrity findings by severity.",
    ["service", "severity"],
)

integrity_artifacts_checked_total = Counter(
    "ivp_integrity_artifacts_checked_total",
    "Protected artifacts checked by audit scope.",
    ["service", "scope"],
)

integrity_scope_failures_total = Counter(
    "ivp_integrity_scope_failures_total",
    "Audit scopes that failed or were unavailable by scope.",
    ["service", "scope"],
)

integrity_scheduler_runs_total = Counter(
    "ivp_integrity_scheduler_runs_total",
    "Integrity scheduler cycles by bounded outcome.",
    ["service", "outcome"],
)

integrity_last_success_timestamp = Gauge(
    "ivp_integrity_last_success_timestamp_seconds",
    "Unix timestamp of the last PASS integrity audit.",
    ["service"],
)

integrity_running_audits = Gauge(
    "ivp_integrity_running_audits",
    "Integrity audits currently running.",
    ["service"],
)

integrity_external_anchor_configured = Gauge(
    "ivp_integrity_external_anchor_configured",
    "Whether an external transparency anchor is configured (V33 is always 0 offline).",
    ["service"],
)


def status_class(code: int) -> str:
    if code < 400:
        return "2xx"
    if code < 500:
        return "4xx"
    return "5xx"


def record_request(service, method, route, status_code, duration_seconds):
    sc = status_class(int(status_code))
    http_requests_total.labels(service=service, method=method, route=route, status_class=sc).inc()
    http_request_duration_seconds.labels(service=service, method=method, route=route).observe(
        duration_seconds
    )
    if int(status_code) >= 400:
        http_errors_total.labels(service=service, route=route, status_class=sc).inc()


def _service(service: str | None = None) -> str:
    """Bounded service label; resolved from settings when not supplied."""
    if service:
        return str(service)
    try:
        from backend.app.core.config import get_settings

        return str(get_settings().service_name)
    except Exception:
        return "unknown"


def mark_start(ts: float | None = None) -> None:
    """Record process start time for ``ivp_app_uptime_seconds``."""
    global _PROCESS_START
    _PROCESS_START = time.time() if ts is None else float(ts)
    app_start_time.set(_PROCESS_START)


def refresh_uptime(service: str | None = None) -> None:
    """Update the uptime gauge (called on each scrape)."""
    app_uptime_seconds.set(max(0.0, time.time() - _PROCESS_START))


def record_worker_heartbeat(worker: str, service: str | None = None) -> None:
    """Mark a successful worker cycle (worker staleness alert input)."""
    worker_last_success_timestamp.labels(service=_service(service), worker=str(worker)).set(time.time())


def record_worker_failure(worker: str, error_category: str, service: str | None = None) -> None:
    worker_failures_total.labels(
        service=_service(service),
        worker=str(worker),
        error_category=(str(error_category)[:64] or "unknown"),
    ).inc()


def record_outbox_processed(outcome: str, service: str | None = None) -> None:
    outbox_processed_total.labels(service=_service(service), outcome=str(outcome)).inc()


def record_notification_delivery(channel: str, outcome: str, service: str | None = None) -> None:
    notification_delivery_total.labels(
        service=_service(service), channel=str(channel), outcome=str(outcome)
    ).inc()


def record_redis_error(operation: str, service: str | None = None) -> None:
    redis_errors_total.labels(service=_service(service), operation=str(operation)).inc()


def record_db_error(operation: str, service: str | None = None) -> None:
    db_errors_total.labels(service=_service(service), operation=str(operation)).inc()


def record_integrity_audit(
    *,
    trigger: str,
    status: str,
    duration_seconds: float,
    artifacts_by_scope: dict[str, int] | None = None,
    findings_by_severity: dict[str, int] | None = None,
    failed_scopes: dict[str, int] | None = None,
    external_anchor_configured: bool = False,
    service: str | None = None,
) -> None:
    """Record one terminal audit run using bounded labels only."""
    resolved = _service(service)
    integrity_audit_runs_total.labels(service=resolved, trigger=str(trigger), status=str(status)).inc()
    integrity_audit_duration_seconds.labels(service=resolved, trigger=str(trigger)).observe(
        max(0.0, float(duration_seconds))
    )
    for scope, count in (artifacts_by_scope or {}).items():
        if int(count) > 0:
            integrity_artifacts_checked_total.labels(service=resolved, scope=str(scope)).inc(int(count))
    for severity, count in (findings_by_severity or {}).items():
        if int(count) > 0:
            integrity_findings_total.labels(service=resolved, severity=str(severity)).inc(int(count))
    for scope, count in (failed_scopes or {}).items():
        if int(count) > 0:
            integrity_scope_failures_total.labels(service=resolved, scope=str(scope)).inc(int(count))
    integrity_external_anchor_configured.labels(service=resolved).set(
        1.0 if external_anchor_configured else 0.0
    )
    if str(status).upper() == "PASS":
        integrity_last_success_timestamp.labels(service=resolved).set(time.time())


def record_integrity_scheduler_run(outcome: str, service: str | None = None) -> None:
    integrity_scheduler_runs_total.labels(service=_service(service), outcome=str(outcome)).inc()


def set_integrity_running_audits(count: int, service: str | None = None) -> None:
    integrity_running_audits.labels(service=_service(service)).set(max(0, int(count)))


def set_integrity_external_anchor_configured(configured: bool, service: str | None = None) -> None:
    integrity_external_anchor_configured.labels(service=_service(service)).set(1.0 if configured else 0.0)


# ---------------------------------------------------------------------------
# V36 governance automation (bounded labels only)
# ---------------------------------------------------------------------------
governance_automation_jobs_total = Counter(
    "ivp_governance_automation_jobs_total",
    "Governance automation jobs by bounded type, trigger, and terminal status.",
    ["service", "job_type", "trigger", "status"],
)

governance_automation_job_duration_seconds = Histogram(
    "ivp_governance_automation_job_duration_seconds",
    "Governance automation job duration by bounded job type.",
    ["service", "job_type"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 300.0),
)

governance_automation_reminders_total = Counter(
    "ivp_governance_automation_reminders_total",
    "Governance reminder evaluations by bounded category and outcome.",
    ["service", "category", "outcome"],
)

governance_automation_snapshots_total = Counter(
    "ivp_governance_automation_snapshots_total",
    "Governance compliance snapshots by trigger and bounded status.",
    ["service", "trigger", "status"],
)

governance_automation_recoveries_total = Counter(
    "ivp_governance_automation_recoveries_total",
    "Recovered governance jobs by bounded job type.",
    ["service", "job_type"],
)

governance_automation_queue_depth = Gauge(
    "ivp_governance_automation_queue_depth",
    "Governance automation queue depth by bounded job status.",
    ["service", "status"],
)

_AUTOMATION_JOB_TYPES = frozenset(
    {
        "RETENTION_EVALUATION",
        "RETENTION_REVIEW_REMINDERS",
        "LEGAL_HOLD_REMINDERS",
        "DISPOSITION_REVIEW_REMINDERS",
        "EXPORT_APPROVAL_REMINDERS",
        "COMPLIANCE_SNAPSHOT",
        "GOVERNANCE_HEALTH_CHECK",
    }
)
_AUTOMATION_TRIGGERS = frozenset({"SCHEDULE", "MANUAL", "RETRY", "RECOVERY"})
_AUTOMATION_STATUSES = frozenset({"PENDING", "RUNNING", "SUCCEEDED", "FAILED", "CANCELLED", "UNAVAILABLE"})
_AUTOMATION_REMINDER_CATEGORIES = frozenset({"RETENTION", "LEGAL_HOLD", "DISPOSITION", "EXPORT_APPROVAL"})
_AUTOMATION_REMINDER_OUTCOMES = frozenset(
    {
        "QUEUED",
        "DEDUPLICATED",
        "COOLDOWN",
        "NO_RULE",
        "DISABLED",
        "MUTED",
        "NOOP",
        "ERROR",
    }
)
_AUTOMATION_SNAPSHOT_TRIGGERS = frozenset({"SCHEDULE", "MANUAL", "RETRY"})
_AUTOMATION_SNAPSHOT_STATUSES = frozenset({"CREATED", "REPLAYED", "FAILED"})


def _bounded_label(value: str | None, allowed: frozenset[str]) -> str:
    candidate = str(value or "").strip().upper()
    return candidate if candidate in allowed else "UNKNOWN"


def record_governance_automation_job(
    *,
    job_type: str,
    trigger: str,
    status: str,
    duration_seconds: float,
    service: str | None = None,
) -> None:
    """Record one terminal governance job using bounded labels only."""
    resolved = _service(service)
    bounded_type = _bounded_label(job_type, _AUTOMATION_JOB_TYPES)
    bounded_trigger = _bounded_label(trigger, _AUTOMATION_TRIGGERS)
    bounded_status = _bounded_label(status, _AUTOMATION_STATUSES)
    governance_automation_jobs_total.labels(
        service=resolved,
        job_type=bounded_type,
        trigger=bounded_trigger,
        status=bounded_status,
    ).inc()
    governance_automation_job_duration_seconds.labels(service=resolved, job_type=bounded_type).observe(
        max(0.0, float(duration_seconds))
    )


def record_governance_automation_reminder(category: str, outcome: str, service: str | None = None) -> None:
    governance_automation_reminders_total.labels(
        service=_service(service),
        category=_bounded_label(category, _AUTOMATION_REMINDER_CATEGORIES),
        outcome=_bounded_label(outcome, _AUTOMATION_REMINDER_OUTCOMES),
    ).inc()


def record_governance_automation_snapshot(trigger: str, status: str, service: str | None = None) -> None:
    governance_automation_snapshots_total.labels(
        service=_service(service),
        trigger=_bounded_label(trigger, _AUTOMATION_SNAPSHOT_TRIGGERS),
        status=_bounded_label(status, _AUTOMATION_SNAPSHOT_STATUSES),
    ).inc()


def record_governance_automation_recovery(job_type: str, service: str | None = None) -> None:
    governance_automation_recoveries_total.labels(
        service=_service(service),
        job_type=_bounded_label(job_type, _AUTOMATION_JOB_TYPES),
    ).inc()


def set_governance_automation_queue_depth(counts: dict[str, int], service: str | None = None) -> None:
    resolved = _service(service)
    for status, count in counts.items():
        governance_automation_queue_depth.labels(
            service=resolved, status=_bounded_label(status, _AUTOMATION_STATUSES)
        ).set(max(0, int(count)))


def metrics_payload() -> bytes:
    return generate_latest(REGISTRY)


def metrics_content_type() -> str:
    return CONTENT_TYPE_LATEST
