"""Prometheus metrics for the Industrial Vision Platform (V18).

Bounded label sets only: route templates, methods, status classes, service.
Never user/camera/incident IDs, raw URLs, IPs or exception messages.
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram, Info, REGISTRY
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

SERVICE_LABEL = "service"

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


def status_class(code: int) -> str:
    if code < 400:
        return "2xx"
    if code < 500:
        return "4xx"
    return "5xx"


def record_request(service, method, route, status_code, duration_seconds):
    sc = status_class(int(status_code))
    http_requests_total.labels(service=service, method=method, route=route, status_class=sc).inc()
    http_request_duration_seconds.labels(service=service, method=method, route=route).observe(duration_seconds)
    if int(status_code) >= 400:
        http_errors_total.labels(service=service, route=route, status_class=sc).inc()


def metrics_payload() -> bytes:
    return generate_latest(REGISTRY)


def metrics_content_type() -> str:
    return CONTENT_TYPE_LATEST