# Observability (V20)

Prometheus metrics, alert rules, and structured logging for the platform.
V20 wires the previously-declared-but-unemitted series and fixes the worker
staleness alert; it adds **no new metric names**.

## Metrics endpoint

`GET /metrics` serves the Prometheus exposition format. Access is controlled
by `METRICS_ACCESS`: in production it must be `internal` (loopback / private
monitoring network) — public scraping fails startup validation. The endpoint
refreshes `ivp_app_uptime_seconds` on each scrape.

## Metric catalog (bounded labels only)

Labels are always small, fixed sets (route **templates**, methods, status
classes, worker names, operation names, channels). Never camera/incident IDs,
raw URLs, IPs, or exception messages.

### HTTP

| Metric | Type | Labels |
|---|---|---|
| `ivp_http_requests_total` | counter | `service`, `method`, `route`, `status_class` |
| `ivp_http_request_duration_seconds` | histogram | `service`, `method`, `route` |
| `ivp_http_requests_in_flight` | gauge | `service`, `method` |
| `ivp_http_errors_total` | counter | `service`, `route`, `status_class` |

`status_class` is one of `2xx`/`4xx`/`5xx`.

### Process

| Metric | Type | Notes |
|---|---|---|
| `ivp_app` (Info) | info | build/environment info |
| `ivp_app_start_time_seconds` | gauge | set via `mark_start()` at app creation |
| `ivp_app_uptime_seconds` | gauge | refreshed on each scrape |

### Domain

| Metric | Type | Labels |
|---|---|---|
| `ivp_camera_connection_attempts_total` | counter | `service`, `outcome` |
| `ivp_cameras_connected` | gauge | `service` |
| `ivp_inference_requests_total` | counter | `service`, `outcome` |
| `ivp_inference_duration_seconds` | histogram | `service` |

### Reliability (wired in V20)

| Metric | Type | Labels | Emitted by |
|---|---|---|---|
| `ivp_outbox_processed_total` | counter | `service`, `outcome` | outbox publisher (`delivered`/`retried`/`dead`/`invalid`) |
| `ivp_notification_delivery_total` | counter | `service`, `channel`, `outcome` | alerting delivery (`delivered`/`retried`/`terminal`/`muted`/`unconfigured`/`notification_missing`) |
| `ivp_worker_last_success_timestamp_seconds` | gauge | `service`, `worker` | `ManagedWorker` heartbeat |
| `ivp_worker_failures_total` | counter | `service`, `worker`, `error_category` | `ManagedWorker` failure |
| `ivp_redis_errors_total` | counter | `service`, `operation` | Redis ping/subscribe/subscribe-poll |
| `ivp_db_errors_total` | counter | `service`, `operation` | session acquisition, outbox claim, delivery claim |

`error_category` is a normalized, bounded string (e.g. `timeout`,
`connection`, `value`, `runtime`, `unknown`), truncated to 64 chars — never a
raw exception message.

## Alert rules

`monitoring/prometheus/alerts.yml` (group `industrial-vision`):

| Alert | Severity | Signal |
|---|---|---|
| `HighApiErrorRate` | warning | `>5%` error ratio over 5m. |
| `ApiLatencyHigh` | warning | p95 latency `>2s` over 5m. |
| `WorkerStale` | critical | a worker has not succeeded in `>300s`, **or** the series is entirely absent (`absent(...)`), so a never-started/dead heartbeat cannot hide. |
| `WorkerFailures` | warning | any worker failing for 10m. |
| `OutboxDeadEvents` | critical | any outbox event reached `dead` in 10m. |
| `NotificationDeliveryFailures` | warning | any `terminal`/`unconfigured` notification in 10m. |
| `DatabaseErrorRate` | warning | sustained DB errors over 5m. |
| `RedisErrorRate` | warning | sustained Redis errors over 5m. |

Every rule references an existing series above; no rule depends on a metric
that is never emitted.

## Logging

Structured JSON logs (default in production) with:
- request context (bounded request ID, method, route template),
- a redaction filter that removes Bearer/Basic/Digest authorization values,
  cookie/CSRF/WS-ticket values, DSN and RTSP passwords, sensitive structured
  extras, and secrets inside exception tracebacks.

Logs never contain credentials, raw URLs with tokens, or full exception
messages that embed secrets. Tune verbosity with `LOG_LEVEL`.

## Dashboards

`compose.monitoring.yaml` runs Prometheus (scraping `/metrics`) and Grafana.
Both services carry healthchecks and log rotation. Grafana requires
`GRAFANA_ADMIN_PASSWORD`; Prometheus alert rules load from
`monitoring/prometheus/alerts.yml`.

## Verifying observability

```powershell
# Metrics exposed:
curl http://localhost:8000/metrics
# Rules parse and reference existing series:
docker compose -f compose.yaml -f compose.monitoring.yaml config -q
# Alert/rule file is valid Prometheus YAML:
promtool check rules monitoring/prometheus/alerts.yml   # if promtool available
```

If `promtool` is not installed, validate the file loads in the Prometheus
service container instead, and report the check honestly.
