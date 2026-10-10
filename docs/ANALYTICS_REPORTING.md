# Analytics & Reporting — V14 Historical Layer

Route: `/analytics` (App Router, client-rendered). All metrics derive
from durable PostgreSQL records; nothing is invented, backfilled, or
approximated.

## Architecture

```text
/analytics page (filters → apply → parallel fetch, per-section isolation)
  ├─ lib/analytics/client.ts   (query builder, fetchers, CSV download)
  ├─ components/analytics/Charts.tsx (Recharts line/bars + table fallback)
  └─ backend GET /api/v1/analytics/{summary,trends,breakdowns,export}
```

## Endpoint contracts and query parameters

Shared: `start_at`, `end_at` (ISO-8601, tz-aware preferred; naive read
as UTC), `bucket` (hour|day|week), `domain`, `severity`, `camera_id`,
`status`, `priority`. Defaults: end = now, start = end − 7 days. Max
window 90 days (retention bound). Hour buckets cap at a 31-day window.
Violations return structured 422s (`validation_error`); unknown
metrics/datasets/groupings/report types are rejected explicitly.

- `GET /api/v1/analytics/summary` — historical overview for the window
  (replaces the V01 placeholder; bare path still 200).
- `GET /api/v1/analytics/trends?metric=events|incidents_created|
  incidents_resolved|incidents_closed` — UTC-aligned buckets.
- `GET /api/v1/analytics/breakdowns?dataset=events|incidents&
  group_by=...` — bounded groupings (`event_type` allowed for events;
  quality-outcome grouping rejected).
- `GET /api/v1/analytics/export?report=events|incidents|safety|
  camera_activity|quality_events` — CSV download (BOM, ≤5000 rows,
  over-limit fails 422 rather than truncating silently).

## Data sources and persistence limitations

- Canonical events: V12 `operational_events` (only incident-linked
  normalized events persist — a subset of all domain activity).
- Incidents: V10 records with full lifecycle timestamps.
- Quality inspection outcomes: **not persisted anywhere** — always
  `UNAVAILABLE`, never zero. `quality_events` exports recorded
  quality-domain *events*, explicitly not inspection counts or rates.
- Camera activity = linked-event counts per camera, never uptime.
- No FPS/latency/track/frame history exists; current in-memory metrics
  display as current status only, never as history.

## Metric definitions, denominators, timestamp semantics

- **Total events:** distinct canonical event IDs with `first_seen` in
  `[start, end)`.
- **Severity/domain breakdowns:** source-defined severity; missing
  severity stored as `UNKNOWN`.
- **Incidents created:** `created_at` in `[start, end)`, grouped by
  current status/priority.
- **Currently open:** present-state count (status ≠ CLOSED), labeled as
  current state, not state-at-time.
- **Resolved/closed:** `resolved_at`/`closed_at` in `[start, end)`.
- **Resolution duration:** terminal = `closed_at` else `resolved_at`;
  only pairs with valid timestamps and terminal ≥ created; denominator
  = valid-pair count; nulls when zero. Avg/median/min/max in seconds.
- **Quality rates:** unsupported (no denominator exists).
- **Camera activity:** qualifying persisted events + created incidents
  per camera.

## Timezone and bucket boundaries

Aggregation in UTC; buckets inclusive-start/exclusive-end, aligned
(hour=:00, day=00:00, week=Monday 00:00). Display formatting uses local
time without changing aggregation. Empty buckets in range render as
genuine zeros (source available); no backfill of unavailable periods.

## Current vs historical metrics

`GET /api/v1/operations/summary` (V13) is the live snapshot;
`/api/v1/analytics/*` is history. They answer different questions and
are never mixed into one unnamed count.

## Event identity and deduplication

Counts use canonical `event_id`s; incident links never inflate event
totals (history rows are unique by identity, links are associations).
Legacy orphan `incident_events` IDs are preserved and excluded from
history aggregates — never fabricated.

## Legacy orphans

Pre-V12 incident links may reference events with no history row. They
are reported via `count_orphan_links()`, counted nowhere, and left
intact.

## Index and query-efficiency rationale

EXPLAIN proved scans on the V14 patterns, so `007` adds
`ix_incidents_resolved_at`, `ix_incidents_closed_at`, and
`ix_operational_events_first_seen` (`created_at` indexed since 005).
One grouped query per aggregate; bounded window reads (≤5000,
`truncated` flag); no per-bucket/per-camera query loops; short
transactions; no summary tables, caches, or materialized views.

## Report/export types and limits

Reports: `events`, `incidents`, `safety` (SAFETY+SPATIAL domains),
`camera_activity`, `quality_events` (recorded events, labeled as such).
Bare `quality` and unknown types → explicit 422. Window ≤90 days,
rows ≤5000, chunks of 500.

## CSV escaping and formula-injection handling

Python `csv` module quoting (delimiters/quotes/line-breaks); UTF-8 with
single leading BOM for Excel; cells starting with `= + - @` or tab/CR
get a `'` prefix. Datetimes ISO-8601. Filenames
`analytics-{report}-{YYYYMMDD}-{YYYYMMDD}.csv` contain no user input.
No credentials, source URLs, stack traces, or personal data exported.

## Failure, partial-availability, no-data semantics

Per-section `ok|degraded|unavailable` + message; one failed section
never breaks others; empty windows render genuine-zero states;
over-limit exports fail loudly. Stale results show until Apply refreshes.

## Unsupported historical metrics

FPS curves, camera uptime %, inference latency trends, inspection
PASS/FAIL rates and trends — no underlying records exist. Listed here
so their absence is a documented decision, not a gap.

## Tests

- Backend: `pytest backend/tests/integration/test_analytics_api.py
  backend/tests/integration/test_analytics_repositories.py
  backend/tests/unit/test_analytics_contracts.py` (+ migration cycle).
- Frontend: `npm run test:run` (analytics suites), `npm run typecheck`,
  `npm run build`.
