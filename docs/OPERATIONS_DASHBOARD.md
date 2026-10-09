# Operations Dashboard — V13 Command Center

Route: `/dashboard` (App Router, client-rendered). No mocks: every panel
reads real backend contracts; empty deployments render intentional empty
states, never fabricated data.

## Architecture

```text
/dashboard page (orchestration: fetch timers, socket, merge, filters)
  ├─ lib/operations/client.ts   (typed fetchers, envelope errors, freshness)
  ├─ lib/operations/timeline.ts (pure normalize / merge / filter logic)
  ├─ lib/websocket/useOperationsSocket.ts (one shared /ws/operations socket)
  └─ components/operations/    (SummaryCards, CameraGrid, EventTimeline,
                                 IncidentQueue, Panels, primitives)
```

## Reused backend APIs

- `GET /api/v1/operations/summary` — snapshot for the six summary cards
  (15s refresh).
- `GET /api/v1/cameras` + `GET /api/v1/cameras/{id}/status` (+ detections
  limit=1, tracks) — camera grid (10s refresh).
- Per-camera `safety/events`, `quality/events`, `autonomous/events`,
  `intelligence/events`, `intelligence/clusters` (bounded limits, first 10
  cameras) + open incidents list — timeline baseline (20s refresh).
- `GET /api/v1/incidents?status=OPEN,...` — read-only queue (15s).
- `GET /api/v1/health` — subsystem component list (30s).

## Real-time subscription strategy

One shared `/ws/operations` socket per dashboard session (never one
socket per camera). The socket multiplexes `stream_status` lifecycle
deltas + the 18 locked bus event types as V12 envelopes; frames,
detections, and tracking are never carried. Unknown/malformed messages
are ignored at the boundary. Socket messages merge incrementally into
the timeline (stable-ID dedup, bounded at 200); REST stays authoritative.

## Reconnection and REST reconciliation

Exponential backoff with jitter (cap 15s), visibility pause, cleanup on
unmount, single active connection. On live-transition after reconnect,
the page re-baselines every REST snapshot, then resumes deltas (no
assumption that every missed event arrived).

## Health versus readiness semantics

`/live` = process alive only. Readiness (`ready` flag) gates the header
state; subsystem components render individually. A 200 from `/live` is
never shown as full readiness. Redis `DISABLED` (local mode) renders as
informational, not failure. Risk renders as an operational heuristic
with an explicit non-probability label.

## Camera preview capability and transport limits

No browser-compatible video transport exists: the WebSocket carries
frame *metadata* only (no image bytes), and no MJPEG/base64 route
exists. Cards show a labelled preview-unavailable note with real stream
metadata (state, FPS, latency, tracks, freshness) and link to
`/cameras`. Browser video transport is a separate future capability;
image bytes must never be pushed through the metadata socket.

## Empty, error, partial-availability, and stale behavior

- Loading skeletons → intentional empty text (genuine zeros) → amber
  error panels that never replace failed state with empty data.
- Per-panel isolation: a quality failure leaves cameras/incidents usable.
- Stale banners when a panel exceeds twice its refresh interval.
- `NOT_CONFIGURED` quality model renders as unavailable, never PASS.
- Disabled engines, missing cameras, and stopped streams each have
  distinct honest states.

## Performance and buffer limits

- Timeline bounded at 200 items (newest 100 rendered).
- Per-camera event fetches capped (50/100/50); cameras capped at 10 for
  timeline fan-out; incident queue shows 10 of N.
- Memoized sections and derived lists; stable React keys; all timers
  and AbortControllers cleaned on unmount; no global store.

## Tests

- `npm run test:run` (Vitest + RTL + jsdom, offline, mocked fetch/sockets).
- `npm run typecheck`, `npm run build`.
- Backend: `pytest backend/tests/integration/test_operations_api.py
  backend/tests/integration/test_operations_ws.py` (+ full suite).
