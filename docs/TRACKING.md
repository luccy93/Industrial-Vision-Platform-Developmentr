# Tracking — V04 Multi-Object Tracking Engine

```text
Camera → V02 Ingestion → V03 YOLO → V04 Tracking → TrackedObjects → WS/API → Frontend
```

> **V03 = Detection. V04 = Tracking. V05 = Industrial Safety Intelligence.**
> No safety, incident, or quality logic exists in this volume.

## Algorithm: native ByteTrack-compatible

No tracking library is installed and none is added. `backend/app/tracking/`
implements the ByteTrack idea with NumPy + `scipy.optimize.linear_sum_assignment`:

1. Split detections into **high** (`confidence >= TRACK_HIGH_CONF`) and **low** bands.
2. Stage-1: Hungarian association (cost `1 − IoU`) of high detections ↔ live tracks.
3. Stage-2: low detections ↔ still-unmatched tracks (weak detections continue
   tracks instead of being discarded — the key ByteTrack insight).
4. Unmatched **high** detections spawn new tracks; unmatched low ones are dropped.
5. Missed tracks → `LOST` → `REMOVED` past `TRACK_MAX_AGE`.

Intentional differences from upstream ByteTrack: no Kalman filter
(constant-position prediction), IoU-only matching without class gating (track
adopts the matched detection's class), no appearance/ReID embeddings. Do not
claim upstream equivalence; ReID is a documented V05+ possibility.

## Lifecycle

```text
Detection → new track → TENTATIVE → CONFIRMED (hits ≥ TRACK_MIN_HITS)
                              ↓              ↓ (missed frames)
                             LOST ←──────────┘
                              ↓ (time_since_update > TRACK_MAX_AGE)
                           REMOVED
```

`TRACK_MIN_HITS=3` default: one accidental detection never confirms (set `1`
only deliberately). A re-found `LOST` track returns to `CONFIRMED`.

## Identity

Track IDs are **per-camera** integers from 1. `(camera_id, track_id)` is the
unique identity — `cam-01/#17` and `cam-02/#17` are independent objects.
Each camera owns an isolated tracker; state never crosses cameras. Stream
restart resets that camera's tracker, so IDs safely restart at 1.

## History & velocity

Each track keeps a bounded deque (`TRACK_HISTORY_SIZE=30`) of
`timestamp/frame_id/bbox/confidence/center` — memory is constant. Velocity is
**image-space pixels/second** from center displacement over timestamp delta
(`velocity.{x,y,speed}`), `None`-safe until two observations exist. Never
interpret it as physical m/s: no calibration exists in V04.

## Metrics (in-memory)

Per camera: `active/confirmed/tentative/lost/created/removed` tracks,
`average_track_age`, `detections_processed`. Global: `tracking_fps`,
`average_latency_ms`, `tracking_updates`, `errors`. Nothing per-frame touches
PostgreSQL.

## Concurrency

Tracking runs inline in each camera's inference worker thread (sub-ms vs
ms-scale inference) — no extra threads/queues, never the FastAPI loop.
Failures are counted and isolated; streams continue.

## API & WebSocket

- `GET /api/v1/tracking/status` — algorithm, cameras, track counts, fps/latency.
- `GET /api/v1/cameras/{id}/tracks` — current runtime tracks only.
- `/ws/cameras/{id}` gains `tracking` messages
  (`frame_id, timestamp, tracks[]` with `track_id/state/age/hits/
  time_since_update/velocity`); `stream_status/frame/detection/stream_error`
  unchanged.

## Testing

Synthetic detections/frames only (no GPU/net/camera): the four lifecycle
cases (stable ID, gap survival, LOST→REMOVED, camera independence), gating,
multi-object/class, IoU math, history bound, velocity, metrics, API, WS, plus
perf bounds (50+ updates/s, 8-camera isolation, intermittent survival) and the
full V01–V03 regression.
