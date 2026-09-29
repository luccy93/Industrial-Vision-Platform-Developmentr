# Video Ingestion — V02 Real-Time Pipeline

```text
USB Camera / RTSP / IP Camera / File
              ↓
        Camera Manager (PostgreSQL config)
              ↓
        Stream Manager (per-camera worker thread)
              ↓
        Frame Capture (OpenCV, off the event loop)
              ↓
        Frame Buffer (bounded, drop-oldest)
              ↓
       Frame Sampling (≈10 FPS from 30 FPS)
              ↓
       Preprocessing (resize / color / hooks)
              ↓
      Inference-ready Frame → V03 Inference Engine
```

## Supported camera types

| Type | `source_type` | `source` example | Notes |
|---|---|---|---|
| USB | `usb` | `"0"` or `"/dev/video0"` | Device index; configurable `width/height/target_fps` |
| RTSP/IP | `rtsp` | `rtsp://host:8554/live` | TCP transport, 5 s connect timeout, backoff reconnect |
| File | `file` | `data/videos/sample.mp4` | Loops; deterministic source for dev/test |

Camera configs persist in PostgreSQL (`cameras` table, Alembic `001_create_cameras`).
Runtime state (stream state, buffers, metrics) stays in memory by design —
writing per-frame telemetry to Postgres would create pointless load.

## USB setup

```json
POST /api/v1/cameras
{"name": "Line 1", "source_type": "usb", "source": "0", "width": 1280, "height": 720, "target_fps": 30}
```

No physical camera is required for startup, tests, or the file-source path.

## RTSP configuration

```json
{"name": "Gate", "source_type": "rtsp", "source": "rtsp://10.0.0.5/live", "source_secret": "user:password"}
```

- `source` holds the URL **without** credentials; `source_secret` is write-only
  (accepted on create/update, never returned, never logged).
- Connection failures move the stream to `ERROR` → `RECONNECTING` with
  exponential backoff (1 s → 30 s max) when `reconnect_enabled` is true.
- Logs/API only ever show the redacted form `rtsp://user:***@host/live`.

## Local video testing

Drop a small clip at `data/videos/sample.mp4` (do NOT commit large binaries;
tests synthesize frames with NumPy/OpenCV instead):

```json
{"name": "Dev", "source_type": "file", "source": "data/videos/sample.mp4"}
```

## Stream lifecycle

```text
DISCONNECTED → CONNECTING → CONNECTED → RUNNING → STOPPING → STOPPED
                    ↓            ↓           ↓
                  ERROR → RECONNECTING ──────┘
```

Transitions are validated (`StreamState.can_transition_to`); invalid ones are
logged and ignored. Control via:

```text
POST /api/v1/cameras/{id}/start
POST /api/v1/cameras/{id}/stop
GET  /api/v1/cameras/{id}/status   # honest state, never faked
```

## Frame buffering

`FrameBuffer` is a fixed-capacity deque (default 30, `BUFFER_SIZE`). On
overflow the **oldest** frame is dropped so latency stays bounded — stale
frames are worthless for realtime control; drops are counted in metrics.

## Frame sampling

`TARGET_PROCESSING_FPS` (default 10) + `FRAME_SKIP` decimate the source rate:
a 30 FPS camera yields ≈10 FPS for downstream stages without frame copies
(frames pass by reference until preprocessing allocates its output).

## Metrics

`GET …/status` exposes `state, source_fps, processing_fps, frames_received,
frames_processed, frames_dropped, latency_ms, width, height, uptime_seconds,
reconnect_count`. No monitoring platform yet — V03+ decides what to persist.

## WebSocket telemetry

`GET /ws/cameras/{camera_id}` sends JSON text frames (~2 Hz):

- `stream_status` — `{camera_id, state, timestamp}`
- `frame` — frame metadata + fps/latency/drop counters (never image bytes)
- `stream_error` — `{code, message}` (`CAMERA_NOT_FOUND`, `STREAM_DISCONNECTED`)

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `ERROR` + reconnects | bad RTSP URL / host down | check URL, network, `source_secret` |
| `frames_dropped` climbs | processing slower than source | lower `TARGET_PROCESSING_FPS`, raise `BUFFER_SIZE` |
| `CONNECTING` forever (file) | missing path | verify file exists in container mount |
| API 500 on cameras | DB unreachable | check `DATABASE_URL`, run `alembic upgrade head` |

## Known limits (V02)

- File sources run unthrottled (as fast as OpenCV decodes); USB/RTSP are hardware-paced.
- One worker thread per camera; validated to 4 concurrent streams (see perf tests).
- No auth on API/WS yet; no persisted metrics history; no GPU path (V03+).
