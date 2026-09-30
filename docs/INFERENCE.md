# Inference — V03 Object Detection Engine

```text
Camera → V02 Ingestion → Frame Buffer → Sampling → V03 Inference Engine
  → YOLO → Detections → Detection Events → WebSocket / API → Frontend
```

> **V03 = detection. V04 = tracking.** No track IDs, safety events, or
> incidents exist in this volume.

## Model architecture

```text
Frame → InferenceModel (ABC) → InferenceResult → Detection[]
              ├── YOLOModel      (production, Ultralytics)
              └── MockModel      (tests, deterministic)
```

The stream pipeline depends only on `InferenceModel`; swapping backends never
touches capture code. Future models (V04+) implement the same interface.

## Model configuration

| Key | Default | Notes |
|---|---|---|
| `MODEL_NAME` | `yolo11n` | label used in results/metrics |
| `MODEL_PATH` | `models/yolo11n.pt` | weights file (external artifact) |
| `MODEL_DEVICE` | `auto` | `auto`→cuda iff available else cpu; explicit `cuda` without CUDA is a structured error, never a crash |
| `MODEL_CONFIDENCE_THRESHOLD` | `0.5` | applied post-inference |
| `MODEL_IOU_THRESHOLD` | `0.45` | NMS IoU |
| `MODEL_IMAGE_SIZE` | `640` | inference resolution |
| `MODEL_MAX_DETECTIONS` | `300` | cap per frame |
| `MODEL_CLASSES` | empty | allowlist e.g. `person,car`; empty = all classes |

## Lifecycle

- **Lazy, load-once**: the shared `ModelManager` loads on first inference;
  concurrent callers share the single load. Per-frame latency excludes load time.
- **Thread-safe**: prediction guarded by lock; one reusable instance.
- **Status**: `model_name, model_path, device, classes, loaded` via
  `GET /api/v1/inference/status`. Missing weights → `NOT_READY` /
  `MODEL_NOT_FOUND`; the app still boots and streams still run.
- **Weights are never committed or silently downloaded.** `models/` holds only
  `.gitkeep`. Obtain explicitly:
  `python -m backend.app.inference.smoke_test --download`, or place a `.pt`
  at `MODEL_PATH`. The normal test suite needs no weights/GPU/internet.

## Detection schema

`x1,y1` top-left → `x2,y2` bottom-right, **original frame pixels** (the adapter
rescales letterboxed predictions back). Each detection carries `id, camera_id,
frame_id, timestamp, class_id, class_name, confidence, bounding_box,
model_name, inference_time_ms, metadata`. Results serialize for API/WS.

## Pipeline & backpressure

`Frame → Preprocessing → Model Inference → Postprocessing → Validation →
InferenceResult`, latency measured per pass. Each camera gets an inference
worker pulling the **latest** buffered frame into a bounded queue
(`drop_oldest` on overflow): when inference lags capture, stale frames drop
and memory stays constant (e.g. 30 FPS camera / 10 FPS inference ≈ 20 frames
skipped). Inference errors increment counters and never kill the stream.

## Metrics (in-memory)

`inference_count, inference_fps, average_inference_ms, last_inference_ms,
detections_per_frame, frames_with_detections, model_load_time_ms`. Nothing
per-frame is written to PostgreSQL in V03.

## WebSocket contract (`/ws/cameras/{id}`)

V02 messages unchanged, plus:

```json
{"type": "detection", "camera_id": "cam-001", "frame_id": "18427",
 "timestamp": "...", "detections": [{"class_id": 0, "class_name": "person",
 "confidence": 0.94, "bounding_box": {"x1": 312, "y1": 180, "x2": 612, "y2": 910}}],
 "inference_time_ms": 18.4, "model_name": "yolo"}
```

## Testing without GPU

Standard suite uses `MockModel` (deterministic, CPU, offline). Optional
`test_yolo_real.py` runs only when `models/yolo11n.pt` exists, else skips.
Smoke: `python -m backend.app.inference.smoke_test` prints `READY …` or
honest `SKIPPED` with the reason.

## Performance behavior

- Model loads once (verified: `load_calls == 1` across infers).
- Queue bounded; `dropped` counter proves backpressure instead of growth.
- Capture and inference run on worker threads; the FastAPI loop stays free.
- No frame copies between stages (references until preprocessing output).
- One inference failure → error counter, stream continues.

## Future tracking (V04)

`InferenceSupervisor` results rings feed the V04 tracker; detection schema
already carries stable `frame_id`/`timestamp` for association. No changes to
capture or inference interfaces are expected.
