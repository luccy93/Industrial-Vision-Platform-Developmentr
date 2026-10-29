"""Optional real-model smoke test — never part of the normal suite.

Usage:
    python -m backend.app.inference.smoke_test            # validate local weights
    python -m backend.app.inference.smoke_test --download # fetch MODEL_PATH explicitly
    python -m backend.app.inference.smoke_test --json --require-cuda

Reports READY with latency/detections, or honest SKIPPED when weights or
ultralytics are absent. ``--json`` emits one machine-readable object for release
evidence; ``--require-cuda`` exits non-zero unless inference actually ran on a
CUDA device. Exit code 0 in all non-error paths without ``--require-cuda``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from typing import Any

import numpy as np


def _cuda_state() -> dict[str, Any]:
    try:
        import torch
    except ImportError:
        return {"available": False, "device_count": 0, "torch": None}
    try:
        return {
            "available": bool(torch.cuda.is_available()),
            "device_count": int(torch.cuda.device_count()),
            "torch": str(torch.__version__),
        }
    except Exception:
        return {"available": False, "device_count": 0, "torch": None}


def _emit(payload: dict[str, Any], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, sort_keys=True))
        return
    status = payload.get("status")
    if status == "READY":
        print(
            "Real-model smoke test: READY\n"
            f"model={payload.get('model')} device={payload.get('device')} "
            f"classes={payload.get('classes')}\n"
            f"latency_ms={payload.get('latency_ms'):.1f} detections={payload.get('detections')}"
        )
    elif status == "SKIPPED":
        print(f"Real-model smoke test: SKIPPED\nReason: {payload.get('reason')}")
    else:
        print(f"Real-model smoke test: ERROR\nReason: {payload.get('reason')}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="YOLO real-model smoke test")
    parser.add_argument("--download", action="store_true", help="fetch weights explicitly")
    parser.add_argument("--model", default=os.environ.get("MODEL_PATH", "models/yolo11n.pt"))
    parser.add_argument("--device", default=os.environ.get("MODEL_DEVICE", "auto"))
    parser.add_argument("--json", action="store_true", help="emit one JSON object")
    parser.add_argument(
        "--require-cuda",
        action="store_true",
        help="exit non-zero unless inference ran on a CUDA device",
    )
    args = parser.parse_args(argv)
    cuda = _cuda_state()
    base: dict[str, Any] = {
        "model": args.model,
        "requested_device": args.device,
        "cuda": cuda,
        "latency_ms": None,
        "detections": None,
        "classes": None,
        "reason": None,
    }

    if args.download:
        try:
            from ultralytics import YOLO
        except ImportError:
            payload = {
                **base,
                "status": "SKIPPED",
                "device": None,
                "reason": "ultralytics not installed; pip install -r backend/requirements.txt",
            }
            _emit(payload, as_json=args.json)
            return 2 if args.require_cuda else 0
        try:
            if not args.json:
                print(f"downloading weights to {args.model} ...")
            YOLO("yolo11n.pt")
            os.makedirs(os.path.dirname(args.model) or ".", exist_ok=True)
            if os.path.abspath("yolo11n.pt") != os.path.abspath(args.model):
                import shutil

                shutil.move("yolo11n.pt", args.model)
            if not args.json:
                print(f"downloaded: {args.model}")
        except Exception as exc:
            payload = {
                **base,
                "status": "ERROR",
                "device": None,
                "reason": f"weight download failed: {type(exc).__name__}",
            }
            _emit(payload, as_json=args.json)
            return 1

    from backend.app.inference.base import ModelError
    from backend.app.inference.yolo_model import YOLOModel

    model = YOLOModel(name="yolo-smoke", model_path=args.model, device=args.device)
    try:
        model.load()
    except ModelError as exc:
        payload = {**base, "status": "SKIPPED", "device": None, "reason": str(exc)}
        _emit(payload, as_json=args.json)
        if args.require_cuda:
            return 2
        return 0

    image = np.zeros((480, 640, 3), dtype=np.uint8)
    started = time.perf_counter()
    try:
        detections, _ = model.predict(image, camera_id="smoke", frame_id=uuid.uuid4())
    except Exception as exc:
        payload = {
            **base,
            "status": "ERROR",
            "device": model.device,
            "reason": f"inference failed: {type(exc).__name__}",
        }
        _emit(payload, as_json=args.json)
        return 1
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    payload = {
        **base,
        "status": "READY",
        "device": model.device,
        "latency_ms": elapsed_ms,
        "detections": len(detections),
        "classes": len(model.class_names),
    }
    _emit(payload, as_json=args.json)
    if args.require_cuda:
        if cuda["available"] is not True or not str(model.device).lower().startswith("cuda"):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
