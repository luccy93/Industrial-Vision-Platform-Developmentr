"""Optional real-model smoke test — never part of the normal suite.

Usage:
    python -m backend.app.inference.smoke_test            # validate local weights
    python -m backend.app.inference.smoke_test --download # fetch MODEL_PATH explicitly

Reports READY with latency/detections, or honest SKIPPED when weights or
ultralytics are absent. Exit code 0 in all non-error paths.
"""

from __future__ import annotations

import argparse
import os
import sys
import time

import numpy as np


def main() -> int:
    parser = argparse.ArgumentParser(description="YOLO real-model smoke test")
    parser.add_argument("--download", action="store_true", help="fetch weights explicitly")
    parser.add_argument("--model", default=os.environ.get("MODEL_PATH", "models/yolo11n.pt"))
    parser.add_argument("--device", default=os.environ.get("MODEL_DEVICE", "auto"))
    args = parser.parse_args()

    if args.download:
        try:
            from ultralytics import YOLO
        except ImportError:
            print("SKIPPED: ultralytics not installed; pip install -r backend/requirements.txt")
            return 0
        print(f"downloading weights to {args.model} ...")
        YOLO("yolo11n.pt")
        os.makedirs(os.path.dirname(args.model) or ".", exist_ok=True)
        if os.path.abspath("yolo11n.pt") != os.path.abspath(args.model):
            import shutil

            shutil.move("yolo11n.pt", args.model)
        print(f"downloaded: {args.model}")

    from backend.app.inference.base import ModelError
    from backend.app.inference.yolo_model import YOLOModel

    model = YOLOModel(name="yolo-smoke", model_path=args.model, device=args.device)
    try:
        model.load()
    except ModelError as exc:
        print(f"Real-model smoke test: SKIPPED\nReason: {exc}")
        return 0

    image = np.zeros((480, 640, 3), dtype=np.uint8)
    started = time.perf_counter()
    detections, _ = model.predict(image, camera_id="smoke", frame_id=__import__("uuid").uuid4())
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    print(
        "Real-model smoke test: READY\n"
        f"model={args.model} device={model.device} classes={len(model.class_names)}\n"
        f"latency_ms={elapsed_ms:.1f} detections={len(detections)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
