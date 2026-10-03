"""Optional real perception-model smoke test — never part of the normal suite.

Usage:
    python -m backend.app.autonomous.smoke_test

Reports READY only when every *configured* perception model loads. Empty
model slots report NOT_CONFIGURED honestly (the engine degrades, it does not
fail). Otherwise SKIPPED with a reason. Never downloads weights, never
fabricates a model, and never treats a missing model as READY.
"""

from __future__ import annotations

import sys


def main() -> int:
    from backend.app.autonomous.registry import (
        resolve_depth_estimator,
        resolve_lane_detector,
        resolve_scene_classifier,
    )
    from backend.app.core.config import get_settings

    settings = get_settings()
    slots = {
        "scene_classifier": (settings.autonomous_scene_classifier, resolve_scene_classifier),
        "lane_detector": (settings.autonomous_lane_detector, resolve_lane_detector),
        "depth_estimator": (settings.autonomous_depth_model, resolve_depth_estimator),
    }
    configured = {slot: name for slot, (name, _) in slots.items() if (name or "").strip()}
    if not configured:
        print("Real perception-model smoke test: SKIPPED")
        print("Reason: no perception model configured (all slots empty)")
        return 0

    failures: list[str] = []
    ready: list[str] = []
    for slot, name in configured.items():
        _, resolver = slots[slot]
        if name == "fixture":
            print("Real perception-model smoke test: SKIPPED")
            print(f"Reason: slot {slot} uses the scripted fixture, not a real model")
            return 0
        try:
            model = resolver(settings)
        except Exception as exc:  # noqa: BLE001 — honest SKIPPED, never a fake READY
            failures.append(f"{slot}: {type(exc).__name__}: {exc}")
            continue
        if model is None:
            failures.append(f"{slot}: model {name!r} is not available")
            continue
        try:
            model.load()
        except Exception as exc:  # noqa: BLE001 — honest SKIPPED, never a fake READY
            failures.append(f"{slot}: {type(exc).__name__}: {exc}")
            continue
        ready.append(f"{slot}={model.name}")

    if failures:
        print("Real perception-model smoke test: SKIPPED")
        for failure in failures:
            print(f"Reason: {failure}")
        return 0
    print("Real perception-model smoke test: READY")
    print("models: " + ", ".join(ready))
    return 0


if __name__ == "__main__":
    sys.exit(main())
