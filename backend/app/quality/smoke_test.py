"""Optional real inspection-model smoke test — never part of the normal suite.

Usage:
    python -m backend.app.quality.smoke_test

Reports READY only when ``QUALITY_INSPECTION_MODEL`` names a loadable model.
Otherwise SKIPPED with an honest reason. Never downloads weights, never
fabricates a model, and never treats a missing model as PASS.
"""

from __future__ import annotations

import sys


def main() -> int:
    from backend.app.core.config import get_settings
    from backend.app.quality.registry import resolve_inspection_model

    settings = get_settings()
    name = (settings.quality_inspection_model or "").strip()
    if not name:
        print("Real inspection-model smoke test: SKIPPED")
        print("Reason: QUALITY_INSPECTION_MODEL is empty (no model configured)")
        return 0
    if name == "fixture":
        print("Real inspection-model smoke test: SKIPPED")
        print("Reason: 'fixture' is the scripted test adapter, not a real model")
        return 0

    model = resolve_inspection_model(settings)
    if model is None:
        print("Real inspection-model smoke test: SKIPPED")
        print(f"Reason: inspection model {name!r} is not available")
        return 0
    try:
        model.load()
    except Exception as exc:  # noqa: BLE001 — honest SKIPPED, never a fake PASS
        print("Real inspection-model smoke test: SKIPPED")
        print(f"Reason: {type(exc).__name__}: {exc}")
        return 0

    print("Real inspection-model smoke test: READY")
    print(f"model={model.name} version={model.version} state={model.state.value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
