"""Quality edge cases — caps, duplicates, filters, disabled paths, bad frames."""

from __future__ import annotations

from typing import Any, cast

import numpy as np
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.app.core.config import Settings
from backend.app.domain.frame import IngestionFrame
from backend.app.inference.manager import ModelManager
from backend.app.inference.worker import InferenceWorker
from backend.app.quality.engine import QualityInspectionEngine
from backend.app.quality.fixture import FixtureInspectionModel
from backend.app.quality.inspection import RawDefect
from backend.app.quality.schemas import QualityDecision
from backend.tests.quality_helpers import make_category, make_profile, synthetic_frame, utc

_BOX = (10.0, 10.0, 100.0, 100.0)


def _app(client: TestClient) -> Any:
    """TestClient types ``app`` as an ASGI callable; we need its state."""
    return cast(FastAPI, cast(Any, client).app).state


def _settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)  # type: ignore[call-arg]


def _frame(camera_id: str = "cam-01") -> IngestionFrame:
    return IngestionFrame(camera_id=camera_id, frame_number=1, width=640, height=480, image=synthetic_frame())


def _camera(client: TestClient, camera_id: str = "cam-edge") -> None:
    assert (
        client.post(
            "/api/v1/cameras",
            json={"name": "Edge", "camera_id": camera_id, "source_type": "file", "source": "v.mp4"},
        ).status_code
        == 201
    )


def test_duplicate_region_id_422(client: TestClient) -> None:
    _camera(client)
    res = client.post(
        "/api/v1/cameras/cam-edge/inspection-profiles",
        json={
            "name": "Dup",
            "regions": [
                {
                    "name": "A",
                    "region_id": "r-1",
                    "geometry": {"x": 0.1, "y": 0.1, "width": 0.5, "height": 0.5},
                },
                {
                    "name": "B",
                    "region_id": "r-1",
                    "geometry": {"x": 0.1, "y": 0.1, "width": 0.5, "height": 0.5},
                },
            ],
        },
    )
    assert res.status_code == 422


def test_duplicate_defect_codes_deduped(client: TestClient) -> None:
    _camera(client)
    assert (
        client.post("/api/v1/quality/defect-categories", json={"code": "CRACK", "name": "Crack"}).status_code
        == 201
    )
    res = client.post(
        "/api/v1/cameras/cam-edge/inspection-profiles",
        json={"name": "Dup", "profile_id": "dup-01", "defect_codes": ["CRACK", "crack", " CRACK "]},
    )
    assert res.status_code == 201, res.text


def test_profile_count_cap_409(client: TestClient) -> None:
    _camera(client, "cam-cap")
    for i in range(10):
        res = client.post(
            "/api/v1/cameras/cam-cap/inspection-profiles",
            json={"name": f"P{i}", "profile_id": f"p-{i}"},
        )
        assert res.status_code == 201, res.text
    capped = client.post(
        "/api/v1/cameras/cam-cap/inspection-profiles",
        json={"name": "Overflow", "profile_id": "p-overflow"},
    )
    assert capped.status_code == 409


def test_region_cap_422(client: TestClient) -> None:
    _camera(client, "cam-rcap")
    regions = [
        {
            "name": f"R{i}",
            "geometry": {"x": 0.0, "y": 0.0, "width": 0.1, "height": 0.1},
        }
        for i in range(21)
    ]
    res = client.post(
        "/api/v1/cameras/cam-rcap/inspection-profiles",
        json={"name": "Many", "regions": regions},
    )
    assert res.status_code == 422


def test_invalid_decision_policy_update_422(client: TestClient) -> None:
    _camera(client, "cam-pol")
    assert (
        client.post(
            "/api/v1/cameras/cam-pol/inspection-profiles",
            json={"name": "P", "profile_id": "p-1"},
        ).status_code
        == 201
    )
    res = client.put(
        "/api/v1/cameras/cam-pol/inspection-profiles/p-1",
        json={"decision_policy": {"fail_threshold": 0.3, "review_threshold": 0.8}},
    )
    assert res.status_code == 422


def test_invalid_frame_dimensions_rejected_at_boundary() -> None:
    """Non-positive dimensions never reach the engine (pydantic boundary)."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        IngestionFrame(
            camera_id="cam-01",
            frame_number=1,
            width=0,
            height=480,
            image=np.zeros((480, 10, 3), dtype=np.uint8),
        )


def test_model_supports_filtering() -> None:
    class CrackOnly(FixtureInspectionModel):
        def supports(self, defect_codes: frozenset[str]) -> frozenset[str]:
            return frozenset({"CRACK"})

    engine = QualityInspectionEngine(
        _settings(),
        CrackOnly(
            observations=[
                RawDefect(code="CRACK", box=_BOX, confidence=0.9),
                RawDefect(code="SCRATCH", box=_BOX, confidence=0.9),
            ]
        ),
    )
    profile = make_profile()
    engine.set_profiles("cam-01", [profile], [], [make_category()], {})
    result = engine.inspect("cam-01", profile, _frame(), utc(0), None)
    assert [o.defect_code for o in result.observations] == ["CRACK"]


def test_category_review_threshold_filters() -> None:
    engine = QualityInspectionEngine(
        _settings(), FixtureInspectionModel(observations=[RawDefect(code="CRACK", box=_BOX, confidence=0.5)])
    )
    profile = make_profile()
    strict = make_category(confidence_threshold=0.9, review_threshold=0.8)
    engine.set_profiles("cam-01", [profile], [], [strict], {})
    result = engine.inspect("cam-01", profile, _frame(), utc(0), None)
    # 0.5 is below the category review threshold: dropped, so the decision
    # falls back to PASS on no qualifying defects.
    assert result.observations == []
    assert result.decision is QualityDecision.PASS


def test_empty_defect_codes_inspects_everything() -> None:
    engine = QualityInspectionEngine(
        _settings(),
        FixtureInspectionModel(observations=[RawDefect(code="ANYTHING", box=_BOX, confidence=0.9)]),
    )
    profile = make_profile()
    engine.set_profiles("cam-01", [profile], [], [], {})
    result = engine.inspect("cam-01", profile, _frame(), utc(0), None)
    assert len(result.observations) == 1


def test_worker_skips_when_quality_disabled() -> None:
    settings = _settings(quality_enabled=False)
    engine = QualityInspectionEngine(settings, FixtureInspectionModel(observations=[]))
    manager = ModelManager.from_settings(settings)
    worker = InferenceWorker("cam-w", manager, lambda: None, quality_engine=engine)
    # Disabled: no frame counting, no engine calls, no results held.
    assert worker._quality_frames == 0
    assert worker.latest_quality() == []


def test_events_status_filter(client: TestClient) -> None:
    _camera(client, "cam-filter")
    assert (
        client.post(
            "/api/v1/cameras/cam-filter/inspection-profiles",
            json={"name": "P", "profile_id": "p-1"},
        ).status_code
        == 201
    )
    engine = _app(client).quality_engine
    profile = engine._cameras["cam-filter"].profiles["p-1"]
    engine.inspect("cam-filter", profile, _frame("cam-filter"), utc(0), None)
    active = client.get("/api/v1/cameras/cam-filter/quality/events?status=active").json()
    assert active["count"] >= 1
    resolved = client.get("/api/v1/cameras/cam-filter/quality/events?status=resolved").json()
    assert resolved["count"] == 0


def test_results_limit(client: TestClient) -> None:
    _camera(client, "cam-lim")
    assert (
        client.post(
            "/api/v1/cameras/cam-lim/inspection-profiles",
            json={"name": "P", "profile_id": "p-1"},
        ).status_code
        == 201
    )
    body = client.get("/api/v1/cameras/cam-lim/quality/results?limit=5").json()
    assert body["results"] == []
    bad = client.get("/api/v1/cameras/cam-lim/quality/results?limit=0")
    assert bad.status_code == 422
