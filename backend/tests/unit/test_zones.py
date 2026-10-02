"""Zone schema + spatial config tests."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from backend.app.core.config import Settings
from backend.app.safety.schemas import SafetySeverity
from backend.app.spatial.engine import SpatialEngine
from backend.app.spatial.schemas import (
    ProximityRelationship,
    ProximityStrategy,
    SafetyZone,
    ZonePoint,
    ZoneTransition,
    ZoneType,
)

_POLYGON = [
    ZonePoint(x=0.1, y=0.1),
    ZonePoint(x=0.9, y=0.1),
    ZonePoint(x=0.9, y=0.9),
    ZonePoint(x=0.1, y=0.9),
]


def _zone(**overrides) -> SafetyZone:  # type: ignore[no-untyped-def]
    params: dict = {
        "zone_id": "restricted-01",
        "camera_id": "cam-01",
        "name": "Furnace area",
        "zone_type": ZoneType.RESTRICTED,
        "polygon": _POLYGON,
    }
    params.update(overrides)
    return SafetyZone(**params)


def test_zone_defaults() -> None:
    zone = _zone()
    assert zone.enabled is True
    assert zone.severity == SafetySeverity.HIGH
    assert zone.dwell_threshold_seconds is None
    assert zone.metadata == {}


def test_zone_types_and_strategies() -> None:
    assert {t.value for t in ZoneType} == {"RESTRICTED", "DANGER", "WARNING", "SAFE", "CUSTOM"}
    assert {t.value for t in ZoneTransition} == {"ENTRY", "EXIT", "STATIONARY_INSIDE", "STATIONARY_OUTSIDE"}
    assert {r.value for r in ProximityRelationship} == {
        "PERSON_VEHICLE",
        "PERSON_PERSON",
        "VEHICLE_VEHICLE",
    }
    assert {s.value for s in ProximityStrategy} == {"CENTER_DISTANCE", "IOU", "HYBRID"}


def test_polygon_validation() -> None:
    with pytest.raises(ValidationError):
        _zone(polygon=[ZonePoint(x=0.1, y=0.1), ZonePoint(x=0.9, y=0.9)])
    with pytest.raises(ValidationError):
        _zone(polygon=[ZonePoint(x=0.5, y=float("nan"))] * 3)
    # Degenerate: no area.
    with pytest.raises(ValidationError):
        _zone(
            polygon=[
                ZonePoint(x=0.5, y=0.1),
                ZonePoint(x=0.5, y=0.5),
                ZonePoint(x=0.5, y=0.9),
            ]
        )


def test_engine_registry_and_membership() -> None:
    engine = SpatialEngine()
    engine.set_zones("cam-01", [_zone()])
    assert engine.camera_count() == 1 and engine.zone_count() == 1
    zone = engine.zones_for("cam-01")[0]
    assert engine.is_inside(zone, (0.5, 0.5)) is True
    assert engine.is_inside(zone, (0.01, 0.01)) is False
    assert engine.classify_transition(False, True).value == "ENTRY"
    assert engine.classify_transition(True, False).value == "EXIT"
    engine.remove_zone("cam-01", "restricted-01")
    assert engine.zone_count() == 0
    engine.remove_camera("cam-01")
    assert engine.camera_count() == 0


def test_spatial_config_defaults() -> None:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.spatial_enabled is True
    assert settings.spatial_default_dwell_seconds == 5.0
    assert settings.spatial_proximity_strategy == "HYBRID"
    assert settings.spatial_person_vehicle_enabled is True
    assert settings.spatial_max_zones_per_camera == 20
    assert settings.spatial_state_grace_seconds == 5.0


def test_spatial_config_validation() -> None:
    with pytest.raises(ValueError):
        Settings(spatial_proximity_strategy="MANHATTAN", _env_file=None)  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        Settings(spatial_person_vehicle_severity="EXTREME", _env_file=None)  # type: ignore[call-arg]
