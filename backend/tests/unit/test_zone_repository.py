"""Zone repository tests — PostgreSQL contract via SQLite, ORM round-trip."""

from __future__ import annotations

from typing import Any

import pytest

from backend.app.infrastructure.db import get_session_factory
from backend.app.models.zone_orm import ZoneORM
from backend.app.safety.schemas import SafetySeverity
from backend.app.spatial.repository import ZoneConflictError, ZoneRepository
from backend.app.spatial.schemas import SafetyZone, ZonePoint, ZoneType

_POLYGON = [
    ZonePoint(x=0.2, y=0.4),
    ZonePoint(x=0.8, y=0.4),
    ZonePoint(x=0.8, y=0.9),
    ZonePoint(x=0.2, y=0.9),
]


@pytest.fixture()  # type: ignore[no-untyped-def]
def zones(tmp_path) -> ZoneRepository:  # type: ignore[no-untyped-def]
    from backend.app.infrastructure.db import init_db

    url = f"sqlite:///{tmp_path}/zones.db"
    init_db(url)
    return ZoneRepository(get_session_factory(url))


def _create(zones: ZoneRepository, **overrides: Any) -> SafetyZone:
    params: dict[str, Any] = {
        "camera_id": "cam-01",
        "zone_id": "z-01",
        "name": "Furnace hall",
        "polygon": _POLYGON,
    }
    params.update(overrides)
    return zones.create(**params)


def test_create_and_get_round_trip(zones: ZoneRepository) -> None:
    zone = _create(
        zones,
        zone_type=ZoneType.DANGER,
        severity=SafetySeverity.CRITICAL,
        dwell_threshold_seconds=4.0,
        metadata={"classes": ["person", "forklift"]},
    )
    assert zone.zone_id == "z-01"
    fetched = zones.get("cam-01", "z-01")
    assert fetched is not None
    assert fetched.zone_type is ZoneType.DANGER
    assert fetched.severity is SafetySeverity.CRITICAL
    assert fetched.dwell_threshold_seconds == 4.0
    assert fetched.metadata == {"classes": ["person", "forklift"]}
    assert [p.model_dump() for p in fetched.polygon] == [p.model_dump() for p in _POLYGON]


def test_generated_zone_id(zones: ZoneRepository) -> None:
    zone = _create(zones, zone_id=None)
    assert zone.zone_id.startswith("zone-")


def test_duplicate_zone_id_conflicts(zones: ZoneRepository) -> None:
    _create(zones)
    with pytest.raises(ZoneConflictError):
        _create(zones)


def test_same_zone_id_allowed_on_other_camera(zones: ZoneRepository) -> None:
    _create(zones)
    other = _create(zones, camera_id="cam-02")
    assert other.camera_id == "cam-02"
    assert zones.get("cam-02", "z-01") is not None


def test_invalid_polygon_is_rejected_by_the_model(zones: ZoneRepository) -> None:
    with pytest.raises(ValueError):
        _create(zones, polygon=[ZonePoint(x=0.1, y=0.1), ZonePoint(x=0.9, y=0.9)])


def test_list_and_count(zones: ZoneRepository) -> None:
    _create(zones)
    _create(zones, zone_id="z-02", name="Paint shop")
    assert len(zones.list("cam-01")) == 2
    assert zones.count("cam-01") == 2
    assert zones.list("cam-99") == []


def test_update_fields(zones: ZoneRepository) -> None:
    _create(zones)
    updated = zones.update(
        "cam-01",
        "z-01",
        name="New name",
        enabled=False,
        severity=SafetySeverity.LOW,
        zone_type=ZoneType.CUSTOM,
        dwell_threshold_seconds=1.5,
        metadata={"note": "rev B"},
    )
    assert updated is not None
    assert updated.name == "New name"
    assert updated.enabled is False
    assert updated.severity is SafetySeverity.LOW
    assert updated.zone_type is ZoneType.CUSTOM
    assert updated.dwell_threshold_seconds == 1.5
    assert updated.metadata == {"note": "rev B"}


def test_update_polygon_revalidates(zones: ZoneRepository) -> None:
    _create(zones)
    new_polygon = [{"x": 0.1, "y": 0.1}, {"x": 0.4, "y": 0.1}, {"x": 0.4, "y": 0.4}]
    updated = zones.update("cam-01", "z-01", polygon=new_polygon)
    assert updated is not None
    assert [p.model_dump() for p in updated.polygon] == new_polygon
    with pytest.raises(ValueError):
        zones.update("cam-01", "z-01", polygon=[{"x": 0.1, "y": 0.1}])


def test_update_unknown_returns_none(zones: ZoneRepository) -> None:
    assert zones.update("cam-01", "missing", name="x") is None


def test_delete(zones: ZoneRepository) -> None:
    _create(zones)
    assert zones.delete("cam-01", "z-01") is True
    assert zones.get("cam-01", "z-01") is None
    assert zones.delete("cam-01", "z-01") is False


def test_delete_for_camera(zones: ZoneRepository) -> None:
    _create(zones)
    _create(zones, zone_id="z-02", name="Paint shop")
    _create(zones, camera_id="cam-02")
    assert zones.delete_for_camera("cam-01") == 2
    assert zones.list("cam-01") == []
    assert len(zones.list("cam-02")) == 1


def test_row_shape_matches_schema(zones: ZoneRepository) -> None:
    """The ORM column layout must stay aligned with the Alembic migration."""
    _create(zones)
    columns = {c.name for c in ZoneORM.__table__.columns}
    assert columns == {
        "id",
        "zone_id",
        "camera_id",
        "name",
        "zone_type",
        "polygon",
        "enabled",
        "severity",
        "dwell_threshold_seconds",
        "metadata",
        "created_at",
        "updated_at",
    }
