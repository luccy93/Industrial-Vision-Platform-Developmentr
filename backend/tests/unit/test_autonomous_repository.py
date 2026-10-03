"""Autonomous repository tests — persistence, camera isolation."""

from __future__ import annotations

import pytest

from backend.app.autonomous.repository import AutonomousProfileConflictError, AutonomousProfileRepository
from backend.app.autonomous.schemas import SceneType
from backend.app.infrastructure.db import get_session_factory, init_db
from backend.app.models.autonomous_orm import AutonomousProfileORM
from backend.tests.autonomous_helpers import make_profile


@pytest.fixture()
def profiles(tmp_path):
    url = f"sqlite:///{tmp_path}/autonomous_repo.db"
    init_db(url)
    return AutonomousProfileRepository(get_session_factory(url))


def test_create_and_get_round_trip(profiles) -> None:
    created = profiles.create(camera_id="cam-01", profile=make_profile())
    assert created.profile_id == "profile-01"
    fetched = profiles.get("cam-01", "profile-01")
    assert fetched is not None
    assert fetched.name == "Road perception"
    assert fetched.scene_type is SceneType.UNKNOWN
    assert fetched.trajectory_horizon_seconds == 2.0
    assert fetched.collision_risk_threshold == 0.5
    assert fetched.lane_detection_enabled is True
    assert fetched.depth_enabled is False


def test_duplicate_profile_id_conflicts(profiles) -> None:
    profiles.create(camera_id="cam-01", profile=make_profile())
    with pytest.raises(AutonomousProfileConflictError):
        profiles.create(camera_id="cam-01", profile=make_profile())


def test_same_profile_id_allowed_on_other_camera(profiles) -> None:
    profiles.create(camera_id="cam-01", profile=make_profile())
    other = profiles.create(camera_id="cam-02", profile=make_profile())
    assert other.camera_id == "cam-02"


def test_list_and_count(profiles) -> None:
    profiles.create(camera_id="cam-01", profile=make_profile())
    profiles.create(camera_id="cam-01", profile=make_profile(profile_id="p-02", name="Second"))
    assert len(profiles.list_all("cam-01")) == 2
    assert profiles.count("cam-01") == 2
    assert profiles.list_all("cam-99") == []


def test_update_fields(profiles) -> None:
    profiles.create(camera_id="cam-01", profile=make_profile())
    updated = profiles.update(
        "cam-01",
        "profile-01",
        name="Yard",
        enabled=False,
        scene_type=SceneType.WAREHOUSE,
        trajectory_horizon_seconds=4.0,
        configuration={"note": "rev"},
    )
    assert updated is not None
    assert updated.name == "Yard"
    assert updated.enabled is False
    assert updated.scene_type is SceneType.WAREHOUSE
    assert updated.trajectory_horizon_seconds == 4.0
    assert updated.configuration == {"note": "rev"}
    assert profiles.update("cam-01", "missing", name="x") is None


def test_delete(profiles) -> None:
    profiles.create(camera_id="cam-01", profile=make_profile())
    assert profiles.delete("cam-01", "profile-01") is True
    assert profiles.get("cam-01", "profile-01") is None
    assert profiles.delete("cam-01", "profile-01") is False


def test_delete_for_camera(profiles) -> None:
    profiles.create(camera_id="cam-01", profile=make_profile())
    profiles.create(camera_id="cam-01", profile=make_profile(profile_id="p-02", name="Second"))
    profiles.create(camera_id="cam-02", profile=make_profile())
    assert profiles.delete_for_camera("cam-01") == 2
    assert profiles.list_all("cam-01") == []
    assert len(profiles.list_all("cam-02")) == 1


def test_orm_table_matches_migration(profiles) -> None:
    """Column layout must stay aligned with 004_create_autonomous_perception_profiles."""
    columns = {c.name for c in AutonomousProfileORM.__table__.columns}
    assert columns == {
        "id",
        "profile_id",
        "camera_id",
        "name",
        "enabled",
        "scene_type",
        "lane_detection_enabled",
        "depth_enabled",
        "trajectory_enabled",
        "collision_risk_enabled",
        "bev_enabled",
        "trajectory_horizon_seconds",
        "collision_risk_threshold",
        "collision_grace_seconds",
        "configuration",
        "metadata",
        "created_at",
        "updated_at",
    }
