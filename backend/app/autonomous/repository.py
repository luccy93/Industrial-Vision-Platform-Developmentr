"""Autonomous profile repository — PostgreSQL-backed perception configuration.

Only slow-changing configuration is stored. The runtime never queries this
layer (the engine holds a snapshot), and frame-level perception output is
never written here.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import datetime

from sqlalchemy.orm import Session

from backend.app.autonomous.schemas import AutonomousProfile, SceneType
from backend.app.domain.common import utcnow
from backend.app.models.autonomous_orm import AutonomousProfileORM


class AutonomousProfileConflictError(ValueError):
    """Raised when a profile_id is already used by the same camera."""


def profile_to_domain(row: AutonomousProfileORM) -> AutonomousProfile:
    return AutonomousProfile(
        profile_id=row.profile_id,
        camera_id=row.camera_id,
        name=row.name,
        enabled=bool(row.enabled),
        scene_type=SceneType(row.scene_type),
        lane_detection_enabled=bool(row.lane_detection_enabled),
        depth_enabled=bool(row.depth_enabled),
        trajectory_enabled=bool(row.trajectory_enabled),
        collision_risk_enabled=bool(row.collision_risk_enabled),
        bev_enabled=bool(row.bev_enabled),
        trajectory_horizon_seconds=row.trajectory_horizon_seconds,
        collision_risk_threshold=row.collision_risk_threshold,
        collision_grace_seconds=row.collision_grace_seconds,
        configuration=dict(row.configuration or {}),
        metadata=dict(row.meta or {}),
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


class AutonomousProfileRepository:
    """CRUD over the ``autonomous_perception_profiles`` table."""

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    def create(self, *, camera_id: str, profile: AutonomousProfile) -> AutonomousProfile:
        now: datetime = utcnow()
        with self._session_factory() as session:
            exists = (
                session.query(AutonomousProfileORM)
                .filter_by(camera_id=camera_id, profile_id=profile.profile_id)
                .one_or_none()
            )
            if exists is not None:
                raise AutonomousProfileConflictError(
                    f"profile {profile.profile_id} already exists for {camera_id}"
                )
            row = AutonomousProfileORM(
                id=str(uuid.uuid4()),
                profile_id=profile.profile_id,
                camera_id=camera_id,
                name=profile.name,
                enabled=profile.enabled,
                scene_type=profile.scene_type.value,
                lane_detection_enabled=profile.lane_detection_enabled,
                depth_enabled=profile.depth_enabled,
                trajectory_enabled=profile.trajectory_enabled,
                collision_risk_enabled=profile.collision_risk_enabled,
                bev_enabled=profile.bev_enabled,
                trajectory_horizon_seconds=profile.trajectory_horizon_seconds,
                collision_risk_threshold=profile.collision_risk_threshold,
                collision_grace_seconds=profile.collision_grace_seconds,
                configuration=profile.configuration,
                meta=profile.metadata,
                created_at=now,
                updated_at=now,
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return profile_to_domain(row)

    def get(self, camera_id: str, profile_id: str) -> AutonomousProfile | None:
        with self._session_factory() as session:
            row = (
                session.query(AutonomousProfileORM)
                .filter_by(camera_id=camera_id, profile_id=profile_id)
                .one_or_none()
            )
            return profile_to_domain(row) if row else None

    def list_all(self, camera_id: str) -> list[AutonomousProfile]:
        with self._session_factory() as session:
            rows = (
                session.query(AutonomousProfileORM)
                .filter_by(camera_id=camera_id)
                .order_by(AutonomousProfileORM.created_at, AutonomousProfileORM.profile_id)
                .all()
            )
            return [profile_to_domain(row) for row in rows]

    def count(self, camera_id: str) -> int:
        with self._session_factory() as session:
            return int(session.query(AutonomousProfileORM).filter_by(camera_id=camera_id).count())

    def update(self, camera_id: str, profile_id: str, **fields: object) -> AutonomousProfile | None:
        allowed = {
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
        }
        with self._session_factory() as session:
            row = (
                session.query(AutonomousProfileORM)
                .filter_by(camera_id=camera_id, profile_id=profile_id)
                .one_or_none()
            )
            if row is None:
                return None
            for key, value in fields.items():
                if key not in allowed or value is None:
                    continue
                if key == "scene_type" and isinstance(value, SceneType):
                    row.scene_type = value.value
                elif key == "configuration" and isinstance(value, dict):
                    row.configuration = dict(value)
                elif key == "metadata" and isinstance(value, dict):
                    row.meta = dict(value)
                elif hasattr(row, key):
                    setattr(row, key, value)
            row.updated_at = utcnow()
            session.commit()
            session.refresh(row)
            return profile_to_domain(row)

    def delete(self, camera_id: str, profile_id: str) -> bool:
        with self._session_factory() as session:
            row = (
                session.query(AutonomousProfileORM)
                .filter_by(camera_id=camera_id, profile_id=profile_id)
                .one_or_none()
            )
            if row is None:
                return False
            session.delete(row)
            session.commit()
            return True

    def delete_for_camera(self, camera_id: str) -> int:
        with self._session_factory() as session:
            rows = session.query(AutonomousProfileORM).filter_by(camera_id=camera_id).all()
            for row in rows:
                session.delete(row)
            session.commit()
            return len(rows)
