"""Zone repository — PostgreSQL-backed zone configuration.

Mirrors ``CameraRepository``: only slow-changing configuration is stored, the
domain model is returned to callers, and the runtime never queries this layer.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import datetime

from sqlalchemy.orm import Session

from backend.app.domain.common import utcnow
from backend.app.models.zone_orm import ZoneORM
from backend.app.safety.schemas import SafetySeverity
from backend.app.spatial.schemas import SafetyZone, ZonePoint, ZoneType


class ZoneConflictError(ValueError):
    """Raised when a zone_id is already used by the same camera."""


def to_domain(row: ZoneORM) -> SafetyZone:
    return SafetyZone(
        zone_id=row.zone_id,
        camera_id=row.camera_id,
        name=row.name,
        zone_type=ZoneType(row.zone_type),
        polygon=[ZonePoint(x=p["x"], y=p["y"]) for p in (row.polygon or [])],
        enabled=bool(row.enabled),
        severity=SafetySeverity(row.severity),
        dwell_threshold_seconds=row.dwell_threshold_seconds,
        metadata=dict(row.meta or {}),
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


class ZoneRepository:
    """CRUD over the ``zones`` table with camera-scoped identity."""

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    def create(
        self,
        *,
        camera_id: str,
        zone_id: str | None,
        name: str,
        zone_type: ZoneType = ZoneType.RESTRICTED,
        polygon: list[ZonePoint] | None = None,
        enabled: bool = True,
        severity: SafetySeverity = SafetySeverity.HIGH,
        dwell_threshold_seconds: float | None = None,
        metadata: dict | None = None,
    ) -> SafetyZone:
        zone = SafetyZone(
            zone_id=zone_id or f"zone-{uuid.uuid4().hex[:8]}",
            camera_id=camera_id,
            name=name,
            zone_type=zone_type,
            polygon=polygon or [],
            enabled=enabled,
            severity=severity,
            dwell_threshold_seconds=dwell_threshold_seconds,
            metadata=dict(metadata or {}),
        )
        now: datetime = utcnow()
        with self._session_factory() as session:
            exists = session.query(ZoneORM).filter_by(camera_id=camera_id, zone_id=zone.zone_id).one_or_none()
            if exists is not None:
                raise ZoneConflictError(f"zone {zone.zone_id} already exists for {camera_id}")
            row = ZoneORM(
                id=str(uuid.uuid4()),
                zone_id=zone.zone_id,
                camera_id=camera_id,
                name=zone.name,
                zone_type=zone.zone_type.value,
                polygon=[p.model_dump() for p in zone.polygon],
                enabled=zone.enabled,
                severity=zone.severity.value,
                dwell_threshold_seconds=zone.dwell_threshold_seconds,
                meta=zone.metadata,
                created_at=now,
                updated_at=now,
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return to_domain(row)

    def get(self, camera_id: str, zone_id: str) -> SafetyZone | None:
        with self._session_factory() as session:
            row = session.query(ZoneORM).filter_by(camera_id=camera_id, zone_id=zone_id).one_or_none()
            return to_domain(row) if row else None

    def list(self, camera_id: str) -> list[SafetyZone]:
        with self._session_factory() as session:
            rows = (
                session.query(ZoneORM)
                .filter_by(camera_id=camera_id)
                .order_by(ZoneORM.created_at, ZoneORM.zone_id)
                .all()
            )
            return [to_domain(row) for row in rows]

    def count(self, camera_id: str) -> int:
        with self._session_factory() as session:
            return int(session.query(ZoneORM).filter_by(camera_id=camera_id).count())

    def update(self, camera_id: str, zone_id: str, **fields: object) -> SafetyZone | None:
        allowed = {
            "name",
            "zone_type",
            "polygon",
            "enabled",
            "severity",
            "dwell_threshold_seconds",
            "metadata",
        }
        with self._session_factory() as session:
            row = session.query(ZoneORM).filter_by(camera_id=camera_id, zone_id=zone_id).one_or_none()
            if row is None:
                return None
            for key, value in fields.items():
                if key not in allowed or value is None:
                    continue
                if key == "zone_type" and isinstance(value, ZoneType):
                    row.zone_type = value.value
                elif key == "severity" and isinstance(value, SafetySeverity):
                    row.severity = value.value
                elif key == "polygon" and isinstance(value, list):
                    points = [ZonePoint(x=p["x"], y=p["y"]) for p in value]  # type: ignore[index]
                    # Re-validate: the DB never stores an invalid polygon.
                    SafetyZone(
                        zone_id=row.zone_id,
                        camera_id=row.camera_id,
                        name=row.name,
                        zone_type=ZoneType(row.zone_type),
                        polygon=points,
                    )
                    row.polygon = [p.model_dump() for p in points]
                elif key == "metadata" and isinstance(value, dict):
                    row.meta = dict(value)
                elif hasattr(row, key):
                    setattr(row, key, value)
            row.updated_at = utcnow()
            session.commit()
            session.refresh(row)
            return to_domain(row)

    def delete(self, camera_id: str, zone_id: str) -> bool:
        with self._session_factory() as session:
            row = session.query(ZoneORM).filter_by(camera_id=camera_id, zone_id=zone_id).one_or_none()
            if row is None:
                return False
            session.delete(row)
            session.commit()
            return True

    def delete_for_camera(self, camera_id: str) -> int:
        with self._session_factory() as session:
            rows = session.query(ZoneORM).filter_by(camera_id=camera_id).all()
            for row in rows:
                session.delete(row)
            session.commit()
            return len(rows)
