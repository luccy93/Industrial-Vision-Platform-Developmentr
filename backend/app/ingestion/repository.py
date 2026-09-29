"""Camera repository — PostgreSQL-backed configuration persistence.

Only slow-changing configuration is stored. Runtime state (stream state,
buffers, metrics) never touches this layer. ``source_secret`` is write-only:
accepted on create/update, never returned.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import datetime

from sqlalchemy.orm import Session

from backend.app.domain.camera import Camera
from backend.app.domain.common import utcnow
from backend.app.domain.stream import SourceType
from backend.app.models.camera_orm import CameraORM


def _to_domain(row: CameraORM) -> Camera:
    meta = dict(row.meta or {})
    return Camera(
        id=uuid.UUID(row.id),
        timestamp=row.created_at,
        metadata=meta,
        name=row.name,
        camera_id=row.camera_id,
        source_type=SourceType(row.source_type),
        source=row.source,
        enabled=row.enabled,
        width=row.width,
        height=row.height,
        target_fps=row.target_fps,
        reconnect_enabled=row.reconnect_enabled,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


class CameraRepository:
    """CRUD over the ``cameras`` table with domain-model boundaries."""

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    def create(
        self,
        *,
        name: str,
        camera_id: str | None,
        source_type: SourceType,
        source: str,
        source_secret: str | None = None,
        enabled: bool = True,
        width: int | None = None,
        height: int | None = None,
        target_fps: float | None = None,
        reconnect_enabled: bool = True,
        metadata: dict | None = None,
    ) -> Camera:
        now: datetime = utcnow()
        resolved_id = camera_id or f"cam-{uuid.uuid4().hex[:8]}"
        row = CameraORM(
            id=str(uuid.uuid4()),
            camera_id=resolved_id,
            name=name,
            source_type=source_type.value,
            source=source,
            source_secret=source_secret,
            enabled=enabled,
            width=width,
            height=height,
            target_fps=target_fps,
            reconnect_enabled=reconnect_enabled,
            meta=dict(metadata or {}),
            created_at=now,
            updated_at=now,
        )
        with self._session_factory() as session:
            session.add(row)
            session.commit()
            session.refresh(row)
            return _to_domain(row)

    def get(self, camera_id: str) -> Camera | None:
        with self._session_factory() as session:
            row = session.query(CameraORM).filter_by(camera_id=camera_id).one_or_none()
            return _to_domain(row) if row else None

    def get_secret(self, camera_id: str) -> str | None:
        """Write-only credential retrieval for stream startup (never in API output)."""
        with self._session_factory() as session:
            row = session.query(CameraORM).filter_by(camera_id=camera_id).one_or_none()
            return row.source_secret if row else None

    def list(self) -> list[Camera]:
        with self._session_factory() as session:
            rows = session.query(CameraORM).order_by(CameraORM.created_at).all()
            return [_to_domain(row) for row in rows]

    def update(self, camera_id: str, **fields: object) -> Camera | None:
        allowed = {
            "name",
            "source_type",
            "source",
            "source_secret",
            "enabled",
            "width",
            "height",
            "target_fps",
            "reconnect_enabled",
            "metadata",
        }
        with self._session_factory() as session:
            row = session.query(CameraORM).filter_by(camera_id=camera_id).one_or_none()
            if row is None:
                return None
            for key, value in fields.items():
                if key not in allowed:
                    continue
                if key == "source_type" and isinstance(value, SourceType):
                    row.source_type = value.value
                elif key == "metadata" and isinstance(value, dict):
                    row.meta = dict(value)
                elif hasattr(row, key):
                    setattr(row, key, value)
            row.updated_at = utcnow()
            session.commit()
            session.refresh(row)
            return _to_domain(row)

    def delete(self, camera_id: str) -> bool:
        with self._session_factory() as session:
            row = session.query(CameraORM).filter_by(camera_id=camera_id).one_or_none()
            if row is None:
                return False
            session.delete(row)
            session.commit()
            return True
