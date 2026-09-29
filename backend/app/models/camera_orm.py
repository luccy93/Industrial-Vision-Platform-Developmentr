"""Camera ORM — persistent camera configuration (PostgreSQL).

Only slow-changing configuration lives here. Runtime stream state, frame
buffers, and per-frame metrics stay in memory (see ``StreamManager``).

Security: ``source`` holds the connection string *without* credentials for
RTSP (``rtsp://host/stream``). Credentials go in ``source_secret``, which is
write-only via the API and never returned or logged.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from backend.app.domain.common import utcnow


class Base(DeclarativeBase):
    pass


class CameraORM(Base):
    __tablename__ = "cameras"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    camera_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    source_type: Mapped[str] = mapped_column(String(16), nullable=False, default="file")
    source: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    # Write-only RTSP credential material (e.g. "user:password"); never serialized.
    source_secret: Mapped[str | None] = mapped_column(String(1024), nullable=True, default=None)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    width: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    height: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    target_fps: Mapped[float | None] = mapped_column(Float, nullable=True, default=None)
    reconnect_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
