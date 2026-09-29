"""Camera repository tests — SQLite-backed persistence, secret isolation."""

from __future__ import annotations

from backend.app.domain.stream import SourceType
from backend.app.infrastructure.db import get_session_factory, init_db
from backend.app.ingestion.repository import CameraRepository


def _repository(tmp_path) -> CameraRepository:  # type: ignore[no-untyped-def]
    url = f"sqlite:///{tmp_path}/repo.db"
    init_db(url)
    return CameraRepository(get_session_factory(url))


def test_create_and_get_round_trip(tmp_path) -> None:  # type: ignore[no-untyped-def]
    repository = _repository(tmp_path)
    created = repository.create(
        name="Line 1",
        camera_id="cam-01",
        source_type=SourceType.file,
        source="data/videos/sample.mp4",
        target_fps=10.0,
    )
    assert created.camera_id == "cam-01"
    fetched = repository.get("cam-01")
    assert fetched is not None and fetched.name == "Line 1"
    assert fetched.target_fps == 10.0


def test_source_secret_is_write_only(tmp_path) -> None:  # type: ignore[no-untyped-def]
    repository = _repository(tmp_path)
    repository.create(
        name="RTSP",
        camera_id="cam-rtsp",
        source_type=SourceType.rtsp,
        source="rtsp://10.0.0.5/live",
        source_secret="admin:s3cret",
    )
    fetched = repository.get("cam-rtsp")
    assert fetched is not None
    assert "s3cret" not in fetched.model_dump_json()
    assert repository.get_secret("cam-rtsp") == "admin:s3cret"


def test_list_update_delete(tmp_path) -> None:  # type: ignore[no-untyped-def]
    repository = _repository(tmp_path)
    repository.create(name="A", camera_id="a", source_type=SourceType.usb, source="0")
    repository.create(name="B", camera_id="b", source_type=SourceType.file, source="f.mp4")
    assert len(repository.list()) == 2
    updated = repository.update("a", name="A2", width=640)
    assert updated is not None and updated.name == "A2" and updated.width == 640
    assert repository.delete("b") is True
    assert repository.get("b") is None
    assert repository.delete("missing") is False
    assert repository.update("missing", name="x") is None


def test_config_survives_new_repository_instance(tmp_path) -> None:  # type: ignore[no-untyped-def]
    url = f"sqlite:///{tmp_path}/persist.db"
    init_db(url)
    CameraRepository(get_session_factory(url)).create(
        name="P", camera_id="p", source_type=SourceType.file, source="p.mp4"
    )
    # A fresh instance (simulating an app restart) sees the same rows.
    assert CameraRepository(get_session_factory(url)).get("p") is not None
