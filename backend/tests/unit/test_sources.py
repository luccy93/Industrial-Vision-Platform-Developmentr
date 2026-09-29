"""VideoSource interface tests — config, redaction, file source (synthetic video)."""

from __future__ import annotations

import pytest

from backend.app.domain.stream import SourceType, redact_source
from backend.app.ingestion.sources import (
    FileVideoSource,
    RTSPVideoSource,
    USBVideoSource,
    create_source,
)
from backend.tests.helpers import make_camera, write_sample_video


def test_factory_selects_implementation() -> None:
    assert isinstance(
        create_source(make_camera(source_type=SourceType.usb, source="0")),
        USBVideoSource,
    )
    assert isinstance(
        create_source(make_camera(source_type=SourceType.rtsp, source="rtsp://h/s")),
        RTSPVideoSource,
    )
    assert isinstance(
        create_source(make_camera(source_type=SourceType.file, source="a.mp4")),
        FileVideoSource,
    )


def test_usb_source_parses_device_index() -> None:
    assert USBVideoSource(make_camera(source="0"))._target() == 0
    assert USBVideoSource(make_camera(source="2"))._target() == 2
    assert USBVideoSource(make_camera(source="/dev/video0"))._target() == 0


def test_rtsp_label_never_exposes_credentials() -> None:
    source = RTSPVideoSource(
        make_camera(source_type=SourceType.rtsp, source="rtsp://admin:s3cret@10.0.0.5/live")
    )
    assert "s3cret" not in source.label
    assert "***" in source.label
    assert "10.0.0.5" in source.label


def test_redact_source_cases() -> None:
    assert redact_source("rtsp://admin:pw@host/s") == "rtsp://admin:***@host/s"
    assert redact_source("rtsp://host/s") == "rtsp://host/s"
    assert redact_source("/dev/video0") == "/dev/video0"
    assert redact_source("data/videos/sample.mp4") == "data/videos/sample.mp4"


def test_file_source_reads_and_loops(tmp_path) -> None:  # type: ignore[no-untyped-def]
    video = write_sample_video(str(tmp_path / "sample.mp4"), frames=5)
    source = FileVideoSource(make_camera(source=video))
    assert source.open()
    assert source.is_open()
    first = source.read()
    assert first is not None
    assert (first.width, first.height) == (320, 240)
    # Exhaust + loop keeps delivering frames indefinitely.
    for _ in range(12):
        assert source.read() is not None
    source.close()
    assert not source.is_open()


def test_source_open_failure_returns_false() -> None:
    source = FileVideoSource(make_camera(source="/nonexistent/missing.mp4"))
    source.loop = False
    assert source.open() is False
    assert source.read() is None


def test_usb_source_configuration_fields() -> None:
    camera = make_camera(source_type=SourceType.usb, source="1", width=640, height=480)
    assert camera.width == 640
    assert camera.height == 480
    with pytest.raises(Exception):
        make_camera(width=0)
