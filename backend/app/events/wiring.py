"""Event wiring helpers — shared subscription setup (V12).

The remote-incident ingest subscription is defined once here so the
application and the tests use identical origin-guard semantics.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("industrial-vision.events")


def register_remote_incident_ingest(bus: Any, incident_manager: Any) -> str:
    """Subscribe incident feed ingest with own-origin echo guard.

    Skips envelopes from this bus (local recording already fanned out),
    skips non-incident types, and delegates the rest to
    ``incident_manager.ingest_remote_change`` (which dedupes redelivery
    by envelope id and drops unknown kinds). Returns subscription id.
    """

    def _ingest(envelope: Any) -> None:
        try:
            if getattr(envelope, "origin", "") == bus.origin:
                return
            if not str(getattr(envelope, "event_type", "")).startswith("incident_"):
                return
            incident_manager.ingest_remote_change(envelope)
        except Exception:
            logger.debug("remote incident ingest failed", exc_info=True)

    return str(bus.subscribe(_ingest))
