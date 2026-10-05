"""Intelligence WebSocket message builders.

Three typed messages join the existing V01–V08 channels:

* ``intelligence_event`` — new/updated unified events, delta-only on
  (event_id, status).
* ``risk_cluster`` — new/updated risk clusters with factors, delta-only on
  (cluster_id, status, risk_level) so escalation re-publishes.
* ``risk_update`` — per-camera highest-risk summary, sent when the highest
  risk level or priority changes. Never carries frames.
"""

from __future__ import annotations

from typing import Any

from backend.app.intelligence.schemas import (
    EventPriority,
    RiskAssessment,
    RiskCluster,
    UnifiedEvent,
)


def intelligence_event_message(camera_id: str, event: UnifiedEvent) -> dict[str, Any]:
    return {
        "type": "intelligence_event",
        "camera_id": camera_id,
        "event": event.to_websocket(),
    }


def risk_cluster_message(camera_id: str, cluster: RiskCluster) -> dict[str, Any]:
    return {
        "type": "risk_cluster",
        "cluster_id": str(cluster.cluster_id),
        "camera_id": camera_id,
        "risk_level": cluster.risk_assessment.risk_level.value,
        "risk_score": cluster.risk_assessment.risk_score,
        "priority": cluster.priority.value,
        "event_ids": [str(e) for e in cluster.event_ids],
        "factors": [
            {
                "name": f.name,
                "value": f.value,
                "weight": f.weight,
                "contribution": f.contribution,
                "reason": f.reason,
            }
            for f in cluster.risk_assessment.factors
        ],
        "timestamp": cluster.last_seen.isoformat(),
    }


def risk_update_message(
    camera_id: str,
    highest_risk: RiskAssessment,
    highest_priority: EventPriority,
    timestamp: str,
) -> dict[str, Any]:
    return {
        "type": "risk_update",
        "camera_id": camera_id,
        "risk_level": highest_risk.risk_level.value,
        "risk_score": highest_risk.risk_score,
        "priority": highest_priority.value,
        "timestamp": timestamp,
    }
