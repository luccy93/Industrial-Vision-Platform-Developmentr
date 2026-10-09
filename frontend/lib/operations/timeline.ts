import type { OperationsWsMessage, TimelineItem, TimelineKind } from "../../types";

export const TIMELINE_LIMIT = 200;
export const TIMELINE_CAMERAS = 10;

type RawEvent = Record<string, unknown>;

function str(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

function timestampOf(value: unknown): string {
  const text = str(value);
  return Number.isNaN(Date.parse(text)) ? "" : text;
}

/** Sort key: epoch ms, unparseable timestamps sort oldest (never dropped). */
export function timeKey(isoTimestamp: string): number {
  const parsed = Date.parse(isoTimestamp);
  return Number.isNaN(parsed) ? 0 : parsed;
}

function base(
  id: string,
  kind: TimelineKind,
  eventType: string,
  severity: string,
  cameraId: string,
  timestamp: string,
  title: string,
  href: string | null,
  source: "rest" | "socket"
): TimelineItem | null {
  if (!id) return null;
  return {
    id,
    kind,
    eventType,
    severity: severity || "UNKNOWN",
    cameraId,
    timestamp,
    title: title || `${eventType} on ${cameraId || "unknown camera"}`,
    href,
    source,
  };
}

export function safetyEventToItem(cameraId: string, event: RawEvent): TimelineItem | null {
  const eventType = str(event.event_type);
  const kind: TimelineKind =
    eventType === "RESTRICTED_ZONE_ENTRY" ||
    eventType === "RESTRICTED_ZONE_EXIT" ||
    eventType === "RESTRICTED_ZONE_DWELL" ||
    eventType.startsWith("ZONE_")
      ? "spatial"
      : eventType.includes("PROXIMITY")
        ? "spatial"
        : "safety";
  return base(
    str(event.event_id),
    kind,
    eventType || "safety_event",
    str(event.severity),
    cameraId,
    timestampOf(event.timestamp),
    str(event.message),
    kind === "spatial" ? "/zones" : "/safety",
    "rest"
  );
}

export function qualityEventToItem(cameraId: string, event: RawEvent): TimelineItem | null {
  return base(
    str(event.event_id),
    "quality",
    str(event.event_type) || "quality_event",
    str(event.severity),
    cameraId,
    timestampOf(event.timestamp),
    str(event.message),
    "/quality",
    "rest"
  );
}

export function autonomousEventToItem(cameraId: string, event: RawEvent): TimelineItem | null {
  return base(
    str(event.event_id),
    "autonomous",
    str(event.event_type) || "lane_event",
    str(event.risk_level),
    cameraId,
    timestampOf(event.timestamp),
    str(event.message),
    "/autonomous",
    "rest"
  );
}

export function intelligenceEventToItem(cameraId: string, event: RawEvent): TimelineItem | null {
  return base(
    str(event.event_id),
    "intelligence",
    str(event.event_type) || "intelligence_event",
    str(event.severity),
    cameraId,
    timestampOf(event.timestamp),
    str(event.message) || str(event.reason),
    "/intelligence",
    "rest"
  );
}

export function riskClusterToItem(cameraId: string, cluster: RawEvent): TimelineItem | null {
  const eventIds = Array.isArray(cluster.event_ids) ? cluster.event_ids.length : 0;
  return base(
    str(cluster.cluster_id),
    "intelligence",
    "risk_cluster",
    str(cluster.risk_level),
    cameraId,
    timestampOf(cluster.last_seen),
    `Risk cluster ${str(cluster.priority)} (${eventIds} events)`,
    "/intelligence",
    "rest"
  );
}

export function incidentToItem(incident: {
  id: string;
  incident_number: string;
  title: string;
  status: string;
  priority: string;
  camera_id: string;
  updated_at?: string;
  created_at?: string;
}): TimelineItem {
  return {
    id: `incident:${incident.id}`,
    kind: "incident",
    eventType: "incident",
    severity: incident.priority,
    cameraId: incident.camera_id,
    timestamp: timestampOf(incident.updated_at) || timestampOf(incident.created_at),
    title: `${incident.incident_number} · ${incident.title} (${incident.status})`,
    href: `/incidents/${incident.id}`,
    source: "rest",
  };
}

/**
 * Normalize one socket message (wire `type` or envelope `event_type`
 * shapes) into a timeline item. Unknown types → null (ignored safely).
 */
export function socketMessageToItem(message: OperationsWsMessage): TimelineItem | null {
  const kind = String(message.type ?? message.event_type ?? "");
  const cameraId = str(message.camera_id);
  const timestamp =
    timestampOf(message.timestamp) || timestampOf((message.payload as RawEvent | undefined)?.timestamp);
  const payload =
    message.event !== undefined && typeof message.event === "object"
      ? (message.event as RawEvent)
      : ((message.payload as RawEvent | undefined) ?? {});
  const innerId =
    str(payload.event_id) || str(payload.cluster_id) || str(payload.incident_id) || str(payload.inspection_id);
  const id = innerId ? `${kind}:${innerId}` : "";
  const severity =
    str(payload.severity) || str(payload.risk_level) || str(payload.priority) || "UNKNOWN";
  const title =
    str(payload.message) ||
    (kind.startsWith("incident_")
      ? `${kind} ${str(payload.incident_number) || str(payload.incident_id)}`
      : `${kind} on ${cameraId || "unknown camera"}`);

  switch (kind) {
    case "safety_event":
      return base(id, "safety", kind, severity, cameraId, timestamp, title, "/safety", "socket");
    case "zone_event":
    case "proximity_event":
      return base(id, "spatial", kind, severity, cameraId, timestamp, title, "/zones", "socket");
    case "quality_event":
    case "quality_result":
      return base(id, "quality", kind, severity, cameraId, timestamp, title, "/quality", "socket");
    case "autonomous_perception":
    case "collision_risk":
    case "lane_event":
      return base(id, "autonomous", kind, severity, cameraId, timestamp, title, "/autonomous", "socket");
    case "intelligence_event":
    case "risk_cluster":
    case "risk_update":
      return base(id, "intelligence", kind, severity, cameraId, timestamp, title, "/intelligence", "socket");
    case "incident_created":
    case "incident_updated":
    case "incident_status_changed":
    case "incident_assigned":
    case "incident_resolved":
    case "incident_closed":
    case "incident_evidence_added": {
      const incidentId = str(payload.incident_id);
      return base(
        id,
        "incident",
        kind,
        severity,
        cameraId,
        timestamp,
        title,
        incidentId ? `/incidents/${incidentId}` : "/incidents",
        "socket"
      );
    }
    default:
      return null;
  }
}

/** Merge incoming items into the bounded timeline (stable-ID dedup, newest first). */
export function mergeTimeline(
  existing: TimelineItem[],
  incoming: TimelineItem[],
  limit = TIMELINE_LIMIT
): TimelineItem[] {
  const byId = new Map<string, TimelineItem>();
  for (const item of existing) byId.set(item.id, item);
  for (const item of incoming) byId.set(item.id, item);
  return Array.from(byId.values())
    .sort((a, b) => timeKey(b.timestamp) - timeKey(a.timestamp))
    .slice(0, Math.max(1, limit));
}

export type TimelineFilter = {
  kinds: Set<TimelineKind>;
  severities: Set<string>;
  cameras: Set<string>;
  sinceMs: number | null;
};

/** Apply kind/severity/camera/time filters (empty sets = no filtering). */
export function filterTimeline(items: TimelineItem[], filter: TimelineFilter): TimelineItem[] {
  return items.filter((item) => {
    if (filter.kinds.size > 0 && !filter.kinds.has(item.kind)) return false;
    if (filter.severities.size > 0 && !filter.severities.has(item.severity)) return false;
    if (filter.cameras.size > 0 && !filter.cameras.has(item.cameraId)) return false;
    if (filter.sinceMs !== null && timeKey(item.timestamp) < filter.sinceMs) return false;
    return true;
  });
}
