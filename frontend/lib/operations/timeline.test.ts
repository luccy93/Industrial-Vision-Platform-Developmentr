import { describe, expect, it } from "vitest";
import {
  filterTimeline,
  incidentToItem,
  intelligenceEventToItem,
  mergeTimeline,
  qualityEventToItem,
  riskClusterToItem,
  safetyEventToItem,
  socketMessageToItem,
  timeKey,
} from "./timeline";
import type { TimelineItem } from "../../types";
import type { TimelineKind } from "../../types";

function item(partial: Partial<TimelineItem> & { id: string }): TimelineItem {
  return {
    kind: "safety",
    eventType: "safety_event",
    severity: "HIGH",
    cameraId: "cam-1",
    timestamp: "2026-01-01T00:00:00.000Z",
    title: "t",
    href: null,
    source: "rest",
    ...partial,
  };
}

describe("normalizers", () => {
  it("maps zone and proximity types to spatial kind", () => {
    expect(safetyEventToItem("c", { event_id: "a", event_type: "RESTRICTED_ZONE_ENTRY" })?.kind).toBe(
      "spatial"
    );
    expect(
      safetyEventToItem("c", { event_id: "b", event_type: "PERSON_VEHICLE_PROXIMITY" })?.kind
    ).toBe("spatial");
    expect(safetyEventToItem("c", { event_id: "c", event_type: "CROWD_WARNING" })?.kind).toBe(
      "safety"
    );
  });

  it("returns null without a stable id", () => {
    expect(safetyEventToItem("c", { event_type: "X" })).toBeNull();
    expect(qualityEventToItem("c", {})).toBeNull();
  });

  it("builds incident links from incident ids", () => {
    const incident = incidentToItem({
      id: "abc",
      incident_number: "INC-2026-000001",
      title: "Jam",
      status: "OPEN",
      priority: "P1",
      camera_id: "cam-1",
      updated_at: "2026-01-01T00:01:00.000Z",
    });
    expect(incident.href).toBe("/incidents/abc");
    expect(incident.severity).toBe("P1");
    expect(incident.kind).toBe("incident");
  });

  it("summarizes risk clusters with priority", () => {
    const cluster = riskClusterToItem("c", {
      cluster_id: "cl-1",
      priority: "P0",
      risk_level: "CRITICAL",
      event_ids: ["a", "b"],
      last_seen: "2026-01-01T00:02:00.000Z",
    });
    expect(cluster?.href).toBe("/intelligence");
    expect(cluster?.title).toContain("P0");
  });

  it("accepts quality and intelligence shapes", () => {
    expect(
      qualityEventToItem("c", { event_id: "q", event_type: "QUALITY_FAIL" })?.kind
    ).toBe("quality");
    expect(
      intelligenceEventToItem("c", { event_id: "i", event_type: "CROWD_WARNING" })?.kind
    ).toBe("intelligence");
  });
});

describe("socketMessageToItem", () => {
  it("handles wire and envelope shapes and drops unknown types", () => {
    expect(
      socketMessageToItem({ type: "safety_event", camera_id: "c", event: { event_id: "e" } })
    ).toMatchObject({ kind: "safety" });
    expect(
      socketMessageToItem({
        event_type: "incident_created",
        camera_id: "c",
        payload: { incident_id: "abc" },
      })
    ).toMatchObject({ kind: "incident", href: "/incidents/abc" });
    expect(socketMessageToItem({ type: "frame" })).toBeNull();
    expect(socketMessageToItem({ type: "bogus_future_type" })).toBeNull();
    expect(socketMessageToItem({})).toBeNull();
  });
});

describe("mergeTimeline", () => {
  it("dedupes by stable id, newest first, bounded", () => {
    const a = item({ id: "a", timestamp: "2026-01-01T00:00:01.000Z" });
    const b = item({ id: "b", timestamp: "2026-01-01T00:00:02.000Z" });
    const aNewer = { ...a, timestamp: "2026-01-01T00:00:03.000Z", source: "socket" as const };
    const merged = mergeTimeline([a, b], [aNewer], 10);
    expect(merged.map((i) => i.id)).toEqual(["a", "b"]);
    expect(merged[0].source).toBe("socket");
    expect(mergeTimeline([a, b], [], 1)).toHaveLength(1);
  });

  it("keeps unparseable timestamps without dropping them", () => {
    const bad = item({ id: "bad", timestamp: "" });
    expect(timeKey("")).toBe(0);
    expect(mergeTimeline([], [bad])).toHaveLength(1);
  });
});

describe("filterTimeline", () => {
  const items = [
    item({ id: "a", kind: "safety", severity: "HIGH", cameraId: "cam-1" }),
    item({ id: "b", kind: "incident", severity: "P1", cameraId: "cam-2" }),
  ];
  const open: {
    kinds: Set<TimelineKind>;
    severities: Set<string>;
    cameras: Set<string>;
    sinceMs: null;
  } = { kinds: new Set(), severities: new Set(), cameras: new Set(), sinceMs: null };

  it("passes everything with empty sets", () => {
    expect(filterTimeline(items, { ...open })).toHaveLength(2);
  });

  it("filters by kind, severity, and camera", () => {
    expect(
      filterTimeline(items, { ...open, kinds: new Set(["incident" as const]) })
    ).toHaveLength(1);
    expect(filterTimeline(items, { ...open, severities: new Set(["P1"]) })).toHaveLength(1);
    expect(filterTimeline(items, { ...open, cameras: new Set(["cam-9"]) })).toHaveLength(0);
  });

  it("filters by time window", () => {
    const since = Date.parse("2026-01-01T00:00:00.000Z") + 1;
    expect(
      filterTimeline(items, {
        kinds: new Set<TimelineKind>(),
        severities: new Set<string>(),
        cameras: new Set<string>(),
        sinceMs: since,
      })
    ).toHaveLength(0);
  });
});
