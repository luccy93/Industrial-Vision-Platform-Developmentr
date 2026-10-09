"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { Card } from "../../components/ui/Card";
import { DataState, SectionBadge } from "../../components/operations/primitives";
import { SummaryCards } from "../../components/operations/SummaryCards";
import { CameraGrid } from "../../components/operations/CameraGrid";
import type { CameraRow } from "../../components/operations/CameraGrid";
import { EventTimelineCard } from "../../components/operations/EventTimeline";
import { IncidentQueue } from "../../components/operations/IncidentQueue";
import { RiskHealth, SafetyQuality } from "../../components/operations/Panels";
import {
  ageMs,
  apiFetch,
  fetchCameraStatus,
  fetchCameras,
  fetchHealth,
  fetchIncidents,
  fetchOperationsSummary,
  isStale,
} from "../../lib/operations/client";
import {
  TIMELINE_CAMERAS,
  autonomousEventToItem,
  filterTimeline,
  incidentToItem,
  intelligenceEventToItem,
  mergeTimeline,
  qualityEventToItem,
  riskClusterToItem,
  safetyEventToItem,
  socketMessageToItem,
  type TimelineFilter,
} from "../../lib/operations/timeline";
import type { TimelineItem } from "../../types";
import { useOperationsSocket } from "../../lib/websocket/useOperationsSocket";
import type {
  DetectionSummary,
  IncidentSummary,
  OperationsSummary,
  TrackSummary,
} from "../../types";

const SUMMARY_MS = 15000;
const CAMERAS_MS = 10000;
const TIMELINE_MS = 20000;
const INCIDENTS_MS = 15000;
const HEALTH_MS = 30000;
const OPEN_STATUSES = ["OPEN", "ACKNOWLEDGED", "INVESTIGATING", "MITIGATED"];

type PanelState = {
  at: string | null;
  error: string | null;
};

function readNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function readMetrics(status: unknown): Record<string, unknown> {
  if (status && typeof status === "object") {
    const metrics = (status as Record<string, unknown>).metrics;
    if (metrics && typeof metrics === "object") return metrics as Record<string, unknown>;
  }
  return {};
}

/**
 * Operations command center — V13.
 *
 * REST snapshots are authoritative; the shared operations socket applies
 * incremental timeline updates. Reconnects re-baseline from REST.
 */
export default function DashboardPage() {
  const [summary, setSummary] = useState<OperationsSummary | null>(null);
  const [cameras, setCameras] = useState<CameraRow[]>([]);
  const [timeline, setTimeline] = useState<TimelineItem[]>([]);
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [openTotal, setOpenTotal] = useState(0);
  const [components, setComponents] = useState<Array<{ component: string; status: string }>>([]);
  const [panels, setPanels] = useState<Record<string, PanelState>>({});
  const [filter, setFilter] = useState<TimelineFilter>({
    kinds: new Set(),
    severities: new Set(),
    cameras: new Set(),
    sinceMs: null,
  });
  const refreshTimer = useRef<Record<string, ReturnType<typeof setInterval> | undefined>>({});

  const mark = useCallback((panel: string, error: string | null) => {
    setPanels((prev) => ({
      ...prev,
      [panel]: { at: error ? (prev[panel]?.at ?? null) : new Date().toISOString(), error },
    }));
  }, []);


  const refreshSummary = useCallback(async () => {
    try {
      const data = await fetchOperationsSummary();
      setSummary(data);
      mark("summary", null);
    } catch (e) {
      mark("summary", e instanceof Error ? e.message : "API unreachable");
    }
  }, [mark]);

  const refreshCameras = useCallback(async () => {
    try {
      const { items } = await fetchCameras();
      const rows = await Promise.all(
        items.map(async (camera): Promise<CameraRow> => {
          const base: CameraRow = {
            camera_id: camera.camera_id,
            name: camera.name,
            source_type: camera.source_type,
            enabled: camera.enabled,
            state: "NOT_STARTED",
            frameAgeMs: null,
            processingFps: null,
            latencyMs: null,
            tracks: null,
            detections: null,
            events: null,
            error: null,
          };
          try {
            const status = await fetchCameraStatus(camera.camera_id);
            base.state = status.state || "UNKNOWN";
            const metrics = readMetrics(status);
            base.processingFps = readNumber(metrics.processing_fps);
            base.latencyMs = readNumber(metrics.latency_ms);
          } catch (e) {
            base.state = "UNKNOWN";
            base.error = e instanceof Error ? e.message : "status failed";
          }
          try {
            const detections = await apiFetch<DetectionSummary>(
              `/api/v1/cameras/${encodeURIComponent(camera.camera_id)}/detections?limit=1`
            );
            const latest = detections.results[0];
            base.detections = latest ? latest.detections.length : 0;
            base.frameAgeMs = latest ? ageMs(latest.timestamp) : null;
          } catch {
            /* detections optional; tracks below may still succeed */
          }
          try {
            const tracks = await apiFetch<TrackSummary>(
              `/api/v1/cameras/${encodeURIComponent(camera.camera_id)}/tracks`
            );
            base.tracks = tracks.count;
          } catch {
            /* tracks optional */
          }
          return base;
        })
      );
      setCameras(rows);
      mark("cameras", null);
    } catch (e) {
      mark("cameras", e instanceof Error ? e.message : "API unreachable");
    }
  }, [mark]);

  const refreshTimeline = useCallback(async () => {
    try {
      const { items } = await fetchCameras();
      const cameraIds = items.slice(0, TIMELINE_CAMERAS).map((c) => c.camera_id);
      const settled = await Promise.allSettled(
        cameraIds.flatMap((cameraId) => [
          apiFetch<{ events: Array<Record<string, unknown>> }>(
            `/api/v1/cameras/${encodeURIComponent(cameraId)}/safety/events?status=all&limit=50`
          ).then((body) => ({
            cameraId,
            items: body.events.map((e) => safetyEventToItem(cameraId, e)),
          })),
          apiFetch<{ events: Array<Record<string, unknown>> }>(
            `/api/v1/cameras/${encodeURIComponent(cameraId)}/quality/events?status=all&limit=50`
          ).then((body) => ({
            cameraId,
            items: body.events.map((e) => qualityEventToItem(cameraId, e)),
          })),
          apiFetch<{ events: Array<Record<string, unknown>> }>(
            `/api/v1/cameras/${encodeURIComponent(cameraId)}/autonomous/events?status=all&limit=50`
          ).then((body) => ({
            cameraId,
            items: body.events.map((e) => autonomousEventToItem(cameraId, e)),
          })),
          apiFetch<{ events: Array<Record<string, unknown>>; clusters?: Array<Record<string, unknown>> }>(
            `/api/v1/cameras/${encodeURIComponent(cameraId)}/intelligence/events?status=all&limit=100`
          ).then((body) => ({
            cameraId,
            items: body.events.map((e) => intelligenceEventToItem(cameraId, e)),
          })),
          apiFetch<{ clusters: Array<Record<string, unknown>> }>(
            `/api/v1/cameras/${encodeURIComponent(cameraId)}/intelligence/clusters?status=all&limit=50`
          ).then((body) => ({
            cameraId,
            items: body.clusters.map((c) => riskClusterToItem(cameraId, c)),
          })),
        ])
      );
      const baseline: TimelineItem[] = [];
      let failed = 0;
      for (const result of settled) {
        if (result.status === "fulfilled") {
          for (const item of result.value.items) if (item) baseline.push(item);
        } else {
          failed += 1;
        }
      }
      const open = await fetchIncidents({ status: OPEN_STATUSES, page: 1, page_size: 20 });
      for (const incident of open.incidents) baseline.push(incidentToItem(incident));
      setTimeline((prev) => mergeTimeline([], [...prev.filter((i) => i.source === "socket"), ...baseline]));
      mark("timeline", failed > 0 ? `${failed} event source(s) failed` : null);
    } catch (e) {
      mark("timeline", e instanceof Error ? e.message : "API unreachable");
    }
  }, [mark]);

  const refreshIncidents = useCallback(async () => {
    try {
      const body = await fetchIncidents({ status: OPEN_STATUSES, page: 1, page_size: 20 });
      setIncidents(body.incidents);
      setOpenTotal(body.total);
      mark("incidents", null);
    } catch (e) {
      mark("incidents", e instanceof Error ? e.message : "API unreachable");
    }
  }, [mark]);

  const refreshHealth = useCallback(async () => {
    try {
      const body = await fetchHealth();
      setComponents(
        (body.components ?? []).map((c) => ({ component: c.component, status: c.status }))
      );
      mark("health", null);
    } catch (e) {
      mark("health", e instanceof Error ? e.message : "API unreachable");
    }
  }, [mark]);

  const refreshAll = useCallback(() => {
    void refreshSummary();
    void refreshCameras();
    void refreshTimeline();
    void refreshIncidents();
    void refreshHealth();
  }, [refreshSummary, refreshCameras, refreshTimeline, refreshIncidents, refreshHealth]);

  useEffect(() => {
    void refreshAll();
    refreshTimer.current.summary = setInterval(() => void refreshSummary(), SUMMARY_MS);
    refreshTimer.current.cameras = setInterval(() => void refreshCameras(), CAMERAS_MS);
    refreshTimer.current.timeline = setInterval(() => void refreshTimeline(), TIMELINE_MS);
    refreshTimer.current.incidents = setInterval(() => void refreshIncidents(), INCIDENTS_MS);
    refreshTimer.current.health = setInterval(() => void refreshHealth(), HEALTH_MS);
    const timers = refreshTimer.current;
    return () => {
      for (const timer of Object.values(timers)) if (timer) clearInterval(timer);
    };
  }, [refreshAll, refreshSummary, refreshCameras, refreshTimeline, refreshIncidents, refreshHealth]);

  const handleSocketMessage = useCallback((message: {
    type?: string;
    event_type?: string;
    camera_id?: string;
    timestamp?: string;
    [key: string]: unknown;
  }) => {
    const item = socketMessageToItem(message);
    if (!item) return;
    setTimeline((prev) => mergeTimeline(prev, [item]));
  }, []);

  const feedStatus = useOperationsSocket(true, null, handleSocketMessage);
  const wasLive = useRef(feedStatus);
  useEffect(() => {
    // Reconnect recovery: re-baseline authoritative state, then resume deltas.
    if (wasLive.current !== "live" && feedStatus === "live") {
      void refreshAll();
    }
    wasLive.current = feedStatus;
  }, [feedStatus, refreshAll]);

  const filteredTimeline = useMemo(() => filterTimeline(timeline, filter), [timeline, filter]);
  const cameraIds = useMemo(() => cameras.map((c) => c.camera_id), [cameras]);
  const severities = useMemo(
    () => Array.from(new Set(timeline.map((i) => i.severity))).sort(),
    [timeline]
  );
  const rowsWithEvents = useMemo(() => {
    const counts = new Map<string, number>();
    for (const item of timeline) counts.set(item.cameraId, (counts.get(item.cameraId) ?? 0) + 1);
    return cameras.map((row) => ({ ...row, events: counts.get(row.camera_id) ?? 0 }));
  }, [cameras, timeline]);

  const panelState = (name: string, empty: boolean, emptyText: string) => {
    const panel = panels[name];
    if (panel?.error) return { state: "error" as const, error: panel.error };
    if (!panel?.at) return { state: "loading" as const, error: null };
    return { state: empty ? ("empty" as const) : ("ready" as const), error: null };
  };

  const overall: "ok" | "degraded" | "unavailable" =
    summary === null
      ? "degraded"
      : !summary.health.ready || summary.health.status !== "ok"
        ? "degraded"
        : "ok";
  const summaryState = panelState("summary", false, "");
  const stale = (name: string, intervalMs: number) =>
    isStale(panels[name]?.at ?? null, intervalMs * 2);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="text-lg font-bold">Operations Command Center</h1>
          <p className="text-xs text-slate-400">
            Live operational state across cameras, safety, quality, risk, and incidents.
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <SectionBadge state={overall} label={overall === "ok" ? "operational" : overall} />
          <span
            className={`rounded-full px-2 py-0.5 ${
              feedStatus === "live"
                ? "bg-emerald-500/15 text-emerald-300"
                : feedStatus === "reconnecting"
                  ? "bg-amber-500/15 text-amber-300"
                  : "bg-slate-500/15 text-slate-400"
            }`}
            role="status"
            aria-label={`event stream: ${feedStatus}`}
          >
            stream: {feedStatus}
          </span>
          <button
            onClick={() => refreshAll()}
            className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm hover:bg-slate-700"
          >
            Refresh
          </button>
        </div>
      </div>

      {(summaryState.state === "error" || stale("summary", SUMMARY_MS)) && (
        <p className="text-sm text-amber-300" role="status">
          {panels.summary?.error ?? "Summary data may be stale"} — other panels keep their own state.
        </p>
      )}

      {summary ? (
        <SummaryCards summary={summary} />
      ) : (
        <Card title="Executive summary">
          <DataState
            state={summaryState.state === "error" ? "error" : "loading"}
            emptyText="No summary data."
            error={summaryState.error}
          />
        </Card>
      )}

      <div className="grid gap-4 xl:grid-cols-2">
        <Card title={`Cameras (${cameras.length})`}>
          <DataState
            state={panelState("cameras", cameras.length === 0, "").state}
            emptyText="No cameras configured."
            error={panels.cameras?.error}
          >
            <CameraGrid rows={rowsWithEvents} />
          </DataState>
          {stale("cameras", CAMERAS_MS) && (
            <p className="mt-1 text-xs text-amber-300" role="status">Camera data may be stale.</p>
          )}
        </Card>
        <Card title="Incident queue (read-only)">
          <DataState
            state={panelState("incidents", incidents.length === 0, "").state}
            emptyText="No open incidents — genuine zero."
            error={panels.incidents?.error}
          >
            <IncidentQueue incidents={incidents} openTotal={openTotal} />
          </DataState>
        </Card>
      </div>

      <EventTimelineCard
        items={filteredTimeline}
        filter={filter}
        cameras={cameraIds}
        severities={severities}
        onFilterChange={setFilter}
      />
      {stale("timeline", TIMELINE_MS) && (
        <p className="-mt-2 text-xs text-amber-300" role="status">
          Timeline baseline may be stale; live socket updates still apply.
        </p>
      )}

      {summary && (
        <div className="grid gap-4 xl:grid-cols-2">
          <SafetyQuality safety={summary.safety} quality={summary.quality} items={timeline} />
          <RiskHealth risk={summary.risk} health={summary.health} components={components} />
        </div>
      )}

      <p className="text-xs text-slate-500">
        Sources: operations summary, camera/status/tracks APIs, per-domain event feeds, incident
        API, shared operations socket. REST is authoritative; the socket applies increments.{" "}
        <Link href="/system" className="text-sky-400 hover:underline">
          System details
        </Link>
      </p>
    </div>
  );
}
