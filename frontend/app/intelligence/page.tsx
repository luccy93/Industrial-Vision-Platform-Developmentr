"use client";

import { useCallback, useEffect, useState } from "react";
import { Card } from "../../components/ui/Card";
import { StatusCard } from "../../components/system/StatusCard";
import { ClusterCard } from "../../components/intelligence/ClusterCard";
import { PriorityBadge, RiskBadge } from "../../components/intelligence/RiskBadge";
import { TimelineList } from "../../components/intelligence/TimelineList";
import {
  useIntelligenceSocket,
  type IntelligenceWsMessage,
} from "../../lib/websocket/useIntelligenceSocket";
import { appConfig } from "../../lib/config";
import type {
  CameraItem,
  IntelligenceStatus,
  RiskClusterView,
  UnifiedEvent,
} from "../../types";

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${appConfig.apiUrl}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) throw new Error(`${path} → ${res.status}`);
  return (await res.json()) as T;
}

const DOMAINS = ["ALL", "SAFETY", "SPATIAL", "QUALITY", "AUTONOMOUS"] as const;

function upsertEvent(events: UnifiedEvent[], incoming: UnifiedEvent): UnifiedEvent[] {
  const index = events.findIndex((e) => e.event_id === incoming.event_id);
  if (index < 0) return [...events, incoming];
  const next = [...events];
  next[index] = incoming;
  return next;
}

function upsertCluster(clusters: RiskClusterView[], incoming: RiskClusterView): RiskClusterView[] {
  const index = clusters.findIndex((c) => c.cluster_id === incoming.cluster_id);
  if (index < 0) return [...clusters, incoming];
  const next = [...clusters];
  next[index] = incoming;
  return next;
}

export default function IntelligencePage() {
  const [status, setStatus] = useState<IntelligenceStatus | null>(null);
  const [cameras, setCameras] = useState<CameraItem[]>([]);
  const [cameraId, setCameraId] = useState<string>("");
  const [events, setEvents] = useState<UnifiedEvent[]>([]);
  const [clusters, setClusters] = useState<RiskClusterView[]>([]);
  const [domain, setDomain] = useState<(typeof DOMAINS)[number]>("ALL");
  const [risk, setRisk] = useState<{
    risk_level: string;
    risk_score: number;
    priority: string;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [s, cams] = await Promise.all([
        api<IntelligenceStatus>("/api/v1/intelligence/status"),
        api<{ items: CameraItem[] }>("/api/v1/cameras"),
      ]);
      setStatus(s);
      setCameras(cams.items);
      setError(null);
      const selected = cameraId || cams.items[0]?.camera_id || "";
      if (selected) {
        if (!cameraId) setCameraId(selected);
        const [ev, cl, rk] = await Promise.all([
          api<{ events: UnifiedEvent[] }>(
            `/api/v1/cameras/${selected}/intelligence/events?status=all&limit=100`
          ),
          api<{ clusters: RiskClusterView[] }>(
            `/api/v1/cameras/${selected}/intelligence/clusters?status=all&limit=50`
          ),
          api<{ risk_level: string; risk_score: number; priority: string }>(
            `/api/v1/cameras/${selected}/intelligence/risk`
          ),
        ]);
        setEvents(ev.events);
        setClusters(cl.clusters);
        setRisk({ risk_level: rk.risk_level, risk_score: rk.risk_score, priority: rk.priority });
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "API unreachable");
    }
  }, [cameraId]);

  const handleMessage = useCallback(
    (message: IntelligenceWsMessage) => {
      if (message.camera_id !== cameraId) return;
      if (message.type === "intelligence_event") {
        setEvents((prev) => upsertEvent(prev, message.event as unknown as UnifiedEvent));
      } else if (message.type === "risk_cluster") {
        setClusters((prev) =>
          upsertCluster(prev, {
            cluster_id: String(message.cluster_id ?? ""),
            camera_id: message.camera_id,
            event_ids: (message.event_ids as string[]) ?? [],
            track_ids: [],
            object_ids: [],
            source_domains: [],
            first_seen: "",
            last_seen: String(message.timestamp ?? ""),
            event_count: (message.event_ids as string[] | undefined)?.length ?? 0,
            risk_level: String(message.risk_level ?? "UNKNOWN"),
            risk_score: Number(message.risk_score ?? 0),
            priority: String(message.priority ?? "P4"),
            status: "ACTIVE",
            factors: (message.factors as RiskClusterView["factors"]) ?? [],
          })
        );
      } else if (message.type === "risk_update") {
        setRisk({
          risk_level: String(message.risk_level ?? "UNKNOWN"),
          risk_score: Number(message.risk_score ?? 0),
          priority: String(message.priority ?? "P4"),
        });
      }
      // Polling refresh below keeps derived state consistent.
      void refresh();
    },
    [cameraId, refresh]
  );

  const feedStatus = useIntelligenceSocket(cameraId || null, handleMessage);

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), 5000);
    return () => clearInterval(timer);
  }, [refresh]);

  const visible = domain === "ALL" ? events : events.filter((e) => e.source_domain === domain);
  const activeEvents = events.filter((e) => e.status === "ACTIVE");
  const activeClusters = clusters.filter((c) => c.status === "ACTIVE");

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-bold">Event &amp; Risk Intelligence — V09</h1>
        <div className="flex items-center gap-2">
          <span
            className={`rounded-full px-2 py-0.5 text-xs ${
              feedStatus === "live"
                ? "bg-emerald-500/15 text-emerald-300"
                : feedStatus === "reconnecting"
                  ? "bg-amber-500/15 text-amber-300"
                  : "bg-slate-500/15 text-slate-300"
            }`}
            title={
              feedStatus === "live"
                ? "Live WebSocket feed"
                : feedStatus === "reconnecting"
                  ? "WebSocket reconnecting — polling continues"
                  : "Polling every 5s"
            }
          >
            {feedStatus === "live" ? "live" : feedStatus === "reconnecting" ? "reconnecting" : "polling"}
          </span>
          <button
            onClick={() => void refresh()}
            className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm hover:bg-slate-700"
          >
            Refresh
          </button>
        </div>
      </div>
      {error && (
        <p className="text-sm text-amber-300">API unreachable ({error}) — start the backend on :8000.</p>
      )}

      <Card title="Engine">
        {status ? (
          <div className="space-y-2">
            <div className="grid grid-cols-2 gap-2 md:grid-cols-3">
              <StatusCard label="Status" status={status.engine_status} />
              <StatusCard label="Active events" status={String(status.active_events)} />
              <StatusCard label="Active clusters" status={String(status.active_clusters)} />
              <StatusCard label="Highest priority" status={status.highest_priority} />
              <StatusCard
                label="Highest risk"
                status={`${status.highest_risk.risk_level} ${(status.highest_risk.risk_score * 100).toFixed(0)}%`}
              />
              <StatusCard
                label="Latency ms"
                status={String(status.metrics.processing_latency_ms ?? "—")}
              />
            </div>
            <div className="flex flex-wrap gap-3 rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2">
              {Object.entries(status.domains).map(([name, info]) => (
                <span key={name} className="text-xs text-slate-300">
                  {name}{" "}
                  <span className={info.available ? "text-emerald-300" : "text-slate-500"}>
                    {info.available ? `on (${info.active_events})` : "off"}
                  </span>
                </span>
              ))}
            </div>
          </div>
        ) : (
          <p className="text-sm text-slate-400">Loading…</p>
        )}
      </Card>

      <Card title="Camera">
        <select
          value={cameraId}
          onChange={(e) => setCameraId(e.target.value)}
          className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm"
        >
          <option value="">Select a camera</option>
          {cameras.map((c) => (
            <option key={c.camera_id} value={c.camera_id}>
              {c.name} ({c.camera_id})
            </option>
          ))}
        </select>
      </Card>

      {risk && (
        <Card title="Highest risk">
          <div className="flex flex-wrap items-center gap-2">
            <RiskBadge level={risk.risk_level} score={risk.risk_score} />
            <PriorityBadge priority={risk.priority} />
            <span className="text-xs text-slate-400">
              {activeEvents.length} active event(s) · {activeClusters.length} active cluster(s)
            </span>
          </div>
        </Card>
      )}

      <Card title={`Risk clusters (${clusters.length})`}>
        {clusters.length === 0 && (
          <p className="text-sm text-slate-400">No risk clusters yet.</p>
        )}
        <div className="grid gap-4 lg:grid-cols-2">
          {clusters.map((cluster) => (
            <ClusterCard key={cluster.cluster_id} cluster={cluster} />
          ))}
        </div>
      </Card>

      <Card title={`Unified events (${visible.length})`}>
        <div className="mb-3 flex gap-2 text-sm">
          {DOMAINS.map((d) => (
            <button
              key={d}
              onClick={() => setDomain(d)}
              className={`rounded-lg px-3 py-1.5 ${
                domain === d ? "bg-slate-100 text-slate-900" : "bg-slate-800 hover:bg-slate-700"
              }`}
            >
              {d === "ALL" ? "All domains" : d}
            </button>
          ))}
        </div>
        <TimelineList events={visible} />
      </Card>

      <p className="text-xs text-slate-500">
        Risk scores are normalized operational heuristics, not probabilities.
        V09 provides no incident management, acknowledgement, or suppression controls.
      </p>
    </div>
  );
}
