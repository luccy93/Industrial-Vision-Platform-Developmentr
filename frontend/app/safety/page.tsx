"use client";

import { useCallback, useEffect, useState } from "react";
import { StatusCard } from "../../components/system/StatusCard";
import { Card } from "../../components/ui/Card";
import { appConfig } from "../../lib/config";
import type { CameraItem, SafetyEventItem, SafetyStatus } from "../../types";

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${appConfig.apiUrl}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json" }
  });
  if (!res.ok) throw new Error(`${path} → ${res.status}`);
  return (await res.json()) as T;
}

const SEVERITY_STYLE: Record<string, string> = {
  CRITICAL: "bg-red-500/15 text-red-300",
  HIGH: "bg-orange-500/15 text-orange-300",
  MEDIUM: "bg-amber-500/15 text-amber-300",
  LOW: "bg-sky-500/15 text-sky-300",
  INFO: "bg-slate-500/15 text-slate-300"
};

// V06 spatial events (zones + relationships) share the V05 event contract.
const SPATIAL_EVENT_TYPES = new Set([
  "RESTRICTED_ZONE_ENTRY",
  "RESTRICTED_ZONE_EXIT",
  "ZONE_DWELL",
  "PERSON_VEHICLE_PROXIMITY",
  "PERSON_PERSON_PROXIMITY",
  "VEHICLE_VEHICLE_PROXIMITY"
]);

export default function SafetyPage() {
  const [status, setStatus] = useState<SafetyStatus | null>(null);
  const [cameras, setCameras] = useState<CameraItem[]>([]);
  const [events, setEvents] = useState<SafetyEventItem[]>([]);
  const [statusFilter, setStatusFilter] = useState<"active" | "resolved" | "all">("all");
  const [severityFilter, setSeverityFilter] = useState<string>("All");
  const [scopeFilter, setScopeFilter] = useState<"all" | "v05" | "spatial">("all");
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [s, cams] = await Promise.all([
        api<SafetyStatus>("/api/v1/safety/status"),
        api<{ items: CameraItem[] }>("/api/v1/cameras")
      ]);
      setStatus(s);
      setCameras(cams.items);
      setError(null);
      const lists = await Promise.all(
        cams.items.map(async (c) => {
          try {
            const body = await api<{ events: SafetyEventItem[] }>(
              `/api/v1/cameras/${c.camera_id}/safety/events?status=all&limit=50`
            );
            return body.events;
          } catch {
            return [];
          }
        })
      );
      setEvents(lists.flat());
    } catch (e) {
      setError(e instanceof Error ? e.message : "API unreachable");
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), 5000);
    return () => clearInterval(timer);
  }, [refresh]);

  const visible = events.filter(
    (e) =>
      (statusFilter === "all" || e.status === statusFilter.toUpperCase()) &&
      (severityFilter === "All" || e.severity === severityFilter) &&
      (scopeFilter === "all" ||
        (scopeFilter === "spatial" ? SPATIAL_EVENT_TYPES.has(e.event_type) : !SPATIAL_EVENT_TYPES.has(e.event_type)))
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-bold">Safety Intelligence — V05</h1>
        <button
          onClick={() => void refresh()}
          className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm hover:bg-slate-700"
        >
          Refresh
        </button>
      </div>
      {error && <p className="text-sm text-amber-300">API unreachable ({error}) — start the backend on :8000.</p>}
      <Card title="Engine">
        {status ? (
          <div className="grid grid-cols-2 gap-2 md:grid-cols-3">
            <StatusCard label="Status" status={status.engine_status} />
            <StatusCard label="Rules" status={status.rules_loaded.join(", ") || "—"} />
            <StatusCard label="Active cameras" status={String(status.active_camera_count)} />
            <StatusCard label="Active events" status={String(status.active_event_count)} />
            <StatusCard label="Avg latency ms" status={String(status.average_latency_ms)} />
          </div>
        ) : (
          <p className="text-sm text-slate-400">Loading…</p>
        )}
      </Card>
      <div className="flex gap-2 text-sm">
        {(["all", "active", "resolved"] as const).map((f) => (
          <button
            key={f}
            onClick={() => setStatusFilter(f)}
            className={`rounded-lg px-3 py-1.5 ${statusFilter === f ? "bg-slate-100 text-slate-900" : "bg-slate-800 hover:bg-slate-700"}`}
          >
            {f[0].toUpperCase() + f.slice(1)}
          </button>
        ))}
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="rounded-lg bg-slate-800 px-3 py-1.5"
        >
          {["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
        {(["all", "v05", "spatial"] as const).map((f) => (
          <button
            key={f}
            onClick={() => setScopeFilter(f)}
            className={`rounded-lg px-3 py-1.5 ${scopeFilter === f ? "bg-slate-100 text-slate-900" : "bg-slate-800 hover:bg-slate-700"}`}
          >
            {f === "v05" ? "V05 rules" : f === "spatial" ? "V06 spatial" : "All scopes"}
          </button>
        ))}
      </div>
      {visible.length === 0 && !error && (
        <Card title="No events">No safety events match the current filters. Start a camera stream to generate detections.</Card>
      )}
      <div className="grid gap-4 lg:grid-cols-2">
        {visible.map((e) => (
          <div key={e.event_id} className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
            <div className="mb-2 flex items-center justify-between">
              <p className="font-semibold">
                {e.event_type}
                {SPATIAL_EVENT_TYPES.has(e.event_type) && (
                  <span className="ml-2 rounded-full bg-indigo-500/15 px-2 py-0.5 text-xs text-indigo-300">
                    V06 spatial
                  </span>
                )}
              </p>
              <div className="flex gap-1">
                <span className={`rounded-full px-2 py-0.5 text-xs ${SEVERITY_STYLE[e.severity] ?? SEVERITY_STYLE.INFO}`}>
                  {e.severity}
                </span>
                <span className="rounded-full bg-slate-500/15 px-2 py-0.5 text-xs text-slate-300">{e.status}</span>
              </div>
            </div>
            <p className="text-sm text-slate-300">{e.message}</p>
            <p className="mt-1 text-xs text-slate-400">
              {e.camera_id} · tracks [{e.track_ids.join(", ")}] · confidence {(e.confidence * 100).toFixed(0)}% ·
              duration {(e.duration_ms / 1000).toFixed(1)}s
            </p>
            <p className="text-xs text-slate-500">{new Date(e.timestamp).toLocaleString()}</p>
          </div>
        ))}
      </div>
      {cameras.length === 0 && !error && <p className="text-xs text-slate-500">No cameras configured.</p>}
    </div>
  );
}
