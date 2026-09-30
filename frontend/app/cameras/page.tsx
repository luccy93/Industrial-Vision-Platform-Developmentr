"use client";

import { useCallback, useEffect, useState } from "react";
import { StatusCard } from "../../components/system/StatusCard";
import { Card } from "../../components/ui/Card";
import { appConfig } from "../../lib/config";
import type { CameraItem, DetectionSummary, InferenceStatus, StreamStatus } from "../../types";

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${appConfig.apiUrl}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json" }
  });
  if (!res.ok) throw new Error(`${path} → ${res.status}`);
  return (await res.json()) as T;
}

const STATE_STYLE: Record<string, string> = {
  RUNNING: "bg-emerald-500/15 text-emerald-300",
  CONNECTED: "bg-emerald-500/15 text-emerald-300",
  CONNECTING: "bg-amber-500/15 text-amber-300",
  RECONNECTING: "bg-amber-500/15 text-amber-300",
  ERROR: "bg-red-500/15 text-red-300"
};

function stateStyle(state: string): string {
  return STATE_STYLE[state] ?? "bg-slate-500/15 text-slate-300";
}

function DetectionPanel({ summary }: { summary: DetectionSummary | undefined }) {
  const latest = summary?.results?.[summary.results.length - 1];
  if (!summary || !latest || latest.detections.length === 0) {
    return <p className="mt-2 text-xs text-slate-400">No detections yet. Bounding-box overlays arrive after V03.</p>;
  }
  return (
    <div className="mt-2 rounded-lg border border-slate-800 p-2">
      <p className="text-xs text-slate-400">
        Latest: {latest.detections.length} detection(s) · {latest.inference_time_ms.toFixed(1)} ms · {latest.model_name}
      </p>
      <div className="mt-1 flex flex-wrap gap-1">
        {latest.detections.map((d, i) => (
          <span key={i} className="rounded-full bg-sky-500/15 px-2 py-0.5 text-xs text-sky-300">
            {d.class_name} {(d.confidence * 100).toFixed(0)}%
          </span>
        ))}
      </div>
    </div>
  );
}

export default function CamerasPage() {
  const [cameras, setCameras] = useState<CameraItem[]>([]);
  const [statuses, setStatuses] = useState<Record<string, StreamStatus>>({});
  const [inference, setInference] = useState<InferenceStatus | null>(null);
  const [detections, setDetections] = useState<Record<string, DetectionSummary>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const data = await api<{ items: CameraItem[] }>("/api/v1/cameras");
      setCameras(data.items);
      setError(null);
      const entries = await Promise.all(
        data.items.map(async (c) => {
          try {
            const s = await api<StreamStatus>(`/api/v1/cameras/${c.camera_id}/status`);
            return [c.camera_id, s] as const;
          } catch {
            return [c.camera_id, null] as const;
          }
        })
      );
      const next: Record<string, StreamStatus> = {};
      for (const [id, s] of entries) if (s) next[id] = s;
      setStatuses(next);
      try {
        setInference(await api<InferenceStatus>("/api/v1/inference/status"));
      } catch {
        setInference(null);
      }
      const detEntries = await Promise.all(
        data.items.map(async (c) => {
          try {
            const d = await api<DetectionSummary>(`/api/v1/cameras/${c.camera_id}/detections?limit=1`);
            return [c.camera_id, d] as const;
          } catch {
            return [c.camera_id, null] as const;
          }
        })
      );
      const detNext: Record<string, DetectionSummary> = {};
      for (const [id, d] of detEntries) if (d) detNext[id] = d;
      setDetections(detNext);
    } catch (e) {
      setError(e instanceof Error ? e.message : "API unreachable");
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function control(cameraId: string, action: "start" | "stop") {
    setBusy(`${action}:${cameraId}`);
    try {
      await api(`/api/v1/cameras/${cameraId}/${action}`, { method: "POST" });
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "control failed");
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-bold">Cameras — V03 Detection</h1>
        <button
          onClick={() => void refresh()}
          className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm hover:bg-slate-700"
        >
          Refresh status
        </button>
      </div>
      {error && <p className="text-sm text-amber-300">API unreachable ({error}) — start the backend on :8000.</p>}
      <Card title="Inference engine">
        {inference ? (
          <div className="grid grid-cols-2 gap-2 md:grid-cols-3">
            <StatusCard label="Model" status={`${inference.model_name} (${inference.device})`} />
            <StatusCard label="Loaded" status={inference.loaded ? "yes" : "not yet"} />
            <StatusCard label="Inference FPS" status={String(inference.inference_fps)} />
            <StatusCard label="Avg latency ms" status={String(inference.average_latency_ms)} />
            <StatusCard label="Detections/frame" status={String(inference.detections_per_frame)} />
            <StatusCard label="Active workers" status={String(inference.active_workers)} />
          </div>
        ) : (
          <p className="text-sm text-slate-400">Inference status unavailable.</p>
        )}
      </Card>
      {cameras.length === 0 && !error && (
        <Card title="No cameras">Configure cameras via POST /api/v1/cameras. Detection overlays arrive in V03+.</Card>
      )}
      <div className="grid gap-4 lg:grid-cols-2">
        {cameras.map((c) => {
          const s = statuses[c.camera_id];
          const state = s?.state ?? "DISCONNECTED";
          const m = s?.metrics;
          return (
            <div key={c.camera_id} className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
              <div className="mb-2 flex items-center justify-between">
                <div>
                  <p className="font-semibold">{c.name}</p>
                  <p className="text-xs text-slate-400">
                    {c.camera_id} · {c.source_type} · {c.width ?? "?"}×{c.height ?? "?"}
                  </p>
                </div>
                <span className={`rounded-full px-2 py-0.5 text-xs ${stateStyle(state)}`}>{state}</span>
              </div>
              <div className="grid grid-cols-2 gap-2 text-sm">
                <StatusCard label="Source FPS" status={String(m?.source_fps ?? "—")} />
                <StatusCard label="Processing FPS" status={String(m?.processing_fps ?? "—")} />
                <StatusCard label="Frames received" status={String(m?.frames_received ?? "—")} />
                <StatusCard label="Frames dropped" status={String(m?.frames_dropped ?? "—")} />
              </div>
              <DetectionPanel summary={detections[c.camera_id]} />
              <div className="mt-3 flex gap-2">
                <button
                  disabled={busy !== null}
                  onClick={() => void control(c.camera_id, "start")}
                  className="rounded-lg bg-emerald-600 px-3 py-1.5 text-sm hover:bg-emerald-500 disabled:opacity-50"
                >
                  Start
                </button>
                <button
                  disabled={busy !== null}
                  onClick={() => void control(c.camera_id, "stop")}
                  className="rounded-lg bg-slate-700 px-3 py-1.5 text-sm hover:bg-slate-600 disabled:opacity-50"
                >
                  Stop
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
