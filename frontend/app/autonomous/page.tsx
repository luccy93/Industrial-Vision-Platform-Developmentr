"use client";

import { useCallback, useEffect, useState } from "react";
import { Card } from "../../components/ui/Card";
import { StatusCard } from "../../components/system/StatusCard";
import { appConfig } from "../../lib/config";
import type { AutonomousStatus } from "../../types";

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${appConfig.apiUrl}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) throw new Error(`${path} → ${res.status}`);
  return (await res.json()) as T;
}

/**
 * Autonomous Perception — V08.
 *
 * Commit 01 ships the page shell (status + empty states). Scene objects,
 * lane/BEV visualization, and profile management wire up in Commit 02.
 */
export default function AutonomousPage() {
  const [status, setStatus] = useState<AutonomousStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setStatus(await api<AutonomousStatus>("/api/v1/autonomous/status"));
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "API unreachable");
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), 5000);
    return () => clearInterval(timer);
  }, [refresh]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-bold">Autonomous Perception — V08</h1>
        <button
          onClick={() => void refresh()}
          className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm hover:bg-slate-700"
        >
          Refresh
        </button>
      </div>
      {error && (
        <p className="text-sm text-amber-300">API unreachable ({error}) — start the backend on :8000.</p>
      )}
      <Card title="Engine">
        {status ? (
          <div className="grid grid-cols-2 gap-2 md:grid-cols-3">
            <StatusCard label="Status" status={status.engine_status} />
            <StatusCard label="Scene classifier" status={status.scene_classifier_status} />
            <StatusCard label="Lane detector" status={status.lane_detector_status} />
            <StatusCard label="Depth" status={status.depth_status} />
            <StatusCard label="Active profiles" status={String(status.active_profiles)} />
            <StatusCard label="Avg latency ms" status={String(status.average_perception_ms)} />
          </div>
        ) : (
          <p className="text-sm text-slate-400">Loading…</p>
        )}
      </Card>
      <Card title="Scene">
        <p className="text-sm text-slate-400">
          No perceived scenes yet. Scene objects, lane/BEV visualization, and
          profile management arrive with the runtime engine.
        </p>
      </Card>
      <Card title="Collision risks">
        <p className="text-sm text-slate-400">No collision-risk assessments yet.</p>
      </Card>
      <Card title="Perception events">
        <p className="text-sm text-slate-400">No perception events yet.</p>
      </Card>
    </div>
  );
}
