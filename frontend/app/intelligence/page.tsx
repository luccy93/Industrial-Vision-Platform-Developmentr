"use client";

import { useCallback, useEffect, useState } from "react";
import { Card } from "../../components/ui/Card";
import { StatusCard } from "../../components/system/StatusCard";
import { appConfig } from "../../lib/config";
import type { IntelligenceStatus } from "../../types";

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${appConfig.apiUrl}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) throw new Error(`${path} → ${res.status}`);
  return (await res.json()) as T;
}

/**
 * Event & Risk Intelligence — V09.
 *
 * Commit 01 ships the page shell (status + empty states). Event tables,
 * cluster cards, the risk timeline, and live updates wire up in Commit 02.
 */
export default function IntelligencePage() {
  const [status, setStatus] = useState<IntelligenceStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setStatus(await api<IntelligenceStatus>("/api/v1/intelligence/status"));
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
        <h1 className="text-lg font-bold">Event &amp; Risk Intelligence — V09</h1>
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
            <StatusCard label="Active events" status={String(status.active_events)} />
            <StatusCard label="Active clusters" status={String(status.active_clusters)} />
            <StatusCard label="Highest priority" status={status.highest_priority} />
            <StatusCard
              label="Highest risk"
              status={`${status.highest_risk.risk_level} ${(status.highest_risk.risk_score * 100).toFixed(0)}%`}
            />
          </div>
        ) : (
          <p className="text-sm text-slate-400">Loading…</p>
        )}
      </Card>
      <Card title="Risk timeline">
        <p className="text-sm text-slate-400">
          No intelligence activity yet. The event timeline, cluster cards, and
          risk factors arrive with the runtime engine.
        </p>
      </Card>
      <Card title="Risk clusters">
        <p className="text-sm text-slate-400">No risk clusters yet.</p>
      </Card>
      <Card title="Unified events">
        <p className="text-sm text-slate-400">No unified events yet.</p>
      </Card>
      <p className="text-xs text-slate-500">
        Risk scores are normalized operational heuristics, not probabilities.
      </p>
    </div>
  );
}
