"use client";

import { useCallback, useEffect, useState } from "react";
import { Card } from "../../components/ui/Card";
import { StatusCard } from "../../components/system/StatusCard";
import { appConfig } from "../../lib/config";
import type { QualityStatus } from "../../types";

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${appConfig.apiUrl}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json" }
  });
  if (!res.ok) throw new Error(`${path} → ${res.status}`);
  return (await res.json()) as T;
}

/**
 * Quality Inspection — V07.
 *
 * Commit 01 ships the page shell (status + empty states). Profile management,
 * the region editor, and result visualization wire up in Commit 02.
 */
export default function QualityPage() {
  const [status, setStatus] = useState<QualityStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setStatus(await api<QualityStatus>("/api/v1/quality/status"));
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
        <h1 className="text-lg font-bold">Quality Inspection — V07</h1>
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
            <StatusCard label="Model" status={status.model_status} />
            <StatusCard label="Active profiles" status={String(status.active_profiles)} />
            <StatusCard label="Inspections" status={String(status.inspection_count)} />
            <StatusCard label="Avg latency ms" status={String(status.average_inspection_ms)} />
          </div>
        ) : (
          <p className="text-sm text-slate-400">Loading…</p>
        )}
      </Card>
      <Card title="Profiles">
        <p className="text-sm text-slate-400">
          No inspection profiles yet. Profile management, region editing, and result
          visualization arrive with the runtime engine.
        </p>
      </Card>
      <Card title="Latest result">
        <p className="text-sm text-slate-400">No inspection results yet.</p>
      </Card>
      <Card title="Quality events">
        <p className="text-sm text-slate-400">No quality events yet.</p>
      </Card>
    </div>
  );
}
