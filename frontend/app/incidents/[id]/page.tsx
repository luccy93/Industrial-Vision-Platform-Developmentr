"use client";

import { useCallback, useEffect, useState } from "react";
import { Card } from "../../../components/ui/Card";
import { appConfig } from "../../../lib/config";
import type { IncidentDetail } from "../../../types";

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${appConfig.apiUrl}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) throw new Error(`${path} → ${res.status}`);
  return (await res.json()) as T;
}

/**
 * Incident detail — V10.
 *
 * Commit 01 ships the shell (summary + empty sections). Timeline, evidence,
 * assignment, and action buttons wire up in Commit 02.
 */
export default function IncidentDetailPage({ params }: { params: { id: string } }) {
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setDetail(await api<IncidentDetail>(`/api/v1/incidents/${params.id}`));
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "API unreachable");
    }
  }, [params.id]);

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), 10000);
    return () => clearInterval(timer);
  }, [refresh]);

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-bold">Incident — V10</h1>
      {error && (
        <p className="text-sm text-amber-300">API unreachable ({error}) — start the backend on :8000.</p>
      )}
      <Card title="Summary">
        {detail ? (
          <div className="text-sm text-slate-300">
            <p className="font-medium">
              {detail.incident.incident_number} · {detail.incident.title}
            </p>
            <p className="text-xs text-slate-400">
              {detail.incident.status} · {detail.incident.priority} · {detail.incident.category}
            </p>
          </div>
        ) : (
          <p className="text-sm text-slate-400">Loading…</p>
        )}
      </Card>
      <Card title="Timeline">
        <p className="text-sm text-slate-400">
          Timeline entries arrive with the runtime workflow.
        </p>
      </Card>
      <Card title="Evidence">
        <p className="text-sm text-slate-400">
          Evidence metadata arrives with the runtime workflow.
        </p>
      </Card>
    </div>
  );
}
