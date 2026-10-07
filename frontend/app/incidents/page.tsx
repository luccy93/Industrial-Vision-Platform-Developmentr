"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { Card } from "../../components/ui/Card";
import { appConfig } from "../../lib/config";
import type { IncidentListResponse } from "../../types";

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${appConfig.apiUrl}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) throw new Error(`${path} → ${res.status}`);
  return (await res.json()) as T;
}

/**
 * Incident Management — V10.
 *
 * Commit 01 ships the page shell (list + empty states). Filters, actions,
 * timeline, and evidence UI wire up in Commit 02.
 */
export default function IncidentsPage() {
  const [data, setData] = useState<IncidentListResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setData(await api<IncidentListResponse>("/api/v1/incidents?page_size=20"));
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "API unreachable");
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), 10000);
    return () => clearInterval(timer);
  }, [refresh]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-bold">Incident Management — V10</h1>
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
      <Card title={`Incidents (${data?.total ?? 0})`}>
        {!data || data.incidents.length === 0 ? (
          <p className="text-sm text-slate-400">
            No incidents yet. Incident list, filters, and actions arrive with the runtime workflow.
          </p>
        ) : (
          <div className="space-y-2">
            {data.incidents.map((incident) => (
              <Link
                key={incident.id}
                href={`/incidents/${incident.id}`}
                className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2 hover:bg-slate-800/60"
              >
                <span className="text-sm font-medium">
                  {incident.incident_number} · {incident.title}
                </span>
                <span className="text-xs text-slate-400">
                  {incident.status} · {incident.priority}
                </span>
              </Link>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
