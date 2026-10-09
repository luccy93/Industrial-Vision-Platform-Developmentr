"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { Card } from "../../components/ui/Card";
import { DataState, SectionBadge } from "../../components/operations/primitives";
import { apiFetch } from "../../lib/operations/client";
import { ageMs } from "../../lib/operations/client";
import { useOperationsSocket } from "../../lib/websocket/useOperationsSocket";
import type { OperationsSummary } from "../../types";

const REFRESH_MS = 15000;
const STALE_AFTER_MS = 30000;

/**
 * Operations command center — V13.
 *
 * Commit 01 ships the route shell: global header (health-derived state,
 * connection status, freshness), section skeleton with intentional empty
 * states, and the shared operations socket. Sections fill in with Commit 02.
 */
export default function DashboardPage() {
  const [summary, setSummary] = useState<OperationsSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState<string | null>(null);

  const refresh = useCallback(async (signal?: AbortSignal) => {
    try {
      const data = await apiFetch<OperationsSummary>("/api/v1/operations/summary", { signal });
      setSummary(data);
      setLastRefresh(new Date().toISOString());
      setError(null);
    } catch (e) {
      if (e instanceof DOMException && e.name === "AbortError") return;
      setError(e instanceof Error ? e.message : "API unreachable");
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void refresh(controller.signal);
    const timer = setInterval(() => void refresh(controller.signal), REFRESH_MS);
    return () => {
      controller.abort();
      clearInterval(timer);
    };
  }, [refresh]);

  const feedStatus = useOperationsSocket(true, null, () => {
    // Commit 01: connection lifecycle only; message handling lands in Commit 02.
  });

  const ready = summary?.health.ready ?? null;
  const overall: "ok" | "degraded" | "unavailable" =
    error !== null || ready === false ? "unavailable" : summary === null ? "degraded" : "ok";
  const stale =
    lastRefresh === null ||
    ageMs(lastRefresh) === null ||
    (ageMs(lastRefresh) ?? Number.MAX_SAFE_INTEGER) > STALE_AFTER_MS;

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
            onClick={() => void refresh()}
            className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm hover:bg-slate-700"
          >
            Refresh
          </button>
        </div>
      </div>

      {stale && (
        <p className="text-sm text-amber-300" role="status">
          {error ?? "Data may be stale"} — last successful refresh: {lastRefresh ?? "never"}.
        </p>
      )}

      <Card title="Executive summary">
        <DataState
          state={error ? "error" : summary === null ? "loading" : "ready"}
          emptyText="No summary data yet."
          error={error}
        >
          <p className="text-sm text-slate-400">
            {summary!.incidents.open_total} open incidents · {summary!.safety.total_active} active
            safety events · {summary!.cameras.configured} cameras configured · risk{" "}
            {summary!.risk.risk_level}. Sections arrive with the functional dashboard.
          </p>
        </DataState>
      </Card>

      <div className="grid gap-4 md:grid-cols-2">
        <Card title="Cameras">
          <DataState
            state={error ? "error" : summary === null ? "loading" : "ready"}
            emptyText="No cameras configured."
            error={error}
          >
            <p className="text-sm text-slate-400">Camera grid arrives with the functional dashboard.</p>
          </DataState>
        </Card>
        <Card title="Incidents">
          <DataState
            state={error ? "error" : summary === null ? "loading" : "ready"}
            emptyText="No incidents."
            error={error}
          >
            <p className="text-sm text-slate-400">
              Incident queue arrives with the functional dashboard.{" "}
              <Link href="/incidents" className="text-sky-400 hover:underline">
                Open incident management
              </Link>
            </p>
          </DataState>
        </Card>
        <Card title="Event timeline">
          <DataState
            state={error ? "error" : summary === null ? "loading" : "ready"}
            emptyText="No events yet."
            error={error}
          >
            <p className="text-sm text-slate-400">Live timeline arrives with the functional dashboard.</p>
          </DataState>
        </Card>
        <Card title="Risk & health">
          <DataState
            state={error ? "error" : summary === null ? "loading" : "ready"}
            emptyText="No health data."
            error={error}
          >
            <p className="text-sm text-slate-400">Risk and dependency panels arrive next.</p>
          </DataState>
        </Card>
      </div>
    </div>
  );
}
