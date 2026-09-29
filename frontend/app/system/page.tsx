"use client";

import { useEffect, useState } from "react";
import { StatusCard } from "../../components/system/StatusCard";
import { healthApi } from "../../lib/api/client";
import type { HealthState } from "../../types";

export default function SystemPage() {
  const [health, setHealth] = useState<HealthState | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    healthApi
      .v1()
      .then((data) => setHealth(data as HealthState))
      .catch((e: Error) => setError(e.message));
  }, []);

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-bold">System Status</h1>
      {error && <p className="text-sm text-amber-300">API unreachable ({error}) — start the backend on :8000.</p>}
      {!health && !error && <p className="text-sm text-slate-400">Loading…</p>}
      {health && (
        <div className="grid gap-2 md:grid-cols-2">
          <StatusCard label="API" status={health.status} />
          {Object.entries(health.checks ?? {}).map(([k, v]) => (
            <StatusCard key={k} label={k} status={String(v.status)} />
          ))}
        </div>
      )}
    </div>
  );
}
