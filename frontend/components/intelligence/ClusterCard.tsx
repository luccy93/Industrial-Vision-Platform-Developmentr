import type { RiskClusterView } from "../../types";
import { PriorityBadge, RiskBadge } from "./RiskBadge";

function formatTime(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString();
}

export function ClusterCard({ cluster }: { cluster: RiskClusterView }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <RiskBadge level={cluster.risk_level} score={cluster.risk_score} />
        <PriorityBadge priority={cluster.priority} />
        <span className="rounded-full bg-slate-500/15 px-2 py-0.5 text-xs text-slate-300">
          {cluster.status}
        </span>
        <span className="text-xs text-slate-400">
          {cluster.source_domains.join(" + ") || "no sources"} · {cluster.event_count} event(s)
        </span>
      </div>
      {(cluster.track_ids.length > 0 || cluster.object_ids.length > 0) && (
        <p className="mb-2 text-xs text-slate-400">
          {cluster.track_ids.length > 0 ? `tracks [${cluster.track_ids.join(", ")}]` : ""}
          {cluster.track_ids.length > 0 && cluster.object_ids.length > 0 ? " · " : ""}
          {cluster.object_ids.length > 0 ? `objects [${cluster.object_ids.join(", ")}]` : ""}
        </p>
      )}
      <div className="space-y-1">
        {cluster.factors.map((factor) => (
          <div key={factor.name} className="flex items-baseline justify-between gap-2 text-xs">
            <span className="text-slate-300">
              {factor.name}{" "}
              <span className="text-slate-500">
                ×{factor.weight.toFixed(2)} = +{(factor.contribution * 100).toFixed(1)}%
              </span>
            </span>
            <span className="shrink-0 text-slate-500" title={factor.reason}>
              {(factor.value * 100).toFixed(0)}%
            </span>
          </div>
        ))}
        {cluster.factors.length === 0 && (
          <p className="text-xs text-slate-500">No risk factors recorded.</p>
        )}
      </div>
      <p className="mt-2 text-xs text-slate-500">
        {formatTime(cluster.first_seen)} → {formatTime(cluster.last_seen)}
      </p>
    </div>
  );
}
