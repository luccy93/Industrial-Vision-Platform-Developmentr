import type { UnifiedEvent } from "../../types";
import { PriorityBadge } from "./RiskBadge";

function formatTime(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString();
}

export function TimelineList({ events }: { events: UnifiedEvent[] }) {
  if (events.length === 0) {
    return <p className="text-sm text-slate-400">No intelligence activity yet.</p>;
  }
  const ordered = [...events].sort((a, b) => (a.timestamp < b.timestamp ? 1 : -1));
  return (
    <ol className="space-y-2">
      {ordered.slice(0, 30).map((event) => (
        <li
          key={event.event_id}
          className="flex flex-wrap items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2"
        >
          <span className="text-xs text-slate-500">{formatTime(event.timestamp)}</span>
          <span className="text-sm font-medium text-slate-200">{event.event_type}</span>
          <span className="rounded-full bg-slate-500/15 px-2 py-0.5 text-xs text-slate-300">
            {event.source_domain}
          </span>
          <span className="rounded-full bg-slate-500/15 px-2 py-0.5 text-xs text-slate-300">
            {event.severity}
          </span>
          <span className="rounded-full bg-slate-500/15 px-2 py-0.5 text-xs text-slate-300">
            risk {(event.risk_score * 100).toFixed(0)}%
          </span>
          <PriorityBadge priority={event.priority} />
          <span className="text-xs text-slate-500">{event.message}</span>
        </li>
      ))}
    </ol>
  );
}
