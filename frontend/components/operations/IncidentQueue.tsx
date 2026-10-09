import { memo } from "react";
import Link from "next/link";
import { Card } from "../ui/Card";
import { PriorityBadge } from "../intelligence/RiskBadge";
import type { IncidentSummary } from "../../types";

function IncidentRow({ incident }: { incident: IncidentSummary }) {
  return (
    <li className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-800 bg-slate-900/60 px-2 py-1 text-xs">
      <Link href={`/incidents/${incident.id}`} className="hover:underline">
        <span className="font-medium text-slate-200">
          {incident.incident_number} · {incident.title}
        </span>
      </Link>
      <span className="flex items-center gap-2 text-slate-400">
        <PriorityBadge priority={incident.priority} />
        <span>{incident.status}</span>
        <span>{incident.camera_id}</span>
        {incident.assigned_to && <span>→ {incident.assigned_to}</span>}
      </span>
    </li>
  );
}

/** Read-only operational queue. Mutations live in /incidents/[id]. */
export const IncidentQueue = memo(function IncidentQueue({
  incidents,
  openTotal,
}: {
  incidents: IncidentSummary[];
  openTotal: number;
}) {
  if (incidents.length === 0) {
    return <p className="text-sm text-slate-400">No open incidents — genuine zero.</p>;
  }
  return (
    <div>
      <ul className="space-y-1">
        {incidents.slice(0, 10).map((incident) => (
          <IncidentRow key={incident.id} incident={incident} />
        ))}
      </ul>
      <p className="mt-2 text-xs text-slate-500">
        Showing {Math.min(incidents.length, 10)} of {openTotal} open.{" "}
        <Link href="/incidents" className="text-sky-400 hover:underline">
          Manage incidents
        </Link>{" "}
        (acknowledge, assign, resolve there).
      </p>
    </div>
  );
});

export function IncidentQueueCard(props: { incidents: IncidentSummary[]; openTotal: number }) {
  return (
    <Card title="Incident queue (read-only)">
      <IncidentQueue {...props} />
    </Card>
  );
}
