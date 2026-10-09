import { memo } from "react";
import Link from "next/link";
import { Card } from "../ui/Card";
import { SectionBadge, StateText } from "./primitives";
import type { OperationsSummary } from "../../types";

function entries(record: Record<string, number>): Array<[string, number]> {
  return Object.entries(record).sort((a, b) => b[1] - a[1]);
}

function Counts({ record }: { record: Record<string, number> }) {
  const rows = entries(record);
  if (rows.length === 0) return <span className="text-slate-500">none</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {rows.map(([key, value]) => (
        <span key={key} className="rounded bg-slate-800 px-1.5 py-0.5 text-xs text-slate-300">
          <StateText level={key} text={`${key}: ${value}`} />
        </span>
      ))}
    </span>
  );
}

function Cameras({ summary }: { summary: OperationsSummary }) {
  const section = summary.cameras;
  return (
    <Card title="Cameras">
      <div className="mb-2 flex items-center gap-2">
        <SectionBadge state={section.status} />
        <span className="text-sm">
          {section.configured} configured · {section.enabled} enabled
        </span>
      </div>
      {section.status === "ok" ? (
        <Counts record={section.by_state} />
      ) : (
        <p className="text-xs text-slate-400">{section.message || "Camera registry unavailable."}</p>
      )}
      <p className="mt-2 text-xs text-slate-500">
        Source: camera registry + stream supervisor. States are lifecycle states, not health claims.
      </p>
    </Card>
  );
}

function Safety({ summary }: { summary: OperationsSummary }) {
  const section = summary.safety;
  return (
    <Card title="Safety events">
      <div className="mb-2 flex items-center gap-2">
        <SectionBadge state={section.status} />
        <span className="text-sm">{section.total_active} active</span>
      </div>
      {section.status === "ok" ? (
        <>
          <Counts record={section.by_severity} />
          <p className="mt-2 text-xs text-slate-500">
            Across {section.cameras_with_events} camera(s)
            {section.truncated ? " · scan truncated at backend cap" : ""}. Source: safety engine.
          </p>
        </>
      ) : (
        <p className="text-xs text-slate-400">{section.message || "Safety data unavailable."}</p>
      )}
    </Card>
  );
}

function Incidents({ summary }: { summary: OperationsSummary }) {
  const section = summary.incidents;
  return (
    <Card title="Incidents">
      <div className="mb-2 flex items-center gap-2">
        <SectionBadge state={section.status} />
        <span className="text-sm">
          {section.open_total} open · {section.total} total
        </span>
        <Link href="/incidents" className="text-xs text-sky-400 hover:underline">
          Manage
        </Link>
      </div>
      {section.status === "ok" ? (
        <div className="space-y-1">
          <Counts record={section.by_status} />
          <Counts record={section.by_priority} />
          <p className="text-xs text-slate-500">Source: incident repository (grouped query).</p>
        </div>
      ) : (
        <p className="text-xs text-slate-400">{section.message || "Incident data unavailable."}</p>
      )}
    </Card>
  );
}

function Quality({ summary }: { summary: OperationsSummary }) {
  const section = summary.quality;
  return (
    <Card title="Quality">
      <div className="mb-2 flex items-center gap-2">
        <SectionBadge state={section.status} />
        <span className="text-sm">model: {section.model_status}</span>
      </div>
      {section.status === "ok" ? (
        <>
          <Counts record={section.outcomes} />
          <p className="mt-2 text-xs text-slate-500">
            {section.active_profiles} active profiles. Source: quality engine.
          </p>
        </>
      ) : (
        <p className="text-xs text-slate-400">
          {section.message ||
            "No inspection model configured — this is not a PASS verdict."}
        </p>
      )}
    </Card>
  );
}

function Risk({ summary }: { summary: OperationsSummary }) {
  const section = summary.risk;
  return (
    <Card title="Risk (heuristic)">
      <div className="mb-2 flex items-center gap-2">
        <SectionBadge state={section.status} />
        <StateText level={section.risk_level} text={`${section.risk_level} · ${section.priority}`} />
      </div>
      {section.status === "ok" ? (
        <p className="text-xs text-slate-400">
          Score {(section.risk_score * 100).toFixed(0)}% (operational heuristic, not a probability) ·{" "}
          {section.active_events} events · {section.active_clusters} clusters. Source: risk engine.
        </p>
      ) : (
        <p className="text-xs text-slate-400">{section.message || "Risk data unavailable."}</p>
      )}
    </Card>
  );
}

function Health({ summary }: { summary: OperationsSummary }) {
  const section = summary.health;
  return (
    <Card title="Backend health">
      <div className="mb-2 flex items-center gap-2">
        <SectionBadge state={section.ready ? "ok" : section.status} />
        <span className="text-sm">{section.ready ? "ready" : `not ready (${section.readiness})`}</span>
      </div>
      <div className="flex flex-wrap gap-1">
        {Object.entries(section.checks).map(([name, value]) => (
          <span key={name} className="rounded bg-slate-800 px-1.5 py-0.5 text-xs text-slate-300">
            {name}: {value}
          </span>
        ))}
      </div>
      <p className="mt-2 text-xs text-slate-500">Source: readiness service. Live ≠ ready.</p>
    </Card>
  );
}

export const SummaryCards = memo(function SummaryCards({ summary }: { summary: OperationsSummary }) {
  return (
    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
      <Cameras summary={summary} />
      <Safety summary={summary} />
      <Incidents summary={summary} />
      <Quality summary={summary} />
      <Risk summary={summary} />
      <Health summary={summary} />
    </div>
  );
});
