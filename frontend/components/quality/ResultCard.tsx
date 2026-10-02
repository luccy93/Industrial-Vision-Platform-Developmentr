import type { DefectObservation, InspectionResult } from "../../types";
import { DecisionBadge } from "./DecisionBadge";

const SEVERITY_STYLE: Record<string, string> = {
  CRITICAL: "bg-red-500/15 text-red-300",
  HIGH: "bg-orange-500/15 text-orange-300",
  MEDIUM: "bg-amber-500/15 text-amber-300",
  LOW: "bg-sky-500/15 text-sky-300",
  INFO: "bg-slate-500/15 text-slate-300"
};

function ObservationRow({ observation }: { observation: DefectObservation }) {
  return (
    <div className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2">
      <div>
        <p className="text-sm font-medium">
          {observation.defect_name}
          <span className="ml-2 text-xs text-slate-400">{observation.defect_code}</span>
        </p>
        <p className="text-xs text-slate-500">
          {observation.region_id ?? "full frame"}
          {observation.track_id != null ? ` · track ${observation.track_id}` : ""} · box{" "}
          {observation.bounding_box
            ? observation.bounding_box.map((v) => v.toFixed(3)).join(", ")
            : "—"}
        </p>
      </div>
      <div className="flex items-center gap-2">
        <span className={`rounded-full px-2 py-0.5 text-xs ${SEVERITY_STYLE[observation.severity] ?? SEVERITY_STYLE.INFO}`}>
          {observation.severity}
        </span>
        <span className="text-xs text-slate-300">{(observation.confidence * 100).toFixed(0)}%</span>
      </div>
    </div>
  );
}

export function ResultCard({ result }: { result: InspectionResult }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
      <div className="mb-2 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <DecisionBadge decision={result.decision} />
          <span className="text-xs text-slate-400">{result.profile_id}</span>
        </div>
        <span className="text-xs text-slate-500">
          {result.inspection_time_ms.toFixed(1)} ms · {result.model_name ?? "no model"}
        </span>
      </div>
      <p className="text-sm text-slate-300">{result.decision_reason}</p>
      <p className="mt-1 text-xs text-slate-500">
        {result.regions_evaluated.length > 0
          ? `regions: ${result.regions_evaluated.join(", ")}`
          : "no regions evaluated"}
        {result.error_code ? ` · error: ${result.error_code}` : ""}
      </p>
      {result.observations.length > 0 && (
        <div className="mt-3 space-y-2">
          {result.observations.map((o) => (
            <ObservationRow key={o.observation_id} observation={o} />
          ))}
        </div>
      )}
      <p className="mt-2 text-xs text-slate-500">{new Date(result.timestamp).toLocaleString()}</p>
    </div>
  );
}
