import { memo } from "react";
import Link from "next/link";
import { Card } from "../ui/Card";
import { SectionBadge, StateText } from "./primitives";
import type {
  HealthSection,
  QualitySection,
  RiskSection,
  SafetySection,
} from "../../types";
import type { TimelineItem } from "../../types";

function SafetyQualityOverview({
  safety,
  quality,
  items,
}: {
  safety: SafetySection;
  quality: QualitySection;
  items: TimelineItem[];
}) {
  const safetyItems = items.filter((i) => i.kind === "safety" || i.kind === "spatial").slice(0, 8);
  const qualityItems = items.filter((i) => i.kind === "quality").slice(0, 8);
  return (
    <Card title="Safety & quality">
      <div className="mb-2 flex items-center gap-2">
        <SectionBadge state={safety.status} />
        <span className="text-sm">{safety.total_active} active safety events</span>
        <Link href="/safety" className="text-xs text-sky-400 hover:underline">
          Safety
        </Link>
        <Link href="/quality" className="text-xs text-sky-400 hover:underline">
          Quality
        </Link>
      </div>
      {safetyItems.length > 0 ? (
        <ul className="mb-2 space-y-1 text-xs">
          {safetyItems.map((item) => (
            <li key={item.id} className="text-slate-300">
              <StateText level={item.severity} text={item.severity} /> · {item.title}
            </li>
          ))}
        </ul>
      ) : (
        <p className="mb-2 text-xs text-slate-500">
          {safety.status === "ok" ? "No active safety events — genuine zero." : "Safety data unavailable."}
        </p>
      )}
      <div className="border-t border-slate-800 pt-2 text-xs">
        {quality.status === "ok" ? (
          <p className="text-slate-300">
            Quality outcomes —{" "}
            {Object.entries(quality.outcomes)
              .map(([k, v]) => `${k}: ${v}`)
              .join(" · ") || "no inspections yet"}{" "}
            ({quality.active_profiles} profiles)
          </p>
        ) : (
          <p className="text-slate-500">
            Quality: {quality.message || "model not configured"} — never shown as PASS.
          </p>
        )}
      </div>
      {qualityItems.length > 0 && (
        <ul className="mt-1 space-y-1 text-xs text-slate-400">
          {qualityItems.map((item) => (
            <li key={item.id}>
              {item.severity} · {item.title}
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

function RiskHealthPanels({
  risk,
  health,
  components,
}: {
  risk: RiskSection;
  health: HealthSection;
  components: Array<{ component: string; status: string }>;
}) {
  return (
    <Card title="Risk & system health">
      <p className="mb-1 text-sm">
        Risk heuristic: <StateText level={risk.risk_level} text={`${risk.risk_level} ${risk.priority}`} />{" "}
        <span className="text-xs text-slate-500">(heuristic, not a probability)</span>
      </p>
      <p className="mb-2 text-xs text-slate-400">
        {risk.active_events} active events · {risk.active_clusters} clusters
      </p>
      <p className="mb-1 text-sm">
        Backend:{" "}
        <span className={health.ready ? "text-emerald-300" : "text-amber-300"}>
          {health.ready ? "ready" : `not ready (${health.readiness})`}
        </span>
      </p>
      <div className="flex flex-wrap gap-1">
        {Object.entries(health.checks).map(([name, value]) => (
          <span key={name} className="rounded bg-slate-800 px-1.5 py-0.5 text-xs text-slate-300">
            {name}: {value}
          </span>
        ))}
      </div>
      {components.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1">
          {components.map((component) => (
            <span
              key={component.component}
              className="rounded bg-slate-800 px-1.5 py-0.5 text-xs text-slate-400"
              title="subsystem health"
            >
              {component.component}: {component.status}
            </span>
          ))}
        </div>
      )}
      <p className="mt-2 text-xs text-slate-500">
        <Link href="/system" className="text-sky-400 hover:underline">
          System details
        </Link>{" "}
        · live endpoint ≠ readiness.
      </p>
    </Card>
  );
}

export const SafetyQuality = memo(SafetyQualityOverview);
export const RiskHealth = memo(RiskHealthPanels);
