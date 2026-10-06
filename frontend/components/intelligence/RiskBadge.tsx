const RISK_STYLE: Record<string, string> = {
  CRITICAL: "bg-red-500/15 text-red-300",
  HIGH: "bg-orange-500/15 text-orange-300",
  MEDIUM: "bg-amber-500/15 text-amber-300",
  LOW: "bg-sky-500/15 text-sky-300",
  NONE: "bg-slate-500/15 text-slate-300",
  UNKNOWN: "bg-rose-500/15 text-rose-300",
};

export function RiskBadge({ level, score }: { level: string; score?: number }) {
  return (
    <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${RISK_STYLE[level] ?? RISK_STYLE.UNKNOWN}`}>
      {level}
      {score !== undefined && score !== null ? ` ${(score * 100).toFixed(0)}%` : ""}
    </span>
  );
}

const PRIORITY_STYLE: Record<string, string> = {
  P0: "bg-red-500/20 text-red-200",
  P1: "bg-orange-500/15 text-orange-300",
  P2: "bg-amber-500/15 text-amber-300",
  P3: "bg-sky-500/15 text-sky-300",
  P4: "bg-slate-500/15 text-slate-300",
};

export function PriorityBadge({ priority }: { priority: string }) {
  return (
    <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${PRIORITY_STYLE[priority] ?? PRIORITY_STYLE.P4}`}>
      {priority}
    </span>
  );
}
