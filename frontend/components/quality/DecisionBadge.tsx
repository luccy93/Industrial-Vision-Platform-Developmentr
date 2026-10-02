import type { QualityDecision } from "../../types";

const DECISION_STYLE: Record<QualityDecision, string> = {
  PASS: "bg-emerald-500/15 text-emerald-300",
  FAIL: "bg-red-500/15 text-red-300",
  REVIEW: "bg-amber-500/15 text-amber-300",
  ERROR: "bg-rose-500/15 text-rose-300"
};

export function DecisionBadge({ decision }: { decision: QualityDecision }) {
  return (
    <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${DECISION_STYLE[decision]}`}>
      {decision}
    </span>
  );
}
