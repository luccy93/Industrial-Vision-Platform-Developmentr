import type { Availability } from "../../types";

const AVAILABILITY_STYLE: Record<Availability, string> = {
  AVAILABLE: "bg-emerald-500/15 text-emerald-300",
  NOT_CONFIGURED: "bg-slate-500/15 text-slate-300",
  ESTIMATED: "bg-amber-500/15 text-amber-300",
  UNKNOWN: "bg-rose-500/15 text-rose-300",
};

export function AvailabilityBadge({ availability, label }: { availability: Availability; label?: string }) {
  return (
    <span className="flex items-center gap-2 text-xs">
      {label && <span className="text-slate-400">{label}</span>}
      <span className={`rounded-full px-2 py-0.5 font-medium ${AVAILABILITY_STYLE[availability]}`}>
        {availability}
      </span>
    </span>
  );
}
