import type { CollisionRiskItem, LaneItem, PerceivedObject } from "../../types";

type Props = {
  objects: PerceivedObject[];
  lanes: LaneItem[];
  trajectories: Record<string, Array<{ x: number; y: number }>>;
  risks: CollisionRiskItem[];
  size?: number;
};

function toBev(x: number, y: number): { lateral: number; longitudinal: number } {
  return {
    lateral: Math.min(1, Math.max(-1, (x - 0.5) * 2)),
    longitudinal: Math.min(1, Math.max(0, 1 - y)),
  };
}

const RISK_FILL: Record<string, string> = {
  CRITICAL: "fill-red-400",
  HIGH: "fill-orange-400",
  MEDIUM: "fill-amber-400",
  LOW: "fill-sky-400",
  NONE: "fill-slate-600",
  UNKNOWN: "fill-slate-500",
};

function riskOf(objectId: string, risks: CollisionRiskItem[]): string {
  const order = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
  let best = "UNKNOWN";
  for (const risk of risks) {
    if (risk.object_ids.includes(objectId) && order.indexOf(risk.risk_level) > order.indexOf(best)) {
      best = risk.risk_level;
    }
  }
  return best;
}

/**
 * Relative bird's-eye canvas. The mapping (lateral, 1−y) preserves ordering
 * only — the canvas is explicitly labelled relative and unitless.
 */
export function BevCanvas({ objects, lanes, trajectories, risks, size = 320 }: Props) {
  const toPx = (lateral: number, longitudinal: number): [number, number] => [
    ((lateral + 1) / 2) * size,
    (1 - longitudinal) * size,
  ];

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-2">
      <svg
        viewBox={`0 0 ${size} ${size}`}
        className="block w-full rounded-lg bg-slate-900"
        role="img"
        aria-label="Relative bird's-eye view (unitless ordering proxy)"
      >
        {lanes.map((lane) => (
          <polyline
            key={lane.lane_id}
            points={lane.points
              .map((p) => {
                const b = toBev(p.x, p.y);
                const [px, py] = toPx(b.lateral, b.longitudinal);
                return `${px},${py}`;
              })
              .join(" ")}
            className="fill-none stroke-emerald-400/70"
            strokeWidth={2}
          />
        ))}
        {Object.entries(trajectories).map(([objectId, points]) =>
          points.length > 1 ? (
            <polyline
              key={`traj-${objectId}`}
              points={points
                .map((p) => {
                  const b = toBev(p.x, p.y);
                  const [px, py] = toPx(b.lateral, b.longitudinal);
                  return `${px},${py}`;
                })
                .join(" ")}
              className="fill-none stroke-amber-300/70"
              strokeWidth={1.5}
              strokeDasharray="4 3"
            />
          ) : null
        )}
        {objects.map((o) => {
          if (o.bounding_box == null) return null;
          const [x1, y1, x2, y2] = o.bounding_box;
          const b = toBev((x1 + x2) / 2, (y1 + y2) / 2);
          const [px, py] = toPx(b.lateral, b.longitudinal);
          const risk = riskOf(o.object_id, risks);
          return (
            <g key={o.object_id}>
              <circle cx={px} cy={py} r={7} className={RISK_FILL[risk] ?? RISK_FILL.UNKNOWN} opacity={0.85} />
              <text x={px + 9} y={py + 4} className="fill-slate-200" fontSize={10}>
                {o.object_id}
              </text>
            </g>
          );
        })}
        <text x={8} y={size - 8} className="fill-slate-500" fontSize={10}>
          Relative BEV — ordering proxy, not meters
        </text>
      </svg>
      <p className="mt-2 text-xs text-slate-500">
        Lateral ∈ [−1,1], longitudinal ∈ [0,1], mapped from normalized image
        coordinates. Relative only.
      </p>
    </div>
  );
}
