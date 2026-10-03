import type { LaneItem, PerceivedObject } from "../../types";

type Props = {
  objects: PerceivedObject[];
  lanes: LaneItem[];
  width?: number;
  height?: number;
};

const RISK_STYLE: Record<string, string> = {
  CRITICAL: "stroke-red-400/90",
  HIGH: "stroke-orange-400/80",
  MEDIUM: "stroke-amber-400/70",
  LOW: "stroke-sky-400/60",
  NONE: "stroke-slate-600/60",
  UNKNOWN: "stroke-slate-500/40",
};

/**
 * Normalized-coordinate lane/object overlay (image space, not metric).
 * Lane boundaries render as emerald polylines; perceived objects as boxes
 * tinted by motion state; velocity shown as a short heading tick.
 */
export function LaneOverlay({ objects, lanes, width = 640, height = 480 }: Props) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-2">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="block w-full rounded-lg bg-slate-900"
        role="img"
        aria-label="Lane and object overlay (normalized image space)"
      >
        <defs>
          <pattern id="lane-grid" width={width / 10} height={height / 10} patternUnits="userSpaceOnUse">
            <path
              d={`M ${width / 10} 0 L 0 0 0 ${height / 10}`}
              fill="none"
              stroke="rgb(51 65 85 / 0.4)"
              strokeWidth={1}
            />
          </pattern>
        </defs>
        <rect width={width} height={height} fill="url(#lane-grid)" />
        {lanes.map((lane) => (
          <g key={lane.lane_id}>
            <polyline
              points={lane.points.map((p) => `${p.x * width},${p.y * height}`).join(" ")}
              className="fill-none stroke-emerald-400/80"
              strokeWidth={2}
            />
            {lane.points.length > 0 && (
              <text
                x={lane.points[0].x * width + 4}
                y={lane.points[0].y * height - 4}
                className="fill-emerald-300"
                fontSize={11}
              >
                {lane.lane_id} · {lane.lane_type} · {(lane.confidence * 100).toFixed(0)}%
              </text>
            )}
          </g>
        ))}
        {objects.map((o) => {
          if (!o.bounding_box) return null;
          const [x1, y1, x2, y2] = o.bounding_box;
          const cx = ((x1 + x2) / 2) * width;
          const cy = ((y1 + y2) / 2) * height;
          return (
            <g key={o.object_id}>
              <rect
                x={x1 * width}
                y={y1 * height}
                width={Math.max(2, (x2 - x1) * width)}
                height={Math.max(2, (y2 - y1) * height)}
                className={`fill-sky-400/10 ${RISK_STYLE.UNKNOWN}`}
                strokeWidth={1.5}
              />
              <text x={x1 * width + 2} y={y1 * height - 4} className="fill-sky-300" fontSize={11}>
                {o.object_id} · {o.object_state}
              </text>
              {o.velocity && (
                <line
                  x1={cx}
                  y1={cy}
                  x2={cx + o.velocity[0] * width * 0.5}
                  y2={cy + o.velocity[1] * height * 0.5}
                  className="stroke-amber-300/80"
                  strokeWidth={1.5}
                />
              )}
            </g>
          );
        })}
      </svg>
      <p className="mt-2 text-xs text-slate-500">
        Normalized [0,1] image space — box positions and velocity ticks are relative, never meters.
      </p>
    </div>
  );
}
