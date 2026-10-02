"use client";

import { useMemo } from "react";
import type { DefectObservation, InspectionRegion } from "../../types";

const REGION_STYLE: Record<string, string> = {
  enabled: "stroke-emerald-400/70 fill-emerald-400/10",
  disabled: "stroke-slate-500/50 fill-slate-500/5"
};

type Props = {
  regions: InspectionRegion[];
  observations: DefectObservation[];
  /** Optional real frame; without one a labelled coordinate canvas is shown. */
  frame?: { width: number; height: number; label: string } | null;
};

/**
 * Normalized-coordinate canvas for inspection regions and defect boxes.
 *
 * V07 has no persistent image storage, so when no live frame is available the
 * canvas is explicitly labelled as a coordinate surface — never a fake image.
 */
export function InspectionCanvas({ regions, observations, frame }: Props) {
  const width = frame?.width ?? 640;
  const height = frame?.height ?? 480;

  const regionShapes = useMemo(
    () =>
      regions.map((region) => {
        if (region.region_type === "RECTANGLE") {
          const g = region.geometry as { x: number; y: number; width: number; height: number };
          return (
            <rect
              key={region.region_id}
              x={g.x * width}
              y={g.y * height}
              width={g.width * width}
              height={g.height * height}
              className={REGION_STYLE[region.enabled ? "enabled" : "disabled"]}
            />
          );
        }
        const points = (region.geometry.points ?? []) as Array<{ x: number; y: number }>;
        return (
          <polygon
            key={region.region_id}
            points={points.map((p) => `${p.x * width},${p.y * height}`).join(" ")}
            className={REGION_STYLE[region.enabled ? "enabled" : "disabled"]}
          />
        );
      }),
    [regions, width, height]
  );

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-2">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="block w-full rounded-lg bg-slate-900"
        role="img"
        aria-label="Inspection coordinate canvas"
      >
        <defs>
          <pattern id="grid" width={width / 10} height={height / 10} patternUnits="userSpaceOnUse">
            <path
              d={`M ${width / 10} 0 L 0 0 0 ${height / 10}`}
              fill="none"
              stroke="rgb(51 65 85 / 0.4)"
              strokeWidth={1}
            />
          </pattern>
        </defs>
        <rect width={width} height={height} fill="url(#grid)" />
        {regionShapes}
        {observations.map((o) => {
          if (!o.bounding_box) return null;
          const [x1, y1, x2, y2] = o.bounding_box;
          return (
            <rect
              key={o.observation_id}
              x={x1 * width}
              y={y1 * height}
              width={Math.max(2, (x2 - x1) * width)}
              height={Math.max(2, (y2 - y1) * height)}
              className="stroke-rose-400/80 fill-rose-400/10"
              strokeWidth={2}
            />
          );
        })}
      </svg>
      <p className="mt-2 text-xs text-slate-500">
        {frame
          ? `Frame surface ${frame.label} (${frame.width}×${frame.height}) — normalized coordinates`
          : "Coordinate canvas (no frame surface available) — normalized [0,1] coordinates"}
      </p>
      {regions.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-2">
          {regions.map((region) => (
            <span
              key={region.region_id}
              className="rounded-full bg-slate-800 px-2 py-0.5 text-xs text-slate-300"
            >
              {region.name}
              {region.required ? " (required)" : ""}
              {region.enabled ? "" : " (disabled)"}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
