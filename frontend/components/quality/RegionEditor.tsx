"use client";

import { useCallback, useMemo, useRef, useState } from "react";
import type { RegionType } from "../../types";

export type RegionDraft = {
  name: string;
  region_type: RegionType;
  geometry: Record<string, unknown>;
  enabled: boolean;
  required: boolean;
};

type Point = { x: number; y: number };

const CANVAS_W = 640;
const CANVAS_H = 480;

export function validateRegionDraft(draft: RegionDraft): string[] {
  const errors: string[] = [];
  if (!draft.name.trim()) errors.push("name is required");
  if (draft.region_type === "RECTANGLE") {
    const g = draft.geometry as { x?: number; y?: number; width?: number; height?: number };
    for (const key of ["x", "y", "width", "height"] as const) {
      if (typeof g[key] !== "number" || !Number.isFinite(g[key] as number)) {
        errors.push(`rectangle requires a numeric ${key}`);
        return errors;
      }
    }
    if (g.x! < 0 || g.x! > 1 || g.y! < 0 || g.y! > 1) errors.push("rectangle origin must be within [0,1]");
    if (g.width! <= 0 || g.width! > 1 || g.height! <= 0 || g.height! > 1)
      errors.push("rectangle width/height must be in (0,1]");
    if (g.x! + g.width! > 1 || g.y! + g.height! > 1) errors.push("rectangle must fit inside the frame");
  } else {
    const points = (draft.geometry.points ?? []) as Point[];
    if (points.length < 3) errors.push("polygon requires at least 3 points");
    for (const p of points) {
      if (!Number.isFinite(p.x) || !Number.isFinite(p.y) || p.x < 0 || p.x > 1 || p.y < 0 || p.y > 1) {
        errors.push("polygon points must be within [0,1]");
        break;
      }
    }
    const xs = new Set(points.map((p) => p.x.toFixed(6)));
    const ys = new Set(points.map((p) => p.y.toFixed(6)));
    if (points.length >= 3 && (xs.size < 2 || ys.size < 2))
      errors.push("polygon must span area in both axes");
  }
  return errors;
}

type DragState =
  | { kind: "rect"; start: Point }
  | { kind: "vertex"; index: number }
  | null;

type Props = {
  initial?: RegionDraft | null;
  onChange: (draft: RegionDraft | null, errors: string[]) => void;
};

/**
 * Lightweight normalized region editor (V07).
 *
 * RECTANGLE: click-drag on the canvas (or edit numeric inputs).
 * POLYGON: click to add vertices, drag a vertex to move it, remove the last
 * selected vertex. All coordinates are normalized [0,1] and shown on screen.
 * Geometry validation mirrors the backend contract (shared rules with V06).
 */
export function RegionEditor({ initial, onChange }: Props) {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const [name, setName] = useState(initial?.name ?? "");
  const [regionType, setRegionType] = useState<RegionType>(initial?.region_type ?? "RECTANGLE");
  const [enabled, setEnabled] = useState(initial?.enabled ?? true);
  const [required, setRequired] = useState(initial?.required ?? false);
  const [points, setPoints] = useState<Point[]>(
    initial?.region_type === "POLYGON"
      ? ((initial.geometry.points as Point[]) ?? [])
      : []
  );
  const [rect, setRect] = useState<{ x: number; y: number; width: number; height: number }>(
    initial?.region_type === "RECTANGLE" && typeof initial.geometry.x === "number"
      ? (initial.geometry as { x: number; y: number; width: number; height: number })
      : { x: 0.25, y: 0.25, width: 0.5, height: 0.5 }
  );
  const [selectedVertex, setSelectedVertex] = useState<number | null>(null);
  const [drag, setDrag] = useState<DragState>(null);

  const emit = useCallback(
    (nextPoints: Point[], nextRect: typeof rect, type: RegionType) => {
      const draft: RegionDraft = {
        name,
        region_type: type,
        geometry:
          type === "RECTANGLE"
            ? { ...nextRect }
            : { points: nextPoints.map((p) => ({ x: p.x, y: p.y })) },
        enabled,
        required,
      };
      onChange(draft, validateRegionDraft(draft));
    },
    [name, enabled, required, onChange]
  );

  const toNormalized = useCallback((clientX: number, clientY: number): Point => {
    const svg = svgRef.current;
    if (!svg) return { x: 0, y: 0 };
    const bounds = svg.getBoundingClientRect();
    const x = ((clientX - bounds.left) / bounds.width) * CANVAS_W;
    const y = ((clientY - bounds.top) / bounds.height) * CANVAS_H;
    return {
      x: Math.min(1, Math.max(0, x / CANVAS_W)),
      y: Math.min(1, Math.max(0, y / CANVAS_H)),
    };
  }, []);

  const handleCanvasPointerDown = (event: React.PointerEvent<SVGSVGElement>) => {
    const point = toNormalized(event.clientX, event.clientY);
    if (regionType === "RECTANGLE") {
      setDrag({ kind: "rect", start: point });
      return;
    }
    const next = [...points, point];
    setPoints(next);
    setSelectedVertex(next.length - 1);
    emit(next, rect, regionType);
  };

  const handleCanvasPointerMove = (event: React.PointerEvent<SVGSVGElement>) => {
    if (!drag) return;
    const point = toNormalized(event.clientX, event.clientY);
    if (drag.kind === "rect") {
      const next = {
        x: Math.min(drag.start.x, point.x),
        y: Math.min(drag.start.y, point.y),
        width: Math.abs(point.x - drag.start.x),
        height: Math.abs(point.y - drag.start.y),
      };
      setRect(next);
      emit(points, next, regionType);
      return;
    }
    const next = points.map((p, i) => (i === drag.index ? point : p));
    setPoints(next);
    emit(next, rect, regionType);
  };

  const handleCanvasPointerUp = () => setDrag(null);

  const removeVertex = () => {
    if (points.length === 0) return;
    const index = selectedVertex ?? points.length - 1;
    const next = points.filter((_, i) => i !== index);
    setPoints(next);
    setSelectedVertex(null);
    emit(next, rect, regionType);
  };

  const reset = () => {
    setPoints([]);
    setRect({ x: 0.25, y: 0.25, width: 0.5, height: 0.5 });
    setSelectedVertex(null);
    setDrag(null);
    emit([], { x: 0.25, y: 0.25, width: 0.5, height: 0.5 }, regionType);
  };

  const errors = useMemo(
    () =>
      validateRegionDraft({
        name,
        region_type: regionType,
        geometry: regionType === "RECTANGLE" ? { ...rect } : { points },
        enabled,
        required,
      }),
    [name, regionType, rect, points, enabled, required]
  );

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <input
          value={name}
          onChange={(e) => {
            setName(e.target.value);
            emit(points, rect, regionType);
          }}
          placeholder="Region name"
          className="rounded-lg bg-slate-800 px-3 py-1.5"
        />
        <select
          value={regionType}
          onChange={(e) => {
            const type = e.target.value as RegionType;
            setRegionType(type);
            emit(points, rect, type);
          }}
          className="rounded-lg bg-slate-800 px-3 py-1.5"
        >
          <option value="RECTANGLE">Rectangle</option>
          <option value="POLYGON">Polygon</option>
        </select>
        <label className="flex items-center gap-1 text-xs text-slate-300">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => {
              setEnabled(e.target.checked);
              emit(points, rect, regionType);
            }}
          />
          Enabled
        </label>
        <label className="flex items-center gap-1 text-xs text-slate-300">
          <input
            type="checkbox"
            checked={required}
            onChange={(e) => {
              setRequired(e.target.checked);
              emit(points, rect, regionType);
            }}
          />
          Required
        </label>
      </div>

      <svg
        ref={svgRef}
        viewBox={`0 0 ${CANVAS_W} ${CANVAS_H}`}
        className="block w-full cursor-crosshair rounded-lg bg-slate-900"
        onPointerDown={handleCanvasPointerDown}
        onPointerMove={handleCanvasPointerMove}
        onPointerUp={handleCanvasPointerUp}
      >
        <defs>
          <pattern id="region-grid" width={CANVAS_W / 10} height={CANVAS_H / 10} patternUnits="userSpaceOnUse">
            <path
              d={`M ${CANVAS_W / 10} 0 L 0 0 0 ${CANVAS_H / 10}`}
              fill="none"
              stroke="rgb(51 65 85 / 0.4)"
              strokeWidth={1}
            />
          </pattern>
        </defs>
        <rect width={CANVAS_W} height={CANVAS_H} fill="url(#region-grid)" />
        {regionType === "RECTANGLE" ? (
          <rect
            x={rect.x * CANVAS_W}
            y={rect.y * CANVAS_H}
            width={rect.width * CANVAS_W}
            height={rect.height * CANVAS_H}
            className="stroke-emerald-400/80 fill-emerald-400/10"
            strokeWidth={2}
          />
        ) : (
          <>
            {points.length >= 2 && (
              <polyline
                points={points.map((p) => `${p.x * CANVAS_W},${p.y * CANVAS_H}`).join(" ")}
                className="stroke-emerald-400/80 fill-emerald-400/10"
                strokeWidth={2}
              />
            )}
            {points.map((p, i) => (
              <circle
                key={i}
                cx={p.x * CANVAS_W}
                cy={p.y * CANVAS_H}
                r={6}
                className={
                  selectedVertex === i
                    ? "fill-amber-300 stroke-amber-200"
                    : "fill-emerald-300 stroke-emerald-200"
                }
                onPointerDown={(e) => {
                  e.stopPropagation();
                  setSelectedVertex(i);
                  setDrag({ kind: "vertex", index: i });
                }}
              />
            ))}
          </>
        )}
      </svg>

      <div className="flex flex-wrap items-center gap-2 text-xs">
        <button
          onClick={() => {
            const next = points.slice(0, -1);
            setPoints(next);
            setSelectedVertex(null);
            emit(next, rect, regionType);
          }}
          disabled={regionType !== "POLYGON" || points.length === 0}
          className="rounded-lg bg-slate-800 px-3 py-1.5 disabled:opacity-40"
        >
          Undo point
        </button>
        <button
          onClick={removeVertex}
          disabled={regionType !== "POLYGON" || points.length === 0}
          className="rounded-lg bg-slate-800 px-3 py-1.5 disabled:opacity-40"
        >
          Remove vertex
        </button>
        <button onClick={reset} className="rounded-lg bg-slate-800 px-3 py-1.5">
          Reset
        </button>
        <span className="text-slate-400">
          {regionType === "RECTANGLE"
            ? `x ${rect.x.toFixed(3)} · y ${rect.y.toFixed(3)} · w ${rect.width.toFixed(3)} · h ${rect.height.toFixed(3)}`
            : `${points.length} vertex${points.length === 1 ? "" : "es"} (click to add, drag to move)`}
        </span>
      </div>

      {regionType === "RECTANGLE" && (
        <div className="grid grid-cols-4 gap-2 text-xs">
          {(["x", "y", "width", "height"] as const).map((key) => (
            <label key={key} className="flex flex-col gap-1 text-slate-400">
              {key}
              <input
                type="number"
                step={0.01}
                min={0}
                max={1}
                value={rect[key]}
                onChange={(e) => {
                  const next = { ...rect, [key]: Number(e.target.value) };
                  setRect(next);
                  emit(points, next, regionType);
                }}
                className="rounded-lg bg-slate-800 px-2 py-1"
              />
            </label>
          ))}
        </div>
      )}

      {errors.length > 0 && (
        <ul className="list-inside list-disc text-xs text-amber-300">
          {errors.map((error) => (
            <li key={error}>{error}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
