import { memo } from "react";
import Link from "next/link";
import { Card } from "../ui/Card";
import { FreshnessBadge, StateText } from "./primitives";

export type CameraRow = {
  camera_id: string;
  name: string;
  source_type: string;
  enabled: boolean;
  /** Stream lifecycle state, NOT_STARTED, UNKNOWN, or FETCH_ERROR. */
  state: string;
  frameAgeMs: number | null;
  processingFps: number | null;
  latencyMs: number | null;
  tracks: number | null;
  detections: number | null;
  events: number | null;
  error: string | null;
};

function CameraCard({ row }: { row: CameraRow }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-sm font-medium">
          {row.name} <span className="text-slate-500">· {row.camera_id}</span>
        </span>
        <Link href="/cameras" className="text-xs text-sky-400 hover:underline" aria-label={`Open camera operations for ${row.camera_id}`}>
          Operate
        </Link>
      </div>
      <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-400">
        <span>{row.source_type}</span>
        <span>{row.enabled ? "enabled" : "disabled"}</span>
        <StateText level={row.state} text={row.state} />
        {row.error && <span className="text-amber-300">{row.error}</span>}
      </div>
      <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-500">
        <FreshnessBadge ageMs={row.frameAgeMs} staleAfterMs={10000} />
        <span>fps: {row.processingFps ?? "—"}</span>
        <span>latency: {row.latencyMs !== null ? `${row.latencyMs}ms` : "—"}</span>
        <span>tracks: {row.tracks ?? "—"}</span>
        <span>events: {row.events ?? "—"}</span>
      </div>
    </div>
  );
}

export const CameraGrid = memo(function CameraGrid({ rows }: { rows: CameraRow[] }) {
  if (rows.length === 0) {
    return <p className="text-sm text-slate-400">No cameras configured. Add one on the cameras page.</p>;
  }
  return (
    <div className="space-y-2">
      <p className="text-xs text-slate-500">
        No browser video transport exists: preview unavailable by design. Cards show real stream
        metadata; operate cameras on the{" "}
        <Link href="/cameras" className="text-sky-400 hover:underline">
          cameras page
        </Link>
        .
      </p>
      <div className="grid gap-2 md:grid-cols-2">
        {rows.map((row) => (
          <CameraCard key={row.camera_id} row={row} />
        ))}
      </div>
    </div>
  );
});

export function CameraGridCard({ rows }: { rows: CameraRow[] }) {
  return (
    <Card title={`Cameras (${rows.length})`}>
      <CameraGrid rows={rows} />
    </Card>
  );
}
