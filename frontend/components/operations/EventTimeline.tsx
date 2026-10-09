import { memo } from "react";
import Link from "next/link";
import { Card } from "../ui/Card";
import { StateText } from "./primitives";
import type { TimelineFilter } from "../../lib/operations/timeline";
import type { TimelineItem, TimelineKind } from "../../types";

const KINDS: TimelineKind[] = ["safety", "spatial", "quality", "autonomous", "intelligence", "incident"];

function FilterBar({
  filter,
  cameras,
  severities,
  onChange,
}: {
  filter: TimelineFilter;
  cameras: string[];
  severities: string[];
  onChange: (next: TimelineFilter) => void;
}) {
  const toggleKind = (kind: TimelineKind) => {
    const kinds = new Set(filter.kinds);
    if (kinds.has(kind)) kinds.delete(kind);
    else kinds.add(kind);
    onChange({ ...filter, kinds });
  };
  return (
    <div className="mb-2 flex flex-wrap items-center gap-2 text-xs">
      <div className="flex flex-wrap gap-1" role="group" aria-label="event category filter">
        {KINDS.map((kind) => (
          <button
            key={kind}
            onClick={() => toggleKind(kind)}
            aria-pressed={filter.kinds.size === 0 || filter.kinds.has(kind)}
            className={`rounded-full px-2 py-0.5 ${
              filter.kinds.size === 0 || filter.kinds.has(kind)
                ? "bg-sky-600 text-white"
                : "bg-slate-800 text-slate-300"
            }`}
          >
            {kind}
          </button>
        ))}
      </div>
      <label className="text-slate-400">
        camera{" "}
        <select
          value={Array.from(filter.cameras)[0] ?? ""}
          onChange={(e) =>
            onChange({ ...filter, cameras: e.target.value ? new Set([e.target.value]) : new Set() })
          }
          className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-slate-200"
          aria-label="camera filter"
        >
          <option value="">all</option>
          {cameras.map((camera) => (
            <option key={camera} value={camera}>
              {camera}
            </option>
          ))}
        </select>
      </label>
      <label className="text-slate-400">
        severity{" "}
        <select
          value={Array.from(filter.severities)[0] ?? ""}
          onChange={(e) =>
            onChange({
              ...filter,
              severities: e.target.value ? new Set([e.target.value]) : new Set(),
            })
          }
          className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-slate-200"
          aria-label="severity filter"
        >
          <option value="">all</option>
          {severities.map((severity) => (
            <option key={severity} value={severity}>
              {severity}
            </option>
          ))}
        </select>
      </label>
    </div>
  );
}

function TimelineRow({ item }: { item: TimelineItem }) {
  const body = (
    <>
      <span className="font-medium text-slate-200">[{item.kind}] </span>
      <StateText level={item.severity} text={item.severity} />
      <span className="text-slate-400"> · {item.title}</span>
      <span className="block text-slate-500">
        {item.cameraId || "—"} · {item.timestamp || "time unknown"}
        {item.source === "socket" ? " · live" : ""}
      </span>
    </>
  );
  return (
    <li key={item.id} className="rounded-lg border border-slate-800 px-2 py-1 text-xs">
      {item.href ? (
        <Link href={item.href} className="hover:underline">
          {body}
        </Link>
      ) : (
        body
      )}
    </li>
  );
}

export const EventTimeline = memo(function EventTimeline({
  items,
  filter,
  cameras,
  severities,
  onFilterChange,
}: {
  items: TimelineItem[];
  filter: TimelineFilter;
  cameras: string[];
  severities: string[];
  onFilterChange: (next: TimelineFilter) => void;
}) {
  if (items.length === 0) {
    return <p className="text-sm text-slate-400">No events yet — genuine quiet, not missing data.</p>;
  }
  return (
    <div>
      <FilterBar filter={filter} cameras={cameras} severities={severities} onChange={onFilterChange} />
      <ol className="max-h-96 space-y-1 overflow-y-auto">
        {items.slice(0, 100).map((item) => (
          <TimelineRow key={item.id} item={item} />
        ))}
      </ol>
      {items.length > 100 && (
        <p className="mt-1 text-xs text-slate-500">
          Showing newest 100 of {items.length} (bounded window).
        </p>
      )}
    </div>
  );
});

export function EventTimelineCard(props: {
  items: TimelineItem[];
  filter: TimelineFilter;
  cameras: string[];
  severities: string[];
  onFilterChange: (next: TimelineFilter) => void;
}) {
  return (
    <Card title={`Live event timeline (${props.items.length})`}>
      <EventTimeline {...props} />
    </Card>
  );
}
