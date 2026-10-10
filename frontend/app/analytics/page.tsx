"use client";

import { useCallback, useEffect, useState } from "react";
import { Card } from "../../components/ui/Card";
import { DataState, SectionBadge } from "../../components/operations/primitives";
import { BreakdownBars, TrendChart } from "../../components/analytics/Charts";
import {
  buildAnalyticsQuery,
  downloadExport,
  exportUrl,
  fetchAnalyticsBreakdowns,
  fetchAnalyticsSummary,
  fetchAnalyticsTrends,
} from "../../lib/analytics/client";
import type {
  AnalyticsBreakdown,
  AnalyticsFilters,
  AnalyticsOverview,
  AnalyticsQuery,
  AnalyticsTrend,
  ExportReportType,
} from "../../types";

function filtersKey(filters: AnalyticsFilters): string {
  return JSON.stringify(filters);
}

const PRESETS = [
  { value: "24h", label: "Last 24 hours" },
  { value: "7d", label: "Last 7 days" },
  { value: "30d", label: "Last 30 days" },
  { value: "custom", label: "Custom range" },
] as const;

const DOMAINS = ["SAFETY", "SPATIAL", "QUALITY", "AUTONOMOUS", "INTELLIGENCE", "INCIDENT"];
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const STATUSES = ["OPEN", "ACKNOWLEDGED", "INVESTIGATING", "MITIGATED", "RESOLVED", "CLOSED"];
const PRIORITIES = ["P0", "P1", "P2", "P3", "P4"];
const METRICS = ["events", "incidents_created", "incidents_resolved", "incidents_closed"];
const REPORTS: ExportReportType[] = ["events", "incidents", "safety", "camera_activity", "quality_events"];

function toggle(list: string[], value: string): string[] {
  return list.includes(value) ? list.filter((v) => v !== value) : [...list, value];
}

function FilterChips({
  label,
  options,
  selected,
  onToggle,
}: {
  label: string;
  options: string[];
  selected: string[];
  onToggle: (value: string) => void;
}) {
  return (
    <div>
      <p className="text-xs text-slate-400">{label}</p>
      <div className="mt-1 flex flex-wrap gap-1" role="group" aria-label={label}>
        {options.map((option) => (
          <button
            key={option}
            onClick={() => onToggle(option)}
            aria-pressed={selected.includes(option)}
            className={`rounded-full px-2 py-0.5 text-xs ${
              selected.includes(option) ? "bg-sky-600 text-white" : "bg-slate-800 text-slate-300"
            }`}
          >
            {option}
          </button>
        ))}
      </div>
    </div>
  );
}

function Definition({ children }: { children: React.ReactNode }) {
  return <p className="mt-1 text-xs text-slate-500">{children}</p>;
}

/**
 * Historical analytics & reporting — V14.
 *
 * Durable PostgreSQL history only. Quality inspection outcomes are
 * unavailable by design (results are not persisted).
 */
export default function AnalyticsPage() {
  const [filters, setFilters] = useState<AnalyticsFilters>({
    preset: "7d",
    startAt: null,
    endAt: null,
    bucket: "day",
    domains: [],
    severities: [],
    cameras: [],
    statuses: [],
    priorities: [],
  });
  const [applied, setApplied] = useState<AnalyticsQuery | null>(null);
  const [filterError, setFilterError] = useState<string | null>(null);
  const [overview, setOverview] = useState<AnalyticsOverview | null>(null);
  const [overviewError, setOverviewError] = useState<string | null>(null);
  const [metric, setMetric] = useState("events");
  const [trend, setTrend] = useState<AnalyticsTrend | null>(null);
  const [trendError, setTrendError] = useState<string | null>(null);
  const [dataset, setDataset] = useState("events");
  const [groupBy, setGroupBy] = useState("domain");
  const [breakdown, setBreakdown] = useState<AnalyticsBreakdown | null>(null);
  const [breakdownError, setBreakdownError] = useState<string | null>(null);
  const [report, setReport] = useState<ExportReportType>("events");
  const [exportState, setExportState] = useState<"idle" | "busy" | "done" | "error">("idle");
  const [exportError, setExportError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [appliedFilters, setAppliedFilters] = useState<string | null>(null);

  const dirty = applied !== null && appliedFilters !== null && filtersKey(filters) !== appliedFilters;

  const apply = useCallback(() => {
    let query;
    try {
      query = buildAnalyticsQuery(filters);
    } catch (e) {
      setFilterError(e instanceof Error ? e.message : "Invalid filters");
      return;
    }
    setFilterError(null);
    setApplied(query);
    setAppliedFilters(filtersKey(filters));
    setLoading(true);
    setExportState("idle");
    setExportError(null);
    const run = async () => {
      const [summaryRes, trendRes, breakdownRes] = await Promise.allSettled([
        fetchAnalyticsSummary(query),
        fetchAnalyticsTrends(query, metric),
        fetchAnalyticsBreakdowns(query, dataset, groupBy),
      ]);
      if (summaryRes.status === "fulfilled") {
        setOverview(summaryRes.value);
        setOverviewError(null);
      } else {
        setOverviewError(summaryRes.reason instanceof Error ? summaryRes.reason.message : "Failed");
      }
      if (trendRes.status === "fulfilled") {
        setTrend(trendRes.value);
        setTrendError(null);
      } else {
        setTrendError(trendRes.reason instanceof Error ? trendRes.reason.message : "Failed");
      }
      if (breakdownRes.status === "fulfilled") {
        setBreakdown(breakdownRes.value);
        setBreakdownError(null);
      } else {
        setBreakdownError(
          breakdownRes.reason instanceof Error ? breakdownRes.reason.message : "Failed"
        );
      }
      setLoading(false);
    };
    void run();
  }, [filters, metric, dataset, groupBy]);

  useEffect(() => {
    // Deliberate submit model: no fetch on keystroke; initial load applies defaults once.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const doExport = useCallback(async () => {
    if (!applied) return;
    setExportState("busy");
    setExportError(null);
    try {
      await downloadExport(exportUrl(applied, report), `analytics-${report}.csv`);
      setExportState("done");
    } catch (e) {
      setExportState("error");
      setExportError(e instanceof Error ? e.message : "Export failed");
    }
  }, [applied, report]);

  const periodLabel = applied
    ? `${new Date(applied.start_at).toLocaleString()} → ${new Date(applied.end_at).toLocaleString()} (UTC source)`
    : "no report generated yet";

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-lg font-bold">Historical Analytics & Reporting</h1>
        <p className="text-xs text-slate-400">
          Durable PostgreSQL history only — never frames, detections, or live telemetry.
          Reporting period: {periodLabel}.
        </p>
      </div>

      <Card title="Report filters">
        <div className="space-y-2">
          <div className="flex flex-wrap gap-1" role="group" aria-label="time preset">
            {PRESETS.map((preset) => (
              <button
                key={preset.value}
                onClick={() => setFilters({ ...filters, preset: preset.value })}
                aria-pressed={filters.preset === preset.value}
                className={`rounded-full px-2 py-0.5 text-xs ${
                  filters.preset === preset.value
                    ? "bg-sky-600 text-white"
                    : "bg-slate-800 text-slate-300"
                }`}
              >
                {preset.label}
              </button>
            ))}
          </div>
          {filters.preset === "custom" && (
            <div className="flex flex-wrap gap-2">
              <label className="text-xs text-slate-400">
                Start (UTC){" "}
                <input
                  type="datetime-local"
                  value={filters.startAt ?? ""}
                  onChange={(e) =>
                    setFilters({
                      ...filters,
                      startAt: e.target.value ? `${e.target.value}:00Z` : null,
                    })
                  }
                  className="mt-1 rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm text-slate-200"
                  aria-label="report start"
                />
              </label>
              <label className="text-xs text-slate-400">
                End (UTC){" "}
                <input
                  type="datetime-local"
                  value={filters.endAt ? filters.endAt.slice(0, 16) : ""}
                  onChange={(e) =>
                    setFilters({
                      ...filters,
                      endAt: e.target.value ? `${e.target.value}:00Z` : null,
                    })
                  }
                  className="mt-1 rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm text-slate-200"
                  aria-label="report end"
                />
              </label>
            </div>
          )}
          <div className="grid gap-2 md:grid-cols-2">
            <FilterChips
              label="Domains"
              options={DOMAINS}
              selected={filters.domains}
              onToggle={(v) => setFilters({ ...filters, domains: toggle(filters.domains, v) })}
            />
            <FilterChips
              label="Severities"
              options={SEVERITIES}
              selected={filters.severities}
              onToggle={(v) => setFilters({ ...filters, severities: toggle(filters.severities, v) })}
            />
            <FilterChips
              label="Incident statuses"
              options={STATUSES}
              selected={filters.statuses}
              onToggle={(v) => setFilters({ ...filters, statuses: toggle(filters.statuses, v) })}
            />
            <FilterChips
              label="Incident priorities"
              options={PRIORITIES}
              selected={filters.priorities}
              onToggle={(v) => setFilters({ ...filters, priorities: toggle(filters.priorities, v) })}
            />
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <label className="text-xs text-slate-400">
              Camera{" "}
              <input
                value={filters.cameras[0] ?? ""}
                onChange={(e) =>
                  setFilters({ ...filters, cameras: e.target.value ? [e.target.value.trim()] : [] })
                }
                placeholder="camera_id (optional)"
                className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm text-slate-200"
                aria-label="camera filter"
              />
            </label>
            <label className="text-xs text-slate-400">
              Bucket{" "}
              <select
                value={filters.bucket}
                onChange={(e) =>
                  setFilters({ ...filters, bucket: e.target.value as AnalyticsFilters["bucket"] })
                }
                className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm text-slate-200"
                aria-label="time bucket"
              >
                <option value="hour">hour</option>
                <option value="day">day</option>
                <option value="week">week</option>
              </select>
            </label>
            <button
              onClick={apply}
              className="rounded-lg bg-sky-700 px-3 py-1.5 text-sm hover:bg-sky-600"
            >
              Apply
            </button>
            <button
              onClick={() =>
                setFilters({
                  preset: "7d",
                  startAt: null,
                  endAt: null,
                  bucket: "day",
                  domains: [],
                  severities: [],
                  cameras: [],
                  statuses: [],
                  priorities: [],
                })
              }
              className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm hover:bg-slate-700"
            >
              Reset
            </button>
          </div>
        </div>
        {filterError && (
          <p className="mt-2 text-sm text-red-300" role="alert">
            {filterError}
          </p>
        )}
        {dirty && !loading && (
          <p className="mt-2 text-xs text-amber-300" role="status">
            Filters changed — results below reflect the previously applied report until you Apply.
          </p>
        )}
      </Card>

      <Card title="Overview">
        <DataState
          state={loading && !overview ? "loading" : overviewError ? "error" : overview ? "ready" : "empty"}
          emptyText="Apply filters to generate a historical report."
          error={overviewError}
        >
          {overview && <OverviewBody overview={overview} />}
        </DataState>
      </Card>

      <Card title="Trends">
        <div className="mb-2 flex items-center gap-2 text-xs">
          <label className="text-slate-400">
            Metric{" "}
            <select
              value={metric}
              onChange={(e) => setMetric(e.target.value)}
              className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-sm text-slate-200"
              aria-label="trend metric"
            >
              {METRICS.map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
          </label>
          <button
            onClick={() => applied && void fetchAnalyticsTrends(applied, metric).then(setTrend, (e: unknown) => setTrendError(e instanceof Error ? e.message : "Failed"))}
            disabled={!applied}
            className="rounded-lg bg-slate-800 px-2 py-1 disabled:opacity-40 hover:bg-slate-700"
          >
            Reload
          </button>
        </div>
        <DataState
          state={loading && !trend ? "loading" : trendError ? "error" : trend ? "ready" : "empty"}
          emptyText="No trend data — apply filters first."
          error={trendError}
        >
          {trend && trend.buckets.length > 0 ? (
            <>
              <TrendChart buckets={trend.buckets} bucket={trend.bucket} label={trend.metric} />
              <table className="mt-2 w-full text-xs text-slate-300">
                <caption className="text-left text-slate-500">
                  Bucket counts for {trend.metric} ({trend.bucket} boundaries, UTC).
                  {trend.truncated ? " Source truncated at row cap." : ""}
                </caption>
                <thead>
                  <tr className="text-left text-slate-500">
                    <th className="pr-4 font-medium">Bucket start (UTC)</th>
                    <th className="font-medium">Count</th>
                  </tr>
                </thead>
                <tbody>
                  {trend.buckets.map((bucket) => (
                    <tr key={bucket.bucket_start} className="border-t border-slate-800">
                      <td className="pr-4">{bucket.bucket_start}</td>
                      <td>{bucket.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          ) : (
            trend && <p className="text-sm text-slate-400">No records in this period — genuine zero.</p>
          )}
        </DataState>
      </Card>

      <Card title="Breakdowns">
        <div className="mb-2 flex items-center gap-2 text-xs">
          <label className="text-slate-400">
            Dataset{" "}
            <select
              value={dataset}
              onChange={(e) => {
                setDataset(e.target.value);
                setGroupBy(e.target.value === "incidents" ? "status" : "domain");
              }}
              className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-sm text-slate-200"
              aria-label="breakdown dataset"
            >
              <option value="events">events</option>
              <option value="incidents">incidents</option>
            </select>
          </label>
          <label className="text-slate-400">
            Group by{" "}
            <select
              value={groupBy}
              onChange={(e) => setGroupBy(e.target.value)}
              className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-sm text-slate-200"
              aria-label="breakdown grouping"
            >
              {(dataset === "incidents"
                ? ["status", "priority", "camera", "category"]
                : ["domain", "severity", "camera", "event_type"]
              ).map((g) => (
                <option key={g} value={g}>
                  {g}
                </option>
              ))}
            </select>
          </label>
          <button
            onClick={() =>
              applied &&
              void fetchAnalyticsBreakdowns(applied, dataset, groupBy).then(setBreakdown, (e: unknown) =>
                setBreakdownError(e instanceof Error ? e.message : "Failed")
              )
            }
            disabled={!applied}
            className="rounded-lg bg-slate-800 px-2 py-1 disabled:opacity-40 hover:bg-slate-700"
          >
            Reload
          </button>
        </div>
        <DataState
          state={loading && !breakdown ? "loading" : breakdownError ? "error" : breakdown ? "ready" : "empty"}
          emptyText="No breakdown data — apply filters first."
          error={breakdownError}
        >
          {breakdown && breakdown.groups.length > 0 ? (
            <>
              <BreakdownBars groups={breakdown.groups} label={`${breakdown.dataset} by ${breakdown.group_by}`} horizontal />
              <table className="mt-2 w-full text-xs text-slate-300">
                <caption className="text-left text-slate-500">
                  {breakdown.dataset} grouped by {breakdown.group_by}.
                  {breakdown.truncated ? " Source truncated at row cap." : ""}
                </caption>
                <thead>
                  <tr className="text-left text-slate-500">
                    <th className="pr-4 font-medium">Group</th>
                    <th className="font-medium">Count</th>
                  </tr>
                </thead>
                <tbody>
                  {breakdown.groups.map((group) => (
                    <tr key={group.key} className="border-t border-slate-800">
                      <td className="pr-4">{group.label}</td>
                      <td>{group.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          ) : (
            breakdown && <p className="text-sm text-slate-400">No records in this period — genuine zero.</p>
          )}
        </DataState>
      </Card>

      <Card title="Export CSV">
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <label className="text-slate-400">
            Report{" "}
            <select
              value={report}
              onChange={(e) => setReport(e.target.value as ExportReportType)}
              className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-sm text-slate-200"
              aria-label="export report type"
            >
              {REPORTS.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </label>
          <button
            onClick={() => void doExport()}
            disabled={!applied || exportState === "busy"}
            className="rounded-lg bg-emerald-700 px-3 py-1.5 text-sm disabled:opacity-40 hover:bg-emerald-600"
          >
            {exportState === "busy" ? "Exporting…" : "Download CSV"}
          </button>
          {exportState === "done" && (
            <span className="text-emerald-300" role="status">Download started.</span>
          )}
          {exportState === "error" && (
            <span className="text-red-300" role="alert">{exportError}</span>
          )}
        </div>
        <Definition>
          Same filters and definitions as the report above. UTF-8 with BOM for Excel; max 5000
          rows — over-limit exports fail explicitly so files never silently truncate.
        </Definition>
      </Card>
    </div>
  );
}

function Counts({ record }: { record: Record<string, number> }) {
  const rows = Object.entries(record).sort((a, b) => b[1] - a[1]);
  if (rows.length === 0) return <span className="text-slate-500">none</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {rows.map(([key, value]) => (
        <span key={key} className="rounded bg-slate-800 px-1.5 py-0.5 text-xs text-slate-300">
          {key}: {value}
        </span>
      ))}
    </span>
  );
}

function OverviewBody({ overview }: { overview: AnalyticsOverview }) {
  const resolution = overview.incidents.resolution;
  return (
    <div className="space-y-3 text-sm">
      <p className="text-xs text-slate-500">
        Period {new Date(overview.start_at).toLocaleString()} →{" "}
        {new Date(overview.end_at).toLocaleString()} · generated{" "}
        {new Date(overview.generated_at).toLocaleString()}
      </p>
      <div>
        <p className="font-medium">Events: {overview.events.total} canonical events</p>
        {overview.events.status === "ok" ? (
          <>
            <Counts record={overview.events.by_domain} />
            <Counts record={overview.events.by_severity} />
            {overview.events.truncated && (
              <p className="text-xs text-amber-300">Source hit the row cap — counts are partial.</p>
            )}
          </>
        ) : (
          <p className="text-xs text-amber-300">{overview.events.message || "Event history unavailable."}</p>
        )}
        <Definition>Distinct canonical event IDs by occurrence timestamp (first_seen).</Definition>
      </div>
      <div>
        <p className="font-medium">
          Incidents: {overview.incidents.created_total} created · {overview.incidents.open_total}{" "}
          currently open · {overview.incidents.resolved_total} resolved ·{" "}
          {overview.incidents.closed_total} closed
        </p>
        {overview.incidents.status === "ok" ? (
          <>
            <Counts record={overview.incidents.by_status} />
            <Counts record={overview.incidents.by_priority} />
            <p className="text-xs text-slate-400">
              Resolution (created → resolved/closed): n={resolution.count}
              {resolution.count > 0 &&
                ` · avg ${resolution.average_seconds}s · median ${resolution.median_seconds}s · range ${resolution.min_seconds}s–${resolution.max_seconds}s`}
            </p>
          </>
        ) : (
          <p className="text-xs text-amber-300">{overview.incidents.message || "Incident data unavailable."}</p>
        )}
        <Definition>
          “Created” uses creation time; “currently open” is present state, not state-at-time.
        </Definition>
      </div>
      <div>
        <p className="font-medium">Quality inspection outcomes</p>
        <p className="text-xs text-slate-400">
          Unavailable — inspection results are not persisted, so totals and rates cannot be
          calculated. Use Recorded Quality Events (quality_events export) for durably recorded
          quality-domain events, which are event counts, not inspection outcomes.
        </p>
      </div>
      <div>
        <p className="font-medium">Camera activity (linked-event counts, not uptime)</p>
        {overview.cameras.status === "ok" ? (
          <Counts record={overview.cameras.by_camera} />
        ) : (
          <p className="text-xs text-amber-300">{overview.cameras.message || "Camera data unavailable."}</p>
        )}
      </div>
    </div>
  );
}
