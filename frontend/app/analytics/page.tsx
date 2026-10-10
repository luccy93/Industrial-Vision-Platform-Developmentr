"use client";

import { useState } from "react";
import { Card } from "../../components/ui/Card";
import { DataState } from "../../components/operations/primitives";
import { buildAnalyticsQuery } from "../../lib/analytics/client";
import type { AnalyticsFilters } from "../../types";

const PRESETS = [
  { value: "24h", label: "Last 24 hours" },
  { value: "7d", label: "Last 7 days" },
  { value: "30d", label: "Last 30 days" },
  { value: "custom", label: "Custom range" },
] as const;

/**
 * Historical analytics & reporting — V14.
 *
 * Commit 01 ships the route, filter contracts, and validation. Report
 * sections, charts, and CSV export wire up in Commit 02.
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
  const [applied, setApplied] = useState<AnalyticsFilters | null>(null);
  const [filterError, setFilterError] = useState<string | null>(null);

  const apply = () => {
    try {
      buildAnalyticsQuery(filters);
      setFilterError(null);
      setApplied(filters);
    } catch (e) {
      setFilterError(e instanceof Error ? e.message : "Invalid filters");
    }
  };

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-lg font-bold">Historical Analytics & Reporting</h1>
        <p className="text-xs text-slate-400">
          Durable PostgreSQL history only — never frames, detections, or live telemetry.
          All timestamps UTC; displayed in local time.
        </p>
      </div>

      <Card title="Report filters">
        <div className="flex flex-wrap items-center gap-2 text-sm">
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
            <>
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
                  className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-sm text-slate-200"
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
                  className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-sm text-slate-200"
                  aria-label="report end"
                />
              </label>
            </>
          )}
          <label className="text-xs text-slate-400">
            Bucket{" "}
            <select
              value={filters.bucket}
              onChange={(e) =>
                setFilters({ ...filters, bucket: e.target.value as AnalyticsFilters["bucket"] })
              }
              className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-sm text-slate-200"
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
        </div>
        {filterError && (
          <p className="mt-2 text-sm text-red-300" role="alert">
            {filterError}
          </p>
        )}
        {applied && !filterError && (
          <p className="mt-2 text-xs text-slate-500">
            Filters validated — report sections arrive with the functional analytics.
          </p>
        )}
      </Card>

      <Card title="Overview">
        <DataState state="empty" emptyText="Apply filters to generate a historical report." />
      </Card>
      <Card title="Trends">
        <DataState state="empty" emptyText="No report generated yet." />
      </Card>
      <Card title="Breakdowns">
        <DataState state="empty" emptyText="No report generated yet." />
      </Card>
      <Card title="Export">
        <DataState state="empty" emptyText="CSV export arrives with the functional analytics." />
      </Card>
    </div>
  );
}
