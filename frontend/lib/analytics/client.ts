import { apiFetch } from "../operations/client";
import type {
  AnalyticsBreakdown,
  AnalyticsFilters,
  AnalyticsOverview,
  AnalyticsQuery,
  AnalyticsTrend,
  ExportReportType,
} from "../../types";

export const PRESET_MS: Record<string, number> = {
  "24h": 24 * 3600 * 1000,
  "7d": 7 * 24 * 3600 * 1000,
  "30d": 30 * 24 * 3600 * 1000,
};

export const MAX_WINDOW_MS = 90 * 24 * 3600 * 1000;

/** Resolve a filter set into validated query params (throws on invalid). */
export function buildAnalyticsQuery(filters: AnalyticsFilters, now = Date.now()): AnalyticsQuery {
  let start: number;
  let end: number;
  if (filters.preset === "custom") {
    if (!filters.startAt || !filters.endAt) {
      throw new Error("Custom range requires start and end dates.");
    }
    start = Date.parse(filters.startAt);
    end = Date.parse(filters.endAt);
    if (Number.isNaN(start) || Number.isNaN(end)) {
      throw new Error("Custom range dates must be valid ISO-8601 timestamps.");
    }
  } else {
    const span = PRESET_MS[filters.preset];
    if (!span) throw new Error(`Unknown preset: ${filters.preset}`);
    end = now;
    start = now - span;
  }
  if (start >= end) throw new Error("Report start must be before report end.");
  if (end - start > MAX_WINDOW_MS) throw new Error("Report window must not exceed 90 days.");
  const query: AnalyticsQuery = {
    start_at: new Date(start).toISOString(),
    end_at: new Date(end).toISOString(),
    bucket: filters.bucket,
  };
  if (filters.domains.length > 0) query.domain = [...filters.domains];
  if (filters.severities.length > 0) query.severity = [...filters.severities];
  if (filters.cameras.length === 1) query.camera_id = filters.cameras[0];
  if (filters.statuses.length > 0) query.status = [...filters.statuses];
  if (filters.priorities.length > 0) query.priority = [...filters.priorities];
  return query;
}

function queryString(query: AnalyticsQuery, extra?: Record<string, string | string[]>): string {
  const params = new URLSearchParams();
  params.set("start_at", query.start_at);
  params.set("end_at", query.end_at);
  params.set("bucket", query.bucket);
  const append = (key: string, value: string | string[] | undefined) => {
    if (value === undefined) return;
    for (const item of Array.isArray(value) ? value : [value]) params.append(key, item);
  };
  append("domain", query.domain);
  append("severity", query.severity);
  if (query.camera_id) params.set("camera_id", query.camera_id);
  append("status", query.status);
  append("priority", query.priority);
  if (extra) {
    for (const [key, value] of Object.entries(extra)) append(key, value);
  }
  return params.toString();
}

export function fetchAnalyticsSummary(
  query: AnalyticsQuery,
  signal?: AbortSignal
): Promise<AnalyticsOverview> {
  return apiFetch<AnalyticsOverview>(`/api/v1/analytics/summary?${queryString(query)}`, { signal });
}

export function fetchAnalyticsTrends(
  query: AnalyticsQuery,
  metric: string,
  signal?: AbortSignal
): Promise<AnalyticsTrend> {
  return apiFetch<AnalyticsTrend>(
    `/api/v1/analytics/trends?${queryString(query, { metric })}`,
    { signal }
  );
}

export function fetchAnalyticsBreakdowns(
  query: AnalyticsQuery,
  dataset: string,
  groupBy: string,
  signal?: AbortSignal
): Promise<AnalyticsBreakdown> {
  return apiFetch<AnalyticsBreakdown>(
    `/api/v1/analytics/breakdowns?${queryString(query, { dataset, group_by: groupBy })}`,
    { signal }
  );
}

export function exportUrl(query: AnalyticsQuery, report: ExportReportType): string {
  return `/api/v1/analytics/export?${queryString(query, { report })}`;
}

/** Trigger a browser file download for an export URL (throws on failure). */
export async function downloadExport(url: string, fallbackName: string): Promise<void> {
  const res = await fetch(url);
  if (!res.ok) {
    let detail = `Export failed (${res.status})`;
    try {
      const body = (await res.json()) as { error?: { message?: string; code?: string } };
      if (body?.error?.message) detail = `${body.error.code ?? res.status}: ${body.error.message}`;
    } catch {
      /* keep status fallback */
    }
    throw new Error(detail);
  }
  const blob = await res.blob();
  const disposition = res.headers.get("content-disposition") ?? "";
  const match = /filename="([^"]+)"/.exec(disposition);
  const objectUrl = URL.createObjectURL(blob);
  try {
    const anchor = document.createElement("a");
    anchor.href = objectUrl;
    anchor.download = match ? match[1] : fallbackName;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
  } finally {
    URL.revokeObjectURL(objectUrl);
  }
}
