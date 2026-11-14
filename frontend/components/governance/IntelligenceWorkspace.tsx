"use client";

import { useCallback, useEffect, useState } from "react";
import { useAuth } from "../auth/AuthProvider";
import { DataState } from "../operations/primitives";
import { Card } from "../ui/Card";
import {
  acknowledgeGovernanceRecommendation,
  compareGovernanceIntelligenceSnapshots,
  dismissGovernanceRecommendation,
  fetchGovernanceIntelligenceSnapshot,
  fetchGovernanceIntelligenceSnapshots,
  fetchGovernanceIntelligenceStatus,
  fetchGovernanceRecommendation,
  fetchGovernanceRecommendations,
  fetchGovernanceRiskCase,
  fetchGovernanceRiskCases,
  fetchGovernanceSlaBacklog,
  fetchGovernanceTrends,
  generateGovernanceIntelligenceSnapshot,
  refreshGovernanceRecommendations,
} from "../../lib/governance/client";
import type {
  GovernanceIntelligenceSnapshot,
  GovernanceIntelligenceSnapshotDetail,
  GovernanceIntelligenceStatus,
  GovernanceRecommendationDetail,
  GovernanceRecommendationListResponse,
  GovernanceRiskCaseDetail,
  GovernanceRiskCaseListResponse,
  GovernanceSlaBacklogResponse,
  GovernanceSnapshotComparison,
  GovernanceTrendsResponse,
} from "../../types";

const RISK_LEVELS = ["", "CRITICAL", "HIGH", "MODERATE", "LOW"];
const SLA_STATES = ["", "BREACHED", "AT_RISK", "WITHIN_TARGET", "UNKNOWN", "NOT_APPLICABLE"];
const SLA_TARGETS = ["", "RETENTION_REVIEW", "DISPOSITION_REVIEW", "LEGAL_HOLD_REVIEW", "EXPORT_APPROVAL"];
const RECOMMENDATION_STATUSES = ["", "OPEN", "ACKNOWLEDGED", "DISMISSED", "RESOLVED"];
const RECOMMENDATION_SEVERITIES = ["", "CRITICAL", "HIGH", "MEDIUM", "LOW"];

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isAbort(error: unknown): boolean {
  return error instanceof Error && error.name === "AbortError";
}

function statusStyle(status: string): string {
  switch (status) {
    case "OK":
    case "VALID":
    case "COMPARED":
    case "OPEN":
    case "MET":
      return "bg-emerald-500/15 text-emerald-300";
    case "DEGRADED":
    case "PARTIAL":
    case "AT_RISK":
    case "ACKNOWLEDGED":
      return "bg-amber-500/15 text-amber-300";
    case "UNAVAILABLE":
    case "INTEGRITY_FAILED":
    case "INCOMPATIBLE":
    case "BREACHED":
    case "CRITICAL":
      return "bg-rose-500/15 text-rose-300";
    case "DISMISSED":
    case "RESOLVED":
      return "bg-slate-500/15 text-slate-300";
    default:
      return "bg-sky-500/15 text-sky-300";
  }
}

function StatusPill({ status }: { status: string }) {
  return (
    <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${statusStyle(status)}`}>
      {status}
    </span>
  );
}

function Metric({ label, value, note }: { label: string; value: string | number; note?: string }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-2">
      <p className="text-xs text-slate-400">{label}</p>
      <p className="text-lg font-semibold text-slate-100">{value}</p>
      {note ? <p className="text-xs text-slate-500">{note}</p> : null}
    </div>
  );
}

function ConfirmAction({
  label,
  description,
  confirmLabel,
  reasonLabel,
  onConfirm,
}: {
  label: string;
  description?: string;
  confirmLabel: string;
  reasonLabel: string;
  onConfirm: (reason: string) => Promise<void>;
}) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!open) {
    return (
      <button
        type="button"
        className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-200 hover:bg-slate-800"
        onClick={() => setOpen(true)}
      >
        {label}
      </button>
    );
  }

  return (
    <div className="mt-2 rounded-lg border border-amber-500/40 bg-amber-500/5 p-2">
      {description ? <p className="mb-1 text-xs text-amber-200">{description}</p> : null}
      <label className="block text-xs text-slate-300">
        {reasonLabel}
        <textarea
          aria-label={reasonLabel}
          className="mt-1 w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-100"
          rows={2}
          value={reason}
          onChange={(event) => setReason(event.target.value)}
        />
      </label>
      <div className="mt-2 flex flex-wrap gap-2">
        <button
          type="button"
          className="rounded bg-amber-500 px-2 py-1 text-xs font-semibold text-slate-950 disabled:opacity-50"
          disabled={busy || !reason.trim()}
          onClick={async () => {
            setBusy(true);
            setError(null);
            try {
              await onConfirm(reason.trim());
              setOpen(false);
              setReason("");
            } catch (exc) {
              setError(messageOf(exc));
            } finally {
              setBusy(false);
            }
          }}
        >
          {confirmLabel}
        </button>
        <button
          type="button"
          className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-300"
          onClick={() => {
            setOpen(false);
            setReason("");
            setError(null);
          }}
        >
          Close
        </button>
      </div>
      {error ? (
        <p className="mt-1 text-xs text-rose-300" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}

function Availability({ value, message }: { value: string; message?: string }) {
  return (
    <span className="inline-flex flex-wrap items-center gap-1 text-xs text-slate-400">
      <StatusPill status={value} />
      {message ? <span>{message}</span> : null}
    </span>
  );
}

function formatHours(value: number | null): string {
  if (value === null || value === undefined) return "—";
  return `${value.toFixed(1)} h`;
}

function TrendSourceCard({ name, source }: { name: string; source: GovernanceTrendsResponse["sources"][string] }) {
  const max = Math.max(
    1,
    ...source.buckets.map((bucket) => (typeof bucket.count === "number" ? bucket.count : 0))
  );
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs font-semibold text-slate-200">{name}</p>
        <Availability value={source.availability} />
      </div>
      <p className="mt-1 text-xs text-slate-500">{source.definition}</p>
      {source.message ? (
        <p className="mt-1 text-xs text-amber-300">{source.message}</p>
      ) : null}
      <p className="mt-1 text-xs text-slate-400">
        Total: {source.total}
        {source.truncated ? " · truncated to the bounded row limit" : ""}
        {source.coverage_start ? ` · recorded from ${source.coverage_start}` : ""}
        {source.no_history ? " · no recorded history" : ""}
        {source.coverage_available === false ? " · coverage unknown" : ""}
      </p>
      <div className="mt-2 flex items-end gap-1 overflow-x-auto pb-1" role="list" aria-label={`${name} trend buckets`}>
        {source.buckets.map((bucket) => {
          const count = bucket.count;
          const height = typeof count === "number" ? Math.max(4, Math.round((count / max) * 48)) : 4;
          const label =
            count === null
              ? "unavailable, not zero"
              : `${count} (${bucket.coverage.toLowerCase().replaceAll("_", " ")})`;
          return (
            <div
              key={bucket.bucket_start}
              role="listitem"
              className="min-w-8 text-center"
              title={`${bucket.bucket_start} · ${label}`}
            >
              <div className="flex h-14 items-end justify-center">
                <div
                  className={`w-5 rounded-t ${
                    count === null
                      ? "border border-dashed border-slate-600 bg-transparent"
                      : bucket.partial_coverage
                        ? "bg-amber-500/70"
                        : "bg-sky-500/70"
                  }`}
                  style={{ height: `${height}px` }}
                  aria-hidden="true"
                />
              </div>
              <span className="block text-[10px] text-slate-500">
                {count === null ? "—" : count}
              </span>
              <span className="block text-[10px] text-slate-600">
                {bucket.bucket_start.slice(5, 10)}
              </span>
            </div>
          );
        })}
      </div>
      {source.categories.length > 0 ? (
        <p className="mt-1 text-xs text-slate-500">
          Categories:{" "}
          {source.categories
            .map((category) => `${category}=${source.category_totals[category] ?? "unavailable"}`)
            .join(" · ")}
        </p>
      ) : null}
    </div>
  );
}

export function IntelligenceWorkspace() {
  const { hasRole } = useAuth();
  const isAdmin = hasRole("ADMIN");
  const canOperate = isAdmin || hasRole("OPERATOR");

  const [status, setStatus] = useState<GovernanceIntelligenceStatus | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [risk, setRisk] = useState<GovernanceRiskCaseListResponse | null>(null);
  const [riskError, setRiskError] = useState<string | null>(null);
  const [riskLevel, setRiskLevel] = useState("");
  const [riskPage, setRiskPage] = useState(1);
  const [riskDetail, setRiskDetail] = useState<GovernanceRiskCaseDetail | null>(null);
  const [riskDetailError, setRiskDetailError] = useState<string | null>(null);
  const [sla, setSla] = useState<GovernanceSlaBacklogResponse | null>(null);
  const [slaError, setSlaError] = useState<string | null>(null);
  const [slaTarget, setSlaTarget] = useState("");
  const [slaState, setSlaState] = useState("");
  const [slaPage, setSlaPage] = useState(1);
  const [trends, setTrends] = useState<GovernanceTrendsResponse | null>(null);
  const [trendsError, setTrendsError] = useState<string | null>(null);
  const [trendDays, setTrendDays] = useState(30);
  const [trendBucket, setTrendBucket] = useState("day");
  const [recommendations, setRecommendations] = useState<GovernanceRecommendationListResponse | null>(
    null
  );
  const [recommendationsError, setRecommendationsError] = useState<string | null>(null);
  const [recommendationStatus, setRecommendationStatus] = useState("");
  const [recommendationSeverity, setRecommendationSeverity] = useState("");
  const [recommendationPage, setRecommendationPage] = useState(1);
  const [recommendationDetail, setRecommendationDetail] =
    useState<GovernanceRecommendationDetail | null>(null);
  const [recommendationDetailError, setRecommendationDetailError] = useState<string | null>(null);
  const [snapshots, setSnapshots] = useState<GovernanceIntelligenceSnapshot[]>([]);
  const [snapshotsTotal, setSnapshotsTotal] = useState(0);
  const [snapshotsError, setSnapshotsError] = useState<string | null>(null);
  const [snapshotDetail, setSnapshotDetail] =
    useState<GovernanceIntelligenceSnapshotDetail | null>(null);
  const [snapshotDetailError, setSnapshotDetailError] = useState<string | null>(null);
  const [leftSnapshot, setLeftSnapshot] = useState("");
  const [rightSnapshot, setRightSnapshot] = useState("");
  const [comparison, setComparison] = useState<GovernanceSnapshotComparison | null>(null);
  const [comparisonError, setComparisonError] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const loadStatus = useCallback(async (signal?: AbortSignal) => {
    try {
      setStatus(await fetchGovernanceIntelligenceStatus(signal));
      setStatusError(null);
    } catch (exc) {
      if (!isAbort(exc)) setStatusError(messageOf(exc));
    }
  }, []);

  const loadRisk = useCallback(
    async (signal?: AbortSignal) => {
      try {
        setRisk(
          await fetchGovernanceRiskCases(
            { risk_level: riskLevel || undefined, page: riskPage, page_size: 10 },
            signal
          )
        );
        setRiskError(null);
      } catch (exc) {
        if (!isAbort(exc)) setRiskError(messageOf(exc));
      }
    },
    [riskLevel, riskPage]
  );

  const loadSla = useCallback(
    async (signal?: AbortSignal) => {
      try {
        setSla(
          await fetchGovernanceSlaBacklog(
            {
              target_key: slaTarget || undefined,
              state: slaState || undefined,
              page: slaPage,
              page_size: 10,
            },
            signal
          )
        );
        setSlaError(null);
      } catch (exc) {
        if (!isAbort(exc)) setSlaError(messageOf(exc));
      }
    },
    [slaPage, slaState, slaTarget]
  );

  const loadTrends = useCallback(
    async (signal?: AbortSignal) => {
      try {
        const end = new Date();
        const start = new Date(end.getTime() - trendDays * 24 * 60 * 60 * 1000);
        setTrends(
          await fetchGovernanceTrends(
            { start_at: start.toISOString(), end_at: end.toISOString(), bucket: trendBucket },
            signal
          )
        );
        setTrendsError(null);
      } catch (exc) {
        if (!isAbort(exc)) setTrendsError(messageOf(exc));
      }
    },
    [trendBucket, trendDays]
  );

  const loadRecommendations = useCallback(
    async (signal?: AbortSignal) => {
      try {
        setRecommendations(
          await fetchGovernanceRecommendations(
            {
              status: recommendationStatus || undefined,
              severity: recommendationSeverity || undefined,
              page: recommendationPage,
              page_size: 10,
            },
            signal
          )
        );
        setRecommendationsError(null);
      } catch (exc) {
        if (!isAbort(exc)) setRecommendationsError(messageOf(exc));
      }
    },
    [recommendationPage, recommendationSeverity, recommendationStatus]
  );

  const loadSnapshots = useCallback(async (signal?: AbortSignal) => {
    try {
      const body = await fetchGovernanceIntelligenceSnapshots({ page: 1, page_size: 20 }, signal);
      setSnapshots(body.items);
      setSnapshotsTotal(body.total);
      setSnapshotsError(body.availability === "UNAVAILABLE" ? body.message : null);
    } catch (exc) {
      if (!isAbort(exc)) setSnapshotsError(messageOf(exc));
    }
  }, []);

  const reloadAll = useCallback(async () => {
    await Promise.allSettled([
      loadStatus(),
      loadRisk(),
      loadSla(),
      loadTrends(),
      loadRecommendations(),
      loadSnapshots(),
    ]);
  }, [loadRecommendations, loadRisk, loadSla, loadSnapshots, loadStatus, loadTrends]);

  useEffect(() => {
    const controller = new AbortController();
    void Promise.allSettled([
      loadStatus(controller.signal),
      loadTrends(controller.signal),
      loadSnapshots(controller.signal),
    ]).finally(() => setLoading(false));
    return () => controller.abort();
  }, [loadSnapshots, loadStatus, loadTrends]);

  useEffect(() => {
    const controller = new AbortController();
    void loadRisk(controller.signal);
    return () => controller.abort();
  }, [loadRisk]);

  useEffect(() => {
    const controller = new AbortController();
    void loadSla(controller.signal);
    return () => controller.abort();
  }, [loadSla]);

  useEffect(() => {
    const controller = new AbortController();
    void loadRecommendations(controller.signal);
    return () => controller.abort();
  }, [loadRecommendations]);

  const openRiskDetail = useCallback(async (caseId: string) => {
    try {
      setRiskDetail(await fetchGovernanceRiskCase(caseId));
      setRiskDetailError(null);
    } catch (exc) {
      setRiskDetailError(messageOf(exc));
    }
  }, []);

  const openRecommendation = useCallback(async (recommendationId: string) => {
    try {
      setRecommendationDetail(await fetchGovernanceRecommendation(recommendationId));
      setRecommendationDetailError(null);
    } catch (exc) {
      setRecommendationDetailError(messageOf(exc));
    }
  }, []);

  const openSnapshot = useCallback(async (snapshotId: string) => {
    try {
      setSnapshotDetail(await fetchGovernanceIntelligenceSnapshot(snapshotId));
      setSnapshotDetailError(null);
    } catch (exc) {
      setSnapshotDetailError(messageOf(exc));
    }
  }, []);

  const riskPageCount = Math.max(1, Math.ceil((risk?.total ?? 0) / 10));
  const slaPageCount = Math.max(1, Math.ceil((sla?.total ?? 0) / 10));
  const recommendationPageCount = Math.max(1, Math.ceil((recommendations?.total ?? 0) / 10));

  return (
    <div className="space-y-4" aria-label="Governance intelligence">
      <Card title="Governance intelligence">
        {statusError ? (
          <DataState state="error" emptyText="" error={statusError} />
        ) : !status ? (
          <DataState state="loading" emptyText="" />
        ) : (
          <div className="space-y-3">
            <div className="grid gap-2 md:grid-cols-3 xl:grid-cols-6">
              <Metric label="Intelligence" value={status.enabled ? "ENABLED" : "DISABLED"} />
              <Metric
                label="Risk model"
                value={`v${status.model.version ?? "—"}`}
                note={status.model.model_id ?? ""}
              />
              <Metric
                label="Open recommendations"
                value={status.recommendation_counts.by_status.OPEN ?? 0}
              />
              <Metric label="Critical recommendations" value={status.recommendation_counts.by_severity.CRITICAL ?? 0} />
              <Metric label="Scheduled intelligence" value={status.scheduled_intelligence ? "ON" : "OFF"} />
              <Metric label="Alerts" value={status.alerts_enabled ? "ENABLED" : "DISABLED"} />
            </div>
            <p className="text-xs text-slate-400">
              Assurance: {status.assurance}. {status.scheduled_intelligence_note}
            </p>
            <div className="overflow-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-900 text-slate-400">
                  <tr>
                    <th className="p-1">Operational SLA target</th>
                    <th className="p-1">Version</th>
                    <th className="p-1">Target</th>
                    <th className="p-1">Warning</th>
                    <th className="p-1">Effective from</th>
                  </tr>
                </thead>
                <tbody>
                  {status.sla_targets.map((target) => (
                    <tr key={target.target_key} className="border-t border-slate-800">
                      <td className="p-1 text-slate-200">{target.target_key}</td>
                      <td className="p-1">{target.version ?? "—"}</td>
                      <td className="p-1">{target.target_hours ?? "—"} h</td>
                      <td className="p-1">{target.warning_hours ?? "—"} h</td>
                      <td className="p-1 text-slate-500">{target.effective_from ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="text-xs text-amber-300">
              Operational SLA targets are organization-configurable and are not legal or regulatory
              deadlines.
            </p>
            <ul className="list-disc space-y-1 pl-5 text-xs text-slate-400">
              {status.non_claims.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </div>
        )}
      </Card>

      <Card title="Risk prioritization">
        {riskError ? (
          <DataState state="error" emptyText="" error={riskError} />
        ) : !risk ? (
          <DataState state="loading" emptyText="" />
        ) : (
          <div className="space-y-3">
            <div className="flex flex-wrap items-end gap-2">
              <label className="text-xs text-slate-300">
                Risk level filter
                <select
                  aria-label="Risk level filter"
                  className="mt-1 block rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-100"
                  value={riskLevel}
                  onChange={(event) => {
                    setRiskPage(1);
                    setRiskLevel(event.target.value);
                  }}
                >
                  {RISK_LEVELS.map((level) => (
                    <option key={level || "all"} value={level}>
                      {level || "All levels"}
                    </option>
                  ))}
                </select>
              </label>
              <p className="text-xs text-slate-400">
                Model {risk.model.model_id ?? "—"} v{risk.model.version ?? "—"} · {risk.total} scored
                case(s) · unavailable {risk.unavailable_case_count}
              </p>
              {risk.partial ? <StatusPill status="PARTIAL" /> : null}
            </div>
            {risk.truncated ? (
              <p className="text-xs text-amber-300">
                The scoring page was truncated at the configured case bound. Counts are not a
                complete inventory.
              </p>
            ) : null}
            {risk.items.length === 0 ? (
              <DataState state="empty" emptyText="No scored cases match the filter." />
            ) : (
              <div className="max-h-96 overflow-auto">
                <table className="w-full text-left text-xs">
                  <thead className="sticky top-0 bg-slate-900 text-slate-400">
                    <tr>
                      <th className="p-1">Case</th>
                      <th className="p-1">Score</th>
                      <th className="p-1">Level</th>
                      <th className="p-1">Completeness</th>
                      <th className="p-1">Top factors</th>
                      <th className="p-1">Calculated</th>
                      <th className="p-1">Factors</th>
                    </tr>
                  </thead>
                  <tbody>
                    {risk.items.map((item) => (
                      <tr key={item.case_id} className="border-t border-slate-800 align-top">
                        <td className="p-1 text-slate-200">
                          {item.case_number ?? item.case_id}
                          <div className="text-slate-500">{item.case_id}</div>
                        </td>
                        <td className="p-1 font-semibold">{item.score}</td>
                        <td className="p-1">
                          <StatusPill status={item.risk_level} />
                        </td>
                        <td className="p-1">{item.data_completeness}</td>
                        <td className="p-1 text-slate-400">
                          {item.top_factors.length > 0 ? item.top_factors.join(", ") : "—"}
                        </td>
                        <td className="p-1 text-slate-500">{item.calculated_at ?? "—"}</td>
                        <td className="p-1">
                          <button
                            type="button"
                            className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-200 hover:bg-slate-800"
                            onClick={() => void openRiskDetail(item.case_id)}
                          >
                            View factors
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <button
                type="button"
                className="rounded border border-slate-700 px-2 py-1 disabled:opacity-50"
                disabled={riskPage <= 1}
                onClick={() => setRiskPage((page) => Math.max(1, page - 1))}
              >
                Previous risk cases
              </button>
              <span>
                Page {riskPage} of {riskPageCount} · {risk.total} total
              </span>
              <button
                type="button"
                className="rounded border border-slate-700 px-2 py-1 disabled:opacity-50"
                disabled={riskPage >= riskPageCount}
                onClick={() => setRiskPage((page) => page + 1)}
              >
                Next risk cases
              </button>
            </div>
            {riskDetailError ? (
              <p className="text-xs text-rose-300" role="alert">
                {riskDetailError}
              </p>
            ) : null}
            {riskDetail ? (
              <div className="rounded-lg border border-slate-700 bg-slate-950/60 p-3">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div>
                    <p className="text-sm font-semibold text-slate-100">
                      {riskDetail.risk.case_number ?? riskDetail.risk.case_id} ·{" "}
                      {riskDetail.risk.score}/100 · {riskDetail.risk.risk_level}
                    </p>
                    <p className="text-xs text-slate-400">
                      Model {riskDetail.risk.model_id ?? "—"} v
                      {riskDetail.risk.model_version ?? "—"} · completeness{" "}
                      {riskDetail.risk.data_completeness} · calculated{" "}
                      {riskDetail.risk.calculated_at ?? "—"}
                    </p>
                  </div>
                  <button
                    type="button"
                    className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-300"
                    onClick={() => setRiskDetail(null)}
                  >
                    Close factors
                  </button>
                </div>
                <div className="mt-2 overflow-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-900 text-slate-400">
                      <tr>
                        <th className="p-1">Factor</th>
                        <th className="p-1">Points</th>
                        <th className="p-1">Data</th>
                        <th className="p-1">Reason</th>
                        <th className="p-1">Source refs</th>
                      </tr>
                    </thead>
                    <tbody>
                      {riskDetail.risk.factors.map((factor) => (
                        <tr key={factor.factor_id} className="border-t border-slate-800 align-top">
                          <td className="p-1 text-slate-200">
                            {factor.factor_id}
                            {factor.suppressed ? (
                              <div className="text-amber-300">
                                suppressed by {factor.suppressed_by ?? "a correlated factor"}
                              </div>
                            ) : null}
                          </td>
                          <td className="p-1">{factor.points}</td>
                          <td className="p-1">
                            <StatusPill status={factor.data_status} />
                          </td>
                          <td className="p-1 text-slate-400">{factor.reason}</td>
                          <td className="p-1 text-slate-500">{factor.source_refs.join(", ") || "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {riskDetail.risk.missing_data.length > 0 ? (
                  <div className="mt-2">
                    <p className="text-xs font-semibold text-amber-200">Missing or unavailable data</p>
                    <ul className="list-disc pl-5 text-xs text-amber-100">
                      {riskDetail.risk.missing_data.map((entry) => (
                        <li key={`${entry.source}:${entry.status}`}>
                          {entry.source} ({entry.status}): {entry.message}
                        </li>
                      ))}
                    </ul>
                  </div>
                ) : null}
                <p className="mt-2 text-xs text-slate-500">
                  Policy context:{" "}
                  {riskDetail.risk.policy_context
                    ? JSON.stringify(riskDetail.risk.policy_context)
                    : "unavailable"}
                </p>
              </div>
            ) : null}
          </div>
        )}
      </Card>

      <Card title="Operational SLA backlog">
        {slaError ? (
          <DataState state="error" emptyText="" error={slaError} />
        ) : !sla ? (
          <DataState state="loading" emptyText="" />
        ) : (
          <div className="space-y-3">
            <p className="text-xs text-amber-300">{sla.non_claim}</p>
            <div className="flex flex-wrap items-end gap-2">
              <label className="text-xs text-slate-300">
                SLA target filter
                <select
                  aria-label="SLA target filter"
                  className="mt-1 block rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-100"
                  value={slaTarget}
                  onChange={(event) => {
                    setSlaPage(1);
                    setSlaTarget(event.target.value);
                  }}
                >
                  {SLA_TARGETS.map((target) => (
                    <option key={target || "all"} value={target}>
                      {target || "All targets"}
                    </option>
                  ))}
                </select>
              </label>
              <label className="text-xs text-slate-300">
                SLA state filter
                <select
                  aria-label="SLA state filter"
                  className="mt-1 block rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-100"
                  value={slaState}
                  onChange={(event) => {
                    setSlaPage(1);
                    setSlaState(event.target.value);
                  }}
                >
                  {SLA_STATES.map((state) => (
                    <option key={state || "all"} value={state}>
                      {state || "All states"}
                    </option>
                  ))}
                </select>
              </label>
              {sla.partial ? <StatusPill status="PARTIAL" /> : null}
            </div>
            <div className="flex flex-wrap gap-2">
              {Object.entries(sla.availability).map(([source, value]) => (
                <Availability key={source} value={value.availability} message={`${source}: ${value.message}`} />
              ))}
            </div>
            {sla.truncated ? (
              <p className="text-xs text-amber-300">
                The backlog was truncated at the configured case bound.
              </p>
            ) : null}
            {sla.items.length === 0 ? (
              <DataState state="empty" emptyText="No backlog items match the filters." />
            ) : (
              <div className="max-h-96 overflow-auto">
                <table className="w-full text-left text-xs">
                  <thead className="sticky top-0 bg-slate-900 text-slate-400">
                    <tr>
                      <th className="p-1">Item</th>
                      <th className="p-1">Case</th>
                      <th className="p-1">State</th>
                      <th className="p-1">Open age</th>
                      <th className="p-1">Duration</th>
                      <th className="p-1">Target</th>
                      <th className="p-1">Due</th>
                      <th className="p-1">Reason</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sla.items.map((item) => (
                      <tr key={`${item.item_type}:${item.item_id}`} className="border-t border-slate-800 align-top">
                        <td className="p-1 text-slate-200">
                          {item.label}
                          <div className="text-slate-500">{item.item_id ?? "—"}</div>
                        </td>
                        <td className="p-1 text-slate-500">{item.case_id ?? "—"}</td>
                        <td className="p-1">
                          <StatusPill status={item.sla.state} />
                        </td>
                        <td className="p-1">{formatHours(item.sla.open_age_hours)}</td>
                        <td className="p-1">
                          {item.sla.resolved
                            ? formatHours(item.sla.duration_hours)
                            : "— (unresolved; no duration claimed)"}
                        </td>
                        <td className="p-1">
                          v{item.sla.target_version ?? "—"} · {item.sla.target_hours ?? "—"} h
                        </td>
                        <td className="p-1 text-slate-500">{item.sla.due_at ?? "—"}</td>
                        <td className="p-1 text-slate-500">{item.sla.reason}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <button
                type="button"
                className="rounded border border-slate-700 px-2 py-1 disabled:opacity-50"
                disabled={slaPage <= 1}
                onClick={() => setSlaPage((page) => Math.max(1, page - 1))}
              >
                Previous SLA items
              </button>
              <span>
                Page {slaPage} of {slaPageCount} · {sla.total} total
              </span>
              <button
                type="button"
                className="rounded border border-slate-700 px-2 py-1 disabled:opacity-50"
                disabled={slaPage >= slaPageCount}
                onClick={() => setSlaPage((page) => page + 1)}
              >
                Next SLA items
              </button>
            </div>
          </div>
        )}
      </Card>

      <Card title="Bounded historical trends">
        {trendsError ? (
          <DataState state="error" emptyText="" error={trendsError} />
        ) : !trends ? (
          <DataState state="loading" emptyText="" />
        ) : (
          <div className="space-y-3">
            <div className="flex flex-wrap items-end gap-2">
              <label className="text-xs text-slate-300">
                Trend window
                <select
                  aria-label="Trend window"
                  className="mt-1 block rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-100"
                  value={trendDays}
                  onChange={(event) => setTrendDays(Number(event.target.value))}
                >
                  <option value={7}>Last 7 days</option>
                  <option value={30}>Last 30 days</option>
                  <option value={90}>Last 90 days</option>
                </select>
              </label>
              <label className="text-xs text-slate-300">
                Bucket
                <select
                  aria-label="Trend bucket"
                  className="mt-1 block rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-100"
                  value={trendBucket}
                  onChange={(event) => setTrendBucket(event.target.value)}
                >
                  <option value="hour">Hour</option>
                  <option value="day">Day</option>
                  <option value="week">Week</option>
                </select>
              </label>
              <span className="text-xs text-slate-400">
                {trends.start_at} → {trends.end_at} · UTC
              </span>
              {trends.partial ? <StatusPill status="PARTIAL" /> : null}
            </div>
            {!trends.coverage.available ? (
              <p className="text-xs text-amber-300">{trends.coverage.message}</p>
            ) : null}
            {trends.unavailable_sources.length > 0 ? (
              <p className="text-xs text-rose-300">
                Unavailable sources: {trends.unavailable_sources.join(", ")}. They are shown as
                unavailable, never as zero.
              </p>
            ) : null}
            {trends.degraded_sources.length > 0 ? (
              <p className="text-xs text-amber-300">
                Degraded sources: {trends.degraded_sources.join(", ")}.
              </p>
            ) : null}
            <div className="grid gap-2 lg:grid-cols-2">
              {trends.source_order.map((name) => {
                const source = trends.sources[name];
                return source ? <TrendSourceCard key={name} name={name} source={source} /> : null;
              })}
            </div>
            <p className="text-xs text-slate-500">
              Buckets before the earliest recorded row are null and marked as outside coverage. A
              source that cannot be read is unavailable, not zero. No forecast or statistical model
              is used.
            </p>
          </div>
        )}
      </Card>

      <Card title="Advisory recommendations">
        {recommendationsError ? (
          <DataState state="error" emptyText="" error={recommendationsError} />
        ) : !recommendations ? (
          <DataState state="loading" emptyText="" />
        ) : (
          <div className="space-y-3">
            <p className="text-xs text-slate-400">
              Recommendations are deterministic and advisory only. Acknowledging or dismissing one
              never approves a disposition, releases a legal hold, modifies evidence, or deletes a
              record.
            </p>
            <div className="flex flex-wrap items-end gap-2">
              <label className="text-xs text-slate-300">
                Recommendation status filter
                <select
                  aria-label="Recommendation status filter"
                  className="mt-1 block rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-100"
                  value={recommendationStatus}
                  onChange={(event) => {
                    setRecommendationPage(1);
                    setRecommendationStatus(event.target.value);
                  }}
                >
                  {RECOMMENDATION_STATUSES.map((value) => (
                    <option key={value || "all"} value={value}>
                      {value || "All statuses"}
                    </option>
                  ))}
                </select>
              </label>
              <label className="text-xs text-slate-300">
                Recommendation severity filter
                <select
                  aria-label="Recommendation severity filter"
                  className="mt-1 block rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-100"
                  value={recommendationSeverity}
                  onChange={(event) => {
                    setRecommendationPage(1);
                    setRecommendationSeverity(event.target.value);
                  }}
                >
                  {RECOMMENDATION_SEVERITIES.map((value) => (
                    <option key={value || "all"} value={value}>
                      {value || "All severities"}
                    </option>
                  ))}
                </select>
              </label>
              {canOperate ? (
                <ConfirmAction
                  label="Refresh recommendations"
                  confirmLabel="Confirm refresh"
                  reasonLabel="Refresh reason"
                  description="Recomputes deterministic recommendations from current governance records. It never executes an action."
                  onConfirm={async (reason) => {
                    setActionError(null);
                    const body = await refreshGovernanceRecommendations({ reason });
                    setActionMessage(
                      `Refresh created ${body.summary.created}, refreshed ${body.summary.refreshed}, reopened ${body.summary.reopened}, and auto-resolved ${body.summary.auto_resolved}.`
                    );
                    await reloadAll();
                  }}
                />
              ) : (
                <p className="text-xs text-slate-500">
                  Refresh and acknowledgement require an operator or administrator; dismissal
                  requires an administrator.
                </p>
              )}
            </div>
            {actionError ? (
              <p className="text-xs text-rose-300" role="alert">
                {actionError}
              </p>
            ) : null}
            {actionMessage ? <p className="text-xs text-emerald-300">{actionMessage}</p> : null}
            {recommendations.items.length === 0 ? (
              <DataState
                state="empty"
                emptyText="No recommendations match the filters. Refresh to recompute them."
              />
            ) : (
              <div className="max-h-96 overflow-auto">
                <table className="w-full text-left text-xs">
                  <thead className="sticky top-0 bg-slate-900 text-slate-400">
                    <tr>
                      <th className="p-1">Severity</th>
                      <th className="p-1">Rule</th>
                      <th className="p-1">Recommendation</th>
                      <th className="p-1">Scope</th>
                      <th className="p-1">Status</th>
                      <th className="p-1">Last evaluated</th>
                      <th className="p-1">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recommendations.items.map((item) => (
                      <tr key={item.recommendation_id} className="border-t border-slate-800 align-top">
                        <td className="p-1">
                          <StatusPill status={item.severity} />
                        </td>
                        <td className="p-1 text-slate-400">{item.rule_id}</td>
                        <td className="p-1 text-slate-200">
                          {item.title}
                          <div className="text-slate-500">{item.rationale}</div>
                        </td>
                        <td className="p-1 text-slate-500">
                          {item.scope_type}
                          <div>{item.case_id ?? item.scope_id}</div>
                        </td>
                        <td className="p-1">
                          <StatusPill status={item.status} />
                          <div className="text-slate-500">v{item.version}</div>
                        </td>
                        <td className="p-1 text-slate-500">{item.last_evaluated_at ?? "—"}</td>
                        <td className="p-1">
                          <div className="flex flex-wrap gap-1">
                            <button
                              type="button"
                              className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-200 hover:bg-slate-800"
                              onClick={() => void openRecommendation(item.recommendation_id)}
                            >
                              View
                            </button>
                            {canOperate && item.status === "OPEN" ? (
                              <ConfirmAction
                                label="Acknowledge"
                                confirmLabel="Confirm acknowledge"
                                reasonLabel="Acknowledgement note"
                                description="Acknowledging records advisory triage only."
                                onConfirm={async (reason) => {
                                  await acknowledgeGovernanceRecommendation(item.recommendation_id, {
                                    reason,
                                    expected_version: item.version,
                                  });
                                  setActionMessage(`Recommendation ${item.rule_id} acknowledged.`);
                                  await reloadAll();
                                }}
                              />
                            ) : null}
                            {isAdmin && (item.status === "OPEN" || item.status === "ACKNOWLEDGED") ? (
                              <ConfirmAction
                                label="Dismiss"
                                confirmLabel="Confirm dismiss"
                                reasonLabel="Dismissal reason (required)"
                                description="Dismissal suppresses this recommendation while the same condition persists. It is auditable and does not resolve the underlying governance item."
                                onConfirm={async (reason) => {
                                  await dismissGovernanceRecommendation(item.recommendation_id, {
                                    reason,
                                    expected_version: item.version,
                                  });
                                  setActionMessage(`Recommendation ${item.rule_id} dismissed.`);
                                  await reloadAll();
                                }}
                              />
                            ) : null}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <button
                type="button"
                className="rounded border border-slate-700 px-2 py-1 disabled:opacity-50"
                disabled={recommendationPage <= 1}
                onClick={() => setRecommendationPage((page) => Math.max(1, page - 1))}
              >
                Previous recommendations
              </button>
              <span>
                Page {recommendationPage} of {recommendationPageCount} · {recommendations.total} total
              </span>
              <button
                type="button"
                className="rounded border border-slate-700 px-2 py-1 disabled:opacity-50"
                disabled={recommendationPage >= recommendationPageCount}
                onClick={() => setRecommendationPage((page) => page + 1)}
              >
                Next recommendations
              </button>
            </div>
            {recommendationDetailError ? (
              <p className="text-xs text-rose-300" role="alert">
                {recommendationDetailError}
              </p>
            ) : null}
            {recommendationDetail ? (
              <div className="rounded-lg border border-slate-700 bg-slate-950/60 p-3">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div>
                    <p className="text-sm font-semibold text-slate-100">
                      {recommendationDetail.recommendation.rule_id} ·{" "}
                      {recommendationDetail.recommendation.title}
                    </p>
                    <p className="text-xs text-slate-400">
                      {recommendationDetail.recommendation.rationale}
                    </p>
                    <p className="text-xs text-slate-500">
                      Source refs: {recommendationDetail.recommendation.source_refs.join(", ") || "—"}
                    </p>
                  </div>
                  <button
                    type="button"
                    className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-300"
                    onClick={() => setRecommendationDetail(null)}
                  >
                    Close recommendation
                  </button>
                </div>
                <table className="mt-2 w-full text-left text-xs">
                  <thead className="bg-slate-900 text-slate-400">
                    <tr>
                      <th className="p-1">Event</th>
                      <th className="p-1">Transition</th>
                      <th className="p-1">Actor</th>
                      <th className="p-1">Reason</th>
                      <th className="p-1">At</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recommendationDetail.events.map((event) => (
                      <tr key={event.event_id} className="border-t border-slate-800 align-top">
                        <td className="p-1 text-slate-200">{event.event_type}</td>
                        <td className="p-1">
                          {event.from_status ?? "—"} → {event.to_status ?? "—"}
                        </td>
                        <td className="p-1 text-slate-500">
                          {event.actor_id ?? "—"} ({event.actor_role ?? "—"})
                        </td>
                        <td className="p-1 text-slate-400">{event.reason || "—"}</td>
                        <td className="p-1 text-slate-500">{event.created_at ?? "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : null}
          </div>
        )}
      </Card>

      <Card title="Intelligence snapshots and comparison">
        {snapshotsError ? (
          <DataState state="error" emptyText="" error={snapshotsError} />
        ) : (
          <div className="space-y-3">
            <p className="text-xs text-slate-400">
              Intelligence snapshots are local aggregate records with a self-digest. They are not
              regulatory certification and are not externally anchored or immutable.
            </p>
            {canOperate ? (
              <ConfirmAction
                label="Generate intelligence snapshot"
                confirmLabel="Confirm snapshot"
                reasonLabel="Snapshot reason"
                description="Stores one local aggregate snapshot. It does not export evidence or approve any governance action."
                onConfirm={async (reason) => {
                  await generateGovernanceIntelligenceSnapshot({
                    idempotency_key: `ui-intelligence-snapshot-${Date.now()}`,
                    reason,
                  });
                  setActionMessage("Intelligence snapshot generated.");
                  await reloadAll();
                }}
              />
            ) : (
              <p className="text-xs text-slate-500">
                Snapshot generation requires an operator or administrator
                (governance_snapshot_generate).
              </p>
            )}
            {snapshots.length === 0 ? (
              <DataState
                state={loading ? "loading" : "empty"}
                emptyText="No intelligence snapshots stored."
              />
            ) : (
              <div className="max-h-80 overflow-auto">
                <table className="w-full text-left text-xs">
                  <thead className="sticky top-0 bg-slate-900 text-slate-400">
                    <tr>
                      <th className="p-1">Compare</th>
                      <th className="p-1">As of</th>
                      <th className="p-1">Rows</th>
                      <th className="p-1">Digest</th>
                      <th className="p-1">Detail</th>
                    </tr>
                  </thead>
                  <tbody>
                    {snapshots.map((snapshot) => (
                      <tr key={snapshot.snapshot_id} className="border-t border-slate-800 align-top">
                        <td className="p-1">
                          <label className="flex items-center gap-1">
                            <input
                              type="radio"
                              name="left-snapshot"
                              aria-label={`Left snapshot ${snapshot.snapshot_id}`}
                              checked={leftSnapshot === snapshot.snapshot_id}
                              onChange={() => setLeftSnapshot(snapshot.snapshot_id)}
                            />
                            A
                          </label>
                          <label className="flex items-center gap-1">
                            <input
                              type="radio"
                              name="right-snapshot"
                              aria-label={`Right snapshot ${snapshot.snapshot_id}`}
                              checked={rightSnapshot === snapshot.snapshot_id}
                              onChange={() => setRightSnapshot(snapshot.snapshot_id)}
                            />
                            B
                          </label>
                        </td>
                        <td className="p-1 text-slate-200">{snapshot.as_of ?? "—"}</td>
                        <td className="p-1">{snapshot.row_count}</td>
                        <td className="p-1">
                          {snapshot.digest_valid ? "valid" : "INVALID"}
                          <div className="break-all text-slate-500">
                            {snapshot.payload_digest.slice(0, 16)}…
                          </div>
                        </td>
                        <td className="p-1">
                          <button
                            type="button"
                            className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-200 hover:bg-slate-800"
                            onClick={() => void openSnapshot(snapshot.snapshot_id)}
                          >
                            View integrity
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <p className="text-xs text-slate-500">
              {snapshotsTotal} snapshot(s). Select A and B to compare compatible local snapshots.
            </p>
            <button
              type="button"
              className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-200 disabled:opacity-50"
              disabled={!leftSnapshot || !rightSnapshot || leftSnapshot === rightSnapshot}
              onClick={async () => {
                setComparisonError(null);
                try {
                  setComparison(
                    await compareGovernanceIntelligenceSnapshots(leftSnapshot, rightSnapshot)
                  );
                } catch (exc) {
                  setComparisonError(messageOf(exc));
                }
              }}
            >
              Compare selected snapshots
            </button>
            {comparisonError ? (
              <p className="text-xs text-rose-300" role="alert">
                {comparisonError}
              </p>
            ) : null}
            {snapshotDetailError ? (
              <p className="text-xs text-rose-300" role="alert">
                {snapshotDetailError}
              </p>
            ) : null}
            {snapshotDetail ? (
              <div className="rounded-lg border border-slate-700 bg-slate-950/60 p-3">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div>
                    <p className="text-sm font-semibold text-slate-100">
                      Snapshot {snapshotDetail.snapshot.snapshot_id.slice(0, 8)} ·{" "}
                      {snapshotDetail.integrity.state}
                    </p>
                    <p className="text-xs text-slate-400">{snapshotDetail.integrity.message}</p>
                  </div>
                  <button
                    type="button"
                    className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-300"
                    onClick={() => setSnapshotDetail(null)}
                  >
                    Close snapshot
                  </button>
                </div>
                <p className="mt-1 text-xs text-slate-500">
                  Digest {snapshotDetail.snapshot.payload_digest.slice(0, 24)}… · rows{" "}
                  {snapshotDetail.snapshot.row_count} · schema v
                  {snapshotDetail.snapshot.schema_version}
                </p>
              </div>
            ) : null}
            {comparison ? (
              <div className="rounded-lg border border-slate-700 bg-slate-950/60 p-3">
                <p className="text-sm font-semibold text-slate-100">
                  Comparison: {comparison.status}
                </p>
                <p className="text-xs text-slate-400">{comparison.message}</p>
                {comparison.tampered_snapshot_ids.length > 0 ? (
                  <p className="text-xs text-rose-300">
                    Tampered snapshot ids: {comparison.tampered_snapshot_ids.join(", ")}
                  </p>
                ) : null}
                {comparison.comparable ? (
                  <>
                    <p className="mt-1 text-xs text-slate-400">
                      Added {comparison.summary.added} · removed {comparison.summary.removed} ·
                      changed {comparison.summary.changed}
                      {comparison.truncated ? " · diff truncated" : ""}
                    </p>
                    {comparison.changes.length > 0 ? (
                      <div className="max-h-64 overflow-auto">
                        <table className="w-full text-left text-xs">
                          <thead className="sticky top-0 bg-slate-900 text-slate-400">
                            <tr>
                              <th className="p-1">Path</th>
                              <th className="p-1">Change</th>
                              <th className="p-1">Before</th>
                              <th className="p-1">After</th>
                            </tr>
                          </thead>
                          <tbody>
                            {comparison.changes.map((change) => (
                              <tr key={`${change.path}:${change.change}`} className="border-t border-slate-800">
                                <td className="p-1 text-slate-200">{change.path}</td>
                                <td className="p-1">{change.change}</td>
                                <td className="p-1 text-slate-500">{JSON.stringify(change.before)}</td>
                                <td className="p-1 text-slate-400">{JSON.stringify(change.after)}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <p className="mt-1 text-xs text-slate-500">
                        No aggregate changes were detected between the selected snapshots.
                      </p>
                    )}
                  </>
                ) : null}
              </div>
            ) : null}
          </div>
        )}
      </Card>
    </div>
  );
}

export default IntelligenceWorkspace;
