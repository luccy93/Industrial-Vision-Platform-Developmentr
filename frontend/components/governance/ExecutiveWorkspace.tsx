"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useAuth } from "../auth/AuthProvider";
import { DataState } from "../operations/primitives";
import { Card } from "../ui/Card";
import {
  assignGovernanceExecutiveAction,
  createGovernanceExecutiveAction,
  downloadGovernanceExecutiveReportContent,
  fetchGovernanceExecutiveAction,
  fetchGovernanceExecutiveActions,
  fetchGovernanceExecutiveComparison,
  fetchGovernanceExecutiveConfig,
  fetchGovernanceExecutiveHealth,
  fetchGovernanceExecutiveKpis,
  fetchGovernanceExecutiveReport,
  fetchGovernanceExecutiveReports,
  fetchGovernanceExecutiveStatus,
  generateGovernanceExecutiveReport,
  transitionGovernanceExecutiveAction,
  updateGovernanceExecutiveConfig,
} from "../../lib/governance/client";
import type {
  GovernanceExecutiveAction,
  GovernanceExecutiveActionDetail,
  GovernanceExecutiveActionListResponse,
  GovernanceExecutiveActionStatus,
  GovernanceExecutiveComparison,
  GovernanceExecutiveConfig,
  GovernanceExecutiveHealthResponse,
  GovernanceExecutiveKpi,
  GovernanceExecutiveKpiResponse,
  GovernanceExecutiveReport,
  GovernanceExecutiveReportDetail,
  GovernanceExecutiveReportListResponse,
  GovernanceExecutiveReportType,
  GovernanceExecutiveStatus,
} from "../../types";

const HEALTH_STYLE: Record<string, string> = {
  HEALTHY: "bg-emerald-500/15 text-emerald-300",
  ATTENTION_REQUIRED: "bg-amber-500/15 text-amber-300",
  DEGRADED: "bg-orange-500/15 text-orange-300",
  CRITICAL: "bg-rose-500/15 text-rose-300",
  UNAVAILABLE: "bg-slate-500/15 text-slate-300",
};

const ACTION_STYLE: Record<string, string> = {
  OPEN: "bg-sky-500/15 text-sky-300",
  IN_PROGRESS: "bg-indigo-500/15 text-indigo-300",
  BLOCKED: "bg-amber-500/15 text-amber-300",
  COMPLETED: "bg-emerald-500/15 text-emerald-300",
  CANCELLED: "bg-slate-500/15 text-slate-300",
};

const ACTION_STATUSES: GovernanceExecutiveActionStatus[] = [
  "OPEN",
  "IN_PROGRESS",
  "BLOCKED",
  "COMPLETED",
  "CANCELLED",
];

const REPORT_TYPES: GovernanceExecutiveReportType[] = [
  "EXECUTIVE_SUMMARY",
  "EXECUTIVE_RISK",
  "EXECUTIVE_SLA",
  "EXECUTIVE_OPERATIONS",
];

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isAbort(error: unknown): boolean {
  return error instanceof Error && error.name === "AbortError";
}

function newIdempotencyKey(prefix: string): string {
  const random =
    typeof crypto !== "undefined" && "randomUUID" in crypto
      ? crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(36).slice(2)}`;
  return `${prefix}-${random}`;
}

function StatusPill({ status, styles }: { status: string; styles: Record<string, string> }) {
  return (
    <span
      className={`rounded-full px-2 py-0.5 text-xs font-medium ${
        styles[status] ?? "bg-slate-500/15 text-slate-300"
      }`}
    >
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

function kpiValue(kpi: GovernanceExecutiveKpi): string {
  if (kpi.availability === "UNAVAILABLE" || kpi.value === null) return "unavailable";
  if (typeof kpi.value === "boolean") return kpi.value ? "true" : "false";
  return `${kpi.value}${kpi.unit ? ` ${kpi.unit}` : ""}`;
}

export function ExecutiveWorkspace() {
  const { hasRole } = useAuth();
  const isAdmin = hasRole("ADMIN");
  const canOperate = isAdmin || hasRole("OPERATOR");

  const [status, setStatus] = useState<GovernanceExecutiveStatus | null>(null);
  const [health, setHealth] = useState<GovernanceExecutiveHealthResponse | null>(null);
  const [kpis, setKpis] = useState<GovernanceExecutiveKpiResponse | null>(null);
  const [actions, setActions] = useState<GovernanceExecutiveActionListResponse | null>(null);
  const [reports, setReports] = useState<GovernanceExecutiveReportListResponse | null>(null);
  const [config, setConfig] = useState<GovernanceExecutiveConfig | null>(null);
  const [actionDetail, setActionDetail] = useState<GovernanceExecutiveActionDetail | null>(null);
  const [reportDetail, setReportDetail] = useState<GovernanceExecutiveReportDetail | null>(null);
  const [comparison, setComparison] = useState<GovernanceExecutiveComparison | null>(null);

  const [statusError, setStatusError] = useState<string | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [kpiError, setKpiError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [reportError, setReportError] = useState<string | null>(null);
  const [configError, setConfigError] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [reportMessage, setReportMessage] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const [actionStatusFilter, setActionStatusFilter] = useState<
    GovernanceExecutiveActionStatus | ""
  >("");
  const [actionPage, setActionPage] = useState(1);
  const [reportPage, setReportPage] = useState(1);

  const [recommendationId, setRecommendationId] = useState("");
  const [actionTitle, setActionTitle] = useState("");
  const [actionOwner, setActionOwner] = useState("");
  const [actionDueAt, setActionDueAt] = useState("");
  const [actionPriority, setActionPriority] = useState("MEDIUM");
  const [actionDescription, setActionDescription] = useState("");
  const [actionReason, setActionReason] = useState("");

  const [transitionTarget, setTransitionTarget] =
    useState<GovernanceExecutiveActionStatus>("IN_PROGRESS");
  const [transitionNote, setTransitionNote] = useState("");
  const [assignOwner, setAssignOwner] = useState("");
  const [assignReason, setAssignReason] = useState("");

  const [reportType, setReportType] =
    useState<GovernanceExecutiveReportType>("EXECUTIVE_SUMMARY");
  const [reportFormat, setReportFormat] = useState<"json" | "csv">("json");
  const [reportWindowDays, setReportWindowDays] = useState(30);
  const [reportReason, setReportReason] = useState("");

  const [configWindowDays, setConfigWindowDays] = useState(30);
  const [configComparisonDays, setConfigComparisonDays] = useState(30);
  const [configDueSoonHours, setConfigDueSoonHours] = useState(72);
  const [configReportRows, setConfigReportRows] = useState(500);
  const [configIncludeRecommendations, setConfigIncludeRecommendations] = useState(true);
  const [configReason, setConfigReason] = useState("");

  const loadStatus = useCallback(async (signal?: AbortSignal) => {
    try {
      setStatus(await fetchGovernanceExecutiveStatus(signal));
      setStatusError(null);
    } catch (exc) {
      if (!isAbort(exc)) setStatusError(messageOf(exc));
    }
  }, []);

  const loadHealth = useCallback(async (signal?: AbortSignal) => {
    try {
      setHealth(await fetchGovernanceExecutiveHealth({}, signal));
      setHealthError(null);
    } catch (exc) {
      if (!isAbort(exc)) setHealthError(messageOf(exc));
    }
  }, []);

  const loadKpis = useCallback(async (signal?: AbortSignal) => {
    try {
      setKpis(await fetchGovernanceExecutiveKpis({}, signal));
      setKpiError(null);
    } catch (exc) {
      if (!isAbort(exc)) setKpiError(messageOf(exc));
    }
  }, []);

  const loadActions = useCallback(
    async (signal?: AbortSignal) => {
      try {
        setActions(
          await fetchGovernanceExecutiveActions(
            {
              status: actionStatusFilter,
              page: actionPage,
              page_size: 10,
            },
            signal
          )
        );
        setActionError(null);
      } catch (exc) {
        if (!isAbort(exc)) setActionError(messageOf(exc));
      }
    },
    [actionPage, actionStatusFilter]
  );

  const loadReports = useCallback(
    async (signal?: AbortSignal) => {
      try {
        setReports(
          await fetchGovernanceExecutiveReports({ page: reportPage, page_size: 10 }, signal)
        );
        setReportError(null);
      } catch (exc) {
        if (!isAbort(exc)) setReportError(messageOf(exc));
      }
    },
    [reportPage]
  );

  const loadConfig = useCallback(async (signal?: AbortSignal) => {
    try {
      const payload = await fetchGovernanceExecutiveConfig(signal);
      setConfig(payload);
      const stored = payload.config ?? {};
      if (typeof stored.default_window_days === "number") {
        setConfigWindowDays(stored.default_window_days);
      }
      if (typeof stored.comparison_period_days === "number") {
        setConfigComparisonDays(stored.comparison_period_days);
      }
      if (typeof stored.action_due_soon_hours === "number") {
        setConfigDueSoonHours(stored.action_due_soon_hours);
      }
      if (typeof stored.report_max_rows === "number") {
        setConfigReportRows(stored.report_max_rows);
      }
      if (typeof stored.include_recommendations_in_summary === "boolean") {
        setConfigIncludeRecommendations(stored.include_recommendations_in_summary);
      }
      setConfigError(null);
    } catch (exc) {
      if (!isAbort(exc)) setConfigError(messageOf(exc));
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    const signal = controller.signal;
    void Promise.all([
      loadStatus(signal),
      loadHealth(signal),
      loadKpis(signal),
      loadActions(signal),
      loadReports(signal),
      loadConfig(signal),
    ]).finally(() => {
      if (!signal.aborted) setLoading(false);
    });
    return () => controller.abort();
  }, [loadActions, loadConfig, loadHealth, loadKpis, loadReports, loadStatus]);

  useEffect(() => {
    const controller = new AbortController();
    void loadActions(controller.signal);
    return () => controller.abort();
  }, [loadActions]);

  useEffect(() => {
    const controller = new AbortController();
    void loadReports(controller.signal);
    return () => controller.abort();
  }, [loadReports]);

  const refreshAll = useCallback(async () => {
    setLoading(true);
    await Promise.all([
      loadStatus(),
      loadHealth(),
      loadKpis(),
      loadActions(),
      loadReports(),
      loadConfig(),
    ]);
    setLoading(false);
  }, [loadActions, loadConfig, loadHealth, loadKpis, loadReports, loadStatus]);

  const openAction = useCallback(async (actionId: string) => {
    try {
      setActionDetail(await fetchGovernanceExecutiveAction(actionId));
      setTransitionNote("");
      setAssignOwner("");
      setAssignReason("");
      setActionError(null);
    } catch (exc) {
      if (!isAbort(exc)) setActionError(messageOf(exc));
    }
  }, []);

  const openReport = useCallback(async (reportId: string) => {
    try {
      setReportDetail(await fetchGovernanceExecutiveReport(reportId));
      setComparison(null);
      setReportError(null);
    } catch (exc) {
      if (!isAbort(exc)) setReportError(messageOf(exc));
    }
  }, []);

  const submitAction = useCallback(
    async (event: React.FormEvent) => {
      event.preventDefault();
      setActionMessage(null);
      setActionError(null);
      try {
        if (!actionDueAt) throw new Error("A due date is required.");
        const result = await createGovernanceExecutiveAction({
          recommendation_id: recommendationId.trim(),
          title: actionTitle.trim(),
          description: actionDescription.trim(),
          owner_id: actionOwner.trim(),
          due_at: new Date(actionDueAt).toISOString(),
          priority: actionPriority,
          idempotency_key: newIdempotencyKey("executive-action"),
          reason: actionReason.trim(),
        });
        setActionMessage(
          result.replayed
            ? `Action ${result.action.action_id} was replayed without duplication.`
            : `Action ${result.action.action_id} created.`
        );
        setRecommendationId("");
        setActionTitle("");
        setActionDescription("");
        setActionReason("");
        await loadActions();
        await openAction(result.action.action_id);
      } catch (exc) {
        setActionError(messageOf(exc));
      }
    },
    [
      actionDescription,
      actionDueAt,
      actionOwner,
      actionPriority,
      actionReason,
      actionTitle,
      loadActions,
      openAction,
      recommendationId,
    ]
  );

  const submitTransition = useCallback(
    async (event: React.FormEvent) => {
      event.preventDefault();
      if (!actionDetail) return;
      setActionMessage(null);
      setActionError(null);
      try {
        const result = await transitionGovernanceExecutiveAction(actionDetail.action.action_id, {
          target_status: transitionTarget,
          expected_version: actionDetail.action.version,
          reason: transitionNote.trim(),
          outcome_summary: transitionTarget === "COMPLETED" ? transitionNote.trim() : "",
          block_reason: transitionTarget === "BLOCKED" ? transitionNote.trim() : "",
          cancel_reason: transitionTarget === "CANCELLED" ? transitionNote.trim() : "",
        });
        setActionMessage(
          `Action moved ${result.from_status} → ${result.to_status}; the linked recommendation is not auto-resolved.`
        );
        setTransitionNote("");
        await loadActions();
        await openAction(actionDetail.action.action_id);
      } catch (exc) {
        setActionError(messageOf(exc));
      }
    },
    [actionDetail, loadActions, openAction, transitionNote, transitionTarget]
  );

  const submitAssign = useCallback(
    async (event: React.FormEvent) => {
      event.preventDefault();
      if (!actionDetail) return;
      setActionMessage(null);
      setActionError(null);
      try {
        const result = await assignGovernanceExecutiveAction(actionDetail.action.action_id, {
          owner_id: assignOwner.trim(),
          expected_version: actionDetail.action.version,
          reason: assignReason.trim(),
        });
        setActionMessage(`Action assigned to ${result.action.owner_id}.`);
        setAssignOwner("");
        setAssignReason("");
        await loadActions();
        await openAction(actionDetail.action.action_id);
      } catch (exc) {
        setActionError(messageOf(exc));
      }
    },
    [actionDetail, assignOwner, assignReason, loadActions, openAction]
  );

  const submitReport = useCallback(
    async (event: React.FormEvent) => {
      event.preventDefault();
      setReportMessage(null);
      setReportError(null);
      try {
        const result = await generateGovernanceExecutiveReport({
          report_type: reportType,
          format: reportFormat,
          window_days: reportWindowDays,
          idempotency_key: newIdempotencyKey("executive-report"),
          reason: reportReason.trim(),
        });
        setReportMessage(
          result.replayed
            ? `Report ${result.report.report_id} was replayed without duplication.`
            : `Report ${result.report.report_id} generated locally; no external distribution occurred.`
        );
        setReportReason("");
        await loadReports();
        await openReport(result.report.report_id);
      } catch (exc) {
        setReportError(messageOf(exc));
      }
    },
    [loadReports, openReport, reportFormat, reportReason, reportType, reportWindowDays]
  );

  const compareCurrent = useCallback(async () => {
    if (!reportDetail) return;
    setReportError(null);
    try {
      setComparison(
        await fetchGovernanceExecutiveComparison(reportDetail.report.report_id, {
          window_days: reportWindowDays,
        })
      );
    } catch (exc) {
      setReportError(messageOf(exc));
    }
  }, [reportDetail, reportWindowDays]);

  const submitConfig = useCallback(
    async (event: React.FormEvent) => {
      event.preventDefault();
      if (!config) return;
      setConfigError(null);
      try {
        const updated = await updateGovernanceExecutiveConfig({
          config: {
            ...config.config,
            default_window_days: configWindowDays,
            comparison_period_days: configComparisonDays,
            action_due_soon_hours: configDueSoonHours,
            report_max_rows: configReportRows,
            include_recommendations_in_summary: configIncludeRecommendations,
          },
          reason: configReason.trim(),
        });
        setConfig(updated);
        setConfigReason("");
        setConfigError(null);
      } catch (exc) {
        setConfigError(messageOf(exc));
      }
    },
    [
      config,
      configComparisonDays,
      configDueSoonHours,
      configIncludeRecommendations,
      configReason,
      configReportRows,
      configWindowDays,
    ]
  );

  const allowedTransitions = useMemo(() => {
    if (!actionDetail) return [];
    return actions?.lifecycle.transitions[actionDetail.action.status] ?? [];
  }, [actionDetail, actions]);

  const healthStatus = health?.health.overall_status ?? "UNAVAILABLE";
  const coverage = health?.source_coverage ?? kpis?.source_coverage;

  return (
    <div className="space-y-4">
      <Card title="Executive governance command center">
        <div className="mb-2 flex justify-end">
          <button
            type="button"
            onClick={() => void refreshAll()}
            className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800"
          >
            Refresh
          </button>
        </div>
        <DataState
          state={loading ? "loading" : statusError ? "error" : "ready"}
          emptyText="No executive status is available."
          error={statusError}
        >
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
            <Metric label="Health model" value={status?.health_model_version ?? "unavailable"} />
            <Metric label="KPIs" value={status?.kpi_count ?? 0} note="source-preserving" />
            <Metric label="Strategic actions" value={status?.action_total ?? 0} />
            <Metric label="Executive reports" value={status?.report_total ?? 0} note="local only" />
          </div>
          <p className="mt-2 text-xs text-slate-400">
            {status?.scheduled_executive_note ??
              "V38 computes executive views on demand; no executive scheduler is started."}
          </p>
        </DataState>
      </Card>

      <Card title="Deterministic executive health (EXEC_HEALTH_V1)">
        <DataState
          state={loading ? "loading" : healthError ? "error" : "ready"}
          emptyText="No health calculation is available."
          error={healthError}
        >
          <div className="flex flex-wrap items-center gap-2">
            <StatusPill status={healthStatus} styles={HEALTH_STYLE} />
            {coverage ? (
              <span className="text-xs text-slate-400">
                coverage {coverage.status} · {coverage.available_kpis}/{coverage.applicable_kpis}{" "}
                applicable KPIs available
              </span>
            ) : null}
          </div>
          <p className="mt-2 text-sm text-slate-300">
            {health?.health.status_reason ?? "unavailable"}
          </p>
          {coverage && coverage.status !== "COMPLETE" ? (
            <p className="mt-1 text-xs text-amber-300">
              Partial or unavailable sources are explicit; missing data is never treated as zero.
            </p>
          ) : null}
          <ul className="mt-2 space-y-1 text-xs">
            {(health?.health.signals ?? []).map((signal) => (
              <li key={signal.code} className="flex flex-wrap items-center gap-2">
                <StatusPill
                  status={signal.triggered ? signal.status : signal.evaluated ? "OK" : "UNAVAILABLE"}
                  styles={{
                    OK: "bg-emerald-500/15 text-emerald-300",
                    ...HEALTH_STYLE,
                  }}
                />
                <span className="font-medium text-slate-200">{signal.code}</span>
                <span className="text-slate-400">
                  {signal.kpi_id} {signal.operator} {signal.threshold}
                </span>
                <span className="text-slate-500">{signal.explanation}</span>
              </li>
            ))}
          </ul>
          <p className="mt-2 text-xs text-slate-500">
            averaged_score_used={String(health?.health.averaged_score_used ?? false)} · fixed
            thresholds={String(health?.health.thresholds.fixed ?? true)}
          </p>
        </DataState>
      </Card>

      <Card title="Executive KPIs">
        <DataState
          state={loading ? "loading" : kpiError ? "error" : "ready"}
          emptyText="No KPI calculation is available."
          error={kpiError}
        >
          <div className="overflow-auto">
            <table className="w-full text-left text-xs">
              <thead className="text-slate-400">
                <tr>
                  <th className="p-1">KPI</th>
                  <th className="p-1">Value</th>
                  <th className="p-1">Availability</th>
                  <th className="p-1">Completeness</th>
                  <th className="p-1">Source</th>
                  <th className="p-1">Versions</th>
                </tr>
              </thead>
              <tbody>
                {(kpis?.items ?? []).map((kpi) => (
                  <tr key={kpi.kpi_id} className="border-t border-slate-800 align-top">
                    <td className="p-1">
                      <p className="font-medium text-slate-200">{kpi.name}</p>
                      <p className="text-slate-500">{kpi.kpi_id}</p>
                      <details className="text-slate-500">
                        <summary>Definition</summary>
                        <p>{kpi.definition}</p>
                      </details>
                    </td>
                    <td className="p-1">{kpiValue(kpi)}</td>
                    <td className="p-1">
                      <StatusPill
                        status={kpi.availability}
                        styles={{
                          AVAILABLE: "bg-emerald-500/15 text-emerald-300",
                          PARTIAL: "bg-amber-500/15 text-amber-300",
                          UNAVAILABLE: "bg-rose-500/15 text-rose-300",
                        }}
                      />
                      {kpi.unavailable_reason ? (
                        <p className="text-slate-500">{kpi.unavailable_reason}</p>
                      ) : null}
                    </td>
                    <td className="p-1">
                      {kpi.completeness.status} ({kpi.completeness.known}/{kpi.completeness.total})
                      {kpi.completeness.unknown ? ` · ${kpi.completeness.unknown} unknown` : ""}
                    </td>
                    <td className="p-1">{kpi.source}</td>
                    <td className="p-1">
                      model {kpi.model_version ?? "n/a"} · policy {kpi.policy_version ?? "n/a"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {kpis ? (
            <p className="mt-2 text-xs text-slate-500">
              Calculated {kpis.calculated_at} · window {String(kpis.window_days)} days ·{" "}
              {kpis.source_coverage.message}
            </p>
          ) : null}
          {kpis && kpis.items.length === 0 ? (
            <p className="mt-2 text-xs text-slate-400">
              No KPI values are available for this window. Missing data is reported as unavailable,
              never as zero.
            </p>
          ) : null}
        </DataState>
      </Card>

      <Card title="Strategic actions linked to V37 recommendations">
        <DataState
          state={loading ? "loading" : actionError && !actions ? "error" : "ready"}
          emptyText="No strategic actions exist."
          error={actionError}
        >
          <div className="flex flex-wrap items-end gap-2">
            <label className="text-xs text-slate-400">
              Status
              <select
                value={actionStatusFilter}
                onChange={(event) => {
                  setActionStatusFilter(event.target.value as GovernanceExecutiveActionStatus | "");
                  setActionPage(1);
                }}
                className="mt-1 block rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-200"
              >
                <option value="">All</option>
                {ACTION_STATUSES.map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
            </label>
          </div>

          <div className="mt-2 overflow-auto">
            <table className="w-full text-left text-xs">
              <thead className="text-slate-400">
                <tr>
                  <th className="p-1">Action</th>
                  <th className="p-1">Status</th>
                  <th className="p-1">Owner</th>
                  <th className="p-1">Due</th>
                  <th className="p-1">Recommendation</th>
                  <th className="p-1" />
                </tr>
              </thead>
              <tbody>
                {(actions?.items ?? []).map((action: GovernanceExecutiveAction) => (
                  <tr key={action.action_id} className="border-t border-slate-800">
                    <td className="p-1">
                      <p className="font-medium text-slate-200">{action.title}</p>
                      <p className="text-slate-500">
                        {action.action_id} · v{action.version}
                      </p>
                    </td>
                    <td className="p-1">
                      <StatusPill status={action.status} styles={ACTION_STYLE} />
                    </td>
                    <td className="p-1">{action.owner_id}</td>
                    <td className="p-1">{action.due_at ?? "unavailable"}</td>
                    <td className="p-1">
                      {action.recommendation_id}
                      <p className="text-slate-500">{action.recommendation_severity}</p>
                    </td>
                    <td className="p-1">
                      <button
                        type="button"
                        onClick={() => void openAction(action.action_id)}
                        className="rounded border border-slate-700 px-2 py-0.5 text-xs text-slate-300 hover:bg-slate-800"
                      >
                        Open
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {actions && actions.items.length === 0 ? (
            <p className="mt-2 text-xs text-slate-400">
              No strategic actions match this filter. Actions are advisory and never resolve the
              linked V37 recommendation automatically.
            </p>
          ) : null}
          {actions && actions.total > actions.page_size ? (
            <div className="mt-2 flex gap-2 text-xs">
              <button
                type="button"
                disabled={actionPage <= 1}
                onClick={() => setActionPage((value) => Math.max(1, value - 1))}
                className="rounded border border-slate-700 px-2 py-0.5 disabled:opacity-40"
              >
                Previous
              </button>
              <span className="text-slate-400">
                Page {actions.page} · {actions.total} total
              </span>
              <button
                type="button"
                disabled={actionPage * actions.page_size >= actions.total}
                onClick={() => setActionPage((value) => value + 1)}
                className="rounded border border-slate-700 px-2 py-0.5 disabled:opacity-40"
              >
                Next
              </button>
            </div>
          ) : null}

          {canOperate ? (
            <form onSubmit={(event) => void submitAction(event)} className="mt-4 space-y-2">
              <p className="text-sm font-medium text-slate-200">Create strategic action</p>
              <div className="grid gap-2 sm:grid-cols-2">
                <label className="text-xs text-slate-400">
                  V37 recommendation ID
                  <input
                    value={recommendationId}
                    onChange={(event) => setRecommendationId(event.target.value)}
                    required
                    className="mt-1 block w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-200"
                  />
                </label>
                <label className="text-xs text-slate-400">
                  Title
                  <input
                    value={actionTitle}
                    onChange={(event) => setActionTitle(event.target.value)}
                    required
                    className="mt-1 block w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-200"
                  />
                </label>
                <label className="text-xs text-slate-400">
                  Owner
                  <input
                    value={actionOwner}
                    onChange={(event) => setActionOwner(event.target.value)}
                    required
                    className="mt-1 block w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-200"
                  />
                </label>
                <label className="text-xs text-slate-400">
                  Due at
                  <input
                    type="datetime-local"
                    value={actionDueAt}
                    onChange={(event) => setActionDueAt(event.target.value)}
                    required
                    className="mt-1 block w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-200"
                  />
                </label>
                <label className="text-xs text-slate-400">
                  Priority
                  <select
                    value={actionPriority}
                    onChange={(event) => setActionPriority(event.target.value)}
                    className="mt-1 block w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-200"
                  >
                    {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((value) => (
                      <option key={value} value={value}>
                        {value}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="text-xs text-slate-400">
                  Reason
                  <input
                    value={actionReason}
                    onChange={(event) => setActionReason(event.target.value)}
                    required
                    className="mt-1 block w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-200"
                  />
                </label>
              </div>
              <label className="block text-xs text-slate-400">
                Description
                <textarea
                  value={actionDescription}
                  onChange={(event) => setActionDescription(event.target.value)}
                  className="mt-1 block w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-200"
                />
              </label>
              <button
                type="submit"
                className="rounded bg-sky-600 px-3 py-1 text-xs font-medium text-white hover:bg-sky-500"
              >
                Create action
              </button>
            </form>
          ) : null}

          {actionMessage ? (
            <p className="mt-2 text-xs text-emerald-300" role="status">
              {actionMessage}
            </p>
          ) : null}
          {actionError ? (
            <p className="mt-2 text-xs text-amber-300" role="alert">
              {actionError}
            </p>
          ) : null}

          {actionDetail ? (
            <div className="mt-4 rounded border border-slate-800 p-2">
              <div className="flex flex-wrap items-center gap-2">
                <p className="text-sm font-medium text-slate-200">
                  {actionDetail.action.title}
                </p>
                <StatusPill status={actionDetail.action.status} styles={ACTION_STYLE} />
                <span className="text-xs text-slate-500">v{actionDetail.action.version}</span>
              </div>
              <p className="mt-1 text-xs text-slate-400">
                Owner {actionDetail.action.owner_id} · due {actionDetail.action.due_at ?? "unavailable"} ·
                recommendation {actionDetail.action.recommendation_id}
              </p>
              <p className="mt-1 text-xs text-slate-500">
                Linked recommendation status:{" "}
                {String(actionDetail.linked_recommendation?.status ?? "unavailable")} · actions do not
                auto-resolve recommendations.
              </p>
              <ol className="mt-2 space-y-1 text-xs">
                {actionDetail.events.map((event) => (
                  <li key={event.event_id} className="text-slate-400">
                    <span className="text-slate-200">{event.event_type}</span> ·{" "}
                    {event.from_status ?? "—"} → {event.to_status ?? "—"} · {event.actor_id ?? "SYSTEM"} ·{" "}
                    {event.reason}
                  </li>
                ))}
              </ol>
              {canOperate && allowedTransitions.length > 0 ? (
                <form onSubmit={(event) => void submitTransition(event)} className="mt-2 space-y-2">
                  <div className="flex flex-wrap items-end gap-2">
                    <label className="text-xs text-slate-400">
                      Transition
                      <select
                        value={transitionTarget}
                        onChange={(event) =>
                          setTransitionTarget(
                            event.target.value as GovernanceExecutiveActionStatus
                          )
                        }
                        className="mt-1 block rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-200"
                      >
                        {allowedTransitions.map((value) => (
                          <option key={value} value={value}>
                            {value}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label className="min-w-48 flex-1 text-xs text-slate-400">
                      Reason / outcome / block / cancel note
                      <input
                        value={transitionNote}
                        onChange={(event) => setTransitionNote(event.target.value)}
                        className="mt-1 block w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-200"
                      />
                    </label>
                    <button
                      type="submit"
                      className="rounded bg-slate-700 px-3 py-1 text-xs text-slate-100 hover:bg-slate-600"
                    >
                      Apply transition
                    </button>
                  </div>
                </form>
              ) : null}
              {isAdmin ? (
                <form onSubmit={(event) => void submitAssign(event)} className="mt-2 flex flex-wrap items-end gap-2">
                  <label className="text-xs text-slate-400">
                    Assign owner
                    <input
                      value={assignOwner}
                      onChange={(event) => setAssignOwner(event.target.value)}
                      className="mt-1 block rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-200"
                    />
                  </label>
                  <label className="min-w-48 flex-1 text-xs text-slate-400">
                    Assignment reason
                    <input
                      value={assignReason}
                      onChange={(event) => setAssignReason(event.target.value)}
                      className="mt-1 block w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-200"
                    />
                  </label>
                  <button
                    type="submit"
                    className="rounded border border-slate-700 px-3 py-1 text-xs text-slate-200 hover:bg-slate-800"
                  >
                    Assign
                  </button>
                </form>
              ) : null}
            </div>
          ) : null}
        </DataState>
      </Card>

      <Card title="Executive reports and compatible comparisons">
        <DataState
          state={loading ? "loading" : reportError && !reports ? "error" : "ready"}
          emptyText="No executive reports have been generated."
          error={reportError}
        >
          <div className="overflow-auto">
            <table className="w-full text-left text-xs">
              <thead className="text-slate-400">
                <tr>
                  <th className="p-1">Report</th>
                  <th className="p-1">Type</th>
                  <th className="p-1">Format</th>
                  <th className="p-1">Window</th>
                  <th className="p-1">Coverage</th>
                  <th className="p-1" />
                </tr>
              </thead>
              <tbody>
                {(reports?.items ?? []).map((report: GovernanceExecutiveReport) => (
                  <tr key={report.report_id} className="border-t border-slate-800">
                    <td className="p-1">
                      <p className="font-medium text-slate-200">{report.report_id}</p>
                      <p className="text-slate-500">{report.generated_at ?? "unavailable"}</p>
                    </td>
                    <td className="p-1">{report.report_type}</td>
                    <td className="p-1">{report.format}</td>
                    <td className="p-1">
                      {report.window_start ?? "—"} → {report.window_end ?? "—"}
                    </td>
                    <td className="p-1">
                      {report.sections_available.length} available
                      {report.sections_unavailable.length
                        ? ` · ${report.sections_unavailable.length} unavailable`
                        : ""}
                    </td>
                    <td className="p-1">
                      <div className="flex flex-wrap gap-1">
                        <button
                          type="button"
                          onClick={() => void openReport(report.report_id)}
                          className="rounded border border-slate-700 px-2 py-0.5 text-xs text-slate-300 hover:bg-slate-800"
                        >
                          Open
                        </button>
                        <button
                          type="button"
                          onClick={() =>
                            void downloadGovernanceExecutiveReportContent(
                              report.report_id,
                              `executive-report.${report.format}`
                            )
                          }
                          className="rounded border border-slate-700 px-2 py-0.5 text-xs text-slate-300 hover:bg-slate-800"
                        >
                          Download
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {reports && reports.items.length === 0 ? (
            <p className="mt-2 text-xs text-slate-400">
              No executive reports have been generated. Reports are bounded local JSON/CSV documents
              and are never emailed, published, or rendered as PDF.
            </p>
          ) : null}
          {reports && reports.total > reports.page_size ? (
            <div className="mt-2 flex gap-2 text-xs">
              <button
                type="button"
                disabled={reportPage <= 1}
                onClick={() => setReportPage((value) => Math.max(1, value - 1))}
                className="rounded border border-slate-700 px-2 py-0.5 disabled:opacity-40"
              >
                Previous
              </button>
              <span className="text-slate-400">
                Page {reports.page} · {reports.total} total
              </span>
              <button
                type="button"
                disabled={reportPage * reports.page_size >= reports.total}
                onClick={() => setReportPage((value) => value + 1)}
                className="rounded border border-slate-700 px-2 py-0.5 disabled:opacity-40"
              >
                Next
              </button>
            </div>
          ) : null}

          {isAdmin ? (
            <form onSubmit={(event) => void submitReport(event)} className="mt-4 space-y-2">
              <p className="text-sm font-medium text-slate-200">Generate executive report</p>
              <div className="grid gap-2 sm:grid-cols-4">
                <label className="text-xs text-slate-400">
                  Type
                  <select
                    value={reportType}
                    onChange={(event) =>
                      setReportType(event.target.value as GovernanceExecutiveReportType)
                    }
                    className="mt-1 block w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-200"
                  >
                    {REPORT_TYPES.map((value) => (
                      <option key={value} value={value}>
                        {value}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="text-xs text-slate-400">
                  Format
                  <select
                    value={reportFormat}
                    onChange={(event) => setReportFormat(event.target.value as "json" | "csv")}
                    className="mt-1 block w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-200"
                  >
                    <option value="json">json</option>
                    <option value="csv">csv</option>
                  </select>
                </label>
                <label className="text-xs text-slate-400">
                  Window days
                  <input
                    type="number"
                    min={1}
                    max={90}
                    value={reportWindowDays}
                    onChange={(event) => setReportWindowDays(Number(event.target.value))}
                    className="mt-1 block w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-200"
                  />
                </label>
                <label className="text-xs text-slate-400">
                  Reason
                  <input
                    value={reportReason}
                    onChange={(event) => setReportReason(event.target.value)}
                    required
                    className="mt-1 block w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-200"
                  />
                </label>
              </div>
              <button
                type="submit"
                className="rounded bg-sky-600 px-3 py-1 text-xs font-medium text-white hover:bg-sky-500"
              >
                Generate report
              </button>
            </form>
          ) : null}

          {reportMessage ? (
            <p className="mt-2 text-xs text-emerald-300" role="status">
              {reportMessage}
            </p>
          ) : null}
          {reportError ? (
            <p className="mt-2 text-xs text-amber-300" role="alert">
              {reportError}
            </p>
          ) : null}

          {reportDetail ? (
            <div className="mt-4 rounded border border-slate-800 p-2">
              <div className="flex flex-wrap items-center gap-2">
                <p className="text-sm font-medium text-slate-200">
                  {reportDetail.report.report_id} · {reportDetail.report.report_type}
                </p>
                <span className="text-xs text-slate-500">
                  {reportDetail.report.format} · schema {reportDetail.report.schema_version}
                </span>
                <button
                  type="button"
                  onClick={() => void compareCurrent()}
                  className="rounded border border-slate-700 px-2 py-0.5 text-xs text-slate-300 hover:bg-slate-800"
                >
                  Compare with current period
                </button>
              </div>
              <p className="mt-1 text-xs text-slate-400">
                digest valid={String(reportDetail.integrity.report_digest_valid)} · snapshot digest
                valid={String(reportDetail.integrity.snapshot_digest_valid)} · redaction applied=
                {String(reportDetail.integrity.redaction_applied)}
              </p>
              <p className="mt-1 text-xs text-slate-500">
                Sections unavailable:{" "}
                {reportDetail.report.sections_unavailable.length
                  ? reportDetail.report.sections_unavailable.join(", ")
                  : "none"}
              </p>
              <pre className="mt-2 max-h-64 overflow-auto rounded bg-slate-950 p-2 text-[10px] text-slate-300">
                {JSON.stringify(reportDetail.payload, null, 2)}
              </pre>
              {comparison ? (
                <div className="mt-2 text-xs">
                  <p className="text-slate-200">
                    Comparison {comparison.status} · {comparison.message}
                  </p>
                  <p className="text-slate-500">
                    interpolated={String(comparison.interpolated)} · fabricated_history=
                    {String(comparison.fabricated_history)} · source_preserved=
                    {String(comparison.source_preserved)}
                  </p>
                  {comparison.incompatibilities.length ? (
                    <ul className="mt-1 list-disc pl-4 text-amber-300">
                      {comparison.incompatibilities.map((item) => (
                        <li key={`${item.code}-${item.kpi_id ?? ""}`}>{item.message}</li>
                      ))}
                    </ul>
                  ) : null}
                  {comparison.gaps.length ? (
                    <ul className="mt-1 list-disc pl-4 text-slate-400">
                      {comparison.gaps.slice(0, 10).map((gap, index) => (
                        <li key={index}>{String(gap.message ?? gap.code ?? "gap")}</li>
                      ))}
                    </ul>
                  ) : null}
                  {comparison.changes.length ? (
                    <div className="mt-1 overflow-auto">
                      <table className="w-full text-left text-xs">
                        <thead className="text-slate-400">
                          <tr>
                            <th className="p-1">KPI</th>
                            <th className="p-1">Baseline</th>
                            <th className="p-1">Current</th>
                            <th className="p-1">Delta</th>
                          </tr>
                        </thead>
                        <tbody>
                          {comparison.changes.slice(0, 15).map((change) => (
                            <tr key={change.kpi_id} className="border-t border-slate-800">
                              <td className="p-1">{change.name}</td>
                              <td className="p-1">{change.baseline_value}</td>
                              <td className="p-1">{change.current_value}</td>
                              <td className="p-1">
                                {change.delta}
                                {change.partial ? " (partial)" : ""}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : null}
                </div>
              ) : null}
            </div>
          ) : null}
        </DataState>
      </Card>

      <Card title="Executive operational configuration">
        <DataState
          state={loading ? "loading" : configError && !config ? "error" : "ready"}
          emptyText="No executive configuration is available."
          error={configError}
        >
          {config ? (
            <>
              <p className="text-xs text-slate-400">
                availability={config.availability} · schema {config.schema_version} · fixed health
                thresholds={String(config.health_thresholds_fixed)} ·{" "}
                {config.fixed_health_model_version}
              </p>
              <pre className="mt-2 max-h-40 overflow-auto rounded bg-slate-950 p-2 text-[10px] text-slate-300">
                {JSON.stringify(config.config, null, 2)}
              </pre>
              {isAdmin ? (
                <form onSubmit={(event) => void submitConfig(event)} className="mt-3 space-y-2">
                  <div className="grid gap-2 sm:grid-cols-3">
                    <label className="text-xs text-slate-400">
                      Default window days
                      <input
                        type="number"
                        min={1}
                        max={90}
                        value={configWindowDays}
                        onChange={(event) => setConfigWindowDays(Number(event.target.value))}
                        className="mt-1 block w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-200"
                      />
                    </label>
                    <label className="text-xs text-slate-400">
                      Comparison period days
                      <input
                        type="number"
                        min={1}
                        max={90}
                        value={configComparisonDays}
                        onChange={(event) => setConfigComparisonDays(Number(event.target.value))}
                        className="mt-1 block w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-200"
                      />
                    </label>
                    <label className="text-xs text-slate-400">
                      Due-soon hours
                      <input
                        type="number"
                        min={1}
                        max={720}
                        value={configDueSoonHours}
                        onChange={(event) => setConfigDueSoonHours(Number(event.target.value))}
                        className="mt-1 block w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-200"
                      />
                    </label>
                    <label className="text-xs text-slate-400">
                      Report max rows
                      <input
                        type="number"
                        min={50}
                        max={5000}
                        value={configReportRows}
                        onChange={(event) => setConfigReportRows(Number(event.target.value))}
                        className="mt-1 block w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-200"
                      />
                    </label>
                    <label className="flex items-center gap-2 text-xs text-slate-400">
                      <input
                        type="checkbox"
                        checked={configIncludeRecommendations}
                        onChange={(event) =>
                          setConfigIncludeRecommendations(event.target.checked)
                        }
                      />
                      Include recommendations in summary
                    </label>
                    <label className="text-xs text-slate-400">
                      Reason
                      <input
                        value={configReason}
                        onChange={(event) => setConfigReason(event.target.value)}
                        required
                        className="mt-1 block w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-200"
                      />
                    </label>
                  </div>
                  <button
                    type="submit"
                    className="rounded bg-sky-600 px-3 py-1 text-xs font-medium text-white hover:bg-sky-500"
                  >
                    Append configuration
                  </button>
                </form>
              ) : (
                <p className="mt-2 text-xs text-slate-500">
                  Configuration writes require the ADMIN role.
                </p>
              )}
              {configError ? (
                <p className="mt-2 text-xs text-amber-300" role="alert">
                  {configError}
                </p>
              ) : null}
            </>
          ) : null}
        </DataState>
      </Card>

      <Card title="Non-claims and limitations">
        <ul className="list-disc pl-4 text-xs text-slate-400">
          {(status?.non_claims ?? []).map((item) => (
            <li key={item}>{item}</li>
          ))}
          {(status?.limitations ?? []).map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </Card>
    </div>
  );
}
