"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useAuth } from "../auth/AuthProvider";
import { DataState } from "../operations/primitives";
import { Card } from "../ui/Card";
import {
  cancelGovernanceAutomationJob,
  fetchGovernanceAutomationHealth,
  fetchGovernanceAutomationJobs,
  fetchGovernanceAutomationSchedules,
  fetchGovernanceAutomationStatus,
  fetchGovernanceReminderActivity,
  fetchGovernanceSnapshots,
  generateGovernanceSnapshot,
  governanceSnapshotCsvUrl,
  retryGovernanceAutomationJob,
  runGovernanceAutomationJob,
  updateGovernanceAutomationSchedule,
} from "../../lib/governance/client";
import type {
  GovernanceAutomationHealth,
  GovernanceAutomationJob,
  GovernanceAutomationJobStatus,
  GovernanceAutomationJobType,
  GovernanceAutomationSchedule,
  GovernanceAutomationStatus,
  GovernanceReminderActivity,
  GovernanceSnapshot,
} from "../../types";

const JOB_TYPES: { value: GovernanceAutomationJobType; label: string }[] = [
  { value: "RETENTION_EVALUATION", label: "Retention evaluation" },
  { value: "RETENTION_REVIEW_REMINDERS", label: "Retention review reminders" },
  { value: "LEGAL_HOLD_REMINDERS", label: "Legal-hold reminders" },
  { value: "DISPOSITION_REVIEW_REMINDERS", label: "Disposition review reminders" },
  { value: "EXPORT_APPROVAL_REMINDERS", label: "Export approval reminders" },
  { value: "COMPLIANCE_SNAPSHOT", label: "Compliance snapshot" },
  { value: "GOVERNANCE_HEALTH_CHECK", label: "Governance health check" },
];

const JOB_STATUSES: GovernanceAutomationJobStatus[] = [
  "PENDING",
  "RUNNING",
  "SUCCEEDED",
  "FAILED",
  "CANCELLED",
  "UNAVAILABLE",
];

const RETRYABLE = new Set<GovernanceAutomationJobStatus>([
  "FAILED",
  "UNAVAILABLE",
  "CANCELLED",
]);
const CANCELLABLE = new Set<GovernanceAutomationJobStatus>(["PENDING", "RUNNING"]);

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isAbort(error: unknown): boolean {
  return error instanceof Error && error.name === "AbortError";
}

function jobTypeLabel(value: string): string {
  return JOB_TYPES.find((item) => item.value === value)?.label ?? value;
}

function statusStyle(status: string): string {
  switch (status) {
    case "SUCCEEDED":
    case "DELIVERED":
    case "OK":
      return "bg-emerald-500/15 text-emerald-300";
    case "RUNNING":
    case "PENDING":
    case "PARTIAL":
      return "bg-sky-500/15 text-sky-300";
    case "FAILED":
    case "UNAVAILABLE":
      return "bg-rose-500/15 text-rose-300";
    case "CANCELLED":
      return "bg-slate-500/15 text-slate-300";
    default:
      return "bg-amber-500/15 text-amber-300";
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

function QueueCounts({ counts }: { counts: Record<string, number> }) {
  return (
    <div className="flex flex-wrap gap-2">
      {Object.entries(counts).map(([status, count]) => (
        <span
          key={status}
          className="rounded border border-slate-800 bg-slate-950/60 px-2 py-1 text-xs text-slate-300"
        >
          {status}: {count}
        </span>
      ))}
    </div>
  );
}

function ScheduleEditor({
  schedule,
  onSaved,
}: {
  schedule: GovernanceAutomationSchedule;
  onSaved: () => Promise<void>;
}) {
  const [enabled, setEnabled] = useState(schedule.enabled);
  const [interval, setInterval] = useState(String(schedule.interval_minutes));
  const [configText, setConfigText] = useState(JSON.stringify(schedule.config, null, 2));
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    setEnabled(schedule.enabled);
    setInterval(String(schedule.interval_minutes));
    setConfigText(JSON.stringify(schedule.config, null, 2));
  }, [schedule]);

  return (
    <div className="mt-2 rounded-lg border border-slate-800 bg-slate-950/60 p-2">
      <div className="grid gap-2 md:grid-cols-3">
        <label className="text-xs text-slate-300">
          Enabled
          <input
            aria-label={`Enabled ${schedule.job_type}`}
            type="checkbox"
            className="ml-2"
            checked={enabled}
            onChange={(event) => setEnabled(event.target.checked)}
          />
        </label>
        <label className="text-xs text-slate-300">
          Interval minutes
          <input
            aria-label={`Interval minutes ${schedule.job_type}`}
            type="number"
            min={5}
            max={10080}
            className="mt-1 w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-100"
            value={interval}
            onChange={(event) => setInterval(event.target.value)}
          />
        </label>
        <label className="text-xs text-slate-300">
          Reason (required)
          <input
            aria-label={`Schedule reason ${schedule.job_type}`}
            className="mt-1 w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-100"
            value={reason}
            onChange={(event) => setReason(event.target.value)}
          />
        </label>
      </div>
      <label className="mt-2 block text-xs text-slate-300">
        Bounded configuration (JSON)
        <textarea
          aria-label={`Config JSON ${schedule.job_type}`}
          className="mt-1 w-full rounded border border-slate-700 bg-slate-950 p-1 font-mono text-xs text-slate-100"
          rows={3}
          value={configText}
          onChange={(event) => setConfigText(event.target.value)}
        />
      </label>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <button
          type="button"
          className="rounded bg-sky-500 px-2 py-1 text-xs font-semibold text-slate-950 disabled:opacity-50"
          disabled={busy || !reason.trim()}
          onClick={async () => {
            setBusy(true);
            setError(null);
            setMessage(null);
            try {
              const parsed = JSON.parse(configText || "{}") as Record<string, unknown>;
              await updateGovernanceAutomationSchedule(schedule.job_type, {
                enabled,
                interval_minutes: Number(interval),
                config: parsed,
                expected_version: schedule.config_version,
                reason: reason.trim(),
              });
              setReason("");
              setMessage("Schedule saved. Version incremented.");
              await onSaved();
            } catch (exc) {
              setError(messageOf(exc));
            } finally {
              setBusy(false);
            }
          }}
        >
          Save schedule
        </button>
        <span className="text-xs text-slate-500">
          version {schedule.config_version} · updated by {schedule.updated_by ?? "SYSTEM"}
        </span>
      </div>
      {error ? (
        <p className="mt-1 text-xs text-rose-300" role="alert">
          {error}
        </p>
      ) : null}
      {message ? <p className="mt-1 text-xs text-emerald-300">{message}</p> : null}
    </div>
  );
}

export function AutomationWorkspace() {
  const { hasRole } = useAuth();
  const isAdmin = hasRole("ADMIN");
  const canOperate = isAdmin || hasRole("OPERATOR");

  const [status, setStatus] = useState<GovernanceAutomationStatus | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [health, setHealth] = useState<GovernanceAutomationHealth | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [schedules, setSchedules] = useState<GovernanceAutomationSchedule[]>([]);
  const [schedulesError, setSchedulesError] = useState<string | null>(null);
  const [jobs, setJobs] = useState<GovernanceAutomationJob[]>([]);
  const [jobsTotal, setJobsTotal] = useState(0);
  const [jobsError, setJobsError] = useState<string | null>(null);
  const [snapshots, setSnapshots] = useState<GovernanceSnapshot[]>([]);
  const [snapshotsError, setSnapshotsError] = useState<string | null>(null);
  const [reminders, setReminders] = useState<GovernanceReminderActivity | null>(null);
  const [remindersError, setRemindersError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const [jobTypeFilter, setJobTypeFilter] = useState("");
  const [jobStatusFilter, setJobStatusFilter] = useState("");
  const [jobPage, setJobPage] = useState(1);
  const [scheduleJobType, setScheduleJobType] = useState<GovernanceAutomationJobType>(
    "RETENTION_EVALUATION"
  );
  const [runJobType, setRunJobType] = useState<GovernanceAutomationJobType>("RETENTION_EVALUATION");
  const [runReason, setRunReason] = useState("");
  const [runBusy, setRunBusy] = useState(false);
  const [runMessage, setRunMessage] = useState<string | null>(null);
  const [runError, setRunError] = useState<string | null>(null);

  const loadStatus = useCallback(async (signal?: AbortSignal) => {
    try {
      setStatus(await fetchGovernanceAutomationStatus(signal));
      setStatusError(null);
    } catch (exc) {
      if (!isAbort(exc)) setStatusError(messageOf(exc));
    }
  }, []);

  const loadHealth = useCallback(async (signal?: AbortSignal) => {
    try {
      setHealth(await fetchGovernanceAutomationHealth(signal));
      setHealthError(null);
    } catch (exc) {
      if (!isAbort(exc)) setHealthError(messageOf(exc));
    }
  }, []);

  const loadSchedules = useCallback(async (signal?: AbortSignal) => {
    try {
      const body = await fetchGovernanceAutomationSchedules(signal);
      setSchedules(body.items);
      setSchedulesError(null);
    } catch (exc) {
      if (!isAbort(exc)) setSchedulesError(messageOf(exc));
    }
  }, []);

  const loadJobs = useCallback(
    async (signal?: AbortSignal) => {
      try {
        const body = await fetchGovernanceAutomationJobs(
          {
            job_type: jobTypeFilter || undefined,
            status: jobStatusFilter || undefined,
            page: jobPage,
            page_size: 10,
          },
          signal
        );
        setJobs(body.items);
        setJobsTotal(body.total);
        setJobsError(null);
      } catch (exc) {
        if (!isAbort(exc)) setJobsError(messageOf(exc));
      }
    },
    [jobPage, jobStatusFilter, jobTypeFilter]
  );

  const loadSnapshots = useCallback(async (signal?: AbortSignal) => {
    try {
      const body = await fetchGovernanceSnapshots({ page: 1, page_size: 10 }, signal);
      setSnapshots(body.items);
      setSnapshotsError(null);
    } catch (exc) {
      if (!isAbort(exc)) setSnapshotsError(messageOf(exc));
    }
  }, []);

  const loadReminders = useCallback(async (signal?: AbortSignal) => {
    try {
      setReminders(await fetchGovernanceReminderActivity({ page: 1, page_size: 20 }, signal));
      setRemindersError(null);
    } catch (exc) {
      if (!isAbort(exc)) setRemindersError(messageOf(exc));
    }
  }, []);

  const reloadAll = useCallback(async () => {
    await Promise.allSettled([
      loadStatus(),
      loadHealth(),
      loadSchedules(),
      loadJobs(),
      loadSnapshots(),
      loadReminders(),
    ]);
  }, [loadHealth, loadJobs, loadReminders, loadSchedules, loadSnapshots, loadStatus]);

  useEffect(() => {
    const controller = new AbortController();
    void Promise.allSettled([
      loadStatus(controller.signal),
      loadHealth(controller.signal),
      loadSchedules(controller.signal),
      loadSnapshots(controller.signal),
      loadReminders(controller.signal),
    ]).finally(() => setLoading(false));
    return () => controller.abort();
  }, [loadHealth, loadReminders, loadSchedules, loadSnapshots, loadStatus]);

  useEffect(() => {
    const controller = new AbortController();
    void loadJobs(controller.signal);
    return () => controller.abort();
  }, [loadJobs]);

  const selectedSchedule = useMemo(
    () => schedules.find((item) => item.job_type === scheduleJobType) ?? null,
    [scheduleJobType, schedules]
  );

  const pageCount = Math.max(1, Math.ceil(jobsTotal / 10));

  return (
    <div className="space-y-4" aria-label="Governance automation">
      <Card title="Governance automation">
        {statusError ? (
          <DataState state="error" emptyText="" error={statusError} />
        ) : !status ? (
          <DataState state="loading" emptyText="" />
        ) : (
          <div className="space-y-3">
            <div className="grid gap-2 md:grid-cols-3 xl:grid-cols-6">
              <Metric label="Automation" value={status.enabled ? "ENABLED" : "DISABLED"} />
              <Metric label="Scheduler" value={status.scheduler.state} />
              <Metric
                label="Enabled schedules"
                value={`${status.enabled_schedule_count}/${status.schedule_count}`}
              />
              <Metric label="Jobs" value={status.job_count} />
              <Metric label="Snapshots" value={status.snapshot_count} />
              <Metric label="Stale leases" value={status.stale_jobs} />
            </div>
            <QueueCounts counts={status.queue} />
            <p className="text-xs text-slate-400">
              Assurance: {status.assurance}. Scheduled retention evaluation is non-destructive and
              never deletes evidence. No automatic hold release, disposition approval, or export
              generation is implemented.
            </p>
            <ul className="list-disc space-y-1 pl-5 text-xs text-slate-400">
              {status.non_claims.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </div>
        )}
      </Card>

      <Card title="Automation schedules">
        {schedulesError ? (
          <DataState state="error" emptyText="" error={schedulesError} />
        ) : schedules.length === 0 ? (
          <DataState state={loading ? "loading" : "empty"} emptyText="No automation schedules." />
        ) : (
          <div className="space-y-3">
            <p className="text-xs text-slate-400">
              Schedules are UTC epoch-aligned and disabled by default. Each slot creates at most
              one job; missed slots are not replayed.
            </p>
            <div className="max-h-80 overflow-auto">
              <table className="w-full text-left text-xs">
                <thead className="sticky top-0 bg-slate-900 text-slate-400">
                  <tr>
                    <th className="p-1">Job type</th>
                    <th className="p-1">Enabled</th>
                    <th className="p-1">Interval</th>
                    <th className="p-1">Version</th>
                    <th className="p-1">Last slot</th>
                  </tr>
                </thead>
                <tbody>
                  {schedules.map((schedule) => (
                    <tr key={schedule.schedule_id} className="border-t border-slate-800">
                      <td className="p-1 text-slate-200">{schedule.job_type}</td>
                      <td className="p-1">
                        <StatusPill status={schedule.enabled ? "ENABLED" : "DISABLED"} />
                      </td>
                      <td className="p-1">{schedule.interval_minutes} min</td>
                      <td className="p-1">{schedule.config_version}</td>
                      <td className="p-1 text-slate-500">{schedule.last_slot ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {!isAdmin ? (
              <p className="text-xs text-slate-500">
                Schedule changes require an administrator (governance_automation_configure).
              </p>
            ) : (
              <div className="space-y-2">
                <label className="block text-xs text-slate-300">
                  Schedule job type
                  <select
                    aria-label="Schedule job type"
                    className="mt-1 w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-100"
                    value={scheduleJobType}
                    onChange={(event) =>
                      setScheduleJobType(event.target.value as GovernanceAutomationJobType)
                    }
                  >
                    {JOB_TYPES.map((item) => (
                      <option key={item.value} value={item.value}>
                        {item.label}
                      </option>
                    ))}
                  </select>
                </label>
                {selectedSchedule ? (
                  <ScheduleEditor schedule={selectedSchedule} onSaved={reloadAll} />
                ) : null}
              </div>
            )}
          </div>
        )}
      </Card>

      <Card title="Automation job history">
        {jobsError ? (
          <DataState state="error" emptyText="" error={jobsError} />
        ) : (
          <div className="space-y-3">
            <div className="flex flex-wrap items-end gap-2">
              <label className="text-xs text-slate-300">
                Job type filter
                <select
                  aria-label="Job type filter"
                  className="mt-1 block rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-100"
                  value={jobTypeFilter}
                  onChange={(event) => {
                    setJobPage(1);
                    setJobTypeFilter(event.target.value);
                  }}
                >
                  <option value="">All types</option>
                  {JOB_TYPES.map((item) => (
                    <option key={item.value} value={item.value}>
                      {item.label}
                    </option>
                  ))}
                </select>
              </label>
              <label className="text-xs text-slate-300">
                Job status filter
                <select
                  aria-label="Job status filter"
                  className="mt-1 block rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-100"
                  value={jobStatusFilter}
                  onChange={(event) => {
                    setJobPage(1);
                    setJobStatusFilter(event.target.value);
                  }}
                >
                  <option value="">All statuses</option>
                  {JOB_STATUSES.map((item) => (
                    <option key={item} value={item}>
                      {item}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            {canOperate ? (
              <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-2">
                <p className="text-xs font-semibold text-slate-200">Run a job now</p>
                <p className="text-xs text-slate-500">
                  Manual execution is synchronous and idempotent. It never approves a hold,
                  disposition, or export.
                </p>
                <div className="mt-2 grid gap-2 md:grid-cols-3">
                  <label className="text-xs text-slate-300">
                    Run job type
                    <select
                      aria-label="Run job type"
                      className="mt-1 w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-100"
                      value={runJobType}
                      onChange={(event) =>
                        setRunJobType(event.target.value as GovernanceAutomationJobType)
                      }
                    >
                      {JOB_TYPES.map((item) => (
                        <option key={item.value} value={item.value}>
                          {item.label}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="text-xs text-slate-300 md:col-span-2">
                    Run reason
                    <input
                      aria-label="Run reason"
                      className="mt-1 w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-100"
                      value={runReason}
                      onChange={(event) => setRunReason(event.target.value)}
                    />
                  </label>
                </div>
                <button
                  type="button"
                  className="mt-2 rounded bg-sky-500 px-2 py-1 text-xs font-semibold text-slate-950 disabled:opacity-50"
                  disabled={runBusy || runReason.trim().length < 3}
                  onClick={async () => {
                    setRunBusy(true);
                    setRunError(null);
                    setRunMessage(null);
                    try {
                      const result = await runGovernanceAutomationJob({
                        job_type: runJobType,
                        idempotency_key: `ui-${runJobType}-${Date.now()}`,
                        reason: runReason.trim(),
                      });
                      const job = result.job as { status?: string; job_id?: string };
                      setRunMessage(
                        result.replayed
                          ? `Replayed existing job ${job.job_id ?? ""}.`
                          : `Executed job ${job.job_id ?? ""} (${job.status ?? "UNKNOWN"}).`
                      );
                      setRunReason("");
                      await reloadAll();
                    } catch (exc) {
                      setRunError(messageOf(exc));
                    } finally {
                      setRunBusy(false);
                    }
                  }}
                >
                  Run job now
                </button>
                {runError ? (
                  <p className="mt-1 text-xs text-rose-300" role="alert">
                    {runError}
                  </p>
                ) : null}
                {runMessage ? (
                  <p className="mt-1 text-xs text-emerald-300">{runMessage}</p>
                ) : null}
              </div>
            ) : (
              <p className="text-xs text-slate-500">
                Manual runs and retries require an operator or administrator
                (governance_automation_retry).
              </p>
            )}
            {jobs.length === 0 ? (
              <DataState
                state={loading ? "loading" : "empty"}
                emptyText="No automation jobs match the filters."
              />
            ) : (
              <div className="max-h-96 overflow-auto">
                <table className="w-full text-left text-xs">
                  <thead className="sticky top-0 bg-slate-900 text-slate-400">
                    <tr>
                      <th className="p-1">Job</th>
                      <th className="p-1">Status</th>
                      <th className="p-1">Trigger</th>
                      <th className="p-1">Attempt</th>
                      <th className="p-1">Created</th>
                      <th className="p-1">Detail</th>
                    </tr>
                  </thead>
                  <tbody>
                    {jobs.map((job) => (
                      <tr key={job.job_id} className="border-t border-slate-800 align-top">
                        <td className="p-1 text-slate-200">
                          {jobTypeLabel(job.job_type)}
                          <div className="text-slate-500">{job.job_id.slice(0, 8)}</div>
                        </td>
                        <td className="p-1">
                          <StatusPill status={job.status} />
                          {job.cancel_requested && job.status === "RUNNING" ? (
                            <div className="text-amber-300">cancel requested</div>
                          ) : null}
                        </td>
                        <td className="p-1">{job.trigger}</td>
                        <td className="p-1">
                          {job.attempt}/{job.max_attempts}
                        </td>
                        <td className="p-1 text-slate-500">{job.created_at ?? "—"}</td>
                        <td className="p-1">
                          {job.error_code ? (
                            <div className="text-rose-300">
                              {job.error_code}: {job.error_message ?? ""}
                            </div>
                          ) : null}
                          {canOperate && RETRYABLE.has(job.status) ? (
                            <ConfirmAction
                              label="Retry job"
                              confirmLabel="Confirm retry"
                              reasonLabel="Retry reason"
                              description="Retry creates one bounded child job linked to this job."
                              onConfirm={async (reason) => {
                                await retryGovernanceAutomationJob(job.job_id, { reason });
                                await reloadAll();
                              }}
                            />
                          ) : null}
                          {canOperate && CANCELLABLE.has(job.status) ? (
                            <ConfirmAction
                              label="Cancel job"
                              confirmLabel="Confirm cancel"
                              reasonLabel="Cancel reason"
                              description="Pending jobs cancel immediately; running jobs observe cooperative cancellation."
                              onConfirm={async (reason) => {
                                await cancelGovernanceAutomationJob(job.job_id, { reason });
                                await reloadAll();
                              }}
                            />
                          ) : null}
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
                disabled={jobPage <= 1}
                onClick={() => setJobPage((page) => Math.max(1, page - 1))}
              >
                Previous jobs
              </button>
              <span>
                Page {jobPage} of {pageCount} · {jobsTotal} total
              </span>
              <button
                type="button"
                className="rounded border border-slate-700 px-2 py-1 disabled:opacity-50"
                disabled={jobPage >= pageCount}
                onClick={() => setJobPage((page) => page + 1)}
              >
                Next jobs
              </button>
            </div>
          </div>
        )}
      </Card>

      <Card title="Reminder activity">
        {remindersError ? (
          <DataState state="error" emptyText="" error={remindersError} />
        ) : !reminders ? (
          <DataState state="loading" emptyText="" />
        ) : (
          <div className="space-y-3">
            <div className="grid gap-2 md:grid-cols-5">
              <Metric label="Notifier" value={reminders.notifier_enabled ? "ENABLED" : "DISABLED"} />
              <Metric label="Pending" value={reminders.delivery_states.PENDING ?? 0} />
              <Metric label="Delivered" value={reminders.delivery_states.DELIVERED ?? 0} />
              <Metric label="Failed" value={reminders.delivery_states.FAILED ?? 0} />
              <Metric label="Muted" value={reminders.muted} />
            </div>
            <p className="text-xs text-slate-400">
              PENDING means queued locally without a successful delivery attempt. It is not a
              claim that an external channel delivered the reminder. Reminders require an enabled
              V15 GOVERNANCE alert rule and GOVERNANCE_ALERTING_ENABLED.
            </p>
            {reminders.items.length === 0 ? (
              <DataState state="empty" emptyText="No governance reminders have been queued." />
            ) : (
              <div className="max-h-80 overflow-auto">
                <table className="w-full text-left text-xs">
                  <thead className="sticky top-0 bg-slate-900 text-slate-400">
                    <tr>
                      <th className="p-1">Event</th>
                      <th className="p-1">Target</th>
                      <th className="p-1">Window</th>
                      <th className="p-1">Delivery</th>
                      <th className="p-1">Created</th>
                    </tr>
                  </thead>
                  <tbody>
                    {reminders.items.map((item) => (
                      <tr key={item.notification_id} className="border-t border-slate-800">
                        <td className="p-1 text-slate-200">{item.event_type}</td>
                        <td className="p-1">
                          {item.target_type ?? "—"}
                          <div className="text-slate-500">{item.target_id ?? ""}</div>
                        </td>
                        <td className="p-1">{item.reminder_window ?? "—"}</td>
                        <td className="p-1">
                          <StatusPill status={item.delivery_state} />
                          {item.muted ? <div className="text-amber-300">muted</div> : null}
                        </td>
                        <td className="p-1 text-slate-500">{item.created_at ?? "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </Card>

      <Card title="Compliance snapshots">
        {snapshotsError ? (
          <DataState state="error" emptyText="" error={snapshotsError} />
        ) : (
          <div className="space-y-3">
            <p className="text-xs text-slate-400">
              Snapshots are local SUMMARY records with a self-digest. They are not regulatory
              certification and are not externally anchored.
            </p>
            {canOperate ? (
              <ConfirmAction
                label="Generate snapshot"
                confirmLabel="Confirm snapshot"
                reasonLabel="Snapshot reason"
                description="Generates one stored SUMMARY snapshot; no export is generated."
                onConfirm={async (reason) => {
                  await generateGovernanceSnapshot({
                    idempotency_key: `ui-snapshot-${Date.now()}`,
                    reason,
                  });
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
              <DataState state={loading ? "loading" : "empty"} emptyText="No snapshots stored." />
            ) : (
              <div className="max-h-80 overflow-auto">
                <table className="w-full text-left text-xs">
                  <thead className="sticky top-0 bg-slate-900 text-slate-400">
                    <tr>
                      <th className="p-1">Type</th>
                      <th className="p-1">As of</th>
                      <th className="p-1">Rows</th>
                      <th className="p-1">Digest</th>
                      <th className="p-1">CSV</th>
                    </tr>
                  </thead>
                  <tbody>
                    {snapshots.map((snapshot) => (
                      <tr key={snapshot.snapshot_id} className="border-t border-slate-800">
                        <td className="p-1 text-slate-200">
                          {snapshot.snapshot_type}
                          <div className="text-slate-500">{snapshot.trigger}</div>
                        </td>
                        <td className="p-1">{snapshot.as_of ?? "—"}</td>
                        <td className="p-1">{snapshot.row_count}</td>
                        <td className="p-1">
                          {snapshot.digest_valid ? "valid" : "INVALID"}
                          <div className="break-all text-slate-500">
                            {snapshot.payload_digest.slice(0, 16)}…
                          </div>
                        </td>
                        <td className="p-1">
                          <a
                            className="text-sky-300 underline"
                            href={governanceSnapshotCsvUrl(snapshot.snapshot_id)}
                            aria-label={`Snapshot CSV ${snapshot.snapshot_id}`}
                          >
                            Snapshot CSV
                          </a>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </Card>

      <Card title="Automation health">
        {healthError ? (
          <DataState state="error" emptyText="" error={healthError} />
        ) : !health ? (
          <DataState state="loading" emptyText="" />
        ) : (
          <div className="space-y-2 text-xs text-slate-300">
            <div className="flex flex-wrap items-center gap-2">
              <span>Overall:</span>
              <StatusPill status={health.overall_status} />
              <span>Governance audit:</span>
              <StatusPill status={health.governance_audit.outcome} />
              <span>Integrity:</span>
              <StatusPill status={health.integrity.status} />
            </div>
            <p>
              Scheduler: {health.scheduler.state} · running:{" "}
              {health.scheduler.running ? "yes" : "no"} · stale jobs: {health.stale_jobs} ·
              generated: {health.generated_at ?? "—"}
            </p>
            <p className="text-slate-500">
              Integrity status is OK only when the latest V33 audit status is PASS. FAIL, PARTIAL,
              UNAVAILABLE, NOT_RUN, and RUNNING are never treated as a pass.
            </p>
            <QueueCounts counts={health.queue} />
            <ul className="list-disc space-y-1 pl-5 text-slate-400">
              {health.non_claims.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </div>
        )}
      </Card>
    </div>
  );
}

export default AutomationWorkspace;
