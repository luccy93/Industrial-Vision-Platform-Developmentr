"use client";

import { useCallback, useEffect, useState } from "react";
import { useAuth } from "../auth/AuthProvider";
import { DataState } from "../operations/primitives";
import { Card } from "../ui/Card";
import {
  acknowledgeGovernanceWorkflowEscalation,
  addGovernanceWorkflowReference,
  assignGovernanceWorkflow,
  assignGovernanceWorkflowTask,
  createGovernanceWorkflow,
  createGovernanceWorkflowEscalation,
  createGovernanceWorkflowTemplate,
  disableGovernanceWorkflowTemplate,
  fetchGovernanceWorkflow,
  fetchGovernanceWorkflowOwnership,
  fetchGovernanceWorkflowStatus,
  fetchGovernanceWorkflowTemplates,
  fetchGovernanceWorkflows,
  resolveGovernanceWorkflowEscalation,
  transitionGovernanceWorkflow,
  transitionGovernanceWorkflowTask,
} from "../../lib/governance/client";
import type {
  GovernanceWorkflowDetail,
  GovernanceWorkflowEscalation,
  GovernanceWorkflowEscalationType,
  GovernanceWorkflowListResponse,
  GovernanceWorkflowOwnershipResponse,
  GovernanceWorkflowPriority,
  GovernanceWorkflowReferenceDomain,
  GovernanceWorkflowStatus,
  GovernanceWorkflowStatusResponse,
  GovernanceWorkflowTaskStatus,
  GovernanceWorkflowTemplate,
  GovernanceWorkflowTemplateListResponse,
} from "../../types";

const WORKFLOW_STYLE: Record<string, string> = {
  DRAFT: "bg-slate-500/15 text-slate-300",
  READY: "bg-sky-500/15 text-sky-300",
  IN_PROGRESS: "bg-indigo-500/15 text-indigo-300",
  BLOCKED: "bg-amber-500/15 text-amber-300",
  UNDER_REVIEW: "bg-violet-500/15 text-violet-300",
  COMPLETED: "bg-emerald-500/15 text-emerald-300",
  CANCELLED: "bg-slate-500/15 text-slate-400",
};

const TASK_STYLE: Record<string, string> = {
  PENDING: "bg-slate-500/15 text-slate-300",
  READY: "bg-sky-500/15 text-sky-300",
  IN_PROGRESS: "bg-indigo-500/15 text-indigo-300",
  BLOCKED: "bg-amber-500/15 text-amber-300",
  COMPLETED: "bg-emerald-500/15 text-emerald-300",
  CANCELLED: "bg-slate-500/15 text-slate-400",
};

const SLA_STYLE: Record<string, string> = {
  ON_TRACK: "bg-emerald-500/15 text-emerald-300",
  AT_RISK: "bg-amber-500/15 text-amber-300",
  OVERDUE: "bg-rose-500/15 text-rose-300",
  PAUSED: "bg-orange-500/15 text-orange-300",
  UNAVAILABLE: "bg-slate-500/15 text-slate-400",
  NOT_APPLICABLE: "bg-slate-500/15 text-slate-400",
  UNKNOWN: "bg-slate-500/15 text-slate-400",
};

const ESCALATION_STYLE: Record<string, string> = {
  OPEN: "bg-rose-500/15 text-rose-300",
  ACKNOWLEDGED: "bg-amber-500/15 text-amber-300",
  RESOLVED: "bg-emerald-500/15 text-emerald-300",
};

const WORKFLOW_STATUSES: GovernanceWorkflowStatus[] = [
  "DRAFT",
  "READY",
  "IN_PROGRESS",
  "BLOCKED",
  "UNDER_REVIEW",
  "COMPLETED",
  "CANCELLED",
];

const TASK_TRANSITIONS: Record<GovernanceWorkflowTaskStatus, GovernanceWorkflowTaskStatus[]> = {
  PENDING: ["READY", "CANCELLED"],
  READY: ["IN_PROGRESS", "CANCELLED"],
  IN_PROGRESS: ["BLOCKED", "COMPLETED", "CANCELLED"],
  BLOCKED: ["IN_PROGRESS", "CANCELLED"],
  COMPLETED: [],
  CANCELLED: [],
};

const REFERENCE_DOMAINS: GovernanceWorkflowReferenceDomain[] = [
  "FORENSIC_CASE",
  "FORENSIC_FINDING",
  "RETENTION_REVIEW",
  "LEGAL_HOLD",
  "DISPOSITION",
  "EXPORT_APPROVAL",
  "AUTOMATION_JOB",
  "RECOMMENDATION",
  "EXECUTIVE_ACTION",
];

const ESCALATION_TYPES: GovernanceWorkflowEscalationType[] = [
  "SLA_OVERDUE",
  "SLA_AT_RISK",
  "BLOCKED",
  "UNASSIGNED",
  "MANUAL",
];

const DEFAULT_TASKS = JSON.stringify(
  [
    { task_key: "intake", title: "Intake", depends_on: [] },
    { task_key: "review", title: "Review", depends_on: ["intake"] },
  ],
  null,
  2
);

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

function formatTime(value: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function parseTasks(text: string): Array<Record<string, unknown>> {
  const parsed: unknown = JSON.parse(text);
  if (!Array.isArray(parsed)) throw new Error("tasks must be a JSON array");
  return parsed.map((item, index) => {
    if (typeof item !== "object" || item === null || Array.isArray(item)) {
      throw new Error(`tasks[${index}] must be an object`);
    }
    return item as Record<string, unknown>;
  });
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

function SlaLine({ state, reason }: { state?: string; reason?: string }) {
  const normalized = state ?? "UNKNOWN";
  return (
    <span className="inline-flex flex-wrap items-center gap-2">
      <StatusPill status={normalized} styles={SLA_STYLE} />
      {reason ? <span className="text-xs text-slate-400">{reason}</span> : null}
    </span>
  );
}

export function WorkflowWorkspace() {
  const { hasRole } = useAuth();
  const isAdmin = hasRole("ADMIN");
  const canOperate = isAdmin || hasRole("OPERATOR");

  const [status, setStatus] = useState<GovernanceWorkflowStatusResponse | null>(null);
  const [ownership, setOwnership] = useState<GovernanceWorkflowOwnershipResponse | null>(null);
  const [templates, setTemplates] = useState<GovernanceWorkflowTemplateListResponse | null>(null);
  const [workflows, setWorkflows] = useState<GovernanceWorkflowListResponse | null>(null);
  const [detail, setDetail] = useState<GovernanceWorkflowDetail | null>(null);

  const [statusError, setStatusError] = useState<string | null>(null);
  const [ownershipError, setOwnershipError] = useState<string | null>(null);
  const [templateError, setTemplateError] = useState<string | null>(null);
  const [workflowError, setWorkflowError] = useState<string | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const [statusFilter, setStatusFilter] = useState<GovernanceWorkflowStatus | "">("");
  const [page, setPage] = useState(1);

  const [templateKey, setTemplateKey] = useState("");
  const [templateName, setTemplateName] = useState("");
  const [templateTasks, setTemplateTasks] = useState(DEFAULT_TASKS);
  const [templateReason, setTemplateReason] = useState("");

  const [createTemplateId, setCreateTemplateId] = useState("");
  const [createTitle, setCreateTitle] = useState("");
  const [createPriority, setCreatePriority] = useState<GovernanceWorkflowPriority>("MEDIUM");
  const [createDueAt, setCreateDueAt] = useState("");
  const [createOwnerType, setCreateOwnerType] = useState<"USER" | "ROLE">("ROLE");
  const [createOwnerId, setCreateOwnerId] = useState("");
  const [createReason, setCreateReason] = useState("");

  const [transitionTarget, setTransitionTarget] = useState<GovernanceWorkflowStatus | "">("");
  const [transitionReason, setTransitionReason] = useState("");
  const [outcomeSummary, setOutcomeSummary] = useState("");
  const [assignOwnerType, setAssignOwnerType] = useState<"USER" | "ROLE">("USER");
  const [assignOwnerId, setAssignOwnerId] = useState("");
  const [assignReason, setAssignReason] = useState("");

  const [selectedTaskId, setSelectedTaskId] = useState("");
  const [taskTarget, setTaskTarget] = useState<GovernanceWorkflowTaskStatus | "">("");
  const [taskReason, setTaskReason] = useState("");
  const [taskOutcome, setTaskOutcome] = useState("");
  const [taskOwnerType, setTaskOwnerType] = useState<"USER" | "ROLE">("USER");
  const [taskOwnerId, setTaskOwnerId] = useState("");
  const [taskAssignReason, setTaskAssignReason] = useState("");

  const [referenceDomain, setReferenceDomain] =
    useState<GovernanceWorkflowReferenceDomain>("FORENSIC_CASE");
  const [referenceSourceId, setReferenceSourceId] = useState("");
  const [referenceReason, setReferenceReason] = useState("");

  const [escalationType, setEscalationType] =
    useState<GovernanceWorkflowEscalationType>("MANUAL");
  const [escalationSeverity, setEscalationSeverity] = useState("MEDIUM");
  const [escalationReason, setEscalationReason] = useState("");
  const [selectedEscalationId, setSelectedEscalationId] = useState("");
  const [escalationActionReason, setEscalationActionReason] = useState("");
  const [escalationResolution, setEscalationResolution] = useState("");

  const loadOverview = useCallback(async (signal?: AbortSignal) => {
    setLoading(true);
    const [statusResult, ownershipResult, templateResult, workflowResult] = await Promise.allSettled([
      fetchGovernanceWorkflowStatus(signal),
      fetchGovernanceWorkflowOwnership(signal),
      fetchGovernanceWorkflowTemplates({ page: 1, page_size: 50 }, signal),
      fetchGovernanceWorkflows(
        {
          status: statusFilter || undefined,
          page,
          page_size: 10,
        },
        signal
      ),
    ]);
    if (signal?.aborted) return;
    if (statusResult.status === "fulfilled") {
      setStatus(statusResult.value);
      setStatusError(null);
    } else if (!isAbort(statusResult.reason)) {
      setStatusError(messageOf(statusResult.reason));
    }
    if (ownershipResult.status === "fulfilled") {
      setOwnership(ownershipResult.value);
      setOwnershipError(null);
    } else if (!isAbort(ownershipResult.reason)) {
      setOwnershipError(messageOf(ownershipResult.reason));
    }
    if (templateResult.status === "fulfilled") {
      setTemplates(templateResult.value);
      setTemplateError(null);
      const firstActive = templateResult.value.items.find((item) => item.status === "ACTIVE");
      if (firstActive) {
        setCreateTemplateId((current) => current || firstActive.template_id);
      }
    } else if (!isAbort(templateResult.reason)) {
      setTemplateError(messageOf(templateResult.reason));
    }
    if (workflowResult.status === "fulfilled") {
      setWorkflows(workflowResult.value);
      setWorkflowError(null);
    } else if (!isAbort(workflowResult.reason)) {
      setWorkflowError(messageOf(workflowResult.reason));
    }
    setLoading(false);
  }, [page, statusFilter]);

  useEffect(() => {
    const controller = new AbortController();
    void loadOverview(controller.signal);
    return () => controller.abort();
  }, [loadOverview]);

  const loadDetail = useCallback(async (workflowId: string) => {
    try {
      const loaded = await fetchGovernanceWorkflow(workflowId);
      setDetail(loaded);
      setDetailError(null);
      setTransitionTarget("");
      setSelectedTaskId("");
      setTaskTarget("");
      setSelectedEscalationId("");
    } catch (exc) {
      setDetailError(messageOf(exc));
    }
  }, []);

  async function refreshAfterMutation(workflowId?: string) {
    await loadOverview();
    if (workflowId && canOperate) await loadDetail(workflowId);
  }

  async function onCreateTemplate() {
    setMessage(null);
    try {
      const tasks = parseTasks(templateTasks);
      const response = await createGovernanceWorkflowTemplate({
        template_key: templateKey.trim().toUpperCase(),
        name: templateName.trim(),
        tasks,
        reason: templateReason.trim(),
        idempotency_key: newIdempotencyKey("workflow-template"),
      });
      setMessage(
        `Template ${response.template.template_key} v${response.template.version} ${
          response.replayed ? "replayed" : "created"
        }.`
      );
      setTemplateKey("");
      setTemplateName("");
      setTemplateReason("");
      await loadOverview();
    } catch (exc) {
      setMessage(messageOf(exc));
    }
  }

  async function onDisableTemplate(template: GovernanceWorkflowTemplate) {
    setMessage(null);
    try {
      const response = await disableGovernanceWorkflowTemplate(template.template_id, {
        reason: templateReason.trim() || "Retire this workflow template from operations.",
      });
      setMessage(
        `Template ${response.template.template_key} v${response.template.version} ${
          response.changed ? "disabled" : "already disabled"
        }.`
      );
      await loadOverview();
    } catch (exc) {
      setMessage(messageOf(exc));
    }
  }

  async function onCreateWorkflow() {
    setMessage(null);
    try {
      const response = await createGovernanceWorkflow({
        template_id: createTemplateId || undefined,
        title: createTitle.trim(),
        priority: createPriority,
        due_at: createDueAt ? new Date(createDueAt).toISOString() : null,
        owner_type: createOwnerId.trim() ? createOwnerType : null,
        owner_id: createOwnerId.trim() || null,
        reason: createReason.trim(),
        idempotency_key: newIdempotencyKey("workflow"),
      });
      setMessage(
        `Workflow ${response.workflow.workflow_id} ${
          response.replayed ? "replayed" : "created"
        } in ${response.workflow.status}.`
      );
      setCreateTitle("");
      setCreateDueAt("");
      setCreateOwnerId("");
      setCreateReason("");
      await refreshAfterMutation(response.workflow.workflow_id);
    } catch (exc) {
      setMessage(messageOf(exc));
    }
  }

  async function onTransitionWorkflow() {
    if (!detail || !transitionTarget) return;
    setMessage(null);
    try {
      const response = await transitionGovernanceWorkflow(detail.workflow.workflow_id, {
        target_status: transitionTarget,
        expected_version: detail.workflow.version,
        reason: transitionReason.trim() || undefined,
        block_reason:
          transitionTarget === "BLOCKED" ? transitionReason.trim() || undefined : undefined,
        cancel_reason:
          transitionTarget === "CANCELLED" ? transitionReason.trim() || undefined : undefined,
        outcome_summary:
          transitionTarget === "COMPLETED" ? outcomeSummary.trim() || undefined : undefined,
      });
      setMessage(`Workflow transitioned to ${response.workflow.status}.`);
      setTransitionTarget("");
      setTransitionReason("");
      setOutcomeSummary("");
      await refreshAfterMutation(response.workflow.workflow_id);
    } catch (exc) {
      setMessage(messageOf(exc));
    }
  }

  async function onAssignWorkflow() {
    if (!detail) return;
    setMessage(null);
    try {
      const response = await assignGovernanceWorkflow(detail.workflow.workflow_id, {
        owner_type: assignOwnerType,
        owner_id: assignOwnerId.trim(),
        expected_version: detail.workflow.version,
        reason: assignReason.trim(),
      });
      setMessage(`Workflow owner is ${response.workflow.owner_type}:${response.workflow.owner_id}.`);
      setAssignOwnerId("");
      setAssignReason("");
      await refreshAfterMutation(response.workflow.workflow_id);
    } catch (exc) {
      setMessage(messageOf(exc));
    }
  }

  async function onTransitionTask() {
    if (!detail || !selectedTaskId || !taskTarget) return;
    const task = detail.tasks.find((item) => item.task_id === selectedTaskId);
    if (!task) return;
    setMessage(null);
    try {
      const response = await transitionGovernanceWorkflowTask(
        detail.workflow.workflow_id,
        task.task_id,
        {
          target_status: taskTarget,
          expected_version: task.version,
          reason: taskReason.trim() || undefined,
          block_reason: taskTarget === "BLOCKED" ? taskReason.trim() || undefined : undefined,
          cancel_reason: taskTarget === "CANCELLED" ? taskReason.trim() || undefined : undefined,
          outcome_summary: taskTarget === "COMPLETED" ? taskOutcome.trim() || undefined : undefined,
        }
      );
      setMessage(`Task ${response.task.task_key} transitioned to ${response.task.status}.`);
      setTaskTarget("");
      setTaskReason("");
      setTaskOutcome("");
      await refreshAfterMutation(detail.workflow.workflow_id);
    } catch (exc) {
      setMessage(messageOf(exc));
    }
  }

  async function onAssignTask() {
    if (!detail || !selectedTaskId) return;
    const task = detail.tasks.find((item) => item.task_id === selectedTaskId);
    if (!task) return;
    setMessage(null);
    try {
      const response = await assignGovernanceWorkflowTask(
        detail.workflow.workflow_id,
        task.task_id,
        {
          owner_type: taskOwnerType,
          owner_id: taskOwnerId.trim(),
          expected_version: task.version,
          reason: taskAssignReason.trim(),
        }
      );
      setMessage(`Task ${response.task.task_key} owner is ${response.task.owner_type}:${response.task.owner_id}.`);
      setTaskOwnerId("");
      setTaskAssignReason("");
      await refreshAfterMutation(detail.workflow.workflow_id);
    } catch (exc) {
      setMessage(messageOf(exc));
    }
  }

  async function onAddReference() {
    if (!detail) return;
    setMessage(null);
    try {
      const response = await addGovernanceWorkflowReference(detail.workflow.workflow_id, {
        domain: referenceDomain,
        source_id: referenceSourceId.trim(),
        reason: referenceReason.trim(),
      });
      setMessage(
        `Reference ${response.reference?.reference_key ?? referenceSourceId} ${
          response.replayed ? "replayed" : "attached"
        }; the source was not modified.`
      );
      setReferenceSourceId("");
      setReferenceReason("");
      await refreshAfterMutation(detail.workflow.workflow_id);
    } catch (exc) {
      setMessage(messageOf(exc));
    }
  }

  async function onCreateEscalation() {
    if (!detail) return;
    setMessage(null);
    try {
      const response = await createGovernanceWorkflowEscalation(detail.workflow.workflow_id, {
        escalation_type: escalationType,
        severity: escalationSeverity,
        reason: escalationReason.trim(),
        idempotency_key: newIdempotencyKey("workflow-escalation"),
      });
      setMessage(
        `Escalation ${response.escalation.escalation_id} ${
          response.replayed ? "replayed" : "created"
        } in ${response.escalation.status}.`
      );
      setEscalationReason("");
      await refreshAfterMutation(detail.workflow.workflow_id);
    } catch (exc) {
      setMessage(messageOf(exc));
    }
  }

  async function onAcknowledgeEscalation(escalation: GovernanceWorkflowEscalation) {
    setMessage(null);
    try {
      const response = await acknowledgeGovernanceWorkflowEscalation(escalation.escalation_id, {
        expected_version: escalation.version,
        reason: escalationActionReason.trim(),
      });
      setMessage(`Escalation ${response.escalation.escalation_id} acknowledged.`);
      setEscalationActionReason("");
      if (detail) await refreshAfterMutation(detail.workflow.workflow_id);
    } catch (exc) {
      setMessage(messageOf(exc));
    }
  }

  async function onResolveEscalation(escalation: GovernanceWorkflowEscalation) {
    setMessage(null);
    try {
      const response = await resolveGovernanceWorkflowEscalation(escalation.escalation_id, {
        expected_version: escalation.version,
        reason: escalationActionReason.trim(),
        resolution: escalationResolution.trim(),
      });
      setMessage(`Escalation ${response.escalation.escalation_id} resolved.`);
      setEscalationActionReason("");
      setEscalationResolution("");
      if (detail) await refreshAfterMutation(detail.workflow.workflow_id);
    } catch (exc) {
      setMessage(messageOf(exc));
    }
  }

  const workflowState: "loading" | "ready" | "empty" | "error" = loading
    ? "loading"
    : workflowError
      ? "error"
      : workflows && workflows.items.length > 0
        ? "ready"
        : "empty";

  const activeTemplates = templates?.items.filter((item) => item.status === "ACTIVE") ?? [];
  const selectedTask = detail?.tasks.find((item) => item.task_id === selectedTaskId) ?? null;
  const selectedEscalation =
    detail?.escalations.find((item) => item.escalation_id === selectedEscalationId) ?? null;
  const allowedWorkflowTargets = detail
    ? detail.lifecycle.transitions[detail.workflow.status] ?? []
    : [];

  return (
    <div className="space-y-4">
      <Card title="Enterprise governance workflow orchestration">
        <p className="text-xs text-slate-400">
          Versioned templates, persistent workflows, dependency-aware tasks, ownership history,
          read-only cross-domain references, deterministic SLA indicators, reasoned escalations, and
          append-only events. V39 coordinates review work only: it never approves or releases a hold,
          never decides a disposition, never modifies evidence, never approves or generates an
          export, never resolves a recommendation, and never completes an executive action. No
          scheduler is started and no record is deleted.
        </p>
        {status ? (
          <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
            <Metric label="Workflows" value={status.workflow_total} />
            <Metric label="Tasks" value={status.task_total} />
            <Metric label="Open escalations" value={status.escalation_total} />
            <Metric
              label="Overdue"
              value={`${status.overdue.workflows} workflows / ${status.overdue.tasks} tasks`}
              note={`Unassigned: ${status.unassigned.workflows} workflows / ${status.unassigned.tasks} tasks`}
            />
          </div>
        ) : (
          <div className="mt-3">
            <DataState state={statusError ? "error" : "loading"} emptyText="No status." error={statusError} />
          </div>
        )}
        {status ? (
          <p className="mt-3 text-xs text-slate-500">
            scheduled_workflows={String(status.scheduled_workflows)} ·{" "}
            {status.scheduled_workflows_note} · SLA sample {status.sla_sample_size}/
            {status.sla_sample_limit}
          </p>
        ) : null}
        {status?.non_claims?.length ? (
          <p className="mt-2 text-xs text-slate-500">{status.non_claims[0]}</p>
        ) : null}
        {message ? (
          <p className="mt-2 text-xs text-sky-300" role="status">
            {message}
          </p>
        ) : null}
      </Card>

      <Card title="Ownership and SLA overview">
        <DataState
          state={ownershipError ? "error" : ownership ? "ready" : "loading"}
          emptyText="No ownership report."
          error={ownershipError}
        >
          {ownership ? (
            <div className="space-y-2 text-xs">
              <p>
                Unassigned: {ownership.unassigned.workflows} workflows, {ownership.unassigned.tasks}{" "}
                tasks. Overdue: {ownership.overdue.workflows} workflows, {ownership.overdue.tasks}{" "}
                tasks.
              </p>
              <p className="text-slate-500">
                Workflow states:{" "}
                {Object.entries(ownership.workflow_counts)
                  .map(([key, value]) => `${key}=${value}`)
                  .join(" · ")}
              </p>
              <p className="text-slate-500">
                Task states:{" "}
                {Object.entries(ownership.task_counts)
                  .map(([key, value]) => `${key}=${value}`)
                  .join(" · ")}
              </p>
              <p className="text-slate-500">
                A missing due date is never treated as zero time; blocked items are paused and
                cancelled items are not applicable.
              </p>
            </div>
          ) : null}
        </DataState>
      </Card>

      <Card title="Versioned workflow templates">
        <DataState
          state={templateError ? "error" : templates ? "ready" : "loading"}
          emptyText="No workflow templates."
          error={templateError}
        >
          {templates ? (
            <div className="space-y-3">
              {templates.items.length === 0 ? (
                <p className="text-xs text-slate-400">
                  No templates yet. A template version is immutable once stored.
                </p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="text-slate-400">
                      <tr>
                        <th className="py-1 pr-3">Key</th>
                        <th className="py-1 pr-3">Version</th>
                        <th className="py-1 pr-3">Status</th>
                        <th className="py-1 pr-3">Tasks</th>
                        <th className="py-1 pr-3">Digest</th>
                        {isAdmin ? <th className="py-1">Action</th> : null}
                      </tr>
                    </thead>
                    <tbody>
                      {templates.items.map((template) => (
                        <tr key={template.template_id} className="border-t border-slate-800">
                          <td className="py-1 pr-3">{template.template_key}</td>
                          <td className="py-1 pr-3">v{template.version}</td>
                          <td className="py-1 pr-3">
                            <StatusPill status={template.status} styles={WORKFLOW_STYLE} />
                          </td>
                          <td className="py-1 pr-3">
                            {template.task_count} tasks / {template.dependency_count} dependencies
                          </td>
                          <td className="py-1 pr-3 font-mono text-[10px] text-slate-500">
                            {template.definition_digest.slice(0, 12)}…
                          </td>
                          {isAdmin ? (
                            <td className="py-1">
                              {template.status === "ACTIVE" ? (
                                <button
                                  type="button"
                                  className="rounded border border-amber-700 px-2 py-0.5 text-amber-300"
                                  onClick={() => void onDisableTemplate(template)}
                                >
                                  Disable
                                </button>
                              ) : (
                                <span className="text-slate-500">terminal</span>
                              )}
                            </td>
                          ) : null}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              {isAdmin ? (
                <div className="grid gap-2 rounded-lg border border-slate-800 p-3 sm:grid-cols-2">
                  <label className="text-xs">
                    Template key
                    <input
                      aria-label="Template key"
                      className="mt-1 w-full rounded bg-slate-950 px-2 py-1"
                      value={templateKey}
                      onChange={(event) => setTemplateKey(event.target.value)}
                    />
                  </label>
                  <label className="text-xs">
                    Template name
                    <input
                      aria-label="Template name"
                      className="mt-1 w-full rounded bg-slate-950 px-2 py-1"
                      value={templateName}
                      onChange={(event) => setTemplateName(event.target.value)}
                    />
                  </label>
                  <label className="text-xs sm:col-span-2">
                    Tasks (JSON array; dependencies are immutable after instantiation)
                    <textarea
                      aria-label="Template tasks"
                      className="mt-1 h-32 w-full rounded bg-slate-950 px-2 py-1 font-mono text-[11px]"
                      value={templateTasks}
                      onChange={(event) => setTemplateTasks(event.target.value)}
                    />
                  </label>
                  <label className="text-xs sm:col-span-2">
                    Template reason
                    <input
                      aria-label="Template reason"
                      className="mt-1 w-full rounded bg-slate-950 px-2 py-1"
                      value={templateReason}
                      onChange={(event) => setTemplateReason(event.target.value)}
                    />
                  </label>
                  <div className="sm:col-span-2">
                    <button
                      type="button"
                      className="rounded bg-sky-600 px-3 py-1 text-xs font-medium"
                      onClick={() => void onCreateTemplate()}
                    >
                      Create template
                    </button>
                  </div>
                </div>
              ) : (
                <p className="text-xs text-slate-500">
                  Template creation and retirement require the ADMIN role.
                </p>
              )}
            </div>
          ) : null}
        </DataState>
      </Card>

      {canOperate ? (
        <Card title="Instantiate a workflow from a pinned template version">
          <div className="grid gap-2 sm:grid-cols-2">
            <label className="text-xs">
              Template
              <select
                aria-label="Workflow template"
                className="mt-1 w-full rounded bg-slate-950 px-2 py-1"
                value={createTemplateId}
                onChange={(event) => setCreateTemplateId(event.target.value)}
              >
                <option value="">Select an active template</option>
                {activeTemplates.map((template) => (
                  <option key={template.template_id} value={template.template_id}>
                    {template.template_key} v{template.version}
                  </option>
                ))}
              </select>
            </label>
            <label className="text-xs">
              Title
              <input
                aria-label="Workflow title"
                className="mt-1 w-full rounded bg-slate-950 px-2 py-1"
                value={createTitle}
                onChange={(event) => setCreateTitle(event.target.value)}
              />
            </label>
            <label className="text-xs">
              Priority
              <select
                aria-label="Workflow priority"
                className="mt-1 w-full rounded bg-slate-950 px-2 py-1"
                value={createPriority}
                onChange={(event) =>
                  setCreatePriority(event.target.value as GovernanceWorkflowPriority)
                }
              >
                {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
            </label>
            <label className="text-xs">
              Due date
              <input
                type="datetime-local"
                aria-label="Workflow due date"
                className="mt-1 w-full rounded bg-slate-950 px-2 py-1"
                value={createDueAt}
                onChange={(event) => setCreateDueAt(event.target.value)}
              />
            </label>
            <label className="text-xs">
              Owner type
              <select
                aria-label="Workflow owner type"
                className="mt-1 w-full rounded bg-slate-950 px-2 py-1"
                value={createOwnerType}
                onChange={(event) => setCreateOwnerType(event.target.value as "USER" | "ROLE")}
              >
                <option value="ROLE">ROLE</option>
                <option value="USER">USER</option>
              </select>
            </label>
            <label className="text-xs">
              Owner (optional)
              <input
                aria-label="Workflow owner"
                className="mt-1 w-full rounded bg-slate-950 px-2 py-1"
                value={createOwnerId}
                onChange={(event) => setCreateOwnerId(event.target.value)}
              />
            </label>
            <label className="text-xs sm:col-span-2">
              Creation reason
              <input
                aria-label="Workflow creation reason"
                className="mt-1 w-full rounded bg-slate-950 px-2 py-1"
                value={createReason}
                onChange={(event) => setCreateReason(event.target.value)}
              />
            </label>
            <div className="sm:col-span-2">
              <button
                type="button"
                className="rounded bg-sky-600 px-3 py-1 text-xs font-medium"
                onClick={() => void onCreateWorkflow()}
              >
                Create workflow
              </button>
            </div>
          </div>
        </Card>
      ) : (
        <Card title="Instantiate a workflow">
          <p className="text-xs text-slate-500">
            Workflow creation requires the OPERATOR or ADMIN role.
          </p>
        </Card>
      )}

      <Card title="Workflow operations">
        <div className="mb-3 flex flex-wrap items-end gap-2">
          <label className="text-xs">
            Status
            <select
              aria-label="Workflow status filter"
              className="ml-1 rounded bg-slate-950 px-2 py-1"
              value={statusFilter}
              onChange={(event) => {
                setStatusFilter(event.target.value as GovernanceWorkflowStatus | "");
                setPage(1);
              }}
            >
              <option value="">All</option>
              {WORKFLOW_STATUSES.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            className="rounded border border-slate-700 px-2 py-1 text-xs"
            onClick={() => void loadOverview()}
          >
            Refresh
          </button>
          <span className="text-xs text-slate-500">
            Page {workflows?.page ?? page} · {workflows?.total ?? 0} total
          </span>
        </div>
        <DataState
          state={workflowState}
          emptyText="No workflows match this filter."
          error={workflowError}
        >
          {workflows ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="text-slate-400">
                  <tr>
                    <th className="py-1 pr-3">Workflow</th>
                    <th className="py-1 pr-3">Status</th>
                    <th className="py-1 pr-3">Priority</th>
                    <th className="py-1 pr-3">Owner</th>
                    <th className="py-1 pr-3">Due</th>
                    <th className="py-1 pr-3">SLA</th>
                    <th className="py-1">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {workflows.items.map((workflow) => (
                    <tr key={workflow.workflow_id} className="border-t border-slate-800">
                      <td className="py-1 pr-3">
                        <span className="font-medium">{workflow.title}</span>
                        <span className="block text-[10px] text-slate-500">
                          {workflow.template_key} v{workflow.template_version} ·{" "}
                          {workflow.workflow_id}
                        </span>
                      </td>
                      <td className="py-1 pr-3">
                        <StatusPill status={workflow.status} styles={WORKFLOW_STYLE} />
                      </td>
                      <td className="py-1 pr-3">{workflow.priority}</td>
                      <td className="py-1 pr-3">
                        {workflow.owner_id
                          ? `${workflow.owner_type}:${workflow.owner_id}`
                          : "unassigned"}
                      </td>
                      <td className="py-1 pr-3">{formatTime(workflow.due_at)}</td>
                      <td className="py-1 pr-3">
                        <StatusPill
                          status={workflow.sla?.state ?? "UNKNOWN"}
                          styles={SLA_STYLE}
                        />
                      </td>
                      <td className="py-1">
                        {canOperate ? (
                          <button
                            type="button"
                            className="rounded border border-slate-700 px-2 py-0.5"
                            onClick={() => void loadDetail(workflow.workflow_id)}
                          >
                            Open
                          </button>
                        ) : (
                          <span className="text-slate-500">detail restricted</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </DataState>
        <div className="mt-2 flex gap-2">
          <button
            type="button"
            className="rounded border border-slate-700 px-2 py-1 text-xs"
            disabled={page <= 1}
            onClick={() => setPage((current) => Math.max(1, current - 1))}
          >
            Previous
          </button>
          <button
            type="button"
            className="rounded border border-slate-700 px-2 py-1 text-xs"
            disabled={!workflows || workflows.page * workflows.page_size >= workflows.total}
            onClick={() => setPage((current) => current + 1)}
          >
            Next
          </button>
        </div>
      </Card>

      {detailError ? (
        <Card title="Workflow detail">
          <DataState state="error" emptyText="No workflow detail." error={detailError} />
        </Card>
      ) : null}

      {detail ? (
        <Card title={`Workflow detail · ${detail.workflow.title}`}>
          <div className="space-y-3">
            <div className="grid gap-2 text-xs sm:grid-cols-2 lg:grid-cols-4">
              <Metric label="Status" value={detail.workflow.status} />
              <Metric label="Version" value={detail.workflow.version} />
              <Metric
                label="Owner"
                value={
                  detail.workflow.owner_id
                    ? `${detail.workflow.owner_type}:${detail.workflow.owner_id}`
                    : "unassigned"
                }
              />
              <Metric label="Due" value={formatTime(detail.workflow.due_at)} />
            </div>
            <p className="text-xs text-slate-400">
              Template {detail.workflow.template_key} v{detail.workflow.template_version} · digest{" "}
              {detail.workflow.template_digest.slice(0, 12)}… · case{" "}
              {detail.workflow.case_id ?? "none"} · created by {detail.workflow.created_by}
            </p>
            <p className="text-xs">
              <span className="text-slate-400">SLA: </span>
              <SlaLine state={detail.sla.state} reason={detail.sla.reason} />
            </p>
            {detail.workflow.terminal ? (
              <p className="text-xs text-slate-500">
                Terminal workflow. History is preserved and cannot be deleted or reopened.
              </p>
            ) : (
              <div className="grid gap-2 rounded-lg border border-slate-800 p-3 sm:grid-cols-2">
                <label className="text-xs">
                  Transition to
                  <select
                    aria-label="Workflow transition target"
                    className="mt-1 w-full rounded bg-slate-950 px-2 py-1"
                    value={transitionTarget}
                    onChange={(event) =>
                      setTransitionTarget(event.target.value as GovernanceWorkflowStatus | "")
                    }
                  >
                    <option value="">Select a target</option>
                    {allowedWorkflowTargets.map((value) => (
                      <option key={value} value={value}>
                        {value}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="text-xs">
                  Transition reason (required for block/cancel)
                  <input
                    aria-label="Workflow transition reason"
                    className="mt-1 w-full rounded bg-slate-950 px-2 py-1"
                    value={transitionReason}
                    onChange={(event) => setTransitionReason(event.target.value)}
                  />
                </label>
                {transitionTarget === "COMPLETED" ? (
                  <label className="text-xs sm:col-span-2">
                    Outcome summary (required)
                    <input
                      aria-label="Workflow outcome summary"
                      className="mt-1 w-full rounded bg-slate-950 px-2 py-1"
                      value={outcomeSummary}
                      onChange={(event) => setOutcomeSummary(event.target.value)}
                    />
                  </label>
                ) : null}
                <div className="sm:col-span-2">
                  <button
                    type="button"
                    className="rounded bg-indigo-600 px-3 py-1 text-xs font-medium"
                    onClick={() => void onTransitionWorkflow()}
                  >
                    Apply workflow transition
                  </button>
                </div>
              </div>
            )}
            <div className="grid gap-2 rounded-lg border border-slate-800 p-3 sm:grid-cols-2">
              <label className="text-xs">
                Owner type
                <select
                  aria-label="Assignment owner type"
                  className="mt-1 w-full rounded bg-slate-950 px-2 py-1"
                  value={assignOwnerType}
                  onChange={(event) => setAssignOwnerType(event.target.value as "USER" | "ROLE")}
                >
                  <option value="USER">USER</option>
                  <option value="ROLE">ROLE</option>
                </select>
              </label>
              <label className="text-xs">
                Owner
                <input
                  aria-label="Assignment owner"
                  className="mt-1 w-full rounded bg-slate-950 px-2 py-1"
                  value={assignOwnerId}
                  onChange={(event) => setAssignOwnerId(event.target.value)}
                />
              </label>
              <label className="text-xs sm:col-span-2">
                Reassignment reason (required)
                <input
                  aria-label="Assignment reason"
                  className="mt-1 w-full rounded bg-slate-950 px-2 py-1"
                  value={assignReason}
                  onChange={(event) => setAssignReason(event.target.value)}
                />
              </label>
              <div className="sm:col-span-2">
                <button
                  type="button"
                  className="rounded border border-slate-700 px-3 py-1 text-xs"
                  onClick={() => void onAssignWorkflow()}
                >
                  Assign workflow owner
                </button>
              </div>
            </div>

            <div>
              <h3 className="mb-1 text-xs font-semibold text-slate-200">Tasks and dependencies</h3>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="text-slate-400">
                    <tr>
                      <th className="py-1 pr-3">Task</th>
                      <th className="py-1 pr-3">Status</th>
                      <th className="py-1 pr-3">Required</th>
                      <th className="py-1 pr-3">Owner</th>
                      <th className="py-1 pr-3">Dependencies</th>
                      <th className="py-1 pr-3">SLA</th>
                      <th className="py-1">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {detail.tasks.map((task) => (
                      <tr key={task.task_id} className="border-t border-slate-800">
                        <td className="py-1 pr-3">
                          {task.title}
                          <span className="block text-[10px] text-slate-500">
                            {task.task_key} · v{task.version}
                          </span>
                        </td>
                        <td className="py-1 pr-3">
                          <StatusPill status={task.status} styles={TASK_STYLE} />
                        </td>
                        <td className="py-1 pr-3">{task.required ? "yes" : "optional"}</td>
                        <td className="py-1 pr-3">
                          {task.owner_id ? `${task.owner_type}:${task.owner_id}` : "unassigned"}
                        </td>
                        <td className="py-1 pr-3">
                          {task.dependencies?.length ? task.dependencies.join(", ") : "none"}
                          <span className="block text-[10px] text-slate-500">
                            {task.dependency_state}
                          </span>
                        </td>
                        <td className="py-1 pr-3">
                          <StatusPill status={task.sla?.state ?? "UNKNOWN"} styles={SLA_STYLE} />
                        </td>
                        <td className="py-1">
                          <button
                            type="button"
                            className="rounded border border-slate-700 px-2 py-0.5"
                            onClick={() => {
                              setSelectedTaskId(task.task_id);
                              setTaskTarget("");
                            }}
                          >
                            Select
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {selectedTask ? (
                <div className="mt-2 grid gap-2 rounded-lg border border-slate-800 p-3 sm:grid-cols-2">
                  <p className="text-xs text-slate-300 sm:col-span-2">
                    Selected task: {selectedTask.task_key} ({selectedTask.status})
                  </p>
                  <label className="text-xs">
                    Transition to
                    <select
                      aria-label="Task transition target"
                      className="mt-1 w-full rounded bg-slate-950 px-2 py-1"
                      value={taskTarget}
                      onChange={(event) =>
                        setTaskTarget(event.target.value as GovernanceWorkflowTaskStatus | "")
                      }
                    >
                      <option value="">Select a target</option>
                      {TASK_TRANSITIONS[selectedTask.status].map((value) => (
                        <option key={value} value={value}>
                          {value}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="text-xs">
                    Reason (required for block/cancel)
                    <input
                      aria-label="Task transition reason"
                      className="mt-1 w-full rounded bg-slate-950 px-2 py-1"
                      value={taskReason}
                      onChange={(event) => setTaskReason(event.target.value)}
                    />
                  </label>
                  {taskTarget === "COMPLETED" ? (
                    <label className="text-xs sm:col-span-2">
                      Task outcome (required)
                      <input
                        aria-label="Task outcome summary"
                        className="mt-1 w-full rounded bg-slate-950 px-2 py-1"
                        value={taskOutcome}
                        onChange={(event) => setTaskOutcome(event.target.value)}
                      />
                    </label>
                  ) : null}
                  <div className="sm:col-span-2">
                    <button
                      type="button"
                      className="rounded bg-indigo-600 px-3 py-1 text-xs font-medium"
                      onClick={() => void onTransitionTask()}
                    >
                      Apply task transition
                    </button>
                  </div>
                  <label className="text-xs">
                    Task owner type
                    <select
                      aria-label="Task assignment owner type"
                      className="mt-1 w-full rounded bg-slate-950 px-2 py-1"
                      value={taskOwnerType}
                      onChange={(event) =>
                        setTaskOwnerType(event.target.value as "USER" | "ROLE")
                      }
                    >
                      <option value="USER">USER</option>
                      <option value="ROLE">ROLE</option>
                    </select>
                  </label>
                  <label className="text-xs">
                    Task owner
                    <input
                      aria-label="Task assignment owner"
                      className="mt-1 w-full rounded bg-slate-950 px-2 py-1"
                      value={taskOwnerId}
                      onChange={(event) => setTaskOwnerId(event.target.value)}
                    />
                  </label>
                  <label className="text-xs sm:col-span-2">
                    Task assignment reason (required)
                    <input
                      aria-label="Task assignment reason"
                      className="mt-1 w-full rounded bg-slate-950 px-2 py-1"
                      value={taskAssignReason}
                      onChange={(event) => setTaskAssignReason(event.target.value)}
                    />
                  </label>
                  <div className="sm:col-span-2">
                    <button
                      type="button"
                      className="rounded border border-slate-700 px-3 py-1 text-xs"
                      onClick={() => void onAssignTask()}
                    >
                      Assign task owner
                    </button>
                  </div>
                </div>
              ) : null}
            </div>

            <div>
              <h3 className="mb-1 text-xs font-semibold text-slate-200">
                Read-only cross-domain references
              </h3>
              {detail.references.length === 0 ? (
                <p className="text-xs text-slate-400">No references attached.</p>
              ) : (
                <ul className="space-y-1 text-xs">
                  {detail.references.map((reference) => (
                    <li key={reference.reference_id} className="border-t border-slate-800 py-1">
                      {reference.domain}:{reference.source_id} · availability{" "}
                      {reference.availability} · source status {reference.source_status || "unknown"}{" "}
                      · case {reference.source_case_id ?? "unscoped"} · added by{" "}
                      {reference.added_by}
                    </li>
                  ))}
                </ul>
              )}
              <div className="mt-2 grid gap-2 rounded-lg border border-slate-800 p-3 sm:grid-cols-2">
                <label className="text-xs">
                  Domain
                  <select
                    aria-label="Reference domain"
                    className="mt-1 w-full rounded bg-slate-950 px-2 py-1"
                    value={referenceDomain}
                    onChange={(event) =>
                      setReferenceDomain(event.target.value as GovernanceWorkflowReferenceDomain)
                    }
                  >
                    {REFERENCE_DOMAINS.map((domain) => (
                      <option key={domain} value={domain}>
                        {domain}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="text-xs">
                  Source ID
                  <input
                    aria-label="Reference source id"
                    className="mt-1 w-full rounded bg-slate-950 px-2 py-1"
                    value={referenceSourceId}
                    onChange={(event) => setReferenceSourceId(event.target.value)}
                  />
                </label>
                <label className="text-xs sm:col-span-2">
                  Reference reason
                  <input
                    aria-label="Reference reason"
                    className="mt-1 w-full rounded bg-slate-950 px-2 py-1"
                    value={referenceReason}
                    onChange={(event) => setReferenceReason(event.target.value)}
                  />
                </label>
                <div className="sm:col-span-2">
                  <button
                    type="button"
                    className="rounded border border-slate-700 px-3 py-1 text-xs"
                    onClick={() => void onAddReference()}
                  >
                    Attach reference
                  </button>
                </div>
              </div>
            </div>

            <div>
              <h3 className="mb-1 text-xs font-semibold text-slate-200">Escalations</h3>
              {detail.escalations.length === 0 ? (
                <p className="text-xs text-slate-400">No escalations recorded.</p>
              ) : (
                <ul className="space-y-1 text-xs">
                  {detail.escalations.map((escalation) => (
                    <li
                      key={escalation.escalation_id}
                      className="border-t border-slate-800 py-1"
                    >
                      <span className="mr-2">
                        <StatusPill
                          status={escalation.status}
                          styles={ESCALATION_STYLE}
                        />
                      </span>
                      {escalation.escalation_type} · {escalation.severity} · v
                      {escalation.version} · {escalation.reason}
                      {escalation.status !== "RESOLVED" ? (
                        <button
                          type="button"
                          className="ml-2 rounded border border-slate-700 px-2 py-0.5"
                          onClick={() => setSelectedEscalationId(escalation.escalation_id)}
                        >
                          Select
                        </button>
                      ) : null}
                    </li>
                  ))}
                </ul>
              )}
              {selectedEscalation ? (
                <div className="mt-2 grid gap-2 rounded-lg border border-slate-800 p-3 sm:grid-cols-2">
                  <p className="text-xs text-slate-300 sm:col-span-2">
                    Selected escalation: {selectedEscalation.escalation_id} (
                    {selectedEscalation.status})
                  </p>
                  <label className="text-xs sm:col-span-2">
                    Action reason (required)
                    <input
                      aria-label="Escalation action reason"
                      className="mt-1 w-full rounded bg-slate-950 px-2 py-1"
                      value={escalationActionReason}
                      onChange={(event) => setEscalationActionReason(event.target.value)}
                    />
                  </label>
                  <label className="text-xs sm:col-span-2">
                    Resolution (required to resolve)
                    <input
                      aria-label="Escalation resolution"
                      className="mt-1 w-full rounded bg-slate-950 px-2 py-1"
                      value={escalationResolution}
                      onChange={(event) => setEscalationResolution(event.target.value)}
                    />
                  </label>
                  <div className="flex gap-2 sm:col-span-2">
                    {selectedEscalation.status === "OPEN" ? (
                      <button
                        type="button"
                        className="rounded border border-slate-700 px-3 py-1 text-xs"
                        onClick={() => void onAcknowledgeEscalation(selectedEscalation)}
                      >
                        Acknowledge escalation
                      </button>
                    ) : null}
                    <button
                      type="button"
                      className="rounded border border-emerald-700 px-3 py-1 text-xs text-emerald-300"
                      onClick={() => void onResolveEscalation(selectedEscalation)}
                    >
                      Resolve escalation
                    </button>
                  </div>
                </div>
              ) : null}
              <div className="mt-2 grid gap-2 rounded-lg border border-slate-800 p-3 sm:grid-cols-2">
                <label className="text-xs">
                  Escalation type
                  <select
                    aria-label="Escalation type"
                    className="mt-1 w-full rounded bg-slate-950 px-2 py-1"
                    value={escalationType}
                    onChange={(event) =>
                      setEscalationType(event.target.value as GovernanceWorkflowEscalationType)
                    }
                  >
                    {ESCALATION_TYPES.map((value) => (
                      <option key={value} value={value}>
                        {value}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="text-xs">
                  Severity
                  <select
                    aria-label="Escalation severity"
                    className="mt-1 w-full rounded bg-slate-950 px-2 py-1"
                    value={escalationSeverity}
                    onChange={(event) => setEscalationSeverity(event.target.value)}
                  >
                    {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((value) => (
                      <option key={value} value={value}>
                        {value}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="text-xs sm:col-span-2">
                  Escalation reason
                  <input
                    aria-label="Escalation reason"
                    className="mt-1 w-full rounded bg-slate-950 px-2 py-1"
                    value={escalationReason}
                    onChange={(event) => setEscalationReason(event.target.value)}
                  />
                </label>
                <div className="sm:col-span-2">
                  <button
                    type="button"
                    className="rounded border border-amber-700 px-3 py-1 text-xs text-amber-300"
                    onClick={() => void onCreateEscalation()}
                  >
                    Create escalation
                  </button>
                </div>
              </div>
            </div>

            <div>
              <h3 className="mb-1 text-xs font-semibold text-slate-200">
                Append-only event history
              </h3>
              <ul className="space-y-1 text-xs">
                {detail.events.slice(-20).map((event) => (
                  <li key={event.event_id} className="border-t border-slate-800 py-1">
                    #{event.sequence} {event.event_type} · {event.actor_role ?? "SYSTEM"} ·{" "}
                    {event.actor_id ?? "system"} · {formatTime(event.created_at)}
                    {event.reason ? <span className="block text-slate-500">{event.reason}</span> : null}
                  </li>
                ))}
              </ul>
            </div>

            <p className="text-xs text-slate-500">
              Workflow coordination only. No hold release, disposition decision, evidence
              modification, export approval, custody change, recommendation resolution, or executive
              action completion is performed. No record is deleted.
            </p>
          </div>
        </Card>
      ) : null}
    </div>
  );
}
