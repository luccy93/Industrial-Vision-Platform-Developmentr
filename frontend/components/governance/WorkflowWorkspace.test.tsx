import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { WorkflowWorkspace } from "./WorkflowWorkspace";

let currentRole = "ADMIN";
let statusFails = false;

vi.mock("../auth/AuthProvider", () => ({
  useAuth: () => ({
    hasRole: (role: string) => currentRole === role,
  }),
}));

function mockFetch(handler: (url: string, init?: RequestInit) => unknown) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: unknown, init?: RequestInit) => {
      const url = String(input);
      const data = handler(url, init);
      if (data instanceof Error) {
        return {
          ok: false,
          status: 503,
          json: async () => ({ error: { code: "service_not_ready", message: data.message } }),
        };
      }
      return { ok: true, status: 200, json: async () => data };
    })
  );
}

const SLA = {
  entity_type: "WORKFLOW",
  entity_id: "workflow-1",
  state: "OVERDUE",
  reason: "Past the workflow due date.",
  v37_state: "OVERDUE",
  target_hours: 24,
  warning_hours: 4,
  start_at: "2026-11-20T00:00:00Z",
  due_at: "2026-11-21T00:00:00Z",
  warning_at: "2026-11-20T20:00:00Z",
  resolution_at: null,
  elapsed_hours: 48,
  open_age_hours: 48,
  duration_hours: null,
  resolved: false,
  computed_at: "2026-11-23T00:00:00Z",
  non_claim: "SLA indicators are advisory workflow signals, not regulatory determinations.",
};

const TASK_SLA = {
  ...SLA,
  entity_type: "TASK",
  entity_id: "task-1",
  state: "AT_RISK",
  reason: "Approaching the task due date.",
  v37_state: "AT_RISK",
};

const TEMPLATE = {
  template_id: "template-1",
  template_key: "EVIDENCE_REVIEW",
  version: 2,
  name: "Evidence review",
  description: "Review evidence for an open forensic case.",
  status: "ACTIVE",
  definition: { tasks: [{ task_key: "collect", title: "Collect evidence" }] },
  definition_digest: "c".repeat(64),
  task_count: 2,
  dependency_count: 1,
  created_by: "admin@example.com",
  created_at: "2026-11-01T00:00:00Z",
  updated_at: "2026-11-01T00:00:00Z",
  idempotency_key: "template-key-1",
  disabled: false,
};

const WORKFLOW = {
  workflow_id: "workflow-1",
  template_id: "template-1",
  template_key: "EVIDENCE_REVIEW",
  template_version: 2,
  template_digest: "c".repeat(64),
  template_snapshot: { tasks: [{ task_key: "collect", title: "Collect evidence" }] },
  case_id: "case-1",
  title: "Quarterly evidence review",
  description: "Coordinate evidence review without modifying source records.",
  status: "IN_PROGRESS",
  version: 3,
  owner_type: "ROLE",
  owner_id: "OPERATOR",
  priority: "HIGH",
  due_at: "2026-11-21T00:00:00Z",
  created_by: "admin@example.com",
  created_at: "2026-11-20T00:00:00Z",
  updated_at: "2026-11-22T00:00:00Z",
  ready_at: "2026-11-20T00:00:00Z",
  started_at: "2026-11-20T01:00:00Z",
  blocked_at: null,
  review_at: null,
  completed_at: null,
  cancelled_at: null,
  outcome_summary: null,
  block_reason: null,
  cancel_reason: null,
  idempotency_key: "workflow-key-1",
  terminal: false,
  unassigned: false,
  sla: SLA,
};

const TASK = {
  task_id: "task-1",
  workflow_id: "workflow-1",
  task_key: "collect",
  title: "Collect evidence",
  description: "Gather the referenced case evidence.",
  status: "IN_PROGRESS" as const,
  version: 2,
  owner_type: "USER" as const,
  owner_id: "operator@example.com",
  required: true,
  order_index: 0,
  due_at: "2026-11-22T00:00:00Z",
  created_at: "2026-11-20T00:00:00Z",
  updated_at: "2026-11-21T00:00:00Z",
  started_at: "2026-11-21T00:00:00Z",
  blocked_at: null,
  completed_at: null,
  cancelled_at: null,
  outcome_summary: null,
  block_reason: null,
  cancel_reason: null,
  terminal: false,
  unassigned: false,
  dependencies: [],
  dependency_state: "SATISFIED",
  sla: TASK_SLA,
};

const REFERENCE = {
  reference_id: "reference-1",
  workflow_id: "workflow-1",
  task_id: null,
  domain: "FORENSIC_CASE" as const,
  source_id: "case-1",
  reference_key: "FORENSIC_CASE:case-1",
  source_label: "Forensic case case-1",
  source_case_id: "case-1",
  availability: "AVAILABLE" as const,
  source_status: "OPEN",
  source_version: 4,
  added_by: "operator@example.com",
  added_at: "2026-11-20T02:00:00Z",
  last_checked_at: "2026-11-23T00:00:00Z",
  reason: "The workflow coordinates review of this case.",
};

const ESCALATION = {
  escalation_id: "escalation-1",
  workflow_id: "workflow-1",
  task_id: null,
  escalation_type: "SLA_OVERDUE" as const,
  severity: "HIGH" as const,
  status: "OPEN" as const,
  reason: "Workflow is past its due date.",
  resolution: null,
  requested_by: "operator@example.com",
  requested_at: "2026-11-22T00:00:00Z",
  acknowledged_by: null,
  acknowledged_at: null,
  resolved_by: null,
  resolved_at: null,
  version: 1,
  idempotency_key: "escalation-key-1",
  terminal: false,
};

const EVENT = {
  event_id: "event-1",
  workflow_id: "workflow-1",
  task_id: null,
  template_id: null,
  event_type: "WORKFLOW_CREATED",
  from_status: null,
  to_status: "DRAFT",
  actor_id: "admin@example.com",
  actor_role: "ADMIN",
  reason: "Workflow created from template.",
  detail: {},
  sequence: 1,
  created_at: "2026-11-20T00:00:00Z",
};

const STATUS = {
  enabled: true,
  assurance: "DETERMINISTIC_LOCAL_AGGREGATES_ONLY",
  workflow_counts: { IN_PROGRESS: 1 },
  workflow_total: 1,
  task_counts: { IN_PROGRESS: 1 },
  task_total: 1,
  escalation_counts: { OPEN: 1 },
  escalation_total: 1,
  unassigned: { workflows: 0, tasks: 0 },
  overdue: { workflows: 1, tasks: 0 },
  sla_counts: { OVERDUE: 1 },
  sla_sample_size: 2,
  sla_sample_limit: 200,
  sources: { sla: "AVAILABLE" },
  lifecycle: {
    workflow_statuses: [
      "DRAFT",
      "READY",
      "IN_PROGRESS",
      "BLOCKED",
      "UNDER_REVIEW",
      "COMPLETED",
      "CANCELLED",
    ],
    task_statuses: ["PENDING", "READY", "IN_PROGRESS", "BLOCKED", "COMPLETED", "CANCELLED"],
    template_statuses: ["ACTIVE", "SUPERSEDED", "DISABLED"],
    escalation_statuses: ["OPEN", "ACKNOWLEDGED", "RESOLVED"],
    workflow_transitions: {
      DRAFT: ["READY", "CANCELLED"],
      READY: ["IN_PROGRESS", "BLOCKED", "CANCELLED"],
      IN_PROGRESS: ["BLOCKED", "UNDER_REVIEW", "CANCELLED"],
      BLOCKED: ["IN_PROGRESS", "CANCELLED"],
      UNDER_REVIEW: ["COMPLETED", "IN_PROGRESS", "CANCELLED"],
      COMPLETED: [],
      CANCELLED: [],
    },
  },
  scheduled_workflows: false,
  scheduled_workflows_note:
    "V39 evaluates workflow SLA on demand; no workflow scheduler is started.",
  generated_at: "2026-11-23T00:00:00Z",
  non_claims: ["Workflows never approve holds, dispositions, exports, or executive actions."],
  limitations: ["No live PostgreSQL migration has been validated in this environment."],
};

const OWNERSHIP = {
  unassigned: { workflows: 0, tasks: 0 },
  overdue: { workflows: 1, tasks: 0 },
  workflow_counts: { IN_PROGRESS: 1 },
  task_counts: { IN_PROGRESS: 1 },
  generated_at: "2026-11-23T00:00:00Z",
  non_claims: ["A missing due date is never treated as zero time."],
};

const TEMPLATES = {
  items: [TEMPLATE],
  total: 1,
  page: 1,
  page_size: 50,
  lifecycle: { statuses: ["ACTIVE", "SUPERSEDED", "DISABLED"], disabled_is_terminal: true },
  non_claims: ["Template versions are immutable."],
};

const WORKFLOWS = {
  items: [WORKFLOW],
  total: 1,
  page: 1,
  page_size: 10,
  filters: {},
  status_counts: { IN_PROGRESS: 1 },
  unassigned: { workflows: 0, tasks: 0 },
  overdue: { workflows: 1, tasks: 0 },
  non_claims: ["Workflows never mutate source records."],
};

const DETAIL = {
  workflow: WORKFLOW,
  sla: SLA,
  tasks: [TASK],
  dependencies: [],
  references: [REFERENCE],
  escalations: [ESCALATION],
  escalation_total: 1,
  events: [EVENT],
  ownership_history: [],
  lifecycle: {
    statuses: STATUS.lifecycle.workflow_statuses,
    transitions: STATUS.lifecycle.workflow_transitions,
    terminal: ["COMPLETED", "CANCELLED"],
  },
  non_claims: ["Workflows never mutate source records."],
};

const REFERENCE_RESPONSE = {
  workflow_id: "workflow-1",
  items: [REFERENCE],
  reference: REFERENCE,
  replayed: false,
  source_mutated: false,
  non_claims: ["The referenced source record was not modified."],
};

function handler(url: string, init?: RequestInit): unknown {
  if (url.includes("/api/v1/governance/workflows/status")) {
    return statusFails ? new Error("status source offline") : STATUS;
  }
  if (url.includes("/api/v1/governance/workflows/ownership")) return OWNERSHIP;
  if (url.includes("/api/v1/governance/workflows/templates")) return TEMPLATES;
  if (url.includes("/api/v1/governance/workflows/workflows/workflow-1")) {
    if (init?.method === "POST" && url.includes("/references")) return REFERENCE_RESPONSE;
    return DETAIL;
  }
  if (url.includes("/api/v1/governance/workflows/workflows")) return WORKFLOWS;
  return new Error(`unexpected request: ${url}`);
}

describe("WorkflowWorkspace", () => {
  beforeEach(() => {
    currentRole = "ADMIN";
    statusFails = false;
    vi.restoreAllMocks();
  });

  it("renders templates, workflows, dependency-aware tasks, references, escalations, and events", async () => {
    mockFetch(handler);
    render(<WorkflowWorkspace />);

    expect(await screen.findByText("Enterprise governance workflow orchestration")).toBeInTheDocument();
    expect(screen.getByText(/never approves or releases a hold/i)).toBeInTheDocument();
    expect(screen.getByText(/no record is deleted/i)).toBeInTheDocument();
    expect(await screen.findByText("EVIDENCE_REVIEW")).toBeInTheDocument();
    expect(screen.getByText("v2")).toBeInTheDocument();
    expect(screen.getByText("2 tasks / 1 dependencies")).toBeInTheDocument();
    expect(await screen.findByText("Quarterly evidence review")).toBeInTheDocument();
    expect(screen.getByText(/scheduled_workflows=false/)).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Open" }));
    expect(
      await screen.findByText("Workflow detail · Quarterly evidence review")
    ).toBeInTheDocument();
    expect(screen.getByText("Collect evidence")).toBeInTheDocument();
    expect(screen.getByText("SATISFIED")).toBeInTheDocument();
    expect(screen.getByText(/FORENSIC_CASE:case-1/)).toBeInTheDocument();
    expect(screen.getByText(/availability AVAILABLE/)).toBeInTheDocument();
    expect(screen.getByText(/SLA_OVERDUE · HIGH/)).toBeInTheDocument();
    expect(screen.getByText(/#1 WORKFLOW_CREATED/)).toBeInTheDocument();
    expect(screen.getByText(/No hold release, disposition decision/)).toBeInTheDocument();

    await userEvent.type(screen.getByLabelText("Reference source id"), "case-2");
    await userEvent.type(screen.getByLabelText("Reference reason"), "Additional case context.");
    await userEvent.click(screen.getByRole("button", { name: "Attach reference" }));
    expect(
      await screen.findByText(/attached; the source was not modified/)
    ).toBeInTheDocument();
  });

  it("hides template, workflow, and task writes from VIEWER while keeping overview reads", async () => {
    currentRole = "VIEWER";
    mockFetch(handler);
    render(<WorkflowWorkspace />);

    expect(await screen.findByText("Enterprise governance workflow orchestration")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Create template" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Create workflow" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Open" })).not.toBeInTheDocument();
    expect(
      screen.getByText("Template creation and retirement require the ADMIN role.")
    ).toBeInTheDocument();
    expect(
      screen.getByText("Workflow creation requires the OPERATOR or ADMIN role.")
    ).toBeInTheDocument();
    expect(screen.getByText("detail restricted")).toBeInTheDocument();
  });

  it("shows an explicit error instead of stale or zero workflow data", async () => {
    statusFails = true;
    currentRole = "OPERATOR";
    mockFetch(handler);
    render(<WorkflowWorkspace />);

    expect(
      await screen.findByText(/Unavailable \(service_not_ready: status source offline\)/)
    ).toBeInTheDocument();
    expect(await screen.findByText("Quarterly evidence review")).toBeInTheDocument();
    expect(screen.getByText(/showing nothing rather than stale data/)).toBeInTheDocument();
  });
});
