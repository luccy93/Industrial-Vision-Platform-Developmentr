import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ExecutiveWorkspace } from "./ExecutiveWorkspace";

let currentRole = "ADMIN";
let healthFails = false;

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

const COVERAGE = {
  status: "PARTIAL",
  message: "3 of 4 applicable KPIs are available; 1 is unavailable.",
  applicable_kpis: 4,
  available_kpis: 3,
  partial_kpis: 0,
  unavailable_kpis: 1,
  partial_kpi_ids: [],
  unavailable_kpi_ids: ["GOV-SLA"],
};

const KPI_AVAILABLE = {
  kpi_id: "GOV-AUDIT",
  name: "Governance audit integrity findings",
  definition: "Latest V33 integrity audit findings by severity.",
  source: "V33 monitoring audit history",
  unit: "findings",
  window: { start_at: "2026-10-16T00:00:00Z", end_at: "2026-11-15T00:00:00Z", days: 30 },
  calculated_at: "2026-11-15T12:00:00Z",
  availability: "AVAILABLE",
  completeness: { status: "COMPLETE", known: 1, unknown: 0, total: 1, message: "" },
  applicable: true,
  value: 2,
  numerator: 2,
  denominator: 2,
  detail: { by_severity: { CRITICAL: 1, HIGH: 1 } },
  model_version: null,
  policy_version: 3,
  unavailable_reason: null,
  source_refs: ["monitoring_audit:audit-1"],
};

const KPI_UNAVAILABLE = {
  ...KPI_AVAILABLE,
  kpi_id: "GOV-SLA",
  name: "SLA compliance (known items)",
  definition: "Known SLA items within target divided by known SLA items.",
  source: "V37 SLA backlog",
  unit: "ratio",
  availability: "UNAVAILABLE",
  completeness: { status: "UNKNOWN", known: 0, unknown: 1, total: 1, message: "" },
  value: null,
  numerator: null,
  denominator: null,
  detail: {},
  model_version: null,
  policy_version: null,
  unavailable_reason: "V37 SLA backlog is unavailable.",
  source_refs: [],
};

const KPIS = {
  items: [KPI_AVAILABLE, KPI_UNAVAILABLE],
  total: 2,
  window: KPI_AVAILABLE.window,
  window_days: 30,
  calculated_at: "2026-11-15T12:00:00Z",
  source_coverage: COVERAGE,
  sources: {
    forensic: { availability: "AVAILABLE", message: "" },
    intelligence: { availability: "UNAVAILABLE", message: "SLA backlog unavailable." },
  },
  assurance: "DETERMINISTIC_LOCAL_AGGREGATES_ONLY",
  non_claims: ["Executive KPIs are deterministic local aggregates, not regulatory certification."],
  limitations: ["No forecast or statistical model is used."],
};

const HEALTH = {
  overall_status: "DEGRADED",
  status_reason: "Triggered signal AUDIT_INTEGRITY_GAPS at DEGRADED severity.",
  model_version: "EXEC_HEALTH_V1",
  calculated_at: "2026-11-15T12:00:00Z",
  coverage: COVERAGE,
  signals: [
    {
      code: "AUDIT_INTEGRITY_GAPS",
      label: "Integrity audit gaps",
      kpi_id: "GOV-AUDIT",
      operator: ">",
      threshold: 0,
      status: "DEGRADED",
      observed_value: 2,
      evaluated: true,
      triggered: true,
      explanation: "2 integrity findings exceed the fixed threshold.",
      source_availability: "AVAILABLE",
    },
    {
      code: "SLA_COMPLIANCE_LOW",
      label: "SLA compliance low",
      kpi_id: "GOV-SLA",
      operator: "<",
      threshold: 0.9,
      status: "ATTENTION_REQUIRED",
      observed_value: null,
      evaluated: false,
      triggered: false,
      explanation: "KPI is unavailable and is not treated as zero.",
      source_availability: "UNAVAILABLE",
    },
  ],
  triggered_signals: ["AUDIT_INTEGRITY_GAPS"],
  evaluated_signal_count: 1,
  triggered_signal_count: 1,
  thresholds: {
    model_version: "EXEC_HEALTH_V1",
    fixed: true,
    signals: [
      {
        code: "AUDIT_INTEGRITY_GAPS",
        kpi_id: "GOV-AUDIT",
        operator: ">",
        threshold: 0,
        status: "DEGRADED",
      },
    ],
  },
  averaged_score_used: false,
  assurance: "DETERMINISTIC_LOCAL_AGGREGATES_ONLY",
  non_claims: ["Health status is not a safety guarantee."],
  limitations: ["Thresholds are fixed in EXEC_HEALTH_V1."],
};

const HEALTH_RESPONSE = {
  health: HEALTH,
  kpi_summary: [KPI_AVAILABLE, KPI_UNAVAILABLE].map((kpi) => ({
    kpi_id: kpi.kpi_id,
    name: kpi.name,
    value: kpi.value,
    unit: kpi.unit,
    availability: kpi.availability,
    completeness: kpi.completeness,
    applicable: kpi.applicable,
    model_version: kpi.model_version,
    policy_version: kpi.policy_version,
  })),
  window: KPI_AVAILABLE.window,
  window_days: 30,
  source_coverage: COVERAGE,
  sources: KPIS.sources,
  calculated_at: "2026-11-15T12:00:00Z",
  assurance: "DETERMINISTIC_LOCAL_AGGREGATES_ONLY",
  non_claims: ["Health status is not a safety guarantee."],
  limitations: ["Thresholds are fixed in EXEC_HEALTH_V1."],
};

const STATUS = {
  enabled: true,
  assurance: "DETERMINISTIC_LOCAL_AGGREGATES_ONLY",
  health_model_version: "EXEC_HEALTH_V1",
  kpi_count: 15,
  kpi_ids: ["GOV-AUDIT", "GOV-SLA"],
  action_counts: { OPEN: 1, IN_PROGRESS: 0, BLOCKED: 0, COMPLETED: 0, CANCELLED: 0 },
  action_total: 1,
  report_counts: { EXECUTIVE_SUMMARY: 1 },
  report_total: 1,
  config_source: { availability: "OK", snapshot_id: "config-snap-1" },
  sources: { forensic: "AVAILABLE", intelligence: "AVAILABLE" },
  scheduled_executive: false,
  scheduled_executive_note:
    "V38 computes executive views on demand; no executive scheduler is started.",
  generated_at: "2026-11-15T12:00:00Z",
  non_claims: ["Executive reports are local-only and are never distributed externally."],
  limitations: ["No live PostgreSQL migration has been validated in this environment."],
};

const ACTION = {
  action_id: "action-1",
  recommendation_id: "rec-1",
  recommendation_rule_id: "GOV-RISK-001",
  recommendation_severity: "CRITICAL",
  case_id: "case-1",
  title: "Mitigate critical forensic finding",
  description: "Strategic follow-up from a V37 recommendation.",
  owner_id: "operator@example.com",
  due_at: "2099-12-01T12:00:00Z",
  priority: "HIGH",
  status: "OPEN",
  version: 1,
  created_by: "admin@example.com",
  created_at: "2026-11-15T12:00:00Z",
  updated_at: "2026-11-15T12:00:00Z",
  started_at: null,
  blocked_at: null,
  completed_at: null,
  cancelled_at: null,
  outcome_summary: null,
  block_reason: null,
  cancel_reason: null,
  idempotency_key: "action-key-1",
  terminal: false,
};

const ACTIONS = {
  items: [ACTION],
  total: 1,
  page: 1,
  page_size: 10,
  status_counts: { OPEN: 1, IN_PROGRESS: 0, BLOCKED: 0, COMPLETED: 0, CANCELLED: 0 },
  lifecycle: {
    statuses: ["OPEN", "IN_PROGRESS", "BLOCKED", "COMPLETED", "CANCELLED"],
    transitions: {
      OPEN: ["IN_PROGRESS", "BLOCKED", "COMPLETED", "CANCELLED"],
      IN_PROGRESS: ["BLOCKED", "COMPLETED", "CANCELLED"],
      BLOCKED: ["IN_PROGRESS", "CANCELLED"],
      COMPLETED: [],
      CANCELLED: [],
    },
    terminal: ["COMPLETED", "CANCELLED"],
  },
  non_claims: ["Actions never resolve a V37 recommendation automatically."],
};

const ACTION_DETAIL = {
  action: ACTION,
  events: [
    {
      event_id: "event-1",
      action_id: "action-1",
      event_type: "CREATED",
      from_status: null,
      to_status: "OPEN",
      actor_id: "admin@example.com",
      actor_role: "ADMIN",
      reason: "Strategic action created.",
      detail: {},
      created_at: "2026-11-15T12:00:00Z",
    },
  ],
  linked_recommendation: { recommendation_id: "rec-1", status: "OPEN" },
  non_claims: ["Actions never resolve a V37 recommendation automatically."],
};

const REPORT = {
  report_id: "report-1",
  report_type: "EXECUTIVE_SUMMARY",
  format: "json",
  status: "GENERATED",
  window_start: "2026-10-16T00:00:00Z",
  window_end: "2026-11-15T12:00:00Z",
  generated_at: "2026-11-15T12:00:00Z",
  generated_by: "admin@example.com",
  snapshot_id: "snapshot-1",
  snapshot_type: "EXECUTIVE_SUMMARY",
  schema_version: 1,
  source_coverage: COVERAGE,
  sections_available: ["health", "kpis", "actions"],
  sections_unavailable: ["sla"],
  payload_digest: "a".repeat(64),
  report_digest: "b".repeat(64),
  row_count: 2,
  redaction_applied: true,
  idempotency_key: "report-key-1",
  reason: "Monthly executive governance review.",
  created_at: "2026-11-15T12:00:00Z",
};

const REPORTS = {
  items: [REPORT],
  total: 1,
  page: 1,
  page_size: 10,
  report_types: ["EXECUTIVE_SUMMARY", "EXECUTIVE_RISK", "EXECUTIVE_SLA", "EXECUTIVE_OPERATIONS"],
  formats: ["json", "csv"],
  non_claims: ["Executive reports are local-only."],
};

const REPORT_DETAIL = {
  report: REPORT,
  payload: {
    report_type: "EXECUTIVE_SUMMARY",
    schema_version: 1,
    sections: {
      health: { availability: "AVAILABLE" },
      sla: { availability: "UNAVAILABLE", message: "V37 SLA backlog is unavailable." },
    },
  },
  integrity: {
    report_digest_valid: true,
    snapshot_digest_valid: true,
    redaction_applied: true,
    schema_version: 1,
  },
  non_claims: ["Executive reports are local-only."],
};

const COMPARISON = {
  status: "COMPARABLE",
  compatibility_version: "EXEC_COMPARE_V1",
  message: "Stored reports use compatible periods and model versions.",
  comparable: true,
  baseline: { report_id: "report-1" },
  current: { label: "CURRENT" },
  model_versions: { baseline_risk_model: "1", current_risk_model: "1" },
  changes: [
    {
      kpi_id: "GOV-AUDIT",
      name: "Governance audit integrity findings",
      unit: "findings",
      baseline_value: 4,
      current_value: 2,
      delta: -2,
      percent_change: -50,
      baseline_availability: "AVAILABLE",
      current_availability: "AVAILABLE",
      baseline_model_version: null,
      current_model_version: null,
      partial: false,
    },
  ],
  gaps: [{ code: "SOURCE_UNAVAILABLE", message: "V37 SLA backlog is unavailable in both periods." }],
  incompatibilities: [],
  truncated: false,
  interpolated: false,
  fabricated_history: false,
  source_preserved: true,
  assurance: "DETERMINISTIC_LOCAL_AGGREGATES_ONLY",
  non_claims: ["No historical value is interpolated."],
};

const CONFIG = {
  config: {
    default_window_days: 30,
    comparison_period_days: 30,
    action_due_soon_hours: 72,
    report_max_rows: 500,
    include_recommendations_in_summary: true,
  },
  schema_version: 1,
  availability: "OK",
  message: "",
  source: { snapshot_id: "config-snap-1", digest_valid: true },
  fixed_health_model_version: "EXEC_HEALTH_V1",
  health_thresholds_fixed: true,
  assurance: "DETERMINISTIC_LOCAL_AGGREGATES_ONLY",
  non_claims: ["Health thresholds are fixed and not configurable."],
  limitations: ["Configuration snapshots are append-only."],
};

function handler(url: string): unknown {
  if (url.includes("/api/v1/governance/executive/status")) return STATUS;
  if (url.includes("/api/v1/governance/executive/health")) {
    return healthFails ? new Error("health source offline") : HEALTH_RESPONSE;
  }
  if (url.includes("/api/v1/governance/executive/kpis")) return KPIS;
  if (url.includes("/api/v1/governance/executive/config")) return CONFIG;
  if (url.includes("/api/v1/governance/executive/actions/")) return ACTION_DETAIL;
  if (url.includes("/api/v1/governance/executive/actions")) return ACTIONS;
  if (url.includes("/api/v1/governance/executive/comparisons/")) return COMPARISON;
  if (url.includes("/api/v1/governance/executive/reports/")) return REPORT_DETAIL;
  if (url.includes("/api/v1/governance/executive/reports")) return REPORTS;
  return new Error(`unexpected request: ${url}`);
}

describe("ExecutiveWorkspace", () => {
  beforeEach(() => {
    currentRole = "ADMIN";
    healthFails = false;
    vi.restoreAllMocks();
  });

  it("renders deterministic health, source-preserving KPIs, actions, reports, comparison, and config", async () => {
    mockFetch(handler);
    render(<ExecutiveWorkspace />);

    expect(await screen.findByText("Executive governance command center")).toBeInTheDocument();
    expect(screen.getByText("EXEC_HEALTH_V1")).toBeInTheDocument();
    expect(screen.getByText(/Triggered signal AUDIT_INTEGRITY_GAPS/)).toBeInTheDocument();
    expect(screen.getByText(/missing data is never treated as zero/i)).toBeInTheDocument();
    expect(screen.getByText(/averaged_score_used=false/)).toBeInTheDocument();

    expect(
      await screen.findByText("Governance audit integrity findings")
    ).toBeInTheDocument();
    expect(screen.getByText("2 findings")).toBeInTheDocument();
    expect(screen.getByText("V37 SLA backlog is unavailable.")).toBeInTheDocument();
    expect(screen.getAllByText("unavailable").length).toBeGreaterThan(0);

    expect(await screen.findByText("Mitigate critical forensic finding")).toBeInTheDocument();
    expect(screen.getByText("operator@example.com")).toBeInTheDocument();
    expect(screen.getByText("rec-1")).toBeInTheDocument();

    await userEvent.click(screen.getAllByRole("button", { name: "Open" })[0]);
    expect(await screen.findByText(/Linked recommendation status:/)).toBeInTheDocument();
    expect(screen.getByText(/actions do not/)).toBeInTheDocument();
    expect(screen.getByText("CREATED")).toBeInTheDocument();

    expect(await screen.findByText("report-1")).toBeInTheDocument();
    await userEvent.click(screen.getAllByRole("button", { name: "Open" })[1]);
    expect(await screen.findByText(/report-1 · EXECUTIVE_SUMMARY/)).toBeInTheDocument();
    expect(screen.getByText(/digest valid=true/)).toBeInTheDocument();
    expect(screen.getByText(/Sections unavailable:/)).toBeInTheDocument();
    expect(screen.getAllByText(/sla/i).length).toBeGreaterThan(0);

    await userEvent.click(screen.getByRole("button", { name: "Compare with current period" }));
    expect(await screen.findByText(/Comparison COMPARABLE/)).toBeInTheDocument();
    expect(screen.getByText(/interpolated=false/)).toBeInTheDocument();
    expect(screen.getByText(/V37 SLA backlog is unavailable in both periods/)).toBeInTheDocument();
    expect(screen.getAllByText("Governance audit integrity findings").length).toBeGreaterThan(0);

    expect(screen.getByText(/availability=OK/)).toBeInTheDocument();
    expect(screen.getByText(/fixed health thresholds=true/)).toBeInTheDocument();
    expect(screen.getByText(/never distributed externally/)).toBeInTheDocument();
  });

  it("keeps report generation, action assignment, and configuration writes admin-only", async () => {
    currentRole = "VIEWER";
    mockFetch(handler);
    render(<ExecutiveWorkspace />);

    expect(await screen.findByText("Executive governance command center")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Create action" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Generate report" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Append configuration" })).not.toBeInTheDocument();
    expect(
      screen.getByText("Configuration writes require the ADMIN role.")
    ).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Open" }).length).toBeGreaterThan(0);

    currentRole = "OPERATOR";
    render(<ExecutiveWorkspace />);
    expect(await screen.findAllByRole("button", { name: "Create action" })).toHaveLength(1);
    expect(screen.queryByRole("button", { name: "Generate report" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Append configuration" })).not.toBeInTheDocument();
  });

  it("shows explicit error and partial/unavailable states instead of stale or zero data", async () => {
    healthFails = true;
    currentRole = "OPERATOR";
    mockFetch(handler);
    render(<ExecutiveWorkspace />);

    expect(
      await screen.findByText(/Unavailable \(service_not_ready: health source offline\)/)
    ).toBeInTheDocument();
    expect(
      screen.getAllByText(/showing nothing rather than stale data/).length
    ).toBeGreaterThan(0);
    expect(screen.getByText(/3 of 4 applicable KPIs are available/)).toBeInTheDocument();
    expect(screen.getByText("V37 SLA backlog is unavailable.")).toBeInTheDocument();
    expect(screen.queryByText("No strategic actions match this filter.")).not.toBeInTheDocument();
  });
});
