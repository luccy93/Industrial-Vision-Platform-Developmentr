import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { IntelligenceWorkspace } from "./IntelligenceWorkspace";

let currentRole = "ADMIN";
let compareMode: "COMPARED" | "INCOMPATIBLE" | "INTEGRITY_FAILED" = "COMPARED";

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

const COUNTS = {
  total: 1,
  by_status: { OPEN: 1, ACKNOWLEDGED: 0, DISMISSED: 0, RESOLVED: 0 },
  by_severity: { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 0 },
  by_status_severity: { OPEN: { CRITICAL: 1 } },
};

const STATUS = {
  enabled: true,
  assurance: "DETERMINISTIC_LOCAL_RULES_ONLY",
  model: { model_id: "RISK-DEFAULT", version: 1, name: "Default", state: "ACTIVE" },
  sla_targets: [
    {
      target_key: "RETENTION_REVIEW",
      version: 1,
      target_hours: 720,
      warning_hours: 168,
      effective_from: "1970-01-01T00:00:00Z",
    },
  ],
  recommendation_counts: COUNTS,
  scheduled_intelligence: false,
  scheduled_intelligence_note:
    "V37 computes intelligence on demand; no intelligence scheduler is started.",
  alerts_enabled: false,
  generated_at: "2026-11-14T12:00:00Z",
  non_claims: ["Risk scores are deterministic prioritization aids, not probabilities."],
  limitations: ["No LLM or external AI service makes a governance decision."],
};

const RISK_LIST = {
  items: [
    {
      case_id: "case-1",
      case_number: "CASE-1",
      case_status: "OPEN",
      case_severity: "CRITICAL",
      score: 88,
      risk_level: "CRITICAL",
      data_completeness: "PARTIAL",
      top_factors: ["CONFIRMED_INTEGRITY_FAILURE"],
      model_version: 1,
      calculated_at: "2026-11-14T12:00:00Z",
    },
  ],
  total: 1,
  page: 1,
  page_size: 10,
  risk_level_counts: { LOW: 0, MODERATE: 0, HIGH: 0, CRITICAL: 1 },
  model: { model_id: "RISK-DEFAULT", version: 1 },
  truncated: false,
  unavailable_case_count: 0,
  partial: false,
  assurance: "DETERMINISTIC_LOCAL_RULES_ONLY",
  non_claims: ["Risk scores are deterministic prioritization aids, not probabilities."],
};

const RISK_DETAIL = {
  risk: {
    case_id: "case-1",
    case_number: "CASE-1",
    case_status: "OPEN",
    case_severity: "CRITICAL",
    score: 88,
    risk_level: "CRITICAL",
    score_available: true,
    data_completeness: "PARTIAL",
    model_id: "RISK-DEFAULT",
    model_version: 1,
    policy_context: { policy_id: "policy-1", version: 2 },
    factors: [
      {
        factor_id: "CONFIRMED_INTEGRITY_FAILURE",
        label: "Confirmed integrity failure",
        points: 45,
        reason: "Confirmed integrity verification failure.",
        source_refs: ["forensic_verification:ver-1"],
        data_status: "AVAILABLE",
        suppressed: false,
        suppressed_by: null,
        suppression_reason: null,
      },
      {
        factor_id: "CASE_SEVERITY_CRITICAL",
        label: "Critical case severity",
        points: 0,
        reason: "Correlated with the confirmed integrity failure.",
        source_refs: ["case:case-1"],
        data_status: "AVAILABLE",
        suppressed: true,
        suppressed_by: "CONFIRMED_INTEGRITY_FAILURE",
        suppression_reason: "Avoids double-counting a correlated factor.",
      },
    ],
    missing_data: [
      {
        source: "retention_evaluation",
        status: "UNAVAILABLE",
        message: "Retention history could not be read; no failure is claimed.",
      },
    ],
    calculated_at: "2026-11-14T12:00:00Z",
    sla_context: {},
    non_claims: ["Risk scores are deterministic prioritization aids, not probabilities."],
  },
  assurance: "DETERMINISTIC_LOCAL_RULES_ONLY",
  non_claims: ["Risk scores are deterministic prioritization aids, not probabilities."],
};

const SLA_CALCULATION = {
  target_key: "RETENTION_REVIEW",
  sla_kind: "OPERATIONAL",
  source_ref: "governance_retention_evaluation:eval-1",
  computed_at: "2026-11-14T12:00:00Z",
  non_claim: "Operational SLA targets are not legal or regulatory deadlines.",
  target_version: 1,
  target_hours: 720,
  warning_hours: 168,
  target_effective_from: "1970-01-01T00:00:00Z",
  start_at: "2026-10-01T00:00:00Z",
  due_at: "2026-10-31T00:00:00Z",
  warning_at: "2026-10-24T00:00:00Z",
  resolution_at: null,
  elapsed_hours: 1000,
  open_age_hours: 1000,
  duration_hours: null,
  resolved: false,
  state: "BREACHED",
  reason: "Open age exceeds the operational target.",
};

const SLA_BACKLOG = {
  items: [
    {
      item_type: "RETENTION_REVIEW",
      item_id: "eval-1",
      case_id: "case-1",
      label: "Retention review",
      sla: SLA_CALCULATION,
    },
  ],
  total: 1,
  page: 1,
  page_size: 10,
  state_counts: { RETENTION_REVIEW: { BREACHED: 1 } },
  availability: {
    retention: { availability: "OK", message: "" },
    disposition: { availability: "UNAVAILABLE", message: "Disposition store unavailable." },
    legal_hold: { availability: "OK", message: "" },
    export_approval: { availability: "OK", message: "" },
  },
  partial: true,
  truncated: false,
  unavailable_sources: ["disposition"],
  sla_kind: "OPERATIONAL",
  non_claim: "Operational SLA targets are not legal or regulatory deadlines.",
  non_claims: ["Risk scores are deterministic prioritization aids, not probabilities."],
};

function trendBucket(start: string, count: number | null, coverage: string) {
  return {
    bucket_start: start,
    bucket_end: start,
    count,
    in_coverage: count === null ? null : true,
    coverage,
    partial_coverage: false,
  };
}

const TRENDS = {
  start_at: "2026-11-01T00:00:00Z",
  end_at: "2026-11-03T00:00:00Z",
  bucket: "day",
  timezone: "UTC",
  source_order: [
    "governance_events",
    "retention_evaluations",
    "recommendations",
    "sla_inflow",
    "risk_scores",
  ],
  sources: {
    governance_events: {
      availability: "OK",
      message: "",
      definition: "Governance access-audit events.",
      coverage_start: null,
      coverage_available: true,
      no_history: true,
      truncated: false,
      total: 0,
      categories: ["ACCESS"],
      category_totals: { ACCESS: null },
      buckets: [
        trendBucket("2026-11-01T00:00:00Z", null, "NO_HISTORY"),
        trendBucket("2026-11-02T00:00:00Z", null, "NO_HISTORY"),
      ],
    },
    retention_evaluations: {
      availability: "OK",
      message: "",
      definition: "Retention evaluation observations.",
      coverage_start: null,
      coverage_available: true,
      no_history: true,
      truncated: false,
      total: 0,
      categories: ["RETENTION"],
      category_totals: { RETENTION: null },
      buckets: [trendBucket("2026-11-01T00:00:00Z", null, "NO_HISTORY")],
    },
    recommendations: {
      availability: "OK",
      message: "",
      definition: "Recommendation lifecycle events.",
      coverage_start: "2026-11-01T00:00:00Z",
      coverage_available: true,
      no_history: false,
      truncated: false,
      total: 1,
      categories: ["CREATED"],
      category_totals: { CREATED: 1 },
      buckets: [trendBucket("2026-11-01T00:00:00Z", 1, "IN_COVERAGE")],
    },
    sla_inflow: {
      availability: "OK",
      message: "",
      definition: "Operational SLA inflow observations.",
      coverage_start: null,
      coverage_available: true,
      no_history: true,
      truncated: false,
      total: 0,
      categories: ["RETENTION_REVIEW"],
      category_totals: { RETENTION_REVIEW: null },
      buckets: [trendBucket("2026-11-01T00:00:00Z", null, "NO_HISTORY")],
    },
    risk_scores: {
      availability: "UNAVAILABLE",
      message: "Historical risk scores are not persisted.",
      definition: "Historical risk-score observations.",
      coverage_start: null,
      coverage_available: false,
      no_history: false,
      truncated: false,
      total: 0,
      categories: [],
      category_totals: {},
      buckets: [trendBucket("2026-11-01T00:00:00Z", null, "UNKNOWN")],
    },
  },
  coverage: {
    available: true,
    message: "",
    earliest: { governance_audit: null },
  },
  partial: true,
  truncated: false,
  unavailable_sources: ["risk_scores"],
  degraded_sources: [],
  assurance: "DETERMINISTIC_LOCAL_RULES_ONLY",
  limitations: ["No forecast or statistical model is used."],
  non_claims: ["Risk scores are deterministic prioritization aids, not probabilities."],
};

const RECOMMENDATION = {
  recommendation_id: "rec-1",
  recommendation_key: "GOV-RISK-001|CASE|case-1",
  rule_id: "GOV-RISK-001",
  scope_type: "CASE",
  scope_id: "case-1",
  case_id: "case-1",
  severity: "CRITICAL",
  risk_level: "CRITICAL",
  title: "Review a critical governance risk case",
  rationale: "A deterministic critical risk condition is present.",
  source_refs: ["risk_case:case-1"],
  status: "OPEN",
  version: 1,
  first_seen_at: "2026-11-14T12:00:00Z",
  last_evaluated_at: "2026-11-14T12:00:00Z",
  acknowledged_by: null,
  acknowledged_at: null,
  acknowledgement_reason: null,
  dismissed_by: null,
  dismissed_at: null,
  dismissal_reason: null,
  resolved_by: null,
  resolved_at: null,
  resolution_reason: null,
  created_at: "2026-11-14T12:00:00Z",
  updated_at: "2026-11-14T12:00:00Z",
};

const RECOMMENDATIONS = {
  items: [RECOMMENDATION],
  total: 1,
  page: 1,
  page_size: 10,
  counts: COUNTS,
  assurance: "DETERMINISTIC_LOCAL_RULES_ONLY",
  non_claims: ["Recommendations are advisory only."],
};

const RECOMMENDATION_DETAIL = {
  recommendation: RECOMMENDATION,
  events: [
    {
      event_id: "event-1",
      recommendation_id: "rec-1",
      event_type: "CREATED",
      from_status: null,
      to_status: "OPEN",
      actor_id: null,
      actor_role: null,
      reason: "Deterministic rule matched.",
      detail: {},
      created_at: "2026-11-14T12:00:00Z",
    },
  ],
  assurance: "DETERMINISTIC_LOCAL_RULES_ONLY",
  non_claims: ["Recommendations are advisory only."],
};

const REFRESH = {
  summary: {
    created: 0,
    refreshed: 1,
    reopened: 0,
    auto_resolved: 0,
    suppressed: 0,
    truncated: false,
    created_ids: [],
    reopened_ids: [],
  },
  counts: COUNTS,
  alerts: { enabled: false, notified: 0 },
  sources: { cases: { availability: "OK", message: "" } },
  partial: false,
  truncated: false,
  unavailable_sources: [],
  degraded_sources: [],
  assurance: "DETERMINISTIC_LOCAL_RULES_ONLY",
  non_claims: ["Recommendations are advisory only."],
};

function snapshot(snapshotId: string, asOf: string) {
  return {
    snapshot_id: snapshotId,
    snapshot_type: "INTELLIGENCE_SUMMARY",
    as_of: asOf,
    generated_at: asOf,
    generated_by: "operator@example.com",
    job_id: null,
    trigger: "MANUAL",
    dedup_key: `intelligence:${snapshotId}`,
    payload_digest: "a".repeat(64),
    digest_valid: true,
    row_count: 2,
    schema_version: 1,
  };
}

const SNAPSHOT_LIST = {
  items: [
    snapshot("snap-1", "2026-11-14T10:00:00Z"),
    snapshot("snap-2", "2026-11-14T11:00:00Z"),
  ],
  total: 2,
  page: 1,
  page_size: 20,
  availability: "OK",
  message: "",
  assurance: "DETERMINISTIC_LOCAL_RULES_ONLY",
  non_claims: ["Snapshots are local aggregate records, not regulatory certification."],
};

const SNAPSHOT_DETAIL = {
  snapshot: { ...snapshot("snap-1", "2026-11-14T10:00:00Z"), payload: { risk: {} } },
  integrity: {
    state: "VALID",
    digest_valid: true,
    message: "The stored payload matches its self-digest.",
  },
  assurance: "DETERMINISTIC_LOCAL_RULES_ONLY",
  non_claims: ["Snapshots are local aggregate records, not regulatory certification."],
};

function comparison() {
  if (compareMode === "INCOMPATIBLE") {
    return {
      snapshot_id: "snap-1",
      other_snapshot_id: "snap-2",
      snapshot_type: "INTELLIGENCE_SUMMARY",
      other_snapshot_type: "COMPLIANCE_SUMMARY",
      schema_version: 1,
      other_schema_version: 1,
      status: "INCOMPATIBLE",
      comparable: false,
      tampered_snapshot_ids: [],
      diff: null,
      changes: [],
      summary: { added: 0, removed: 0, changed: 0, total: 0 },
      truncated: false,
      message: "Snapshots have a different type or schema version and cannot be compared.",
      assurance: "DETERMINISTIC_LOCAL_RULES_ONLY",
      non_claims: [],
    };
  }
  if (compareMode === "INTEGRITY_FAILED") {
    return {
      snapshot_id: "snap-1",
      other_snapshot_id: "snap-2",
      snapshot_type: "INTELLIGENCE_SUMMARY",
      other_snapshot_type: "INTELLIGENCE_SUMMARY",
      schema_version: 1,
      other_schema_version: 1,
      status: "INTEGRITY_FAILED",
      comparable: false,
      tampered_snapshot_ids: ["snap-1"],
      diff: null,
      changes: [],
      summary: { added: 0, removed: 0, changed: 0, total: 0 },
      truncated: false,
      message:
        "At least one snapshot payload does not match its stored self-digest. No diff is produced and both snapshots are preserved for investigation.",
      assurance: "DETERMINISTIC_LOCAL_RULES_ONLY",
      non_claims: [],
    };
  }
  return {
    snapshot_id: "snap-1",
    other_snapshot_id: "snap-2",
    snapshot_type: "INTELLIGENCE_SUMMARY",
    other_snapshot_type: "INTELLIGENCE_SUMMARY",
    schema_version: 1,
    other_schema_version: 1,
    status: "COMPARED",
    comparable: true,
    tampered_snapshot_ids: [],
    diff: {
      changes: [
        {
          path: "risk.total_cases",
          change: "CHANGED",
          before: 2,
          after: 3,
        },
      ],
      truncated: false,
    },
    changes: [
      {
        path: "risk.total_cases",
        change: "CHANGED",
        before: 2,
        after: 3,
      },
    ],
    summary: { added: 0, removed: 0, changed: 1, total: 1 },
    truncated: false,
    message:
      "Local aggregate comparison only. This is not regulatory certification and the snapshots are not externally anchored.",
    assurance: "DETERMINISTIC_LOCAL_RULES_ONLY",
    non_claims: [],
  };
}

function handler(url: string, init?: RequestInit): unknown {
  const method = String(init?.method ?? "GET").toUpperCase();
  if (url.includes("/api/v1/governance/intelligence/status")) return STATUS;
  if (url.includes("/api/v1/governance/intelligence/risk/cases/")) return RISK_DETAIL;
  if (url.includes("/api/v1/governance/intelligence/risk/cases")) return RISK_LIST;
  if (url.includes("/api/v1/governance/intelligence/sla/backlog")) return SLA_BACKLOG;
  if (url.includes("/api/v1/governance/intelligence/trends")) return TRENDS;
  if (url.includes("/recommendations/refresh")) return REFRESH;
  if (url.includes("/acknowledge")) {
    return {
      ...RECOMMENDATION_DETAIL,
      recommendation: { ...RECOMMENDATION, status: "ACKNOWLEDGED", version: 2 },
    };
  }
  if (url.includes("/dismiss")) {
    return {
      ...RECOMMENDATION_DETAIL,
      recommendation: {
        ...RECOMMENDATION,
        status: "DISMISSED",
        version: 2,
        dismissal_reason: "Duplicate of an existing review task.",
      },
    };
  }
  if (url.includes("/api/v1/governance/intelligence/recommendations/")) {
    return RECOMMENDATION_DETAIL;
  }
  if (url.includes("/api/v1/governance/intelligence/recommendations")) return RECOMMENDATIONS;
  if (url.includes("/compare/")) return comparison();
  if (url.includes("/api/v1/governance/intelligence/snapshots/")) return SNAPSHOT_DETAIL;
  if (url.includes("/api/v1/governance/intelligence/snapshots")) {
    if (method === "POST") {
      return {
        snapshot: snapshot("snap-generated", "2026-11-14T12:00:00Z"),
        replayed: false,
        availability: "OK",
        assurance: "DETERMINISTIC_LOCAL_RULES_ONLY",
        non_claims: [],
      };
    }
    return SNAPSHOT_LIST;
  }
  return new Error(`unexpected request: ${url}`);
}

function fetchCalls(): Array<[string, RequestInit | undefined]> {
  return (global.fetch as ReturnType<typeof vi.fn>).mock.calls.map(([url, init]) => [
    String(url),
    init as RequestInit | undefined,
  ]);
}

describe("IntelligenceWorkspace", () => {
  beforeEach(() => {
    currentRole = "ADMIN";
    compareMode = "COMPARED";
    vi.restoreAllMocks();
  });

  it("renders status, explainable risk, SLA backlog, trends, recommendations, and snapshots", async () => {
    mockFetch(handler);
    render(<IntelligenceWorkspace />);

    expect(await screen.findByText("Governance intelligence")).toBeInTheDocument();
    expect(screen.getAllByText("ENABLED").length).toBeGreaterThan(0);
    expect(screen.getByText("Scheduled intelligence")).toBeInTheDocument();
    expect(screen.getAllByText("RETENTION_REVIEW").length).toBeGreaterThan(0);
    expect(screen.getAllByText(/not legal or regulatory/).length).toBeGreaterThan(0);

    expect(await screen.findByText("CASE-1")).toBeInTheDocument();
    expect(screen.getByText("88")).toBeInTheDocument();
    expect(screen.getAllByText("CRITICAL").length).toBeGreaterThan(0);
    expect(screen.getByText("Risk prioritization")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "View factors" }));
    expect(await screen.findByText(/Confirmed integrity verification failure/)).toBeInTheDocument();
    expect(screen.getByText(/suppressed by CONFIRMED_INTEGRITY_FAILURE/)).toBeInTheDocument();
    expect(screen.getByText("Missing or unavailable data")).toBeInTheDocument();
    expect(screen.getByText(/policy-1/)).toBeInTheDocument();

    expect(screen.getByText("Retention review")).toBeInTheDocument();
    expect(screen.getAllByText("BREACHED").length).toBeGreaterThan(0);
    expect(screen.getByText(/unresolved; no duration claimed/)).toBeInTheDocument();
    expect(screen.getByText(/Disposition store unavailable/)).toBeInTheDocument();

    expect(screen.getByText("Bounded historical trends")).toBeInTheDocument();
    expect(screen.getByText(/Historical risk scores are not persisted/)).toBeInTheDocument();
    expect(screen.getByText(/never as zero/)).toBeInTheDocument();
    expect(screen.getByText(/no forecast or statistical model/i)).toBeInTheDocument();

    expect(screen.getByText("Advisory recommendations")).toBeInTheDocument();
    expect(screen.getByText("GOV-RISK-001")).toBeInTheDocument();
    expect(screen.getByText("Review a critical governance risk case")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "View" }));
    expect(await screen.findByText("CREATED")).toBeInTheDocument();
    expect(screen.getByText(/risk_case:case-1/)).toBeInTheDocument();

    expect(screen.getByText("Intelligence snapshots and comparison")).toBeInTheDocument();
    expect(screen.getByText(/not regulatory certification/)).toBeInTheDocument();
    await userEvent.click(screen.getAllByRole("button", { name: "View integrity" })[0]);
    expect(await screen.findByText(/Snapshot snap-1 · VALID/)).toBeInTheDocument();
    expect(screen.getByText(/matches its self-digest/)).toBeInTheDocument();
  });

  it("keeps refresh, acknowledgement, dismissal, and generation away from viewers", async () => {
    currentRole = "VIEWER";
    mockFetch(handler);
    render(<IntelligenceWorkspace />);

    expect(await screen.findByText("Governance intelligence")).toBeInTheDocument();
    expect(
      await screen.findByText(/Refresh and acknowledgement require an operator or administrator/)
    ).toBeInTheDocument();
    expect(screen.getByText(/Snapshot generation requires an operator/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Refresh recommendations" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Acknowledge" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Dismiss" })).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Generate intelligence snapshot" })
    ).not.toBeInTheDocument();
    // Read-only inspection stays available.
    expect(screen.getByRole("button", { name: "View factors" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "View" })).toBeInTheDocument();
  });

  it("requires an explicit reason before dismissing and sends the expected version", async () => {
    mockFetch(handler);
    render(<IntelligenceWorkspace />);

    await userEvent.click(await screen.findByRole("button", { name: "Dismiss" }));
    expect(screen.getByText(/Dismissal suppresses this recommendation/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Confirm dismiss" })).toBeDisabled();
    await userEvent.type(
      screen.getByLabelText("Dismissal reason (required)"),
      "Duplicate of an existing review task."
    );
    await userEvent.click(screen.getByRole("button", { name: "Confirm dismiss" }));

    expect(
      await screen.findByText("Recommendation GOV-RISK-001 dismissed.")
    ).toBeInTheDocument();
    await waitFor(() => {
      const post = fetchCalls().find(([url]) => url.includes("/recommendations/rec-1/dismiss"));
      expect(post).toBeTruthy();
      expect(JSON.parse(String(post?.[1]?.body))).toMatchObject({
        reason: "Duplicate of an existing review task.",
        expected_version: 1,
      });
    });
  });

  it("acknowledges and refreshes only with a reason", async () => {
    mockFetch(handler);
    render(<IntelligenceWorkspace />);

    await userEvent.click(await screen.findByRole("button", { name: "Acknowledge" }));
    await userEvent.type(screen.getByLabelText("Acknowledgement note"), "Operator triage.");
    await userEvent.click(screen.getByRole("button", { name: "Confirm acknowledge" }));
    expect(
      await screen.findByText("Recommendation GOV-RISK-001 acknowledged.")
    ).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Refresh recommendations" }));
    await userEvent.type(screen.getByLabelText("Refresh reason"), "Synthetic operator refresh.");
    await userEvent.click(screen.getByRole("button", { name: "Confirm refresh" }));
    expect(
      await screen.findByText(/Refresh created 0, refreshed 1, reopened 0/)
    ).toBeInTheDocument();
    await waitFor(() => {
      expect(
        fetchCalls().some(([url]) => url.includes("/recommendations/refresh"))
      ).toBe(true);
    });
  });

  it("generates a snapshot with an idempotency key and reason", async () => {
    mockFetch(handler);
    render(<IntelligenceWorkspace />);

    await userEvent.click(
      await screen.findByRole("button", { name: "Generate intelligence snapshot" })
    );
    await userEvent.type(screen.getByLabelText("Snapshot reason"), "Synthetic local snapshot.");
    await userEvent.click(screen.getByRole("button", { name: "Confirm snapshot" }));

    expect(await screen.findByText("Intelligence snapshot generated.")).toBeInTheDocument();
    const post = fetchCalls().find(
      ([url, init]) =>
        url.includes("/intelligence/snapshots") &&
        String(init?.method).toUpperCase() === "POST"
    );
    expect(post).toBeTruthy();
    const body = JSON.parse(String(post?.[1]?.body));
    expect(body.reason).toBe("Synthetic local snapshot.");
    expect(body.idempotency_key).toMatch(/^ui-intelligence-snapshot-/);
  });

  it("compares compatible snapshots and reports aggregate changes", async () => {
    mockFetch(handler);
    render(<IntelligenceWorkspace />);

    await userEvent.click(await screen.findByLabelText("Left snapshot snap-1"));
    await userEvent.click(screen.getByLabelText("Right snapshot snap-2"));
    await userEvent.click(screen.getByRole("button", { name: "Compare selected snapshots" }));

    expect(await screen.findByText("Comparison: COMPARED")).toBeInTheDocument();
    expect(screen.getByText(/Added 0 · removed 0 · changed 1/)).toBeInTheDocument();
    expect(screen.getByText("risk.total_cases")).toBeInTheDocument();
    expect(screen.getAllByText(/not externally anchored/).length).toBeGreaterThan(0);
  });

  it("never diffs incompatible or tampered snapshots", async () => {
    compareMode = "INCOMPATIBLE";
    mockFetch(handler);
    render(<IntelligenceWorkspace />);

    await userEvent.click(await screen.findByLabelText("Left snapshot snap-1"));
    await userEvent.click(screen.getByLabelText("Right snapshot snap-2"));
    await userEvent.click(screen.getByRole("button", { name: "Compare selected snapshots" }));
    expect(await screen.findByText("Comparison: INCOMPATIBLE")).toBeInTheDocument();
    expect(
      screen.getByText(/different type or schema version and cannot be compared/)
    ).toBeInTheDocument();
    expect(screen.queryByText("risk.total_cases")).not.toBeInTheDocument();

    compareMode = "INTEGRITY_FAILED";
    await userEvent.click(screen.getByRole("button", { name: "Compare selected snapshots" }));
    expect(await screen.findByText("Comparison: INTEGRITY_FAILED")).toBeInTheDocument();
    expect(screen.getByText(/Tampered snapshot ids: snap-1/)).toBeInTheDocument();
    expect(screen.getByText(/preserved for investigation/)).toBeInTheDocument();
    expect(screen.queryByText("risk.total_cases")).not.toBeInTheDocument();
  });

  it("isolates one failing section so the rest keep rendering", async () => {
    mockFetch((url, init) => {
      if (url.includes("/intelligence/trends")) {
        return new Error("trend store unavailable");
      }
      return handler(url, init);
    });
    render(<IntelligenceWorkspace />);

    expect(await screen.findByText(/trend store unavailable/)).toBeInTheDocument();
    expect(screen.getByText("Governance intelligence")).toBeInTheDocument();
    expect(screen.getByText("Risk prioritization")).toBeInTheDocument();
    expect(screen.getByText("Advisory recommendations")).toBeInTheDocument();
    expect(screen.getByText("CASE-1")).toBeInTheDocument();
  });

  it("never renders destructive controls or delete requests", async () => {
    mockFetch(handler);
    render(<IntelligenceWorkspace />);
    await screen.findByText("Governance intelligence");

    expect(screen.queryByRole("button", { name: /delete/i })).not.toBeInTheDocument();
    expect(screen.queryByText(/Delete recommendation/i)).not.toBeInTheDocument();
    expect(
      fetchCalls().every(([url, init]) => {
        const method = String(init?.method ?? "GET").toUpperCase();
        return method !== "DELETE" && !url.includes("DELETE");
      })
    ).toBe(true);
  });
});
