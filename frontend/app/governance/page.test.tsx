import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import GovernancePage from "./page";

let currentRole = "ADMIN";

vi.mock("../../components/auth/AuthProvider", () => ({
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

const STATUS = {
  enabled: true,
  assurance: "LOCAL_GOVERNANCE_AUDIT_ONLY",
  policy_count: 1,
  evaluation_states: { ACTIVE: 1 },
  hold_states: { ACTIVE: 1, PENDING_APPROVAL: 1 },
  disposition_states: { REVIEW_REQUIRED: 1 },
  export_states: { PENDING_APPROVAL: 1 },
  audit_event_count: 1,
  audit_integrity: { checked: 1, verified: 1, outcome: "OK", assurance: "LOCAL_SELF_DIGEST_ONLY" },
  retention_scheduler: "DISABLED",
  automatic_deletion: false,
  automatic_hold_release: false,
  automatic_disposition_approval: false,
  regulatory_certification_claimed: false,
  external_immutable_storage_claimed: false,
  external_anchor_claimed: false,
  non_claims: ["No automatic physical evidence deletion is performed."],
  limitations: ["Retention evaluation is manual."],
};

const POLICY = {
  policy_id: "POL-DEFAULT",
  version: 2,
  name: "Default governance policy",
  state: "ENABLED",
  case_type: null,
  evidence_category: null,
  retention_days: 30,
  review_interval_days: 10,
  required_approval_level: "SINGLE_REVIEWER",
  export_allowed: true,
  export_requires_approval: true,
  allow_evidence_bytes: false,
  export_expiry_days: null,
  export_review_days: null,
  legal_hold_eligible: true,
  disposition_review_required: true,
  actor_id: "admin@example.com",
  actor_role: "ADMIN",
  reason: "Synthetic test policy.",
  idempotency_key: null,
  created_at: "2026-01-01T00:00:00Z",
  is_default: true,
};

const EVALUATION = {
  evaluation_id: "eval-1",
  case_id: "case-1",
  evaluation_kind: "EVALUATION",
  evaluation_version: 1,
  policy_id: "POL-DEFAULT",
  policy_version: 2,
  policy_snapshot: {},
  as_of: "2026-02-01",
  evaluated_at: "2026-02-01T00:00:00Z",
  retention_start: "2026-01-01T00:00:00Z",
  retention_deadline: "2026-03-03T00:00:00Z",
  next_review_at: "2026-02-11T00:00:00Z",
  governance_state: "REVIEW_DUE",
  data_status: "OK",
  disposition_eligible: true,
  integrity_status: "PASS",
  verification_id: "verification-1",
  legal_hold_ids: [],
  reasons: ["RETENTION_REVIEW_DUE"],
  reviewed_by: null,
  review_reason: null,
  created_by: "operator@example.com",
  request_id: "req-1",
  idempotency_key: null,
  created_at: "2026-02-01T00:00:00Z",
  deletion_authorized: false,
  deletion_note: "Retention state is not a deletion instruction.",
};

const HOLD = {
  hold_id: "hold-1",
  hold_number: "HOLD-2026-000001",
  case_id: "case-1",
  evidence_reference_id: null,
  status: "ACTIVE",
  scope: "case",
  reason: "Synthetic legal hold.",
  requested_by: "operator@example.com",
  requested_role: "OPERATOR",
  requested_at: "2026-01-01T00:00:00Z",
  approved_by: "admin@example.com",
  approved_at: "2026-01-01T00:00:01Z",
  approval_reason: "Synthetic approval.",
  rejected_by: null,
  rejected_at: null,
  rejection_reason: null,
  released_by: null,
  released_at: null,
  release_reason: null,
  withdrawn_by: null,
  withdrawn_at: null,
  withdrawal_reason: null,
  version: 2,
  idempotency_key: null,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:01Z",
  metadata: {},
};

const DISPOSITION = {
  disposition_id: "disp-1",
  request_number: "DISP-20260101-00000001",
  case_id: "case-1",
  evaluation_id: "eval-1",
  status: "REVIEW_REQUIRED",
  justification: "Synthetic disposition review.",
  requested_by: "operator@example.com",
  requested_role: "OPERATOR",
  requested_at: "2026-01-01T00:00:00Z",
  policy_id: "POL-DEFAULT",
  policy_version: 2,
  required_approval_level: "SINGLE_REVIEWER",
  approval_count: 0,
  reviewer_id: null,
  reviewed_at: null,
  decision_reason: null,
  blocked_reason_codes: [],
  version: 1,
  idempotency_key: null,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
  metadata: {},
  physical_deletion_performed: false,
  authorizes_future_process: false,
  disposition_approval_note: "Approval authorizes only a future process.",
};

const EXPORT = {
  approval_id: "approval-1",
  request_number: "EXPORT-20260101-00000001",
  case_id: "case-1",
  status: "PENDING_APPROVAL",
  reason: "Synthetic export request.",
  requested_by: "operator@example.com",
  requested_role: "OPERATOR",
  requested_at: "2026-01-01T00:00:00Z",
  policy_id: "POL-DEFAULT",
  policy_version: 2,
  include_evidence_bytes: false,
  required_approval_level: "SINGLE_REVIEWER",
  approved_by: null,
  approved_at: null,
  approval_reason: null,
  rejected_by: null,
  rejected_at: null,
  rejection_reason: null,
  withdrawn_by: null,
  withdrawn_at: null,
  withdrawal_reason: null,
  export_id: null,
  export_sha256: null,
  manifest_digest: null,
  root_digest: null,
  filename: null,
  size_bytes: null,
  file_count: null,
  generated_by: null,
  generated_at: null,
  generation_error: null,
  verified_by: null,
  verified_at: null,
  verification_outcome: "NOT_RUN",
  verification_detail: "",
  expires_at: null,
  review_at: null,
  version: 1,
  idempotency_key: null,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
  metadata: {},
  delivery_claimed: false,
  external_recipient_validated: false,
};

const AUDIT = {
  event_id: "audit-1",
  event_type: "EXPORT_REQUESTED",
  actor_id: "operator@example.com",
  actor_role: "OPERATOR",
  target_type: "EXPORT_APPROVAL",
  target_id: "approval-1",
  case_id: "case-1",
  outcome: "SUCCESS",
  reason: "Synthetic export request.",
  request_id: "req-1",
  occurred_at: "2026-01-01T00:00:00Z",
  event_key: "audit:export:approval-1:requested",
  event_hash: "a".repeat(64),
  metadata: {},
  created_at: "2026-01-01T00:00:00Z",
};

const REPORT = {
  generated_at: "2026-01-01T00:00:00Z",
  generated_by: "admin@example.com",
  as_of: "2026-01-01",
  scope: "SUMMARY",
  case_id: null,
  format: "json",
  assurance: "LOCAL_GOVERNANCE_AUDIT_ONLY",
  audit_assurance: "LOCAL_SELF_DIGEST_ONLY",
  overall_status: "REVIEW_REQUIRED",
  sections: {
    policy: { status: "PARTIAL", count: 1 },
    retention: { status: "OK", evaluated_cases: 1 },
    legal_holds: { status: "OK", blocking: 1 },
    dispositions: { status: "OK", open: 1, physical_deletion_performed: false },
    exports: { status: "OK", delivery_claimed: false },
    audit: { status: "OK", assurance: "LOCAL_SELF_DIGEST_ONLY" },
  },
  detail: null,
  regulatory_certification_claimed: false,
  external_immutable_storage_claimed: false,
  external_anchor_claimed: false,
  automatic_deletion: false,
  automatic_hold_release: false,
  automatic_disposition_approval: false,
  non_claims: ["No automatic physical evidence deletion is performed."],
  limitations: ["Retention evaluation is manual."],
};

function handler(url: string): unknown {
  if (url.includes("/api/v1/governance/status")) return STATUS;
  if (url.includes("/api/v1/governance/policies")) {
    return { items: [POLICY], total: 1, page: 1, page_size: 50 };
  }
  if (url.includes("/api/v1/governance/retention/queue")) {
    return {
      items: [EVALUATION],
      total: 1,
      page: 1,
      page_size: 50,
      as_of: "2026-02-01",
      non_claims: [],
    };
  }
  if (url.includes("/api/v1/governance/holds")) {
    return { items: [HOLD], total: 1, page: 1, page_size: 50 };
  }
  if (url.includes("/api/v1/governance/dispositions")) {
    return { items: [DISPOSITION], total: 1, page: 1, page_size: 50 };
  }
  if (url.includes("/api/v1/governance/exports")) {
    return { items: [EXPORT], total: 1, page: 1, page_size: 50 };
  }
  if (url.includes("/api/v1/governance/audit")) {
    return {
      items: [AUDIT],
      total: 1,
      page: 1,
      page_size: 50,
      assurance: "LOCAL_SELF_DIGEST_ONLY",
      non_claims: [],
    };
  }
  if (url.includes("/api/v1/governance/reports/compliance")) return REPORT;
  return new Error(`unexpected request: ${url}`);
}

describe("GovernancePage", () => {
  beforeEach(() => {
    currentRole = "ADMIN";
    vi.restoreAllMocks();
  });

  it("renders overview, policy versions, queues, audit, and readiness report", async () => {
    mockFetch(handler);
    render(<GovernancePage />);

    expect(await screen.findByText("Governance & Compliance Readiness")).toBeInTheDocument();
    expect(await screen.findByText(/Default governance policy/)).toBeInTheDocument();
    expect(screen.getByText(/version 2/)).toBeInTheDocument();
    expect(screen.getByText(/retention 30 days/)).toBeInTheDocument();
    expect(screen.getByText("REVIEW_DUE")).toBeInTheDocument();
    expect(screen.getByText("HOLD-2026-000001")).toBeInTheDocument();
    expect(screen.getByText("DISP-20260101-00000001")).toBeInTheDocument();
    expect(screen.getByText("EXPORT-20260101-00000001")).toBeInTheDocument();
    expect(screen.getByText("EXPORT_REQUESTED")).toBeInTheDocument();
    expect(screen.getAllByText("REVIEW_REQUIRED").length).toBeGreaterThan(0);
    expect(screen.getByText(/No automatic physical evidence deletion/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create policy" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Release hold" })).toBeInTheDocument();
  });

  it("hides audit and policy writes from viewers while keeping read-only queues", async () => {
    currentRole = "VIEWER";
    mockFetch(handler);
    render(<GovernancePage />);

    expect(await screen.findByText("Governance & Compliance Readiness")).toBeInTheDocument();
    expect(await screen.findByText("HOLD-2026-000001")).toBeInTheDocument();
    expect(screen.getByText(/Access audit history requires an administrator/)).toBeInTheDocument();
    expect(screen.getByText(/Policy changes require an administrator/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Create policy" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Approve hold" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Evaluate retention" })).not.toBeInTheDocument();
  });

  it("confirms a sensitive hold release with a required reason", async () => {
    mockFetch(handler);
    render(<GovernancePage />);

    await userEvent.click(await screen.findByRole("button", { name: "Release hold" }));
    expect(screen.getByText(/Release requires an explicit reason/)).toBeInTheDocument();
    const confirm = screen.getByRole("button", { name: "Confirm release" });
    expect(confirm).toBeDisabled();
    await userEvent.type(screen.getByLabelText("Release hold reason"), "Synthetic release.");
    expect(confirm).toBeEnabled();
  });
});
