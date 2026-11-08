import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import IntegrityPage from "./page";

vi.mock("../../components/auth/AuthProvider", () => ({
  useAuth: () => ({
    hasRole: (role: string) => role === "ADMIN" || role === "OPERATOR",
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

const RUN = {
  audit_run_id: "audit-1",
  trigger: "MANUAL",
  requested_scopes: ["TRANSPARENCY_LOG"],
  completed_scopes: ["TRANSPARENCY_LOG"],
  status: "PASS",
  started_at: "2026-01-01T00:00:00Z",
  completed_at: "2026-01-01T00:00:01Z",
  duration_ms: 12,
  cancelled: false,
  timed_out: false,
  retry_count: 0,
  artifacts_checked: 3,
  finding_counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
  reason_code_counts: {},
  error_summary: null,
  external_anchor_configured: false,
  assurance: "LOCAL_VERIFIED",
  requested_by: "admin@example.com",
  created_at: "2026-01-01T00:00:00Z",
  schedule_slot: null,
};

const STATUS = {
  enabled: true,
  store_status: "AVAILABLE",
  store_error: null,
  latest_audit: RUN,
  last_success: RUN,
  last_failure: null,
  running_audits: 0,
  total_audits: 1,
  total_audited_artifacts: 3,
  verified_evidence_count: 0,
  verified_checkpoint_count: 0,
  verified_tree_head_count: 2,
  open_findings: 1,
  findings_by_severity: { HIGH: 1 },
  trust: {
    trusted_key_count: 1,
    active_key_count: 1,
    expired_key_count: 0,
    revoked_key_count: 0,
    unknown_key_count: 0,
    evidence_trust_state: "MISSING",
    transparency_trust_state: "PRESENT",
    latest_tree_head_size: 3,
    latest_tree_head_digest: "abc123",
    latest_tree_head_id: "head-3",
    external_anchor_status: "NOT_CONFIGURED",
    external_anchor_detail: "No external transparency provider is configured.",
    assurance: "LOCAL_VERIFIED",
    limitations: ["Local verification only; no external anchoring."],
  },
  scheduler: {
    enabled: false,
    state: "STOPPED",
    interval_seconds: 300,
    last_heartbeat: null,
    last_cycle_at: null,
    last_success_at: null,
    last_error: null,
  },
  external_anchor_configured: false,
  assurance: "LOCAL_VERIFIED",
  generated_at: "2026-01-01T00:00:02Z",
};

const FINDING = {
  finding_id: "finding-1",
  audit_run_id: "audit-1",
  scope: "TRANSPARENCY_LOG",
  severity: "HIGH",
  reason_code: "TREE_HEAD_SIGNATURE_INVALID",
  artifact_id: "head-3",
  detected_at: "2026-01-01T00:00:01Z",
  explanation: "Tree head signature verification failed.",
  verification_source: "V32 transparency verifier",
  recommended_action: "Inspect the signing key and re-issue the tree head.",
};

const DETAIL = {
  audit: RUN,
  scope_results: [
    {
      audit_run_id: "audit-1",
      scope: "TRANSPARENCY_LOG",
      status: "FAIL",
      started_at: "2026-01-01T00:00:00Z",
      completed_at: "2026-01-01T00:00:01Z",
      duration_ms: 12,
      artifacts_checked: 3,
      checks_total: 4,
      checks_failed: 1,
      findings_count: 1,
      reason_codes: ["TREE_HEAD_SIGNATURE_INVALID"],
      error_summary: null,
      truncated: false,
      details: {},
    },
  ],
  findings: [FINDING],
  findings_total: 1,
};

function healthyFetch(overrides: { audits?: unknown; findings?: unknown } = {}) {
  mockFetch((url: string, init?: RequestInit) => {
    if (url.includes("/integrity/status")) return STATUS;
    if (url.includes("/integrity/summary")) return { total_runs: 1 };
    if (url.includes("/integrity/audits/") && init?.method === "POST") {
      return { ...RUN, status: "FAIL", scope_results: DETAIL.scope_results, findings: [FINDING] };
    }
    if (url.includes("/integrity/audits/")) return DETAIL;
    if (url.includes("/integrity/audits")) {
      return (
        overrides.audits ?? {
          items: [RUN],
          total: 1,
          page: 1,
          page_size: 20,
          pages: 1,
        }
      );
    }
    if (url.includes("/integrity/findings")) {
      return (
        overrides.findings ?? {
          items: [FINDING],
          total: 1,
          page: 1,
          page_size: 20,
          pages: 1,
        }
      );
    }
    throw new Error(`unexpected ${url}`);
  });
}

describe("IntegrityPage", () => {
  it("renders the audit overview, trust boundary, and findings", async () => {
    healthyFetch();
    try {
      render(<IntegrityPage />);
      await waitFor(() => {
        expect(screen.getByText(/Continuous Integrity Monitoring/)).toBeInTheDocument();
        expect(screen.getByText(/TREE_HEAD_SIGNATURE_INVALID/)).toBeInTheDocument();
      });
      expect(screen.getByText(/No external transparency provider is configured/)).toBeInTheDocument();
      expect(screen.getByText(/size 3/)).toBeInTheDocument();
      expect(screen.getAllByText(/LOCAL_VERIFIED/).length).toBeGreaterThanOrEqual(1);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("shows genuine empty states instead of fabricating history", async () => {
    healthyFetch({
      audits: { items: [], total: 0, page: 1, page_size: 20, pages: 0 },
      findings: { items: [], total: 0, page: 1, page_size: 20, pages: 0 },
    });
    try {
      render(<IntegrityPage />);
      await waitFor(() => {
        expect(screen.getByText(/No findings recorded/)).toBeInTheDocument();
        expect(screen.getByText(/No audits recorded yet/)).toBeInTheDocument();
      });
      expect(screen.queryByText(/sample|demo/i)).not.toBeInTheDocument();
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("runs a bounded audit and reports a non-pass honestly", async () => {
    healthyFetch();
    try {
      render(<IntegrityPage />);
      const user = userEvent.setup();
      await waitFor(() => expect(screen.getByRole("button", { name: "Run audit" })).toBeEnabled());
      await user.click(screen.getByRole("button", { name: "Run audit" }));
      await waitFor(() => {
        expect(screen.getByText(/Not a clean pass/)).toBeInTheDocument();
      });
      expect(screen.getByText(/FAIL/)).toBeInTheDocument();
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("reports an unavailable status without faking a pass", async () => {
    mockFetch((url: string) => {
      if (url.includes("/integrity/status")) return new Error("store unavailable");
      if (url.includes("/integrity/audits")) {
        return { items: [], total: 0, page: 1, page_size: 20, pages: 0 };
      }
      if (url.includes("/integrity/findings")) {
        return { items: [], total: 0, page: 1, page_size: 20, pages: 0 };
      }
      throw new Error(`unexpected ${url}`);
    });
    try {
      render(<IntegrityPage />);
      await waitFor(() => {
        expect(screen.getByText(/Integrity status unavailable/)).toBeInTheDocument();
      });
      expect(screen.queryByText(/Latest audit.*PASS/)).not.toBeInTheDocument();
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
