import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import ForensicsPage from "./page";

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

const CASE = {
  case_id: "case-1",
  case_number: "CASE-2026-000001",
  title: "Synthetic evidence tampering review",
  description: "Synthetic API fixture; no real evidence.",
  case_type: "EVIDENCE_TAMPERING",
  severity: "CRITICAL",
  status: "INVESTIGATING",
  priority: "P1",
  source: "CORRELATION",
  originating_incident_id: "incident-1",
  originating_audit_run_id: "run-1",
  created_by: "operator@example.com",
  assigned_to: null,
  version: 2,
  resolution_summary: null,
  correlation_key: "key-1",
  custody_event_count: 1,
  custody_head_hash: "a".repeat(64),
  metadata: {},
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:01Z",
  closed_at: null,
};

const PASS_VERIFICATION = {
  outcome: "PASS",
  event_count: 1,
  head_hash: "a".repeat(64),
  expected_head_hash: "a".repeat(64),
  checks: [{ name: "custody-sequence-order", outcome: "PASS", detail: "ok" }],
  reason_codes: [],
  limitations: ["Local chain only."],
  assurance: "LOCAL_HASH_CHAIN_ONLY",
  external_anchor_claimed: false,
  external_anchor_note: "No external transparency provider is configured.",
};

const DETAIL = {
  case: CASE,
  correlations: [
    {
      correlation_id: "corr-1",
      case_id: "case-1",
      correlation_key: "key-1",
      finding_id: "finding-1",
      audit_run_id: "run-1",
      artifact_id: "evidence/a.bin",
      evidence_identifier: "evidence/a.bin",
      reason_code: "EVIDENCE_MODIFIED",
      classification: "CONFIRMED_FAILURE",
      severity: "CRITICAL",
      resolved: false,
      metadata: {},
      created_at: "2026-01-01T00:00:00Z",
    },
  ],
  incident_links: [
    {
      link_id: "link-1",
      case_id: "case-1",
      incident_id: "incident-1",
      linked_by: "operator@example.com",
      linked_at: "2026-01-01T00:00:01Z",
      metadata: {},
    },
  ],
  evidence_references: [
    {
      reference_id: "ref-1",
      case_id: "case-1",
      artifact_type: "V33_FINDING",
      artifact_id: "finding-1",
      original_relative_path: "",
      expected_sha256: "b".repeat(64),
      observed_sha256: "",
      source_audit_run_id: "run-1",
      source_finding_id: "finding-1",
      capture_timestamp: "2026-01-01T00:00:00Z",
      verification_status: "NOT_RUN",
      verification_outcome: "NOT_RUN",
      verification_detail: "",
      reference_created_at: "2026-01-01T00:00:00Z",
      metadata: {},
    },
  ],
  custody: {
    events: [
      {
        event_id: "event-1",
        case_id: "case-1",
        sequence: 1,
        event_type: "CASE_CREATED",
        timestamp: "2026-01-01T00:00:00Z",
        actor_id: "operator@example.com",
        actor_role: "OPERATOR",
        artifact_id: null,
        previous_hash: "0".repeat(64),
        event_hash: "a".repeat(64),
        metadata: {},
      },
    ],
    verification: PASS_VERIFICATION,
  },
  notes: [],
  actions: [],
  assignments: [],
  exports: [],
  latest_verification: null,
  assurance: "LOCAL_HASH_CHAIN_ONLY",
  external_anchor_claimed: false,
  external_anchor_note: "No external transparency provider is configured.",
};

const STATUS = {
  enabled: true,
  summary: {
    total: 1,
    open: 0,
    triaged: 0,
    investigating: 1,
    containment_recommended: 0,
    awaiting_review: 0,
    resolved: 0,
    closed: 0,
    critical: 1,
    by_status: { INVESTIGATING: 1 },
    by_severity: { CRITICAL: 1 },
    by_type: { EVIDENCE_TAMPERING: 1 },
    recent: [CASE],
  },
  v33_source: "AVAILABLE",
  alerting_enabled: false,
  export_evidence_bytes_enabled: false,
  assurance: "LOCAL_HASH_CHAIN_ONLY",
  external_anchor_claimed: false,
  external_anchor_note:
    "No external transparency provider is configured or independently verified; the local custody chain is not externally anchored.",
};

const FINDING = {
  finding_id: "finding-1",
  audit_run_id: "run-1",
  scope: "EVIDENCE",
  severity: "CRITICAL",
  reason_code: "EVIDENCE_MODIFIED",
  artifact_id: "evidence/a.bin",
  detected_at: "2026-01-01T00:00:00Z",
  explanation: "Evidence digest mismatch.",
  verification_source: "v30-evidence",
  recommended_action: "Investigate the modified artifact.",
};

function healthyFetch(
  overrides: {
    cases?: unknown;
    findings?: unknown;
    detail?: unknown;
    verify?: unknown;
  } = {}
) {
  mockFetch((url: string, init?: RequestInit) => {
    if (url.includes("/forensics/status")) return STATUS;
    if (url.includes("/forensics/summary")) return STATUS.summary;
    if (url.includes("/forensics/cases/") && url.endsWith("/verify") && init?.method === "POST") {
      return (
        overrides.verify ?? {
          outcome: "PASS",
          checks: [],
          observations: [],
          reason_codes: [],
          limitations: [],
          custody: PASS_VERIFICATION,
          verified_at: "2026-01-01T00:00:02Z",
          external_anchor_claimed: false,
          external_anchor_note: "No external transparency provider is configured.",
          assurance: "LOCAL_HASH_CHAIN_ONLY",
          counts: { checks: 1, passed: 1, failed: 0, unavailable: 0, not_run: 0 },
        }
      );
    }
    if (url.includes("/forensics/cases/") && init?.method === "POST") {
      return {};
    }
    if (url.includes("/forensics/cases/")) return overrides.detail ?? DETAIL;
    if (url.includes("/forensics/cases")) {
      return (
        overrides.cases ?? {
          items: [CASE],
          total: 1,
          page: 1,
          page_size: 20,
          pages: 1,
        }
      );
    }
    if (url.includes("/forensics/findings")) {
      return (
        overrides.findings ?? {
          items: [FINDING],
          total: 1,
          available: true,
        }
      );
    }
    if (url.includes("/forensics/correlate")) {
      return {
        stats: {
          examined: 1,
          confirmed: 1,
          suspicious: 0,
          skipped_unavailable: 1,
          skipped_not_run: 0,
          skipped_simulated: 0,
          skipped_operational: 0,
          duplicates: 0,
          conflicts: 0,
          cases_created: 1,
          cases_updated: 0,
          incidents_created: 1,
          incidents_linked: 0,
          failed: 0,
        },
      };
    }
    throw new Error(`unexpected ${url}`);
  });
}

describe("ForensicsPage", () => {
  beforeEach(() => {
    currentRole = "ADMIN";
  });

  it("renders cases, findings, the assurance boundary, and custody state", async () => {
    healthyFetch();
    try {
      render(<ForensicsPage />);
      await waitFor(() => {
        expect(screen.getByText(/Integrity Incident Response/)).toBeInTheDocument();
        expect(screen.getByText(/CASE-2026-000001/)).toBeInTheDocument();
        expect(screen.getByText(/EVIDENCE_MODIFIED/)).toBeInTheDocument();
      });
      expect(
        screen.getByText(/No external transparency provider is configured or independently verified/)
      ).toBeInTheDocument();
      expect(screen.getByText(/LOCAL_HASH_CHAIN_ONLY/)).toBeInTheDocument();

      const user = userEvent.setup();
      await user.click(screen.getByRole("button", { name: /CASE-2026-000001/ }));
      await waitFor(() => {
        expect(screen.getByText(/Custody verification: PASS/)).toBeInTheDocument();
        expect(screen.getByText(/Incident incident-1/)).toBeInTheDocument();
      });
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("shows genuine empty states instead of fabricating cases or findings", async () => {
    healthyFetch({
      cases: { items: [], total: 0, page: 1, page_size: 20, pages: 0 },
      findings: { items: [], total: 0, available: true },
    });
    try {
      render(<ForensicsPage />);
      await waitFor(() => {
        expect(screen.getByText(/No forensic cases recorded/)).toBeInTheDocument();
        expect(screen.getByText(/No V33 findings recorded/)).toBeInTheDocument();
      });
      expect(screen.queryByText(/sample|demo/i)).not.toBeInTheDocument();
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("reports an unavailable status and V33 source without faking a pass", async () => {
    mockFetch((url: string) => {
      if (url.includes("/forensics/status")) return new Error("database unavailable");
      if (url.includes("/forensics/cases")) {
        return { items: [], total: 0, page: 1, page_size: 20, pages: 0 };
      }
      if (url.includes("/forensics/findings")) {
        return {
          items: [],
          total: 0,
          available: false,
          detail: "V33 monitoring store is unavailable",
        };
      }
      throw new Error(`unexpected ${url}`);
    });
    try {
      render(<ForensicsPage />);
      await waitFor(() => {
        expect(screen.getByText(/Forensic status unavailable/)).toBeInTheDocument();
        expect(screen.getByText(/V33 monitoring store is unavailable/)).toBeInTheDocument();
      });
      expect(screen.queryByText(/Custody verification: PASS/)).not.toBeInTheDocument();
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("correlates selected findings and reports skipped classes honestly", async () => {
    healthyFetch();
    try {
      render(<ForensicsPage />);
      const user = userEvent.setup();
      await waitFor(() =>
        expect(screen.getByLabelText("select finding finding-1")).toBeInTheDocument()
      );
      await user.click(screen.getByLabelText("select finding finding-1"));
      await user.click(screen.getByRole("button", { name: /Correlate selected \(1\)/ }));
      await waitFor(() => {
        expect(screen.getByText(/Skipped: 1 unavailable/)).toBeInTheDocument();
        expect(screen.getByText(/none were promoted/)).toBeInTheDocument();
      });
      expect(screen.getByText(/incidents created 1/)).toBeInTheDocument();
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("surfaces custody tampering and verification failures without claiming integrity", async () => {
    const tamperedDetail = {
      ...DETAIL,
      custody: {
        ...DETAIL.custody,
        verification: {
          ...PASS_VERIFICATION,
          outcome: "FAIL",
          reason_codes: ["CUSTODY_EVENT_HASH_INVALID"],
        },
      },
    };
    healthyFetch({
      detail: tamperedDetail,
      verify: {
        outcome: "FAIL",
        checks: [],
        observations: [],
        reason_codes: ["FORENSIC_CUSTODY_CHAIN_INVALID"],
        limitations: [],
        custody: tamperedDetail.custody.verification,
        verified_at: "2026-01-01T00:00:02Z",
        external_anchor_claimed: false,
        external_anchor_note: "No external transparency provider is configured.",
        assurance: "LOCAL_HASH_CHAIN_ONLY",
        counts: { checks: 2, passed: 1, failed: 1, unavailable: 0, not_run: 0 },
      },
    });
    try {
      render(<ForensicsPage />);
      const user = userEvent.setup();
      await waitFor(() =>
        expect(screen.getByRole("button", { name: /CASE-2026-000001/ })).toBeInTheDocument()
      );
      await user.click(screen.getByRole("button", { name: /CASE-2026-000001/ }));
      await waitFor(() => {
        expect(screen.getByText(/Do not treat this case as intact/)).toBeInTheDocument();
        expect(screen.getByText(/CUSTODY_EVENT_HASH_INVALID/)).toBeInTheDocument();
      });
      await user.click(screen.getByRole("button", { name: /Run read-only verification/ }));
      await waitFor(() => {
        expect(screen.getByText(/Verification FAIL/)).toBeInTheDocument();
        expect(screen.getByText(/FORENSIC_CUSTODY_CHAIN_INVALID/)).toBeInTheDocument();
      });
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("hides write and export controls from a viewer", async () => {
    currentRole = "VIEWER";
    healthyFetch();
    try {
      render(<ForensicsPage />);
      await waitFor(() =>
        expect(screen.getByRole("button", { name: /CASE-2026-000001/ })).toBeInTheDocument()
      );
      expect(screen.queryByRole("button", { name: "Open case" })).not.toBeInTheDocument();
      const user = userEvent.setup();
      await user.click(screen.getByRole("button", { name: /CASE-2026-000001/ }));
      await waitFor(() => {
        expect(screen.getByText(/Transitions require ADMIN or OPERATOR/)).toBeInTheDocument();
        expect(
          screen.getByText(/Export generation, download, and verification require/)
        ).toBeInTheDocument();
      });
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
