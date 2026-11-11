import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AutomationWorkspace } from "./AutomationWorkspace";

let currentRole = "ADMIN";

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

const SCHEDULE = {
  schedule_id: "sched-retention",
  job_type: "RETENTION_EVALUATION",
  enabled: false,
  interval_minutes: 1440,
  config: {},
  config_version: 1,
  last_slot: null,
  last_idempotency_key: null,
  updated_by: null,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

const JOB = {
  job_id: "job-1",
  job_type: "GOVERNANCE_HEALTH_CHECK",
  status: "SUCCEEDED",
  trigger: "MANUAL",
  schedule_slot: null,
  dedup_key: "manual:health:1",
  retry_of_job_id: null,
  attempt: 1,
  max_attempts: 3,
  config_version: null,
  config_snapshot: {},
  requested_by: "operator@example.com",
  requested_role: "OPERATOR",
  request_id: "req-1",
  created_at: "2026-01-01T00:00:00Z",
  available_at: "2026-01-01T00:00:00Z",
  started_at: "2026-01-01T00:00:01Z",
  finished_at: "2026-01-01T00:00:02Z",
  lease_owner: null,
  lease_expires_at: null,
  heartbeat_at: null,
  cancel_requested_at: null,
  cancel_requested_by: null,
  cancel_requested: false,
  result: {},
  error_code: null,
  error_message: null,
};

const FAILED_JOB = {
  ...JOB,
  job_id: "job-failed",
  status: "FAILED",
  error_code: "SYNTHETIC",
  error_message: "Synthetic failure.",
};

const PENDING_JOB = {
  ...JOB,
  job_id: "job-pending",
  status: "PENDING",
  started_at: null,
  finished_at: null,
};

const SNAPSHOT = {
  snapshot_id: "snapshot-1",
  snapshot_type: "COMPLIANCE_SUMMARY",
  as_of: "2026-01-01",
  generated_at: "2026-01-01T00:00:00Z",
  generated_by: "operator@example.com",
  job_id: "job-1",
  trigger: "MANUAL",
  dedup_key: "snapshot:1",
  payload_digest: "c".repeat(64),
  digest_valid: true,
  row_count: 1,
  schema_version: 1,
  payload: {},
};

const STATUS = {
  enabled: true,
  assurance: "LOCAL_GOVERNANCE_AUTOMATION_ONLY",
  scheduler: {
    enabled: true,
    state: "RUNNING",
    running: true,
    queue: { PENDING: 1, RUNNING: 0 },
    stale_jobs: 0,
  },
  schedule_count: 7,
  enabled_schedule_count: 1,
  schedules: [SCHEDULE],
  queue: { PENDING: 1, RUNNING: 0, SUCCEEDED: 2 },
  job_count: 3,
  snapshot_count: 1,
  last_jobs: {},
  stale_jobs: 0,
  supported_job_types: [],
  non_claims: ["No automatic physical evidence deletion is performed."],
  limitations: ["Scheduled retention evaluation is non-destructive."],
};

const HEALTH = {
  enabled: true,
  overall_status: "OK",
  scheduler: { enabled: true, state: "RUNNING", running: true },
  governance_audit: { outcome: "OK", checked: 1, verified: 1 },
  integrity: { status: "OK", latest_audit_status: "PASS" },
  queue: { PENDING: 1, RUNNING: 0 },
  stale_jobs: 0,
  generated_at: "2026-01-01T00:00:00Z",
  assurance: "LOCAL_GOVERNANCE_AUTOMATION_ONLY",
  non_claims: ["No automatic physical evidence deletion is performed."],
};

function reminders(overrides: Record<string, unknown> = {}) {
  return {
    items: [
      {
        notification_id: "notification-1",
        event_type: "RETENTION_REVIEW_DUE",
        target_type: "RETENTION_EVALUATION",
        target_id: "eval-1",
        case_id: "case-1",
        reminder_window: "20260101T000000Z",
        severity: "HIGH",
        created_at: "2026-01-01T00:00:00Z",
        muted: false,
        muted_until: null,
        delivery_state: "PENDING",
        delivery_claimed: false,
        channels: ["in_app"],
      },
    ],
    total: 1,
    page: 1,
    page_size: 20,
    summary_limit: 1000,
    by_event_type: { RETENTION_REVIEW_DUE: 1 },
    delivery_states: { PENDING: 1, DELIVERED: 0, FAILED: 0, PARTIAL: 0 },
    muted: 0,
    notifier_enabled: true,
    delivery_claimed: false,
    non_claims: [],
    ...overrides,
  };
}

function handler(url: string, init?: RequestInit): unknown {
  const method = String(init?.method ?? "GET").toUpperCase();
  if (url.includes("/api/v1/governance/automation/status")) return STATUS;
  if (url.includes("/api/v1/governance/automation/health")) return HEALTH;
  if (url.includes("/api/v1/governance/automation/schedules")) {
    if (method === "PUT") {
      const body = JSON.parse(String(init?.body ?? "{}"));
      return {
        schedule: {
          ...SCHEDULE,
          enabled: body.enabled,
          interval_minutes: body.interval_minutes,
          config_version: SCHEDULE.config_version + 1,
        },
        non_claims: [],
      };
    }
    return { items: [SCHEDULE], automation_enabled: true, non_claims: [] };
  }
  if (url.includes("/api/v1/governance/automation/jobs/run")) {
    return { job: { ...JOB, job_id: "job-run" }, replayed: false, executed: true };
  }
  if (url.includes("/api/v1/governance/automation/jobs/job-failed/retry")) {
    return { job: { ...JOB, job_id: "job-retry" }, replayed: false, executed: true };
  }
  if (url.includes("/api/v1/governance/automation/jobs/job-pending/cancel")) {
    return {
      job: { ...PENDING_JOB, status: "CANCELLED" },
      cancelled: true,
      cancel_requested: false,
      non_claims: [],
    };
  }
  if (url.includes("/api/v1/governance/automation/jobs")) {
    return { items: [JOB, FAILED_JOB, PENDING_JOB], total: 3, page: 1, page_size: 10 };
  }
  if (url.includes("/api/v1/governance/automation/snapshots")) {
    return { items: [SNAPSHOT], total: 1, page: 1, page_size: 10, non_claims: [] };
  }
  if (url.includes("/api/v1/governance/automation/reminders")) return reminders();
  return new Error(`unexpected request: ${url}`);
}

function fetchCalls(): string[] {
  return (global.fetch as ReturnType<typeof vi.fn>).mock.calls.map(([url]) => String(url));
}

describe("AutomationWorkspace", () => {
  beforeEach(() => {
    currentRole = "ADMIN";
    vi.restoreAllMocks();
  });

  it("renders overview, schedules, jobs, reminders, snapshots, and health", async () => {
    mockFetch(handler);
    render(<AutomationWorkspace />);

    expect(await screen.findByText("Governance automation")).toBeInTheDocument();
    expect(screen.getAllByText("ENABLED").length).toBeGreaterThan(0);
    expect(screen.getAllByText("RUNNING").length).toBeGreaterThan(0);
    expect(screen.getAllByText("RETENTION_EVALUATION").length).toBeGreaterThan(0);
    expect(await screen.findByText(/Synthetic failure/)).toBeInTheDocument();
    expect(screen.getByText("RETENTION_REVIEW_DUE")).toBeInTheDocument();
    expect(screen.getByText("COMPLIANCE_SUMMARY")).toBeInTheDocument();
    expect(screen.getByText(/Integrity status is OK only/)).toBeInTheDocument();
    expect(screen.getAllByText(/No automatic physical evidence deletion/).length).toBeGreaterThan(0);
  });

  it("keeps schedule configuration, runs, retries, cancels, and generation away from viewers", async () => {
    currentRole = "VIEWER";
    mockFetch(handler);
    render(<AutomationWorkspace />);

    expect(await screen.findByText("Governance automation")).toBeInTheDocument();
    expect(await screen.findByText("Automation schedules")).toBeInTheDocument();
    expect(
      screen.getByText(/Schedule changes require an administrator/)
    ).toBeInTheDocument();
    expect(screen.getByText(/Manual runs and retries require an operator/)).toBeInTheDocument();
    expect(
      screen.getByText(/Snapshot generation requires an operator/)
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Save schedule" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Run job now" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Retry job" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Cancel job" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Generate snapshot" })).not.toBeInTheDocument();
    // Read-only CSV download remains available.
    expect(await screen.findByRole("link", { name: /Snapshot CSV/ })).toBeInTheDocument();
  });

  it("saves a schedule with an explicit reason and version", async () => {
    mockFetch(handler);
    render(<AutomationWorkspace />);
    await screen.findByText("Automation schedules");

    await userEvent.click(screen.getByLabelText("Enabled RETENTION_EVALUATION"));
    await userEvent.type(screen.getByLabelText("Schedule reason RETENTION_EVALUATION"), "Enable nightly.");
    await userEvent.click(screen.getByRole("button", { name: "Save schedule" }));

    expect(await screen.findByText(/Schedule saved/)).toBeInTheDocument();
    await waitFor(() => {
      const put = (global.fetch as ReturnType<typeof vi.fn>).mock.calls.find(
        ([url, init]) =>
          String(url).includes("/schedules/RETENTION_EVALUATION") &&
          String((init as RequestInit | undefined)?.method).toUpperCase() === "PUT"
      );
      expect(put).toBeTruthy();
      expect(JSON.parse(String((put?.[1] as RequestInit).body))).toMatchObject({
        enabled: true,
        interval_minutes: 1440,
        expected_version: 1,
        reason: "Enable nightly.",
      });
    });
  });

  it("runs a job now with an idempotency key and reason", async () => {
    mockFetch(handler);
    render(<AutomationWorkspace />);
    await screen.findByText("Run a job now");

    await userEvent.type(screen.getByLabelText("Run reason"), "Manual health check.");
    await userEvent.click(screen.getByRole("button", { name: "Run job now" }));

    expect(await screen.findByText(/Executed job job-run/)).toBeInTheDocument();
    const post = (global.fetch as ReturnType<typeof vi.fn>).mock.calls.find(([url]) =>
      String(url).includes("/jobs/run")
    );
    expect(post).toBeTruthy();
    const body = JSON.parse(String((post?.[1] as RequestInit).body));
    expect(body.job_type).toBe("RETENTION_EVALUATION");
    expect(body.reason).toBe("Manual health check.");
    expect(body.idempotency_key).toMatch(/^ui-RETENTION_EVALUATION-/);
  });

  it("confirms retry and cancel with required reasons", async () => {
    mockFetch(handler);
    render(<AutomationWorkspace />);

    await userEvent.click(await screen.findByRole("button", { name: "Retry job" }));
    expect(screen.getByText(/Retry creates one bounded child job/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Confirm retry" })).toBeDisabled();
    await userEvent.type(screen.getByLabelText("Retry reason"), "Synthetic retry.");
    await userEvent.click(screen.getByRole("button", { name: "Confirm retry" }));

    await userEvent.click(await screen.findByRole("button", { name: "Cancel job" }));
    expect(screen.getByText(/Pending jobs cancel immediately/)).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Cancel reason"), "Synthetic cancel.");
    await userEvent.click(screen.getByRole("button", { name: "Confirm cancel" }));

    await waitFor(() => {
      expect(fetchCalls().some((url) => url.includes("/jobs/job-failed/retry"))).toBe(true);
      expect(fetchCalls().some((url) => url.includes("/jobs/job-pending/cancel"))).toBe(true);
    });
  });

  it("labels queued reminders as pending, never delivered", async () => {
    mockFetch(handler);
    render(<AutomationWorkspace />);

    expect(await screen.findByText("Reminder activity")).toBeInTheDocument();
    expect(screen.getAllByText("PENDING").length).toBeGreaterThan(0);
    expect(
      screen.getByText(/PENDING means queued locally without a successful delivery attempt/)
    ).toBeInTheDocument();
    expect(screen.getByText(/not a claim that an external channel delivered/)).toBeInTheDocument();
  });

  it("shows delivered reminder state when the delivery row is sent", async () => {
    mockFetch((url) => {
      if (url.includes("/api/v1/governance/automation/reminders")) {
        return reminders({
          items: [{ ...reminders().items[0], delivery_state: "DELIVERED" }],
          delivery_states: { PENDING: 0, DELIVERED: 1, FAILED: 0, PARTIAL: 0 },
        });
      }
      return handler(url);
    });
    render(<AutomationWorkspace />);

    expect(await screen.findByText("DELIVERED")).toBeInTheDocument();
    expect(screen.getByText(/not a claim that an external channel delivered/)).toBeInTheDocument();
  });

  it("isolates one failing section so the rest keep rendering", async () => {
    mockFetch((url) => {
      if (url.includes("/api/v1/governance/automation/reminders")) {
        return new Error("reminder store unavailable");
      }
      return handler(url);
    });
    render(<AutomationWorkspace />);

    expect(await screen.findByText(/reminder store unavailable/)).toBeInTheDocument();
    expect(await screen.findByText("Governance automation")).toBeInTheDocument();
    expect(screen.getByText("COMPLIANCE_SUMMARY")).toBeInTheDocument();
    expect(screen.getAllByText("RUNNING").length).toBeGreaterThan(0);
  });

  it("never renders destructive controls or delete routes", async () => {
    mockFetch(handler);
    render(<AutomationWorkspace />);
    await screen.findByText("Governance automation");

    expect(screen.queryByRole("button", { name: /delete/i })).not.toBeInTheDocument();
    expect(screen.queryByText(/Delete job/i)).not.toBeInTheDocument();
    expect(fetchCalls().every((url) => !url.includes("DELETE"))).toBe(true);
  });
});
