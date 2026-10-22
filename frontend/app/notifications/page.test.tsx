import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import NotificationsPage from "./page";

type Handler = ((event: { data: string }) => void) | null;

class MockSocket {
  static instances: MockSocket[] = [];
  url: string;
  onopen: (() => void) | null = null;
  onmessage: Handler = null;
  onerror: (() => void) | null = null;
  onclose: (() => void) | null = null;
  closed = false;
  readyState = 1;

  constructor(url: string) {
    this.url = url;
    MockSocket.instances.push(this);
  }

  close() {
    this.closed = true;
  }

  serverOpen() {
    this.onopen?.();
  }

  serverMessage(payload: unknown) {
    this.onmessage?.({ data: typeof payload === "string" ? payload : JSON.stringify(payload) });
  }

  serverClose() {
    this.onclose?.();
  }
}

function mockFetch(handler: (url: string, init?: RequestInit) => unknown) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: unknown, init?: RequestInit) => {
      const url = String(input);
      const data = handler(url, init);
      if (data instanceof Error) {
        return {
          ok: false,
          status: 422,
          json: async () => ({ error: { code: "validation_error", message: data.message } }),
        };
      }
      return { ok: true, status: 200, json: async () => data };
    })
  );
}

const STATUS = {
  enabled: true,
  evaluator: { state: "RUNNING" },
  delivery_worker: { state: "RUNNING" },
  channels: { in_app: { available: true }, email: { available: false }, webhook: { available: true, destinations: 1 } },
  deliveries: { sent: 3, failed: 1 },
  security_note: "test",
};

const NOTIFICATION = {
  id: "n1",
  rule_id: "r1",
  source_event_id: "evt-1",
  source_domain: "SAFETY",
  event_type: "CROWD_WARNING",
  camera_id: "cam-01",
  incident_id: null,
  title: "[HIGH] CROWD_WARNING",
  message: "Rule matched",
  severity: "HIGH",
  priority: "P4",
  context: {},
  created_at: "2026-01-01T00:00:00+00:00",
};

const DETAIL = {
  ...NOTIFICATION,
  deliveries: [
    {
      id: "d1",
      notification_id: "n1",
      channel: "webhook",
      destination: "https://ops.example.com/hook",
      status: "failed",
      attempts: 8,
      next_retry_at: null,
      last_attempt_at: "2026-01-01T00:01:00+00:00",
      delivered_at: null,
      last_error: "timeout",
      created_at: "2026-01-01T00:00:00+00:00",
    },
  ],
};

const RULE = {
  id: "r1",
  name: "Critical safety",
  description: "",
  enabled: true,
  domains: ["SAFETY"],
  event_types: [],
  min_severity: "HIGH",
  min_priority: null,
  camera_ids: [],
  incident_statuses: [],
  channels: ["in_app"],
  cooldown_seconds: 0,
  suppression_scope: "RULE",
  trigger_count: 2,
  suppressed_count: 1,
  last_triggered_at: null,
  created_at: null,
  updated_at: null,
};

function healthyFetch() {
  let retried = false;
  mockFetch((url: string, init?: RequestInit) => {
    if (url.includes("/alerting/status")) return STATUS;
    if (url.includes("/alerting/rules/") && init?.method === "PATCH") {
      return { ...RULE, enabled: JSON.parse(String(init.body)).enabled ?? true };
    }
    if (url.includes("/alerting/rules") && init?.method === "POST") return RULE;
    if (url.includes("/alerting/rules")) return { rules: [RULE], total: 1, page: 1, page_size: 20 };
    if (url.includes("/alerting/notifications/")) {
      return {
        ...DETAIL,
        deliveries: retried
          ? [{ ...DETAIL.deliveries[0], status: "pending" }]
          : DETAIL.deliveries,
      };
    }
    if (url.includes("/alerting/notifications")) {
      return { notifications: [NOTIFICATION], total: 1, page: 1, page_size: 20 };
    }
    if (url.includes("/deliveries/") && url.includes("/retry")) {
      retried = true;
      return { ...DETAIL.deliveries[0], status: "pending", retried: true };
    }
    throw new Error(`unexpected ${url}`);
  });
}

describe("NotificationsPage", () => {
  it("renders system-wide history without fabricating data", async () => {
    vi.stubGlobal("WebSocket", MockSocket);
    healthyFetch();
    try {
      render(<NotificationsPage />);
      await waitFor(() => {
        expect(screen.getAllByText(/CROWD_WARNING/).length).toBeGreaterThanOrEqual(1);
      });
      expect(screen.queryByText(/fabricated|sample|demo/i)).not.toBeInTheDocument();
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("shows empty state with no fake notifications", async () => {
    vi.stubGlobal("WebSocket", MockSocket);
    mockFetch((url: string) => {
      if (url.includes("/alerting/status")) return STATUS;
      if (url.includes("/alerting/rules")) return { rules: [], total: 0, page: 1, page_size: 20 };
      if (url.includes("/alerting/notifications")) {
        return { notifications: [], total: 0, page: 1, page_size: 20 };
      }
      throw new Error(`unexpected ${url}`);
    });
    try {
      render(<NotificationsPage />);
      await waitFor(() => {
        expect(screen.getByText(/genuine quiet/)).toBeInTheDocument();
      });
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("shows delivery status and retries failed deliveries", async () => {
    const user = userEvent.setup();
    vi.stubGlobal("WebSocket", MockSocket);
    healthyFetch();
    try {
      render(<NotificationsPage />);
      await waitFor(() => {
        expect(screen.getAllByText(/CROWD_WARNING/).length).toBeGreaterThanOrEqual(1);
      });
      await user.click(screen.getByText("[HIGH] CROWD_WARNING"));
      await waitFor(() => {
        expect(screen.getByText("failed")).toBeInTheDocument();
      });
      await user.click(screen.getByRole("button", { name: /Retry webhook delivery/ }));
      await waitFor(() => {
        expect(screen.queryByText("failed")).not.toBeInTheDocument();
      });
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("surfaces retry errors without losing the detail view", async () => {
    const user = userEvent.setup();
    vi.stubGlobal("WebSocket", MockSocket);
    mockFetch((url: string, _init?: RequestInit) => {
      if (url.includes("/alerting/status")) return STATUS;
      if (url.includes("/alerting/rules")) return { rules: [], total: 0, page: 1, page_size: 20 };
      if (url.includes("/alerting/notifications/")) return DETAIL;
      if (url.includes("/alerting/notifications")) {
        return { notifications: [NOTIFICATION], total: 1, page: 1, page_size: 20 };
      }
      if (url.includes("/retry")) return new Error("provider exploded");
      throw new Error(`unexpected ${url}`);
    });
    try {
      render(<NotificationsPage />);
      await waitFor(() => {
        expect(screen.getAllByText(/CROWD_WARNING/).length).toBeGreaterThanOrEqual(1);
      });
      await user.click(screen.getByText("[HIGH] CROWD_WARNING"));
      await user.click(screen.getByRole("button", { name: /Retry webhook delivery/ }));
      await waitFor(() => {
        expect(screen.getByText(/provider exploded/)).toBeInTheDocument();
      });
      // Detail view survives the failed retry.
      expect(screen.getByText(/Rule matched/)).toBeInTheDocument();
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("validates rule forms and toggles rules", async () => {
    const user = userEvent.setup();
    vi.stubGlobal("WebSocket", MockSocket);
    healthyFetch();
    try {
      render(<NotificationsPage />);
      await user.click(screen.getByRole("tab", { name: "rules" }));
      await user.click(screen.getByRole("button", { name: "New rule" }));
      await user.click(screen.getByRole("button", { name: "Create rule" }));
      expect(await screen.findByText(/Rule name is required/)).toBeInTheDocument();
      await user.type(screen.getByLabelText(/rule name/i), "Night watch");
      await user.click(screen.getByRole("button", { name: "Create rule" }));
      await waitFor(() => {
        expect(screen.queryByText(/Rule name is required/)).not.toBeInTheDocument();
      });
      await user.click(screen.getByRole("button", { name: /Disable rule/ }));
      await waitFor(() => {
        expect(screen.getByText(/Critical safety/)).toBeInTheDocument();
      });
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("marks unconfigured channels honestly", async () => {
    vi.stubGlobal("WebSocket", MockSocket);
    mockFetch((url: string) => {
      if (url.includes("/alerting/status")) {
        return {
          ...STATUS,
          channels: {
            in_app: { available: true },
            email: { available: false },
            webhook: { available: false, destinations: 0 },
          },
        };
      }
      if (url.includes("/alerting/rules")) return { rules: [], total: 0, page: 1, page_size: 20 };
      if (url.includes("/alerting/notifications")) {
        return { notifications: [], total: 0, page: 1, page_size: 20 };
      }
      throw new Error(`unexpected ${url}`);
    });
    try {
      render(<NotificationsPage />);
      await userEvent.setup().click(screen.getByRole("tab", { name: "status" }));
      await waitFor(() => {
        expect(screen.getByText(/email:/)).toBeInTheDocument();
      });
      // Both email and webhook report unavailable; in_app stays configured.
      expect(screen.getAllByText(/unavailable/).length).toBeGreaterThanOrEqual(2);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
