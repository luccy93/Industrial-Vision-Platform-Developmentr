import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import AnalyticsPage from "./page";

function mockFetch(handler: (url: string) => unknown) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: unknown) => {
      const url = String(input);
      const data = handler(url);
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

const SUMMARY = {
  start_at: "2026-01-01T00:00:00+00:00",
  end_at: "2026-01-08T00:00:00+00:00",
  generated_at: "2026-01-08T00:00:00+00:00",
  events: { status: "ok", message: "", total: 5, by_domain: { SAFETY: 5 }, by_severity: { HIGH: 5 } },
  incidents: {
    status: "ok",
    message: "",
    created_total: 2,
    open_total: 2,
    resolved_total: 0,
    closed_total: 0,
    by_status: { OPEN: 2 },
    by_priority: { P1: 2 },
    resolution: { count: 0, average_seconds: null, median_seconds: null, min_seconds: null, max_seconds: null },
  },
  quality: { status: "unavailable", message: "x", reason: "not persisted" },
  cameras: { status: "ok", message: "", by_camera: { "cam-1": 5 } },
};

const TREND = {
  metric: "events",
  bucket: "day",
  start_at: SUMMARY.start_at,
  end_at: SUMMARY.end_at,
  buckets: [
    { bucket_start: "2026-01-01T00:00:00+00:00", count: 3 },
    { bucket_start: "2026-01-02T00:00:00+00:00", count: 2 },
  ],
  truncated: false,
};

const BREAKDOWN = {
  dataset: "events",
  group_by: "domain",
  start_at: SUMMARY.start_at,
  end_at: SUMMARY.end_at,
  groups: [{ key: "SAFETY", label: "SAFETY", count: 5 }],
  truncated: false,
};

function healthyFetch() {
  mockFetch((url: string) => {
    if (url.includes("/analytics/summary")) return SUMMARY;
    if (url.includes("/analytics/trends")) return TREND;
    if (url.includes("/analytics/breakdowns")) return BREAKDOWN;
    throw new Error(`unexpected ${url}`);
  });
}

describe("AnalyticsPage", () => {
  it("renders totals from real response contracts after apply", async () => {
    const user = userEvent.setup();
    healthyFetch();
    try {
      render(<AnalyticsPage />);
      await user.click(screen.getByRole("button", { name: "Apply" }));
      await waitFor(() => {
        expect(screen.getByText(/5 canonical events/)).toBeInTheDocument();
      });
      expect(screen.getByText(/2 created/)).toBeInTheDocument();
      expect(screen.getByText(/SAFETY: 5/)).toBeInTheDocument();
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("shows unavailable quality without zeros", async () => {
    const user = userEvent.setup();
    healthyFetch();
    try {
      render(<AnalyticsPage />);
      await user.click(screen.getByRole("button", { name: "Apply" }));
      await waitFor(() => {
        expect(screen.getByText(/Quality inspection outcomes/)).toBeInTheDocument();
      });
      expect(screen.getByText(/results are not persisted/)).toBeInTheDocument();
      expect(screen.queryByText(/PASS:/)).not.toBeInTheDocument();
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("isolates a failed section from healthy ones", async () => {
    const user = userEvent.setup();
    mockFetch((url: string) => {
      if (url.includes("/analytics/summary")) return SUMMARY;
      if (url.includes("/analytics/trends")) return new Error("trends down");
      if (url.includes("/analytics/breakdowns")) return BREAKDOWN;
      throw new Error(`unexpected ${url}`);
    });
    try {
      render(<AnalyticsPage />);
      await user.click(screen.getByRole("button", { name: "Apply" }));
      await waitFor(() => {
        expect(screen.getByText(/5 canonical events/)).toBeInTheDocument();
      });
      expect(screen.getByText(/trends down/)).toBeInTheDocument();
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("rejects invalid custom ranges before any request", async () => {
    const user = userEvent.setup();
    const spy = vi.fn(async () => ({ ok: true, status: 200, json: async () => SUMMARY }));
    vi.stubGlobal("fetch", spy);
    try {
      render(<AnalyticsPage />);
      await user.click(screen.getByRole("button", { name: "Custom range" }));
      await user.click(screen.getByRole("button", { name: "Apply" }));
      expect(await screen.findByText(/requires start and end/)).toBeInTheDocument();
      expect(spy).not.toHaveBeenCalled();
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("keeps applied results visible when the export fails", async () => {
    const user = userEvent.setup();
    healthyFetch();
    const originalFetch = globalThis.fetch;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string) => {
        const url = String(input);
        if (url.includes("/analytics/export")) {
          return {
            ok: false,
            status: 422,
            json: async () => ({ error: { code: "validation_error", message: "too many rows" } }),
          };
        }
        return (originalFetch as typeof fetch)(input);
      })
    );
    try {
      render(<AnalyticsPage />);
      await user.click(screen.getByRole("button", { name: "Apply" }));
      await waitFor(() => {
        expect(screen.getByText(/5 canonical events/)).toBeInTheDocument();
      });
      await user.click(screen.getByRole("button", { name: /Download CSV/ }));
      await waitFor(() => {
        expect(screen.getByText(/too many rows/)).toBeInTheDocument();
      });
      // Applied report survives the export failure.
      expect(screen.getByText(/5 canonical events/)).toBeInTheDocument();
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
