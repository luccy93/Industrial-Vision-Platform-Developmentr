import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { SummaryCards } from "./SummaryCards";
import type { OperationsSummary } from "../../types";

function summary(overrides: Partial<OperationsSummary> = {}): OperationsSummary {
  return {
    timestamp: "2026-01-01T00:00:00.000Z",
    cameras: {
      status: "ok",
      message: "",
      updated_at: "",
      configured: 2,
      enabled: 1,
      by_state: { RUNNING: 1, STOPPED: 1 },
    },
    safety: {
      status: "ok",
      message: "",
      updated_at: "",
      total_active: 3,
      by_severity: { HIGH: 2, LOW: 1 },
      cameras_with_events: 1,
      truncated: false,
    },
    incidents: {
      status: "ok",
      message: "",
      updated_at: "",
      total: 4,
      open_total: 3,
      by_status: { OPEN: 2, CLOSED: 1 },
      by_priority: { P1: 1 },
    },
    quality: {
      status: "ok",
      message: "",
      updated_at: "",
      model_status: "READY",
      outcomes: { PASS: 5, FAIL: 1 },
      active_profiles: 1,
    },
    risk: {
      status: "ok",
      message: "",
      updated_at: "",
      risk_level: "HIGH",
      risk_score: 0.7,
      priority: "P1",
      active_events: 2,
      active_clusters: 1,
    },
    health: {
      status: "ok",
      message: "",
      updated_at: "",
      ready: true,
      readiness: "ready",
      checks: { database: "READY" },
    },
    ...overrides,
  };
}

describe("SummaryCards", () => {
  it("renders real counts with sources", () => {
    render(<SummaryCards summary={summary()} />);
    expect(screen.getByText(/2 configured/)).toBeInTheDocument();
    expect(screen.getByText(/3 active/)).toBeInTheDocument();
    expect(screen.getByText(/3 open/)).toBeInTheDocument();
    expect(screen.getByText(/model: READY/)).toBeInTheDocument();
  });

  it("never shows unavailable quality as PASS", () => {
    render(
      <SummaryCards
        summary={summary({
          quality: {
            status: "unavailable",
            message: "inspection model not configured",
            updated_at: "",
            model_status: "NOT_CONFIGURED",
            outcomes: {},
            active_profiles: 0,
          },
        })}
      />
    );
    expect(screen.getByText(/model not configured/)).toBeInTheDocument();
    expect(screen.queryByText(/PASS/)).not.toBeInTheDocument();
  });

  it("marks not-ready backends honestly", () => {
    render(
      <SummaryCards
        summary={summary({
          health: {
            status: "ok",
            message: "",
            updated_at: "",
            ready: false,
            readiness: "not_ready",
            checks: { database: "NOT_READY" },
          },
        })}
      />
    );
    expect(screen.getByText(/not ready/)).toBeInTheDocument();
  });

  it("labels risk as heuristic, not probability", () => {
    render(<SummaryCards summary={summary()} />);
    expect(screen.getByText(/heuristic, not a probability/)).toBeInTheDocument();
  });
});
