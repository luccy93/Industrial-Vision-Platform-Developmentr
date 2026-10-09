import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { RiskHealth, SafetyQuality } from "./Panels";

describe("SafetyQuality", () => {
  const safety = {
    status: "ok" as const,
    message: "",
    updated_at: "",
    total_active: 1,
    by_severity: { HIGH: 1 },
    cameras_with_events: 1,
    truncated: false,
  };

  it("shows safety items and honest quality state", () => {
    render(
      <SafetyQuality
        safety={safety}
        quality={{
          status: "ok",
          message: "",
          updated_at: "",
          model_status: "READY",
          outcomes: { PASS: 2, FAIL: 0 },
          active_profiles: 1,
        }}
        items={[
          {
            id: "s1",
            kind: "safety",
            eventType: "safety_event",
            severity: "HIGH",
            cameraId: "cam-1",
            timestamp: "",
            title: "crowd warning",
            href: "/safety",
            source: "rest",
          },
        ]}
      />
    );
    expect(screen.getByText(/crowd warning/)).toBeInTheDocument();
    expect(screen.getByText(/PASS: 2/)).toBeInTheDocument();
  });

  it("never renders missing quality as PASS", () => {
    render(
      <SafetyQuality
        safety={{ ...safety, status: "unavailable", total_active: 0, by_severity: {} }}
        quality={{
          status: "unavailable",
          message: "inspection model not configured",
          updated_at: "",
          model_status: "NOT_CONFIGURED",
          outcomes: {},
          active_profiles: 0,
        }}
        items={[]}
      />
    );
    expect(screen.getByText(/never shown as PASS/)).toBeInTheDocument();
    expect(screen.queryByText(/PASS:/)).not.toBeInTheDocument();
  });
});

describe("RiskHealth", () => {
  it("labels risk as heuristic and links system details", () => {
    render(
      <RiskHealth
        risk={{
          status: "ok",
          message: "",
          updated_at: "",
          risk_level: "MEDIUM",
          risk_score: 0.5,
          priority: "P2",
          active_events: 1,
          active_clusters: 0,
        }}
        health={{
          status: "ok",
          message: "",
          updated_at: "",
          ready: true,
          readiness: "ready",
          checks: { database: "READY" },
        }}
        components={[{ component: "database", status: "READY" }]}
      />
    );
    expect(screen.getByText("(heuristic, not a probability)")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /System details/ })).toHaveAttribute("href", "/system");
    expect(screen.getAllByText("database: READY")).toHaveLength(2);
  });
});
