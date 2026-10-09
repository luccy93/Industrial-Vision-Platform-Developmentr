import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { IncidentQueue } from "./IncidentQueue";
import type { IncidentSummary } from "../../types";

function incident(overrides: Partial<IncidentSummary> = {}): IncidentSummary {
  return {
    id: "abc",
    incident_number: "INC-2026-000001",
    camera_id: "cam-1",
    title: "Conveyor jam",
    status: "OPEN",
    category: "OPERATIONAL",
    priority: "P1",
    severity: "HIGH",
    risk_level: "HIGH",
    risk_score: 0.7,
    assigned_to: null,
    source: "AUTOMATIC",
    first_seen: "2026-01-01T00:00:00.000Z",
    last_seen: "2026-01-01T00:00:00.000Z",
    created_at: "2026-01-01T00:00:00.000Z",
    ...overrides,
  };
}

describe("IncidentQueue", () => {
  it("renders status, priority, camera, and assignment", () => {
    render(<IncidentQueue incidents={[incident({ assigned_to: "ops-2" })]} openTotal={1} />);
    expect(screen.getByText(/INC-2026-000001/)).toBeInTheDocument();
    expect(screen.getByText("OPEN")).toBeInTheDocument();
    expect(screen.getByText("P1")).toBeInTheDocument();
    expect(screen.getByText(/ops-2/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /INC-2026-000001/ })).toHaveAttribute(
      "href",
      "/incidents/abc"
    );
  });

  it("renders genuine zero without pagination assumptions", () => {
    render(<IncidentQueue incidents={[]} openTotal={0} />);
    expect(screen.getByText(/genuine zero/)).toBeInTheDocument();
  });

  it("bounds the visible window and links management", () => {
    const many = Array.from({ length: 15 }, (_, i) =>
      incident({ id: `id-${i}`, incident_number: `INC-2026-${String(i).padStart(6, "0")}` })
    );
    render(<IncidentQueue incidents={many} openTotal={42} />);
    expect(screen.getByText(/Showing 10 of 42 open/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Manage incidents/ })).toHaveAttribute(
      "href",
      "/incidents"
    );
  });
});
