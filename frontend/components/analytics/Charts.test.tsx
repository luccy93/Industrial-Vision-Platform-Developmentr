import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { BreakdownBars, TrendChart } from "./Charts";

const BUCKETS = [
  { bucket_start: "2026-01-01T00:00:00+00:00", count: 3 },
  { bucket_start: "2026-01-02T00:00:00+00:00", count: 0 },
  { bucket_start: "2026-01-03T00:00:00+00:00", count: 7 },
];

describe("TrendChart", () => {
  it("renders series values with labels and caption", () => {
    const { container } = render(<TrendChart buckets={BUCKETS} bucket="day" label="events" />);
    expect(screen.getByRole("img", { name: /events over time/ })).toBeInTheDocument();
    expect(screen.getByText(/events per day/)).toBeInTheDocument();
    // Legend carries the series name; the SVG surface itself renders.
    expect(screen.getByText("events", { exact: true })).toBeInTheDocument();
    expect(container.querySelector("svg")).not.toBeNull();
  });

  it("renders an empty series without crashing", () => {
    render(<TrendChart buckets={[]} bucket="day" label="events" />);
    expect(screen.getByRole("img", { name: /events over time/ })).toBeInTheDocument();
  });
});

describe("BreakdownBars", () => {
  const groups = [
    { key: "SAFETY", label: "SAFETY", count: 5 },
    { key: "QUALITY", label: "QUALITY", count: 2 },
  ];

  it("renders vertical bars with group labels", () => {
    render(<BreakdownBars groups={groups} label="events by domain" />);
    expect(screen.getByRole("img", { name: "events by domain" })).toBeInTheDocument();
    expect(screen.getByText("SAFETY")).toBeInTheDocument();
    expect(screen.getByText(/bounded top 20/)).toBeInTheDocument();
  });

  it("renders horizontal bars for rankings", () => {
    const { container } = render(
      <BreakdownBars groups={groups} label="camera activity" horizontal />
    );
    expect(screen.getByRole("img", { name: "camera activity" })).toBeInTheDocument();
    expect(screen.getAllByText("QUALITY").length).toBeGreaterThanOrEqual(1);
    expect(container.querySelector("svg")).not.toBeNull();
  });
});
