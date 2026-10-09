import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { EventTimeline } from "./EventTimeline";
import type { TimelineFilter } from "../../lib/operations/timeline";
import type { TimelineItem as ItemType, TimelineKind } from "../../types";

function item(partial: Partial<ItemType> & { id: string }): ItemType {
  return {
    kind: "safety",
    eventType: "safety_event",
    severity: "HIGH",
    cameraId: "cam-1",
    timestamp: "2026-01-01T00:00:00.000Z",
    title: "crowd warning",
    href: "/safety",
    source: "rest",
    ...partial,
  };
}

const openFilter = (): TimelineFilter => ({
  kinds: new Set<TimelineKind>(),
  severities: new Set<string>(),
  cameras: new Set<string>(),
  sinceMs: null,
});

describe("EventTimeline", () => {
  it("renders items with links and live markers", () => {
    render(
      <EventTimeline
        items={[
          item({ id: "a" }),
          item({ id: "b", source: "socket", href: null, title: "remote note" }),
        ]}
        filter={openFilter()}
        cameras={["cam-1"]}
        severities={["HIGH"]}
        onFilterChange={() => {}}
      />
    );
    expect(screen.getByText(/crowd warning/)).toBeInTheDocument();
    expect(screen.getByText(/remote note/)).toBeInTheDocument();
    expect(screen.getByText(/live/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /crowd warning/ })).toHaveAttribute("href", "/safety");
  });

  it("renders an intentional empty state", () => {
    render(
      <EventTimeline items={[]} filter={openFilter()} cameras={[]} severities={[]} onFilterChange={() => {}} />
    );
    expect(screen.getByText(/genuine quiet/)).toBeInTheDocument();
  });

  it("toggles kind filters", async () => {
    const user = userEvent.setup();
    let current = openFilter();
    const { rerender } = render(
      <EventTimeline
        items={[item({ id: "a" })]}
        filter={current}
        cameras={[]}
        severities={[]}
        onFilterChange={(next) => {
          current = next;
        }}
      />
    );
    await user.click(screen.getByRole("button", { name: "incident" }));
    expect(current.kinds.has("incident")).toBe(true);
    rerender(
      <EventTimeline
        items={[item({ id: "a" })]}
        filter={current}
        cameras={[]}
        severities={[]}
        onFilterChange={() => {}}
      />
    );
    expect(screen.getByRole("button", { name: "incident" })).toHaveAttribute("aria-pressed", "true");
  });
});
