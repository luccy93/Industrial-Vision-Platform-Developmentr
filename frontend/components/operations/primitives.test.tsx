import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { DataState, SectionBadge } from "./primitives";

describe("SectionBadge", () => {
  it("announces section state accessibly", () => {
    render(<SectionBadge state="degraded" />);
    expect(screen.getByLabelText("section status: degraded")).toHaveTextContent("degraded");
  });
});

describe("DataState", () => {
  it("renders loading, empty, and error states", () => {
    const { rerender } = render(<DataState state="loading" emptyText="Nothing here" />);
    expect(screen.getByRole("status")).toHaveTextContent("Loading…");

    rerender(<DataState state="empty" emptyText="Nothing here" />);
    expect(screen.getByText("Nothing here")).toBeInTheDocument();

    rerender(<DataState state="error" emptyText="Nothing here" error="boom" />);
    expect(screen.getByRole("alert")).toHaveTextContent("boom");
  });

  it("shows stale banners without hiding content", () => {
    render(
      <DataState state="stale" emptyText="Nothing here">
        <span>real content</span>
      </DataState>
    );
    expect(screen.getByText("real content")).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Stale");
  });
});
