import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { CameraGrid } from "./CameraGrid";
import type { CameraRow } from "./CameraGrid";

function row(overrides: Partial<CameraRow> = {}): CameraRow {
  return {
    camera_id: "cam-1",
    name: "Furnace",
    source_type: "file",
    enabled: true,
    state: "RUNNING",
    frameAgeMs: 1200,
    processingFps: 10,
    latencyMs: 42,
    tracks: 3,
    detections: 2,
    events: 1,
    error: null,
    ...overrides,
  };
}

describe("CameraGrid", () => {
  it("renders running cameras with real metadata", () => {
    render(<CameraGrid rows={[row()]} />);
    expect(screen.getByText(/Furnace/)).toBeInTheDocument();
    expect(screen.getByText("RUNNING")).toBeInTheDocument();
    expect(screen.getByText(/fps: 10/)).toBeInTheDocument();
    expect(screen.getByText(/tracks: 3/)).toBeInTheDocument();
  });

  it("distinguishes stopped, failed, and unknown states", () => {
    render(
      <CameraGrid
        rows={[
          row({ camera_id: "a", state: "STOPPED" }),
          row({ camera_id: "b", state: "ERROR", error: "source unreachable" }),
          row({ camera_id: "c", state: "NOT_STARTED" }),
        ]}
      />
    );
    expect(screen.getByText("STOPPED")).toBeInTheDocument();
    expect(screen.getByText("ERROR")).toBeInTheDocument();
    expect(screen.getByText(/source unreachable/)).toBeInTheDocument();
    expect(screen.getByText("NOT_STARTED")).toBeInTheDocument();
  });

  it("renders missing values as unavailable, never zero-filled", () => {
    render(
      <CameraGrid
        rows={[row({ processingFps: null, latencyMs: null, tracks: null, frameAgeMs: null })]}
      />
    );
    expect(screen.getByText(/fps: —/)).toBeInTheDocument();
    expect(screen.getByText(/tracks: —/)).toBeInTheDocument();
    expect(screen.getByText(/age unknown/)).toBeInTheDocument();
  });

  it("states preview-unavailable honesty and links operations", () => {
    render(<CameraGrid rows={[row()]} />);
    expect(screen.getByText(/preview unavailable by design/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Open camera operations/ })).toHaveAttribute(
      "href",
      "/cameras"
    );
  });

  it("renders an intentional empty state", () => {
    render(<CameraGrid rows={[]} />);
    expect(screen.getByText(/No cameras configured/)).toBeInTheDocument();
  });
});
