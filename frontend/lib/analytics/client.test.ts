import { describe, expect, it, vi } from "vitest";
import {
  MAX_WINDOW_MS,
  buildAnalyticsQuery,
  downloadExport,
  exportUrl,
} from "./client";
import type { AnalyticsFilters } from "../../types";

function filters(overrides: Partial<AnalyticsFilters> = {}): AnalyticsFilters {
  return {
    preset: "7d",
    startAt: null,
    endAt: null,
    bucket: "day",
    domains: [],
    severities: [],
    cameras: [],
    statuses: [],
    priorities: [],
    ...overrides,
  };
}

describe("buildAnalyticsQuery", () => {
  const now = Date.parse("2026-02-01T00:00:00.000Z");

  it("resolves presets against now", () => {
    const query = buildAnalyticsQuery(filters({ preset: "24h" }), now);
    expect(query.end_at).toBe("2026-02-01T00:00:00.000Z");
    expect(query.start_at).toBe("2026-01-31T00:00:00.000Z");
    expect(query.bucket).toBe("day");
    expect(query.domain).toBeUndefined();
  });

  it("passes multi-value filters through", () => {
    const query = buildAnalyticsQuery(
      filters({ domains: ["SAFETY", "QUALITY"], statuses: ["OPEN"], cameras: ["cam-1", "cam-2"] }),
      now
    );
    expect(query.domain).toEqual(["SAFETY", "QUALITY"]);
    expect(query.status).toEqual(["OPEN"]);
    expect(query.camera_id).toBeUndefined();
  });

  it("uses a single camera filter directly", () => {
    const query = buildAnalyticsQuery(filters({ cameras: ["cam-9"] }), now);
    expect(query.camera_id).toBe("cam-9");
  });

  it("validates custom ranges", () => {
    expect(() =>
      buildAnalyticsQuery(
        filters({
          preset: "custom",
          startAt: "2026-01-10T00:00:00Z",
          endAt: "2026-01-01T00:00:00Z",
        }),
        now
      )
    ).toThrow("before report end");
    expect(() =>
      buildAnalyticsQuery(filters({ preset: "custom", startAt: null, endAt: null }), now)
    ).toThrow("requires start and end");
    expect(() =>
      buildAnalyticsQuery(
        filters({
          preset: "custom",
          startAt: "2025-01-01T00:00:00Z",
          endAt: "2026-01-01T00:00:00Z",
        }),
        now
      )
    ).toThrow("90 days");
    expect(MAX_WINDOW_MS).toBe(90 * 24 * 3600 * 1000);
  });

  it("rejects unknown presets", () => {
    expect(() => buildAnalyticsQuery(filters({ preset: "1y" as never }), now)).toThrow(
      "Unknown preset"
    );
  });
});

describe("exportUrl", () => {
  it("normalizes custom offsets to Z so no raw + reaches the query", () => {
    const query = buildAnalyticsQuery(
      filters({
        preset: "custom",
        startAt: "2026-01-01T00:00:00+02:00",
        endAt: "2026-01-08T00:00:00+02:00",
      }),
      Date.now()
    );
    expect(query.start_at).toBe("2025-12-31T22:00:00.000Z");
    const url = exportUrl(query, "incidents");
    expect(url).toContain("report=incidents");
    expect(url).not.toMatch(/start_at=[^&]*\+/);
  });
});

describe("downloadExport", () => {
  it("triggers a download and revokes the object URL", async () => {
    const anchor = { href: "", download: "", click: vi.fn(), remove: vi.fn() };
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: true,
        blob: async () => new Blob(["a,b\n1,2\n"]),
        headers: new Headers({ "content-disposition": 'attachment; filename="r.csv"' }),
      }))
    );
    const createSpy = vi.spyOn(document, "createElement").mockReturnValue(anchor as never);
    const url = URL as unknown as {
      createObjectURL: (blob: Blob) => string;
      revokeObjectURL: (url: string) => void;
    };
    const hadCreate = "createObjectURL" in URL;
    const hadRevoke = "revokeObjectURL" in URL;
    const savedCreate = url.createObjectURL;
    const savedRevoke = url.revokeObjectURL;
    url.createObjectURL = vi.fn(() => "blob:mock");
    url.revokeObjectURL = vi.fn();
    const appendSpy = vi.spyOn(document.body, "appendChild").mockImplementation((node) => node);
    try {
      await downloadExport("/api/v1/analytics/export?report=events", "fallback.csv");
      expect(anchor.download).toBe("r.csv");
      expect(anchor.click).toHaveBeenCalled();
      expect(url.revokeObjectURL).toHaveBeenCalledWith("blob:mock");
    } finally {
      vi.unstubAllGlobals();
      createSpy.mockRestore();
      appendSpy.mockRestore();
      if (hadCreate) url.createObjectURL = savedCreate;
      else delete (url as Record<string, unknown>).createObjectURL;
      if (hadRevoke) url.revokeObjectURL = savedRevoke;
      else delete (url as Record<string, unknown>).revokeObjectURL;
    }
  });

  it("keeps the analytics view usable on failure", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: false,
        status: 422,
        json: async () => ({ error: { code: "validation_error", message: "too many rows" } }),
      }))
    );
    try {
      await expect(downloadExport("/x", "f.csv")).rejects.toThrow("too many rows");
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
