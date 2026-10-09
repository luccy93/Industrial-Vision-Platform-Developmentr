import { describe, expect, it, vi } from "vitest";
import { ageMs, apiFetch, isStale } from "./client";

describe("ageMs / isStale", () => {
  it("measures age from ISO timestamps", () => {
    expect(ageMs("2026-01-01T00:00:10.000Z", Date.parse("2026-01-01T00:00:13.000Z"))).toBe(3000);
  });

  it("returns null for missing or unparseable timestamps", () => {
    expect(ageMs(null)).toBeNull();
    expect(ageMs(undefined)).toBeNull();
    expect(ageMs("not-a-date")).toBeNull();
  });

  it("flags stale data past the threshold, unknown as stale", () => {
    const now = Date.parse("2026-01-01T00:01:00.000Z");
    expect(isStale("2026-01-01T00:00:00.000Z", 30_000, now)).toBe(true);
    expect(isStale("2026-01-01T00:00:50.000Z", 30_000, now)).toBe(false);
    expect(isStale(null, 30_000, now)).toBe(true);
  });
});

describe("apiFetch", () => {
  it("shapes envelope errors readably", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: false,
        status: 409,
        json: async () => ({
          error: { code: "invalid_transition", message: "Cannot transition OPEN -> CLOSED" },
        }),
      }))
    );
    try {
      await expect(apiFetch("/api/v1/incidents/x/acknowledge")).rejects.toThrow(
        "invalid_transition: Cannot transition OPEN -> CLOSED"
      );
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("reports unreachable backends distinctly", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("connection refused");
      })
    );
    try {
      await expect(apiFetch("/api/v1/health")).rejects.toThrow("API unreachable");
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
