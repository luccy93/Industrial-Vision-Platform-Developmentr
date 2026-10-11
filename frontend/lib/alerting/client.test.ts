import { describe, expect, it, vi } from "vitest";
import {
  emptyRuleForm,
  fetchNotifications,
  validateRuleForm,
} from "./client";

describe("validateRuleForm", () => {
  it("requires a name and at least one channel", () => {
    expect(validateRuleForm({ ...emptyRuleForm(), name: "  " })).toBe("Rule name is required.");
    expect(validateRuleForm({ ...emptyRuleForm(), name: "R", channels: [] })).toBe(
      "Select at least one channel."
    );
  });

  it("bounds cooldowns", () => {
    expect(
      validateRuleForm({ ...emptyRuleForm(), name: "R", cooldown_seconds: -5 })
    ).toBe("Cooldown must be a non-negative whole number of seconds.");
    expect(
      validateRuleForm({ ...emptyRuleForm(), name: "R", cooldown_seconds: 90000 })
    ).toBe("Cooldown must not exceed 86400 seconds.");
    expect(
      validateRuleForm({ ...emptyRuleForm(), name: "R", cooldown_seconds: 300 })
    ).toBeNull();
  });

  it("accepts a fully specified rule", () => {
    expect(
      validateRuleForm({
        ...emptyRuleForm(),
        name: "Critical safety",
        domains: ["SAFETY"],
        event_types: ["CROWD_WARNING"],
        min_severity: "HIGH",
        camera_ids: "cam-01",
        incident_statuses: ["RESOLVED"],
        channels: ["in_app", "webhook"],
      })
    ).toBeNull();
  });
});

describe("emptyRuleForm", () => {
  it("defaults to enabled in-app delivery with no cooldown", () => {
    const form = emptyRuleForm();
    expect(form.enabled).toBe(true);
    expect(form.channels).toEqual(["in_app"]);
    expect(form.cooldown_seconds).toBe(0);
  });
});

describe("fetchNotifications", () => {
  it("builds filter query parameters", async () => {
    const seen: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: unknown) => {
        seen.push(String(input));
        return {
          ok: true,
          status: 200,
          json: async () => ({ notifications: [], total: 0, page: 2, page_size: 20 }),
        };
      })
    );
    try {
      const body = await fetchNotifications({ severity: "HIGH", page: 2 });
      expect(body.total).toBe(0);
      expect(seen[0]).toContain("severity=HIGH");
      expect(seen[0]).toContain("page=2");
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
