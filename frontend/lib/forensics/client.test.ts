import { describe, expect, it, vi } from "vitest";
import {
  fetchForensicCases,
  fetchForensicFindings,
  forensicExportDownloadUrl,
} from "./client";

function stubFetch() {
  const seen: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: unknown) => {
      seen.push(String(input));
      return { ok: true, status: 200, json: async () => ({ items: [], total: 0 }) };
    })
  );
  return seen;
}

describe("forensic client", () => {
  it("builds repeated status filters and bounds pagination", async () => {
    const seen = stubFetch();
    try {
      await fetchForensicCases({
        status: ["OPEN", "TRIAGED"],
        severity: ["CRITICAL"],
        search: "CASE-2026",
        page: 2,
        page_size: 20,
      });
      expect(seen[0]).toContain("status=OPEN");
      expect(seen[0]).toContain("status=TRIAGED");
      expect(seen[0]).toContain("severity=CRITICAL");
      expect(seen[0]).toContain("search=CASE-2026");
      expect(seen[0]).toContain("page=2");
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("encodes finding filters and export identifiers", async () => {
    const seen = stubFetch();
    try {
      await fetchForensicFindings({ audit_run_id: "run 1", reason_code: "EVIDENCE_MODIFIED" });
      expect(seen[0]).toContain("audit_run_id=run+1");
      expect(seen[0]).toContain("reason_code=EVIDENCE_MODIFIED");
      expect(forensicExportDownloadUrl("export/1")).toContain(
        "/api/v1/forensics/exports/export%2F1"
      );
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
