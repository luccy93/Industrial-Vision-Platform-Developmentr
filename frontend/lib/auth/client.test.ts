import { describe, expect, it, vi, beforeEach } from "vitest";
import {
  fetchMe,
  fetchWsTicket,
  login,
  logout,
} from "./client";
import { ApiError, getCsrfToken } from "./session";

function mockFetchOnce(body: unknown, status = 200, headers: Record<string, string> = {}) {
  const response = new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
  vi.stubGlobal("fetch", vi.fn(async () => response));
}

describe("auth client", () => {
  beforeEach(() => {
    vi.unstubAllGlobals();
  });

  it("stores the CSRF token on login and sends cookies", async () => {
    const seen: RequestInit[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: unknown, init?: RequestInit) => {
        seen.push(init ?? {});
        return new Response(
          JSON.stringify({
            user: { id: "u1", email: "op@example.com", role: "OPERATOR" },
            csrf_token: "csrf-1",
            session_expires_at: null,
            must_change_password: false,
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      })
    );
    const result = await login("op@example.com", "password-value-long-enough");
    expect(result.user.email).toBe("op@example.com");
    expect(getCsrfToken()).toBe("csrf-1");
    expect(seen[0]?.credentials).toBe("include");
  });

  it("raises ApiError with status and code on failure", async () => {
    mockFetchOnce({ error: { code: "invalid_credentials", message: "Invalid email or password." } }, 401);
    try {
      await login("op@example.com", "wrong");
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(ApiError);
      expect((e as ApiError).status).toBe(401);
      expect((e as ApiError).code).toBe("invalid_credentials");
      expect((e as Error).message).toContain("Invalid email or password");
    }
  });

  it("sends the CSRF header on mutations and clears it on logout", async () => {
    mockFetchOnce({ ok: true });
    await logout();
    expect(getCsrfToken()).toBeNull();
  });

  it("parses structured detail errors", async () => {
    mockFetchOnce({ detail: { code: "recent_auth_required", message: "Recent authentication required." } }, 403);
    try {
      await fetchWsTicket("operations");
      expect.unreachable();
    } catch (e) {
      expect((e as ApiError).status).toBe(403);
      expect((e as ApiError).code).toBe("recent_auth_required");
    }
  });
});
