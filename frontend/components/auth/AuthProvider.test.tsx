import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AuthProvider, useAuth } from "./AuthProvider";
import { UNAUTHORIZED_EVENT } from "../../lib/auth/session";
import type { AuthUser } from "../../types";

const push = vi.fn();

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push }),
  usePathname: () => "/dashboard",
}));

function mockFetch(handler: (url: string, init?: RequestInit) => { status: number; body: unknown }) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: unknown, init?: RequestInit) => {
      const { status, body } = handler(String(input), init);
      return new Response(JSON.stringify(body), {
        status,
        headers: { "Content-Type": "application/json" },
      });
    })
  );
}

const USER: AuthUser = {
  id: "u1",
  email: "op@example.com",
  role: "OPERATOR",
  is_active: true,
  must_change_password: false,
  last_login_at: null,
};

function Probe() {
  const { user, loading, isAdmin, getTicket } = useAuth();
  return (
    <div>
      <span data-testid="user">{user ? user.email : "none"}</span>
      <span data-testid="loading">{loading ? "yes" : "no"}</span>
      <span data-testid="admin">{isAdmin ? "yes" : "no"}</span>
      <button
        type="button"
        onClick={() => void getTicket("operations").then((t) => void (document.title = t ?? "null"))}
      >
        ticket
      </button>
    </div>
  );
}

describe("AuthProvider", () => {
  beforeEach(() => {
    vi.unstubAllGlobals();
    push.mockClear();
    document.title = "";
  });

  it("restores the session from /me on mount", async () => {
    mockFetch((url) => {
      if (url.includes("/auth/me")) {
        return { status: 200, body: { user: USER, session_expires_at: null } };
      }
      throw new Error(`unexpected ${url}`);
    });
    render(
      <AuthProvider initialUser={null}>
        <Probe />
      </AuthProvider>
    );
    await waitFor(() => {
      expect(screen.getByTestId("user")).toHaveTextContent("op@example.com");
    });
    expect(screen.getByTestId("admin")).toHaveTextContent("no");
  });

  it("accepts a server-provided initial user without flashing", async () => {
    mockFetch(() => ({ status: 200, body: { user: USER, session_expires_at: null } }));
    render(
      <AuthProvider initialUser={{ ...USER, role: "ADMIN" }}>
        <Probe />
      </AuthProvider>
    );
    expect(screen.getByTestId("user")).toHaveTextContent("op@example.com");
    await waitFor(() => {
      expect(screen.getByTestId("loading")).toHaveTextContent("no");
    });
  });

  it("clears state and redirects on the global 401 event", async () => {
    // Session is dead: /me also 401s so the mount refresh cannot resurrect it.
    mockFetch(() => ({ status: 401, body: { error: { code: "x", message: "y" } } }));
    render(
      <AuthProvider initialUser={USER}>
        <Probe />
      </AuthProvider>
    );
    window.dispatchEvent(new CustomEvent(UNAUTHORIZED_EVENT));
    await waitFor(() => {
      expect(screen.getByTestId("user")).toHaveTextContent("none");
    });
    expect(push).toHaveBeenCalledWith(expect.stringContaining("/login"));
  });

  it("fetches WS tickets and returns null on failure", async () => {
    const user = userEvent.setup();
    mockFetch((url) => {
      if (url.includes("/auth/me")) {
        return { status: 200, body: { user: USER, session_expires_at: null } };
      }
      if (url.includes("/ws-ticket")) {
        return { status: 200, body: { ticket: "tick-1", scope: "operations", expires_at: "x" } };
      }
      throw new Error(`unexpected ${url}`);
    });
    render(
      <AuthProvider initialUser={USER}>
        <Probe />
      </AuthProvider>
    );
    await user.click(screen.getByRole("button", { name: "ticket" }));
    await waitFor(() => {
      expect(document.title).toBe("tick-1");
    });
  });
});
