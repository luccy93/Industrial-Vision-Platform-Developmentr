import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import UsersPage from "./page";
import { AuthProvider } from "../../components/auth/AuthProvider";
import type { AuthUser } from "../../types";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn() }),
  usePathname: () => "/users",
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

const ADMIN: AuthUser = {
  id: "a1",
  email: "root@example.com",
  role: "ADMIN",
  is_active: true,
  must_change_password: false,
  last_login_at: null,
};

const VIEWER: AuthUser = { ...ADMIN, id: "v1", email: "view@example.com", role: "VIEWER" };

describe("UsersPage", () => {
  beforeEach(() => {
    vi.unstubAllGlobals();
  });

  it("shows access-denied to non-admins without fetching", async () => {
    const spy = vi.fn(async (..._args: unknown[]) => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", spy);
    render(
      <AuthProvider initialUser={VIEWER}>
        <UsersPage />
      </AuthProvider>
    );
    expect(await screen.findByText(/Administrators only/)).toBeInTheDocument();
    expect(spy.mock.calls.some((args) => String(args[0]).includes("/auth/users"))).toBe(false);
  });

  it("lists users and creates with forced-change notice", async () => {
    const user = userEvent.setup();
    mockFetch((url, init) => {
      if (url.includes("/auth/users") && (!init || (init.method ?? "GET") === "GET")) {
        return {
          status: 200,
          body: {
            users: [ADMIN, { ...VIEWER, must_change_password: true }],
            total: 2,
            page: 1,
            page_size: 50,
          },
        };
      }
      if (url.includes("/auth/users") && init?.method === "POST") {
        return { status: 201, body: { user: { ...VIEWER, must_change_password: true } } };
      }
      return { status: 200, body: { user: ADMIN, session_expires_at: null } };
    });
    render(
      <AuthProvider initialUser={ADMIN}>
        <UsersPage />
      </AuthProvider>
    );
    await waitFor(() => {
      expect(screen.getByText("view@example.com")).toBeInTheDocument();
    });
    expect(screen.getByText(/password change required/)).toBeInTheDocument();
    await user.type(screen.getByLabelText(/email/i), "new@example.com");
    await user.type(screen.getByLabelText(/initial password/i), "long-enough-password-value");
    await user.click(screen.getByRole("button", { name: "Create user" }));
    await waitFor(() => {
      expect(screen.getByText(/must change their password at first login/)).toBeInTheDocument();
    });
  });
});
