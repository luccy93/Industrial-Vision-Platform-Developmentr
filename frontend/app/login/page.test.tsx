import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import LoginPage from "./page";
import { AuthProvider } from "../../components/auth/AuthProvider";
import type { AuthUser } from "../../types";

const push = vi.fn();

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push }),
  usePathname: () => "/login",
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

describe("LoginPage", () => {
  beforeEach(() => {
    vi.unstubAllGlobals();
    push.mockClear();
  });

  it("validates empty input without calling the API", async () => {
    const user = userEvent.setup();
    const spy = vi.fn(async (..._args: unknown[]) => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", spy);
    render(
      <AuthProvider initialUser={null}>
        <LoginPage />
      </AuthProvider>
    );
    // Provider refresh fires /me; the login call itself must not happen.
    // Wait for the mount refresh to settle (button reads "Sign in" when idle).
    await user.click(await screen.findByRole("button", { name: "Sign in" }));
    expect(await screen.findByText(/Email and password are required/)).toBeInTheDocument();
    expect(spy.mock.calls.every((args) => String(args[0]).includes("/auth/me"))).toBe(true);
  });

  it("redirects to the validated next destination on success", async () => {
    const user = userEvent.setup();
    mockFetch((url) => {
      if (url.includes("/auth/login")) {
        return {
          status: 200,
          body: {
            user: USER,
            csrf_token: "c1",
            session_expires_at: null,
            must_change_password: false,
          },
        };
      }
      return { status: 401, body: { error: { code: "x", message: "y" } } };
    });
    render(
      <AuthProvider initialUser={null}>
        <LoginPage />
      </AuthProvider>
    );
    await user.type(screen.getByLabelText(/email/i), "op@example.com");
    await user.type(screen.getByLabelText(/password/i), "long-enough-password-value");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    await waitFor(() => {
      expect(push).toHaveBeenCalledWith("/dashboard");
    });
  });

  it("shows a generic message on invalid credentials", async () => {
    const user = userEvent.setup();
    mockFetch((url) => {
      if (url.includes("/auth/login")) {
        return {
          status: 401,
          body: { error: { code: "invalid_credentials", message: "Invalid email or password." } },
        };
      }
      return { status: 401, body: { error: { code: "x", message: "y" } } };
    });
    render(
      <AuthProvider initialUser={null}>
        <LoginPage />
      </AuthProvider>
    );
    await user.type(screen.getByLabelText(/email/i), "op@example.com");
    await user.type(screen.getByLabelText(/password/i), "wrong-password-value-here");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByText("Invalid email or password.")).toBeInTheDocument();
    expect(push).not.toHaveBeenCalled();
  });

  it("routes forced-change users to change-password", async () => {
    const user = userEvent.setup();
    mockFetch((url) => {
      if (url.includes("/auth/login")) {
        return {
          status: 200,
          body: {
            user: { ...USER, must_change_password: true },
            csrf_token: "c1",
            session_expires_at: null,
            must_change_password: true,
          },
        };
      }
      return { status: 401, body: { error: { code: "x", message: "y" } } };
    });
    render(
      <AuthProvider initialUser={null}>
        <LoginPage />
      </AuthProvider>
    );
    await user.type(screen.getByLabelText(/email/i), "new@example.com");
    await user.type(screen.getByLabelText(/password/i), "long-enough-password-value");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    await waitFor(() => {
      expect(push).toHaveBeenCalledWith("/change-password");
    });
  });
});
