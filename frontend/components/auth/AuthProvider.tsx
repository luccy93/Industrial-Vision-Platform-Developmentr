"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { usePathname, useRouter } from "next/navigation";
import {
  changePassword as apiChangePassword,
  fetchMe,
  fetchWsTicket,
  login as apiLogin,
  logout as apiLogout,
} from "../../lib/auth/client";
import { ApiError, UNAUTHORIZED_EVENT } from "../../lib/auth/session";
import type { AuthRole, AuthUser } from "../../types";

interface AuthContextValue {
  user: AuthUser | null;
  loading: boolean;
  error: string | null;
  login: (email: string, password: string) => Promise<{ mustChangePassword: boolean }>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
  getTicket: (scope: string) => Promise<string | null>;
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>;
  hasRole: (role: AuthRole) => boolean;
  isAdmin: boolean;
}

/** Null-safe default so pages render in tests without a provider. */
const AuthContext = createContext<AuthContextValue>({
  user: null,
  loading: false,
  error: null,
  login: async () => ({ mustChangePassword: false }),
  logout: async () => {},
  refresh: async () => {},
  getTicket: async () => null,
  changePassword: async () => {},
  hasRole: () => false,
  isAdmin: false,
});

export function useAuth(): AuthContextValue {
  return useContext(AuthContext);
}

function safeNext(value: string | null): string {
  if (value && value.startsWith("/") && !value.startsWith("//")) return value;
  return "/dashboard";
}

export function AuthProvider({
  children,
  initialUser = null,
}: {
  children: ReactNode;
  initialUser?: AuthUser | null;
}) {
  const router = useRouter();
  const pathname = usePathname();
  const [user, setUser] = useState<AuthUser | null>(initialUser);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const redirectToLogin = useCallback(
    (from: string) => {
      if (from !== "/login") router.push(`/login?next=${encodeURIComponent(safeNext(from))}`);
    },
    [router]
  );

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const session = await fetchMe();
      setUser(session.user);
      setError(null);
    } catch (e) {
      if (!(e instanceof ApiError && e.status === 401)) {
        setError(e instanceof Error ? e.message : "Session check failed.");
      }
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    const onUnauthorized = () => {
      setUser(null);
      redirectToLogin(pathname ?? "/dashboard");
    };
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
  }, [pathname, redirectToLogin]);

  const login = useCallback(async (email: string, password: string) => {
    setLoading(true);
    setError(null);
    try {
      const result = await apiLogin(email, password);
      setUser(result.user);
      return { mustChangePassword: result.must_change_password };
    } catch (e) {
      const message =
        e instanceof ApiError && e.status === 401
          ? "Invalid email or password."
          : e instanceof Error
            ? e.message
            : "Login failed.";
      setError(message);
      throw new Error(message);
    } finally {
      setLoading(false);
    }
  }, []);

  const logout = useCallback(async () => {
    try {
      await apiLogout();
    } finally {
      setUser(null);
      setError(null);
      router.push("/login");
    }
  }, [router]);

  const getTicket = useCallback(async (scope: string) => {
    try {
      const issued = await fetchWsTicket(scope);
      return issued.ticket;
    } catch {
      return null;
    }
  }, []);

  const changePassword = useCallback(async (currentPassword: string, newPassword: string) => {
    await apiChangePassword(currentPassword, newPassword);
    await refresh();
  }, [refresh]);

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      loading,
      error,
      login,
      logout,
      refresh,
      getTicket,
      changePassword,
      hasRole: (role) => user?.role === role,
      isAdmin: user?.role === "ADMIN",
    }),
    [user, loading, error, login, logout, refresh, getTicket, changePassword]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
