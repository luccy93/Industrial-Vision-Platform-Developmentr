import { appConfig } from "../config";
import {
  ApiError,
  getCsrfToken,
  setCsrfToken,
  type LoginResult,
  type SessionInfo,
} from "./session";
import type { AuthUser } from "../../types";

async function authFetch<T>(path: string, init?: RequestInit): Promise<{ data: T; status: number }> {
  const method = (init?.method ?? "GET").toUpperCase();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...((init?.headers ?? {}) as Record<string, string>),
  };
  if (method !== "GET" && method !== "HEAD") {
    const csrf = getCsrfToken();
    if (csrf) headers["X-CSRF-Token"] = csrf;
  }
  let res: Response;
  try {
    res = await fetch(`${appConfig.apiUrl}${path}`, { ...init, credentials: "include", headers });
  } catch (e) {
    throw new Error(`API unreachable (${path}): ${e instanceof Error ? e.message : e}`);
  }
  if (!res.ok) {
    let detail = `${path} → ${res.status}`;
    let code: string | null = null;
    try {
      const body = (await res.json()) as {
        error?: { message?: string; code?: string };
        detail?: unknown;
      };
      if (body?.error?.message) {
        code = body.error.code ?? null;
        detail = `${body.error.code ?? res.status}: ${body.error.message}`;
      } else if (typeof body?.detail === "string") {
        detail = body.detail;
      } else if (body?.detail !== null && typeof body.detail === "object") {
        const d = body.detail as { message?: string; code?: string };
        if (d?.message) {
          code = d.code ?? null;
          detail = d.message;
        }
      }
    } catch {
      /* keep the status fallback */
    }
    throw new ApiError(detail, res.status, code);
  }
  return { data: (await res.json()) as T, status: res.status };
}

export async function login(email: string, password: string): Promise<LoginResult> {
  const { data } = await authFetch<LoginResult>("/api/v1/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
  setCsrfToken(data.csrf_token);
  return data;
}

export async function logout(): Promise<void> {
  try {
    await authFetch<{ ok: boolean }>("/api/v1/auth/logout", { method: "POST" });
  } finally {
    setCsrfToken(null);
  }
}

export async function fetchMe(signal?: AbortSignal): Promise<SessionInfo> {
  const { data } = await authFetch<SessionInfo>("/api/v1/auth/me", { signal });
  return data;
}

export async function rotateCsrf(): Promise<string> {
  const { data } = await authFetch<{ csrf_token: string }>("/api/v1/auth/csrf", {
    method: "POST",
    body: JSON.stringify({}),
  });
  setCsrfToken(data.csrf_token);
  return data.csrf_token;
}

export async function changePassword(currentPassword: string, newPassword: string): Promise<void> {
  await authFetch<{ ok: boolean }>("/api/v1/auth/change-password", {
    method: "POST",
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  });
}

export async function fetchWsTicket(scope: string): Promise<{ ticket: string; expires_at: string; scope: string }> {
  const { data } = await authFetch<{ ticket: string; expires_at: string; scope: string }>(
    "/api/v1/auth/ws-ticket",
    { method: "POST", body: JSON.stringify({ scope }) }
  );
  return data;
}

export interface UserListResponse {
  users: AuthUser[];
  total: number;
  page: number;
  page_size: number;
}

export async function fetchUsers(page = 1, pageSize = 50): Promise<UserListResponse> {
  const { data } = await authFetch<UserListResponse>(
    `/api/v1/auth/users?page=${page}&page_size=${pageSize}`
  );
  return data;
}

export async function createUser(input: {
  email: string;
  password: string;
  role: string;
}): Promise<{ user: AuthUser }> {
  const { data } = await authFetch<{ user: AuthUser }>("/api/v1/auth/users", {
    method: "POST",
    body: JSON.stringify(input),
  });
  return data;
}

export async function patchUser(
  id: string,
  input: { role?: string; is_active?: boolean; must_change_password?: boolean }
): Promise<{ user: AuthUser }> {
  const { data } = await authFetch<{ user: AuthUser }>(`/api/v1/auth/users/${id}`, {
    method: "PATCH",
    body: JSON.stringify(input),
  });
  return data;
}

export async function revokeUserSessions(id: string): Promise<{ ok: boolean; revoked: number }> {
  const { data } = await authFetch<{ ok: boolean; revoked: number }>(
    `/api/v1/auth/users/${id}/revoke-sessions`,
    { method: "POST", body: JSON.stringify({}) }
  );
  return data;
}
