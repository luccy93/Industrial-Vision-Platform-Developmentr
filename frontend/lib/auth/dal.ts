import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import type { AuthRole, AuthUser } from "../../types";

/**
 * Server-only data-access layer (V16). Verifies the real session against
 * FastAPI on every call (`no-store`, forwarded HttpOnly cookie) — browser
 * role claims are never trusted. Layouts use this for route gating;
 * FastAPI remains the authoritative enforcer for all data access.
 */

const SESSION_COOKIE = "ivp_session";

function apiBase(): string {
  return (
    process.env.API_INTERNAL_URL ??
    process.env.NEXT_PUBLIC_API_URL ??
    "http://localhost:8000"
  );
}

export function safeNext(value: string | null | undefined): string {
  if (value && value.startsWith("/") && !value.startsWith("//")) return value;
  return "/dashboard";
}

/** Resolve the current user via FastAPI /me, or null (never throws). */
export async function getSessionUser(): Promise<AuthUser | null> {
  let cookieHeader = "";
  try {
    cookieHeader = (await cookies()).toString();
  } catch {
    return null;
  }
  if (!cookieHeader.includes(SESSION_COOKIE)) return null;
  try {
    const res = await fetch(`${apiBase()}/api/v1/auth/me`, {
      headers: { Cookie: cookieHeader },
      cache: "no-store",
    });
    if (!res.ok) return null;
    const body = (await res.json()) as { user?: AuthUser };
    const user = body?.user;
    if (!user || typeof user.email !== "string" || typeof user.role !== "string") return null;
    return user;
  } catch {
    // Backend unreachable (e.g. static build): fail open at this UX layer.
    // FastAPI stays authoritative — data requests fail closed with 401.
    return null;
  }
}

/** Gate a protected path: valid session required; forced-change reroutes. */
export async function requireUser(path: string): Promise<AuthUser> {
  const user = await getSessionUser();
  if (!user) redirect(`/login?next=${encodeURIComponent(safeNext(path))}`);
  if (user.must_change_password && path !== "/change-password") redirect("/change-password");
  return user;
}

/** Gate an admin-only path on top of requireUser. */
export async function requireRole(path: string, role: AuthRole): Promise<AuthUser> {
  const user = await requireUser(path);
  if (user.role !== role) redirect("/dashboard");
  return user;
}
