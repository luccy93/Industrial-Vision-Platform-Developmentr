import type { AuthUser } from "../../types";

/** Minimal session identity returned by /me and login. */
export interface SessionInfo {
  user: AuthUser;
  session_expires_at: string | null;
}

export interface LoginResult extends SessionInfo {
  csrf_token: string;
  must_change_password: boolean;
}

/** Error carrying the HTTP status so callers can branch on 401/403. */
export class ApiError extends Error {
  status: number;
  code: string | null;

  constructor(message: string, status: number, code: string | null = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

/** Event dispatched on stateless clients when a 401 is observed. */
export const UNAUTHORIZED_EVENT = "ivp:unauthorized";

export function dispatchUnauthorized(): void {
  if (typeof window !== "undefined" && typeof window.dispatchEvent === "function") {
    window.dispatchEvent(new CustomEvent(UNAUTHORIZED_EVENT));
  }
}

/** In-memory CSRF token only — never browser storage. */
let csrfToken: string | null = null;

export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

export function getCsrfToken(): string | null {
  return csrfToken;
}
