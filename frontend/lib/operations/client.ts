import { appConfig } from "../config";
import { ApiError, dispatchUnauthorized, getCsrfToken } from "../auth/session";
import type {
  CameraItem,
  IncidentListResponse,
  OperationsSummary,
  StreamStatus,
} from "../../types";

/** Shared fetch honoring the backend error envelope (never throws raw).
 *
 * Sends the session cookie (`credentials: "include"`) and the CSRF header
 * on state-changing requests. A 401 dispatches the global unauthorized
 * event (the AuthProvider redirects to /login) and throws ApiError.
 */
export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const started = Date.now();
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
    res = await fetch(`${appConfig.apiUrl}${path}`, {
      ...init,
      credentials: "include",
      headers,
    });
  } catch (e) {
    throw new Error(`API unreachable (${path}): ${e instanceof Error ? e.message : e}`);
  }
  void started;
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
      } else if (
        body?.detail !== null &&
        typeof body.detail === "object" &&
        (body.detail as { message?: string; code?: string })?.message
      ) {
        const d = body.detail as { message?: string; code?: string };
        code = d.code ?? null;
        detail = d.message ?? detail;
      }
    } catch {
      /* keep the status fallback */
    }
    if (res.status === 401) dispatchUnauthorized();
    throw new ApiError(detail, res.status, code);
  }
  return (await res.json()) as T;
}

export function fetchOperationsSummary(signal?: AbortSignal): Promise<OperationsSummary> {
  return apiFetch<OperationsSummary>("/api/v1/operations/summary", { signal });
}

export function fetchCameras(signal?: AbortSignal): Promise<{ items: CameraItem[] }> {
  return apiFetch<{ items: CameraItem[] }>("/api/v1/cameras", { signal });
}

export function fetchCameraStatus(
  cameraId: string,
  signal?: AbortSignal
): Promise<StreamStatus> {
  return apiFetch<StreamStatus>(
    `/api/v1/cameras/${encodeURIComponent(cameraId)}/status`,
    { signal }
  );
}

export function fetchIncidents(
  params: { status?: string[]; page?: number; page_size?: number },
  signal?: AbortSignal
): Promise<IncidentListResponse> {
  const query = new URLSearchParams();
  for (const s of params.status ?? []) query.append("status", s);
  query.set("page", String(params.page ?? 1));
  query.set("page_size", String(params.page_size ?? 20));
  return apiFetch<IncidentListResponse>(`/api/v1/incidents?${query.toString()}`, { signal });
}

export function fetchSafetyEvents(
  cameraId: string,
  limit = 50,
  signal?: AbortSignal
): Promise<{ count: number; events: Array<Record<string, unknown>> }> {
  return apiFetch(
    `/api/v1/cameras/${encodeURIComponent(cameraId)}/safety/events?status=all&limit=${limit}`,
    { signal }
  );
}

export function fetchQualityEvents(
  cameraId: string,
  limit = 50,
  signal?: AbortSignal
): Promise<{ count: number; events: Array<Record<string, unknown>> }> {
  return apiFetch(
    `/api/v1/cameras/${encodeURIComponent(cameraId)}/quality/events?status=all&limit=${limit}`,
    { signal }
  );
}

export function fetchAutonomousEvents(
  cameraId: string,
  limit = 50,
  signal?: AbortSignal
): Promise<{ count: number; events: Array<Record<string, unknown>> }> {
  return apiFetch(
    `/api/v1/cameras/${encodeURIComponent(cameraId)}/autonomous/events?status=all&limit=${limit}`,
    { signal }
  );
}

export function fetchIntelligenceEvents(
  cameraId: string,
  limit = 100,
  signal?: AbortSignal
): Promise<{ count: number; events: Array<Record<string, unknown>> }> {
  return apiFetch(
    `/api/v1/cameras/${encodeURIComponent(cameraId)}/intelligence/events?status=all&limit=${limit}`,
    { signal }
  );
}

export function fetchHealth(signal?: AbortSignal): Promise<{
  status: string;
  components: Array<{ component: string; status: string }>;
  summary: string;
}> {
  return apiFetch("/api/v1/health", { signal });
}

/** Freshness: ms since `isoTimestamp`; null when unparseable. */
export function ageMs(isoTimestamp: string | null | undefined, now = Date.now()): number | null {
  if (!isoTimestamp) return null;
  const parsed = Date.parse(isoTimestamp);
  if (Number.isNaN(parsed)) return null;
  return Math.max(0, now - parsed);
}

/** True when the data is older than `staleAfterMs` (or has no timestamp). */
export function isStale(
  isoTimestamp: string | null | undefined,
  staleAfterMs: number,
  now = Date.now()
): boolean {
  const age = ageMs(isoTimestamp, now);
  if (age === null) return true;
  return age > staleAfterMs;
}
