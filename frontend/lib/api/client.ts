import { appConfig } from "../config";

export async function apiGet<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${appConfig.apiUrl}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) }
  });
  if (!res.ok) {
    throw new Error(`API ${path} failed with ${res.status}`);
  }
  return (await res.json()) as T;
}

export const healthApi = {
  root: () => apiGet("/health"),
  ready: () => apiGet("/ready"),
  v1: () => apiGet("/api/v1/health")
};
