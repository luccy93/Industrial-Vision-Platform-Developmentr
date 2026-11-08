import { apiFetch } from "../operations/client";
import type {
  IntegrityAuditDetail,
  IntegrityAuditListResponse,
  IntegrityAuditRunResponse,
  IntegrityFindingListResponse,
  IntegrityScope,
  IntegrityStatus,
  IntegritySummary,
} from "../../types";

export type IntegrityAuditQuery = {
  status?: string;
  scope?: string;
  trigger?: string;
  started_from?: string;
  started_to?: string;
  page?: number;
  page_size?: number;
};

export type IntegrityFindingQuery = {
  severity?: string;
  reason_code?: string;
  scope?: string;
  audit_run_id?: string;
  artifact_id?: string;
  detected_from?: string;
  detected_to?: string;
  page?: number;
  page_size?: number;
};

function queryString(params: Record<string, string | number | undefined>): string {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === "") continue;
    query.set(key, String(value));
  }
  const encoded = query.toString();
  return encoded ? `?${encoded}` : "";
}

export function fetchIntegrityStatus(signal?: AbortSignal): Promise<IntegrityStatus> {
  return apiFetch<IntegrityStatus>("/api/v1/integrity/status", { signal });
}

export function fetchIntegritySummary(signal?: AbortSignal): Promise<IntegritySummary> {
  return apiFetch<IntegritySummary>("/api/v1/integrity/summary", { signal });
}

export function fetchIntegrityAudits(
  params: IntegrityAuditQuery = {},
  signal?: AbortSignal
): Promise<IntegrityAuditListResponse> {
  return apiFetch<IntegrityAuditListResponse>(
    `/api/v1/integrity/audits${queryString({
      status: params.status,
      scope: params.scope,
      trigger: params.trigger,
      started_from: params.started_from,
      started_to: params.started_to,
      page: params.page,
      page_size: params.page_size,
    })}`,
    { signal }
  );
}

export function fetchIntegrityHistory(
  params: { page?: number; page_size?: number } = {},
  signal?: AbortSignal
): Promise<IntegrityAuditListResponse> {
  return apiFetch<IntegrityAuditListResponse>(
    `/api/v1/integrity/history${queryString({
      page: params.page,
      page_size: params.page_size,
    })}`,
    { signal }
  );
}

export function fetchIntegrityAudit(
  auditId: string,
  signal?: AbortSignal
): Promise<IntegrityAuditDetail> {
  return apiFetch<IntegrityAuditDetail>(
    `/api/v1/integrity/audits/${encodeURIComponent(auditId)}`,
    { signal }
  );
}

export function fetchIntegrityFindings(
  params: IntegrityFindingQuery = {},
  signal?: AbortSignal
): Promise<IntegrityFindingListResponse> {
  return apiFetch<IntegrityFindingListResponse>(
    `/api/v1/integrity/findings${queryString({
      severity: params.severity,
      reason_code: params.reason_code,
      scope: params.scope,
      audit_run_id: params.audit_run_id,
      artifact_id: params.artifact_id,
      detected_from: params.detected_from,
      detected_to: params.detected_to,
      page: params.page,
      page_size: params.page_size,
    })}`,
    { signal }
  );
}

export function startIntegrityAudit(
  scopes: IntegrityScope[],
  idempotencyKey?: string
): Promise<IntegrityAuditRunResponse> {
  return apiFetch<IntegrityAuditRunResponse>("/api/v1/integrity/audits", {
    method: "POST",
    body: JSON.stringify({
      scopes,
      idempotency_key: idempotencyKey ?? null,
    }),
  });
}

export function cancelIntegrityAudit(
  auditId: string
): Promise<{ cancelled: boolean; audit_run_id: string }> {
  return apiFetch(`/api/v1/integrity/audits/${encodeURIComponent(auditId)}/cancel`, {
    method: "POST",
  });
}
