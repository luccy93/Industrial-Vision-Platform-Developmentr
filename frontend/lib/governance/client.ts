import { appConfig } from "../config";
import { dispatchUnauthorized } from "../auth/session";
import { apiFetch } from "../operations/client";
import type {
  GovernanceAuditListResponse,
  GovernanceComplianceReport,
  GovernanceDispositionDetail,
  GovernanceDispositionListResponse,
  GovernanceExportApproval,
  GovernanceExportApprovalListResponse,
  GovernanceLegalHoldDetail,
  GovernanceLegalHoldListResponse,
  GovernancePolicy,
  GovernancePolicyListResponse,
  GovernancePolicyVersionsResponse,
  GovernanceRetentionCaseResponse,
  GovernanceRetentionQueueResponse,
  GovernanceStatus,
} from "../../types";

function queryString(
  params: Record<string, string | number | string[] | undefined | null>
): string {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    if (Array.isArray(value)) {
      for (const item of value) query.append(key, item);
    } else {
      query.set(key, String(value));
    }
  }
  const encoded = query.toString();
  return encoded ? `?${encoded}` : "";
}

export function fetchGovernanceStatus(signal?: AbortSignal): Promise<GovernanceStatus> {
  return apiFetch<GovernanceStatus>("/api/v1/governance/status", { signal });
}

export function fetchGovernancePolicies(
  params: { page?: number; page_size?: number } = {},
  signal?: AbortSignal
): Promise<GovernancePolicyListResponse> {
  return apiFetch<GovernancePolicyListResponse>(
    `/api/v1/governance/policies${queryString(params)}`,
    { signal }
  );
}

export function fetchGovernancePolicyVersions(
  policyId: string,
  signal?: AbortSignal
): Promise<GovernancePolicyVersionsResponse> {
  return apiFetch<GovernancePolicyVersionsResponse>(
    `/api/v1/governance/policies/${encodeURIComponent(policyId)}/versions`,
    { signal }
  );
}

export type GovernancePolicyInput = {
  policy_id?: string;
  name: string;
  state?: string;
  case_type?: string | null;
  evidence_category?: string | null;
  retention_days?: number | null;
  review_interval_days?: number | null;
  required_approval_level?: string;
  export_allowed?: boolean;
  export_requires_approval?: boolean;
  allow_evidence_bytes?: boolean;
  export_expiry_days?: number | null;
  export_review_days?: number | null;
  legal_hold_eligible?: boolean;
  disposition_review_required?: boolean;
  reason: string;
  expected_version?: number;
  idempotency_key?: string;
};

export function createGovernancePolicy(
  input: GovernancePolicyInput
): Promise<{ policy: GovernancePolicy; replayed: boolean }> {
  return apiFetch("/api/v1/governance/policies", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function updateGovernancePolicy(
  policyId: string,
  input: GovernancePolicyInput
): Promise<{ policy: GovernancePolicy; replayed: boolean }> {
  return apiFetch(`/api/v1/governance/policies/${encodeURIComponent(policyId)}`, {
    method: "PATCH",
    body: JSON.stringify(input),
  });
}

export function setGovernancePolicyState(
  policyId: string,
  input: { state: string; reason: string; expected_version?: number; idempotency_key?: string }
): Promise<{ policy: GovernancePolicy; replayed: boolean }> {
  return apiFetch(`/api/v1/governance/policies/${encodeURIComponent(policyId)}/state`, {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function fetchGovernanceRetentionQueue(
  params: { state?: string; page?: number; page_size?: number } = {},
  signal?: AbortSignal
): Promise<GovernanceRetentionQueueResponse> {
  return apiFetch<GovernanceRetentionQueueResponse>(
    `/api/v1/governance/retention/queue${queryString(params)}`,
    { signal }
  );
}

export function fetchGovernanceRetentionCase(
  caseId: string,
  signal?: AbortSignal
): Promise<GovernanceRetentionCaseResponse> {
  return apiFetch<GovernanceRetentionCaseResponse>(
    `/api/v1/governance/retention/cases/${encodeURIComponent(caseId)}`,
    { signal }
  );
}

export function evaluateGovernanceRetention(
  input: { case_id?: string; case_ids?: string[]; as_of?: string }
): Promise<{ evaluation?: unknown; items?: unknown[]; replayed?: boolean }> {
  return apiFetch("/api/v1/governance/retention/evaluate", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function reviewGovernanceRetention(
  caseId: string,
  input: { reason: string; as_of?: string }
): Promise<{ evaluation: unknown; replayed: boolean }> {
  return apiFetch(`/api/v1/governance/retention/cases/${encodeURIComponent(caseId)}/review`, {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function fetchGovernanceHolds(
  params: { case_id?: string; status?: string[]; page?: number; page_size?: number } = {},
  signal?: AbortSignal
): Promise<GovernanceLegalHoldListResponse> {
  return apiFetch<GovernanceLegalHoldListResponse>(
    `/api/v1/governance/holds${queryString(params)}`,
    { signal }
  );
}

export function fetchGovernanceHold(
  holdId: string,
  signal?: AbortSignal
): Promise<GovernanceLegalHoldDetail> {
  return apiFetch<GovernanceLegalHoldDetail>(
    `/api/v1/governance/holds/${encodeURIComponent(holdId)}`,
    { signal }
  );
}

export function createGovernanceHold(input: {
  case_id: string;
  evidence_reference_id?: string;
  scope?: string;
  reason: string;
  idempotency_key?: string;
}): Promise<{ hold: unknown; replayed: boolean }> {
  return apiFetch("/api/v1/governance/holds", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

type GovernanceHoldAction = "approve" | "reject" | "release" | "withdraw";

export function actOnGovernanceHold(
  holdId: string,
  action: GovernanceHoldAction,
  input: { reason: string; expected_version?: number; idempotency_key?: string }
): Promise<{ hold: unknown; replayed: boolean }> {
  return apiFetch(`/api/v1/governance/holds/${encodeURIComponent(holdId)}/${action}`, {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function fetchGovernanceDispositions(
  params: { case_id?: string; status?: string[]; page?: number; page_size?: number } = {},
  signal?: AbortSignal
): Promise<GovernanceDispositionListResponse> {
  return apiFetch<GovernanceDispositionListResponse>(
    `/api/v1/governance/dispositions${queryString(params)}`,
    { signal }
  );
}

export function fetchGovernanceDisposition(
  dispositionId: string,
  signal?: AbortSignal
): Promise<GovernanceDispositionDetail> {
  return apiFetch<GovernanceDispositionDetail>(
    `/api/v1/governance/dispositions/${encodeURIComponent(dispositionId)}`,
    { signal }
  );
}

export function requestGovernanceDisposition(input: {
  case_id: string;
  justification: string;
  idempotency_key?: string;
}): Promise<{ disposition: unknown; replayed: boolean }> {
  return apiFetch("/api/v1/governance/dispositions", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function decideGovernanceDisposition(
  dispositionId: string,
  input: {
    decision: "APPROVE" | "REJECT" | "BLOCK";
    reason: string;
    expected_version?: number;
    idempotency_key?: string;
  }
): Promise<{ disposition: unknown; replayed: boolean }> {
  return apiFetch(
    `/api/v1/governance/dispositions/${encodeURIComponent(dispositionId)}/decide`,
    { method: "POST", body: JSON.stringify(input) }
  );
}

export function withdrawGovernanceDisposition(
  dispositionId: string,
  input: { reason: string; expected_version?: number; idempotency_key?: string }
): Promise<{ disposition: unknown; replayed: boolean }> {
  return apiFetch(
    `/api/v1/governance/dispositions/${encodeURIComponent(dispositionId)}/withdraw`,
    { method: "POST", body: JSON.stringify(input) }
  );
}

export function fetchGovernanceExports(
  params: { case_id?: string; status?: string[]; page?: number; page_size?: number } = {},
  signal?: AbortSignal
): Promise<GovernanceExportApprovalListResponse> {
  return apiFetch<GovernanceExportApprovalListResponse>(
    `/api/v1/governance/exports${queryString(params)}`,
    { signal }
  );
}

export function requestGovernanceExport(input: {
  case_id: string;
  include_evidence_bytes?: boolean;
  reason: string;
  idempotency_key?: string;
}): Promise<{ approval: GovernanceExportApproval; replayed: boolean }> {
  return apiFetch("/api/v1/governance/exports", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function actOnGovernanceExport(
  approvalId: string,
  action: "approve" | "reject" | "withdraw",
  input: { reason: string; expected_version?: number; idempotency_key?: string }
): Promise<{ approval: GovernanceExportApproval; replayed: boolean }> {
  return apiFetch(
    `/api/v1/governance/exports/${encodeURIComponent(approvalId)}/${action}`,
    { method: "POST", body: JSON.stringify(input) }
  );
}

export function generateGovernanceExport(
  approvalId: string
): Promise<{ approval: GovernanceExportApproval; replayed: boolean; delivery_claimed: false }> {
  return apiFetch(`/api/v1/governance/exports/${encodeURIComponent(approvalId)}/generate`, {
    method: "POST",
  });
}

export function verifyGovernanceExport(
  approvalId: string
): Promise<{
  approval: GovernanceExportApproval;
  verification: { outcome: string };
  delivery_claimed: false;
}> {
  return apiFetch(`/api/v1/governance/exports/${encodeURIComponent(approvalId)}/verify`, {
    method: "POST",
  });
}

export function governanceExportDownloadUrl(approvalId: string): string {
  return `${appConfig.apiUrl}/api/v1/governance/exports/${encodeURIComponent(approvalId)}/download`;
}

export function fetchGovernanceAudit(
  params: {
    event_type?: string;
    actor_id?: string;
    case_id?: string;
    outcome?: string;
    page?: number;
    page_size?: number;
  } = {},
  signal?: AbortSignal
): Promise<GovernanceAuditListResponse> {
  return apiFetch<GovernanceAuditListResponse>(
    `/api/v1/governance/audit${queryString(params)}`,
    { signal }
  );
}

export function fetchGovernanceComplianceReport(
  params: { scope?: "SUMMARY" | "DETAIL"; case_id?: string; as_of?: string } = {},
  signal?: AbortSignal
): Promise<GovernanceComplianceReport> {
  return apiFetch<GovernanceComplianceReport>(
    `/api/v1/governance/reports/compliance${queryString(params)}`,
    { signal }
  );
}

export function governanceComplianceCsvUrl(
  params: { scope?: "SUMMARY" | "DETAIL"; case_id?: string; as_of?: string } = {}
): string {
  return `${appConfig.apiUrl}/api/v1/governance/reports/compliance.csv${queryString(params)}`;
}

/** Trigger a cookie-authenticated CSV download (throws on failure). */
export async function downloadGovernanceComplianceCsv(
  params: { scope?: "SUMMARY" | "DETAIL"; case_id?: string; as_of?: string } = {},
  fallbackName = "governance-compliance.csv"
): Promise<void> {
  const res = await fetch(governanceComplianceCsvUrl(params), { credentials: "include" });
  if (res.status === 401) dispatchUnauthorized();
  if (!res.ok) {
    let detail = `Export failed (${res.status})`;
    try {
      const body = (await res.json()) as { error?: { message?: string; code?: string } };
      if (body?.error?.message) detail = `${body.error.code ?? res.status}: ${body.error.message}`;
    } catch {
      /* keep status fallback */
    }
    throw new Error(detail);
  }
  const blob = await res.blob();
  const disposition = res.headers.get("content-disposition") ?? "";
  const match = /filename="([^"]+)"/.exec(disposition);
  const objectUrl = URL.createObjectURL(blob);
  try {
    const anchor = document.createElement("a");
    anchor.href = objectUrl;
    anchor.download = match?.[1] ?? fallbackName;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
  } finally {
    URL.revokeObjectURL(objectUrl);
  }
}
