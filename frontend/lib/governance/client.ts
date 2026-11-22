import { appConfig } from "../config";
import { dispatchUnauthorized } from "../auth/session";
import { apiFetch } from "../operations/client";
import type {
  GovernanceAuditListResponse,
  GovernanceAutomationHealth,
  GovernanceAutomationJobDetail,
  GovernanceAutomationJobListResponse,
  GovernanceAutomationJobType,
  GovernanceAutomationSchedule,
  GovernanceAutomationScheduleListResponse,
  GovernanceAutomationStatus,
  GovernanceComplianceReport,
  GovernanceDispositionDetail,
  GovernanceDispositionListResponse,
  GovernanceExecutiveActionDetail,
  GovernanceExecutiveActionListResponse,
  GovernanceExecutiveActionMutationResponse,
  GovernanceExecutiveActionStatus,
  GovernanceExecutiveComparison,
  GovernanceExecutiveConfig,
  GovernanceExecutiveHealthResponse,
  GovernanceExecutiveKpiResponse,
  GovernanceExecutiveReportDetail,
  GovernanceExecutiveReportGenerateResponse,
  GovernanceExecutiveReportListResponse,
  GovernanceExecutiveReportType,
  GovernanceExecutiveStatus,
  GovernanceExportApproval,
  GovernanceExportApprovalListResponse,
  GovernanceIntelligenceSnapshotDetail,
  GovernanceIntelligenceSnapshotListResponse,
  GovernanceIntelligenceStatus,
  GovernanceLegalHoldDetail,
  GovernanceLegalHoldListResponse,
  GovernancePolicy,
  GovernancePolicyListResponse,
  GovernancePolicyVersionsResponse,
  GovernanceRecommendationDetail,
  GovernanceRecommendationListResponse,
  GovernanceRecommendationRefreshResponse,
  GovernanceReminderActivity,
  GovernanceRetentionCaseResponse,
  GovernanceRetentionQueueResponse,
  GovernanceRiskCaseDetail,
  GovernanceRiskCaseListResponse,
  GovernanceSlaBacklogResponse,
  GovernanceSnapshot,
  GovernanceSnapshotComparison,
  GovernanceSnapshotDetail,
  GovernanceSnapshotListResponse,
  GovernanceStatus,
  GovernanceTrendsResponse,
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

// ---------------------------------------------------------------------------
// V36 governance automation
// ---------------------------------------------------------------------------
export function fetchGovernanceAutomationStatus(
  signal?: AbortSignal
): Promise<GovernanceAutomationStatus> {
  return apiFetch<GovernanceAutomationStatus>("/api/v1/governance/automation/status", {
    signal,
  });
}

export function fetchGovernanceAutomationHealth(
  signal?: AbortSignal
): Promise<GovernanceAutomationHealth> {
  return apiFetch<GovernanceAutomationHealth>("/api/v1/governance/automation/health", {
    signal,
  });
}

export function fetchGovernanceAutomationSchedules(
  signal?: AbortSignal
): Promise<GovernanceAutomationScheduleListResponse> {
  return apiFetch<GovernanceAutomationScheduleListResponse>(
    "/api/v1/governance/automation/schedules",
    { signal }
  );
}

export function updateGovernanceAutomationSchedule(
  jobType: GovernanceAutomationJobType | string,
  input: {
    enabled: boolean;
    interval_minutes: number;
    config: Record<string, unknown>;
    expected_version: number;
    reason: string;
  }
): Promise<{ schedule: GovernanceAutomationSchedule; non_claims: string[] }> {
  return apiFetch(
    `/api/v1/governance/automation/schedules/${encodeURIComponent(jobType)}`,
    { method: "PUT", body: JSON.stringify(input) }
  );
}

export function fetchGovernanceAutomationJobs(
  params: {
    job_type?: string;
    status?: string;
    trigger?: string;
    page?: number;
    page_size?: number;
  } = {},
  signal?: AbortSignal
): Promise<GovernanceAutomationJobListResponse> {
  return apiFetch<GovernanceAutomationJobListResponse>(
    `/api/v1/governance/automation/jobs${queryString(params)}`,
    { signal }
  );
}

export function fetchGovernanceAutomationJob(
  jobId: string,
  signal?: AbortSignal
): Promise<GovernanceAutomationJobDetail> {
  return apiFetch<GovernanceAutomationJobDetail>(
    `/api/v1/governance/automation/jobs/${encodeURIComponent(jobId)}`,
    { signal }
  );
}

export function runGovernanceAutomationJob(input: {
  job_type: GovernanceAutomationJobType | string;
  idempotency_key: string;
  reason: string;
}): Promise<{ job: Record<string, unknown>; replayed: boolean; executed: boolean }> {
  return apiFetch("/api/v1/governance/automation/jobs/run", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function retryGovernanceAutomationJob(
  jobId: string,
  input: { reason: string }
): Promise<{ job: Record<string, unknown>; replayed: boolean; executed: boolean }> {
  return apiFetch(
    `/api/v1/governance/automation/jobs/${encodeURIComponent(jobId)}/retry`,
    { method: "POST", body: JSON.stringify(input) }
  );
}

export function cancelGovernanceAutomationJob(
  jobId: string,
  input: { reason: string }
): Promise<{
  job: Record<string, unknown>;
  cancelled: boolean;
  cancel_requested: boolean;
  non_claims: string[];
}> {
  return apiFetch(
    `/api/v1/governance/automation/jobs/${encodeURIComponent(jobId)}/cancel`,
    { method: "POST", body: JSON.stringify(input) }
  );
}

export function fetchGovernanceSnapshots(
  params: { snapshot_type?: string; page?: number; page_size?: number } = {},
  signal?: AbortSignal
): Promise<GovernanceSnapshotListResponse> {
  return apiFetch<GovernanceSnapshotListResponse>(
    `/api/v1/governance/automation/snapshots${queryString(params)}`,
    { signal }
  );
}

export function fetchGovernanceSnapshot(
  snapshotId: string,
  signal?: AbortSignal
): Promise<GovernanceSnapshotDetail> {
  return apiFetch<GovernanceSnapshotDetail>(
    `/api/v1/governance/automation/snapshots/${encodeURIComponent(snapshotId)}`,
    { signal }
  );
}

export function generateGovernanceSnapshot(input: {
  idempotency_key: string;
  reason: string;
}): Promise<{ snapshot: GovernanceSnapshot; replayed: boolean; non_claims: string[] }> {
  return apiFetch("/api/v1/governance/automation/snapshots", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function governanceSnapshotCsvUrl(snapshotId: string): string {
  return `${appConfig.apiUrl}/api/v1/governance/automation/snapshots/${encodeURIComponent(
    snapshotId
  )}/csv`;
}

export function fetchGovernanceReminderActivity(
  params: { event_type?: string; page?: number; page_size?: number } = {},
  signal?: AbortSignal
): Promise<GovernanceReminderActivity> {
  return apiFetch<GovernanceReminderActivity>(
    `/api/v1/governance/automation/reminders${queryString(params)}`,
    { signal }
  );
}

// ---------------------------------------------------------------------------
// V37 governance intelligence
// ---------------------------------------------------------------------------
export function fetchGovernanceIntelligenceStatus(
  signal?: AbortSignal
): Promise<GovernanceIntelligenceStatus> {
  return apiFetch<GovernanceIntelligenceStatus>("/api/v1/governance/intelligence/status", {
    signal,
  });
}

export function fetchGovernanceRiskCases(
  params: {
    risk_level?: string;
    case_status?: string;
    case_severity?: string;
    page?: number;
    page_size?: number;
  } = {},
  signal?: AbortSignal
): Promise<GovernanceRiskCaseListResponse> {
  return apiFetch<GovernanceRiskCaseListResponse>(
    `/api/v1/governance/intelligence/risk/cases${queryString(params)}`,
    { signal }
  );
}

export function fetchGovernanceRiskCase(
  caseId: string,
  signal?: AbortSignal
): Promise<GovernanceRiskCaseDetail> {
  return apiFetch<GovernanceRiskCaseDetail>(
    `/api/v1/governance/intelligence/risk/cases/${encodeURIComponent(caseId)}`,
    { signal }
  );
}

export function fetchGovernanceSlaBacklog(
  params: {
    target_key?: string;
    state?: string;
    page?: number;
    page_size?: number;
  } = {},
  signal?: AbortSignal
): Promise<GovernanceSlaBacklogResponse> {
  return apiFetch<GovernanceSlaBacklogResponse>(
    `/api/v1/governance/intelligence/sla/backlog${queryString(params)}`,
    { signal }
  );
}

export function fetchGovernanceTrends(
  params: { start_at?: string; end_at?: string; bucket?: string } = {},
  signal?: AbortSignal
): Promise<GovernanceTrendsResponse> {
  return apiFetch<GovernanceTrendsResponse>(
    `/api/v1/governance/intelligence/trends${queryString(params)}`,
    { signal }
  );
}

export function refreshGovernanceRecommendations(input: {
  reason: string;
}): Promise<GovernanceRecommendationRefreshResponse> {
  return apiFetch("/api/v1/governance/intelligence/recommendations/refresh", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function fetchGovernanceRecommendations(
  params: {
    status?: string;
    severity?: string;
    rule_id?: string;
    page?: number;
    page_size?: number;
  } = {},
  signal?: AbortSignal
): Promise<GovernanceRecommendationListResponse> {
  return apiFetch<GovernanceRecommendationListResponse>(
    `/api/v1/governance/intelligence/recommendations${queryString(params)}`,
    { signal }
  );
}

export function fetchGovernanceRecommendation(
  recommendationId: string,
  signal?: AbortSignal
): Promise<GovernanceRecommendationDetail> {
  return apiFetch<GovernanceRecommendationDetail>(
    `/api/v1/governance/intelligence/recommendations/${encodeURIComponent(recommendationId)}`,
    { signal }
  );
}

export function acknowledgeGovernanceRecommendation(
  recommendationId: string,
  input: { reason?: string; expected_version?: number }
): Promise<GovernanceRecommendationDetail> {
  return apiFetch(
    `/api/v1/governance/intelligence/recommendations/${encodeURIComponent(
      recommendationId
    )}/acknowledge`,
    { method: "POST", body: JSON.stringify(input) }
  );
}

export function dismissGovernanceRecommendation(
  recommendationId: string,
  input: { reason: string; expected_version?: number }
): Promise<GovernanceRecommendationDetail> {
  return apiFetch(
    `/api/v1/governance/intelligence/recommendations/${encodeURIComponent(
      recommendationId
    )}/dismiss`,
    { method: "POST", body: JSON.stringify(input) }
  );
}

export function fetchGovernanceIntelligenceSnapshots(
  params: { page?: number; page_size?: number } = {},
  signal?: AbortSignal
): Promise<GovernanceIntelligenceSnapshotListResponse> {
  return apiFetch<GovernanceIntelligenceSnapshotListResponse>(
    `/api/v1/governance/intelligence/snapshots${queryString(params)}`,
    { signal }
  );
}

export function generateGovernanceIntelligenceSnapshot(input: {
  idempotency_key: string;
  reason: string;
}): Promise<{
  snapshot: GovernanceIntelligenceSnapshotDetail["snapshot"];
  replayed: boolean;
  availability: string;
  assurance: string;
  non_claims: string[];
}> {
  return apiFetch("/api/v1/governance/intelligence/snapshots", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function fetchGovernanceIntelligenceSnapshot(
  snapshotId: string,
  signal?: AbortSignal
): Promise<GovernanceIntelligenceSnapshotDetail> {
  return apiFetch<GovernanceIntelligenceSnapshotDetail>(
    `/api/v1/governance/intelligence/snapshots/${encodeURIComponent(snapshotId)}`,
    { signal }
  );
}

export function compareGovernanceIntelligenceSnapshots(
  snapshotId: string,
  otherSnapshotId: string,
  signal?: AbortSignal
): Promise<GovernanceSnapshotComparison> {
  return apiFetch<GovernanceSnapshotComparison>(
    `/api/v1/governance/intelligence/snapshots/${encodeURIComponent(
      snapshotId
    )}/compare/${encodeURIComponent(otherSnapshotId)}`,
    { signal }
  );
}

// ---------------------------------------------------------------------------
// V38 executive governance command center
// ---------------------------------------------------------------------------
export function fetchGovernanceExecutiveStatus(
  signal?: AbortSignal
): Promise<GovernanceExecutiveStatus> {
  return apiFetch<GovernanceExecutiveStatus>("/api/v1/governance/executive/status", {
    signal,
  });
}

export function fetchGovernanceExecutiveHealth(
  params: { window_days?: number } = {},
  signal?: AbortSignal
): Promise<GovernanceExecutiveHealthResponse> {
  return apiFetch<GovernanceExecutiveHealthResponse>(
    `/api/v1/governance/executive/health${queryString(params)}`,
    { signal }
  );
}

export function fetchGovernanceExecutiveKpis(
  params: { window_days?: number } = {},
  signal?: AbortSignal
): Promise<GovernanceExecutiveKpiResponse> {
  return apiFetch<GovernanceExecutiveKpiResponse>(
    `/api/v1/governance/executive/kpis${queryString(params)}`,
    { signal }
  );
}

export function fetchGovernanceExecutiveConfig(
  signal?: AbortSignal
): Promise<GovernanceExecutiveConfig> {
  return apiFetch<GovernanceExecutiveConfig>("/api/v1/governance/executive/config", {
    signal,
  });
}

export function updateGovernanceExecutiveConfig(input: {
  config: Record<string, unknown>;
  reason: string;
}): Promise<GovernanceExecutiveConfig & { replayed: boolean; snapshot_id: string }> {
  return apiFetch("/api/v1/governance/executive/config", {
    method: "PUT",
    body: JSON.stringify(input),
  });
}

export function fetchGovernanceExecutiveActions(
  params: {
    status?: GovernanceExecutiveActionStatus | "";
    owner_id?: string;
    recommendation_id?: string;
    page?: number;
    page_size?: number;
  } = {},
  signal?: AbortSignal
): Promise<GovernanceExecutiveActionListResponse> {
  return apiFetch<GovernanceExecutiveActionListResponse>(
    `/api/v1/governance/executive/actions${queryString(params)}`,
    { signal }
  );
}

export function fetchGovernanceExecutiveAction(
  actionId: string,
  signal?: AbortSignal
): Promise<GovernanceExecutiveActionDetail> {
  return apiFetch<GovernanceExecutiveActionDetail>(
    `/api/v1/governance/executive/actions/${encodeURIComponent(actionId)}`,
    { signal }
  );
}

export type GovernanceExecutiveActionInput = {
  recommendation_id: string;
  title: string;
  description?: string;
  owner_id: string;
  due_at: string;
  priority?: string;
  idempotency_key: string;
  reason: string;
};

export function createGovernanceExecutiveAction(
  input: GovernanceExecutiveActionInput
): Promise<GovernanceExecutiveActionMutationResponse> {
  return apiFetch("/api/v1/governance/executive/actions", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function transitionGovernanceExecutiveAction(
  actionId: string,
  input: {
    target_status: GovernanceExecutiveActionStatus;
    expected_version: number;
    reason?: string;
    outcome_summary?: string;
    block_reason?: string;
    cancel_reason?: string;
  }
): Promise<GovernanceExecutiveActionMutationResponse> {
  return apiFetch(
    `/api/v1/governance/executive/actions/${encodeURIComponent(actionId)}/transition`,
    { method: "POST", body: JSON.stringify(input) }
  );
}

export function assignGovernanceExecutiveAction(
  actionId: string,
  input: { owner_id: string; expected_version: number; reason: string }
): Promise<GovernanceExecutiveActionMutationResponse> {
  return apiFetch(
    `/api/v1/governance/executive/actions/${encodeURIComponent(actionId)}/assign`,
    { method: "POST", body: JSON.stringify(input) }
  );
}

export function fetchGovernanceExecutiveReports(
  params: { report_type?: GovernanceExecutiveReportType | ""; page?: number; page_size?: number } = {},
  signal?: AbortSignal
): Promise<GovernanceExecutiveReportListResponse> {
  return apiFetch<GovernanceExecutiveReportListResponse>(
    `/api/v1/governance/executive/reports${queryString(params)}`,
    { signal }
  );
}

export function fetchGovernanceExecutiveReport(
  reportId: string,
  signal?: AbortSignal
): Promise<GovernanceExecutiveReportDetail> {
  return apiFetch<GovernanceExecutiveReportDetail>(
    `/api/v1/governance/executive/reports/${encodeURIComponent(reportId)}`,
    { signal }
  );
}

export function generateGovernanceExecutiveReport(input: {
  report_type: GovernanceExecutiveReportType;
  format: "json" | "csv";
  window_days?: number;
  idempotency_key: string;
  reason: string;
}): Promise<GovernanceExecutiveReportGenerateResponse> {
  return apiFetch("/api/v1/governance/executive/reports", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function fetchGovernanceExecutiveComparison(
  reportId: string,
  params: { other_report_id?: string; window_days?: number } = {},
  signal?: AbortSignal
): Promise<GovernanceExecutiveComparison> {
  if (params.other_report_id) {
    return apiFetch<GovernanceExecutiveComparison>(
      `/api/v1/governance/executive/comparisons/${encodeURIComponent(
        reportId
      )}/vs/${encodeURIComponent(params.other_report_id)}`,
      { signal }
    );
  }
  return apiFetch<GovernanceExecutiveComparison>(
    `/api/v1/governance/executive/comparisons/${encodeURIComponent(reportId)}${queryString({
      window_days: params.window_days,
    })}`,
    { signal }
  );
}

/** Trigger a cookie-authenticated executive report content download. */
export async function downloadGovernanceExecutiveReportContent(
  reportId: string,
  fallbackName = "executive-report.json"
): Promise<void> {
  const res = await fetch(
    `${appConfig.apiUrl}/api/v1/governance/executive/reports/${encodeURIComponent(
      reportId
    )}/content`,
    { credentials: "include" }
  );
  if (res.status === 401) dispatchUnauthorized();
  if (!res.ok) {
    let detail = `Report download failed (${res.status})`;
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
