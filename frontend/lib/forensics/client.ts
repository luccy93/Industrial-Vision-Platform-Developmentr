import { appConfig } from "../config";
import { apiFetch } from "../operations/client";
import type {
  ForensicCase,
  ForensicCaseDetail,
  ForensicCaseListResponse,
  ForensicCaseStatus,
  ForensicCaseSummary,
  ForensicCorrelationResponse,
  ForensicCustodyEvent,
  ForensicCustodyVerification,
  ForensicEvidenceReference,
  ForensicExportListResponse,
  ForensicExportRecord,
  ForensicExportVerifyResponse,
  ForensicFindingsResponse,
  ForensicNote,
  ForensicNoteRevision,
  ForensicStatus,
  ForensicVerificationReport,
} from "../../types";

export type ForensicCaseQuery = {
  status?: string[];
  severity?: string[];
  case_type?: string[];
  assigned_to?: string;
  source?: string;
  originating_incident_id?: string;
  search?: string;
  page?: number;
  page_size?: number;
};

export type ForensicFindingQuery = {
  audit_run_id?: string;
  severity?: string;
  reason_code?: string;
  page?: number;
  page_size?: number;
};

function queryString(
  params: Record<string, string | number | string[] | undefined>
): string {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === "") continue;
    if (Array.isArray(value)) {
      for (const item of value) query.append(key, item);
    } else {
      query.set(key, String(value));
    }
  }
  const encoded = query.toString();
  return encoded ? `?${encoded}` : "";
}

export function fetchForensicStatus(signal?: AbortSignal): Promise<ForensicStatus> {
  return apiFetch<ForensicStatus>("/api/v1/forensics/status", { signal });
}

export function fetchForensicSummary(signal?: AbortSignal): Promise<ForensicCaseSummary> {
  return apiFetch<ForensicCaseSummary>("/api/v1/forensics/summary", { signal });
}

export function fetchForensicCases(
  params: ForensicCaseQuery = {},
  signal?: AbortSignal
): Promise<ForensicCaseListResponse> {
  return apiFetch<ForensicCaseListResponse>(
    `/api/v1/forensics/cases${queryString({
      status: params.status,
      severity: params.severity,
      case_type: params.case_type,
      assigned_to: params.assigned_to,
      source: params.source,
      originating_incident_id: params.originating_incident_id,
      search: params.search,
      page: params.page,
      page_size: params.page_size,
    })}`,
    { signal }
  );
}

export function fetchForensicCase(
  caseId: string,
  signal?: AbortSignal
): Promise<ForensicCaseDetail> {
  return apiFetch<ForensicCaseDetail>(
    `/api/v1/forensics/cases/${encodeURIComponent(caseId)}`,
    { signal }
  );
}

export function fetchForensicCustody(
  caseId: string,
  signal?: AbortSignal
): Promise<{ events: ForensicCustodyEvent[]; verification: ForensicCustodyVerification }> {
  return apiFetch<{
    events: ForensicCustodyEvent[];
    verification: ForensicCustodyVerification;
  }>(`/api/v1/forensics/cases/${encodeURIComponent(caseId)}/custody`, { signal });
}

export function fetchForensicTimeline(
  caseId: string,
  signal?: AbortSignal
): Promise<{ items: ForensicCustodyEvent[] }> {
  return apiFetch<{ items: ForensicCustodyEvent[] }>(
    `/api/v1/forensics/cases/${encodeURIComponent(caseId)}/timeline`,
    { signal }
  );
}

export function fetchForensicFindings(
  params: ForensicFindingQuery = {},
  signal?: AbortSignal
): Promise<ForensicFindingsResponse> {
  return apiFetch<ForensicFindingsResponse>(
    `/api/v1/forensics/findings${queryString({
      audit_run_id: params.audit_run_id,
      severity: params.severity,
      reason_code: params.reason_code,
      page: params.page,
      page_size: params.page_size,
    })}`,
    { signal }
  );
}

export function createForensicCase(input: {
  title: string;
  description?: string;
  case_type?: string;
  severity?: string;
  priority?: string;
  originating_incident_id?: string;
  originating_audit_run_id?: string;
  assigned_to?: string;
}): Promise<ForensicCase> {
  return apiFetch<ForensicCase>("/api/v1/forensics/cases", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function correlateForensicFindings(input: {
  finding_ids: string[];
  audit_run_id?: string;
  case_id?: string;
}): Promise<ForensicCorrelationResponse> {
  const { case_id, ...payload } = input;
  const path = case_id
    ? `/api/v1/forensics/cases/${encodeURIComponent(case_id)}/correlate`
    : "/api/v1/forensics/correlate";
  return apiFetch<ForensicCorrelationResponse>(path, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function transitionForensicCase(
  caseId: string,
  input: {
    target_status: ForensicCaseStatus;
    reason: string;
    expected_version?: number;
    resolution_summary?: string;
    reopening?: boolean;
    acknowledge_critical_findings?: boolean;
    acknowledge_evidence_failures?: boolean;
    allow_unverified_evidence?: boolean;
  }
): Promise<ForensicCase> {
  return apiFetch<ForensicCase>(
    `/api/v1/forensics/cases/${encodeURIComponent(caseId)}/transition`,
    { method: "POST", body: JSON.stringify(input) }
  );
}

export function assignForensicCase(
  caseId: string,
  input: { assignee: string | null; reason?: string; expected_version?: number }
): Promise<ForensicCase> {
  return apiFetch<ForensicCase>(
    `/api/v1/forensics/cases/${encodeURIComponent(caseId)}/assign`,
    { method: "POST", body: JSON.stringify(input) }
  );
}

export function addForensicNote(
  caseId: string,
  input: {
    note_type: string;
    content: string;
    visibility?: string;
    related_evidence_ids?: string[];
  }
): Promise<ForensicNote> {
  return apiFetch<ForensicNote>(
    `/api/v1/forensics/cases/${encodeURIComponent(caseId)}/notes`,
    { method: "POST", body: JSON.stringify(input) }
  );
}

export function updateForensicNote(
  caseId: string,
  noteId: string,
  input: { content: string; expected_version?: number; related_evidence_ids?: string[] }
): Promise<ForensicNote> {
  return apiFetch<ForensicNote>(
    `/api/v1/forensics/cases/${encodeURIComponent(caseId)}/notes/${encodeURIComponent(noteId)}`,
    { method: "PATCH", body: JSON.stringify(input) }
  );
}

export function fetchForensicNoteRevisions(
  caseId: string,
  noteId: string,
  signal?: AbortSignal
): Promise<{ items: ForensicNoteRevision[] }> {
  return apiFetch<{ items: ForensicNoteRevision[] }>(
    `/api/v1/forensics/cases/${encodeURIComponent(caseId)}/notes/${encodeURIComponent(
      noteId
    )}/revisions`,
    { signal }
  );
}

export function addForensicAction(
  caseId: string,
  input: {
    action_type: string;
    description: string;
    related_finding_ids?: string[];
    result?: string;
    approval_reference?: string;
  }
): Promise<Record<string, unknown>> {
  return apiFetch(`/api/v1/forensics/cases/${encodeURIComponent(caseId)}/actions`, {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function addForensicEvidenceReference(
  caseId: string,
  input: {
    artifact_type: string;
    artifact_id: string;
    original_relative_path?: string;
    expected_sha256?: string;
    source_audit_run_id?: string;
    source_finding_id?: string;
  }
): Promise<ForensicEvidenceReference> {
  return apiFetch<ForensicEvidenceReference>(
    `/api/v1/forensics/cases/${encodeURIComponent(caseId)}/evidence`,
    { method: "POST", body: JSON.stringify(input) }
  );
}

export function verifyForensicCase(
  caseId: string
): Promise<ForensicVerificationReport> {
  return apiFetch<ForensicVerificationReport>(
    `/api/v1/forensics/cases/${encodeURIComponent(caseId)}/verify`,
    { method: "POST" }
  );
}

export function fetchForensicExports(
  caseId: string,
  signal?: AbortSignal
): Promise<ForensicExportListResponse> {
  return apiFetch<ForensicExportListResponse>(
    `/api/v1/forensics/cases/${encodeURIComponent(caseId)}/exports`,
    { signal }
  );
}

export function createForensicExport(
  caseId: string,
  includeEvidenceBytes = false
): Promise<ForensicExportRecord> {
  return apiFetch<ForensicExportRecord>(
    `/api/v1/forensics/cases/${encodeURIComponent(caseId)}/exports`,
    { method: "POST", body: JSON.stringify({ include_evidence_bytes: includeEvidenceBytes }) }
  );
}

export function verifyForensicExport(
  exportId: string
): Promise<ForensicExportVerifyResponse> {
  return apiFetch<ForensicExportVerifyResponse>(
    `/api/v1/forensics/exports/${encodeURIComponent(exportId)}/verify`,
    { method: "POST" }
  );
}

export function forensicExportDownloadUrl(exportId: string): string {
  return `${appConfig.apiUrl}/api/v1/forensics/exports/${encodeURIComponent(exportId)}`;
}
