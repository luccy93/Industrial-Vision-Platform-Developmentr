"use client";

import { useCallback, useEffect, useState } from "react";
import { Card } from "../../components/ui/Card";
import { DataState, SectionBadge } from "../../components/operations/primitives";
import { useAuth } from "../../components/auth/AuthProvider";
import {
  addForensicNote,
  correlateForensicFindings,
  createForensicCase,
  createForensicExport,
  fetchForensicCase,
  fetchForensicCases,
  fetchForensicFindings,
  fetchForensicStatus,
  forensicExportDownloadUrl,
  transitionForensicCase,
  verifyForensicCase,
  verifyForensicExport,
} from "../../lib/forensics/client";
import type {
  ForensicCase,
  ForensicCaseDetail,
  ForensicCaseStatus,
  ForensicCaseType,
  ForensicExportRecord,
  ForensicStatus,
  ForensicVerificationReport,
  IntegrityFinding,
} from "../../types";

const PAGE_SIZE = 20;

const STATUSES: ForensicCaseStatus[] = [
  "OPEN",
  "TRIAGED",
  "INVESTIGATING",
  "CONTAINMENT_RECOMMENDED",
  "AWAITING_REVIEW",
  "RESOLVED",
  "CLOSED",
];

const CASE_TYPES: ForensicCaseType[] = [
  "EVIDENCE_TAMPERING",
  "CHECKPOINT_COMPROMISE",
  "SIGNATURE_FAILURE",
  "TRANSPARENCY_CONFLICT",
  "TRUST_KEY_COMPROMISE",
  "CHAIN_OF_CUSTODY_FAILURE",
  "FORENSIC_REVIEW",
  "OTHER",
];

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

const TRANSITIONS: Record<ForensicCaseStatus, ForensicCaseStatus[]> = {
  OPEN: ["TRIAGED"],
  TRIAGED: ["INVESTIGATING"],
  INVESTIGATING: ["CONTAINMENT_RECOMMENDED", "AWAITING_REVIEW"],
  CONTAINMENT_RECOMMENDED: ["AWAITING_REVIEW"],
  AWAITING_REVIEW: ["INVESTIGATING", "RESOLVED"],
  RESOLVED: ["CLOSED"],
  CLOSED: [],
};

const CLOSE_STATUSES: ForensicCaseStatus[] = ["RESOLVED", "CLOSED"];

function statusStyle(status: string): string {
  if (status === "PASS" || status === "RESOLVED") return "bg-emerald-500/15 text-emerald-300";
  if (status === "FAIL" || status === "CRITICAL") return "bg-red-500/15 text-red-300";
  if (status === "PARTIAL" || status === "AWAITING_REVIEW") {
    return "bg-amber-500/15 text-amber-300";
  }
  if (status === "UNAVAILABLE" || status === "NOT_RUN") return "bg-slate-500/15 text-slate-400";
  return "bg-sky-500/15 text-sky-300";
}

function StatusPill({ status }: { status: string }) {
  return (
    <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${statusStyle(status)}`}>
      {status}
    </span>
  );
}

function Metric({ label, value, note }: { label: string; value: string | number; note?: string }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2">
      <p className="text-[11px] uppercase tracking-wide text-slate-500">{label}</p>
      <p className="text-lg font-semibold text-slate-100">{value}</p>
      {note && <p className="text-[11px] text-slate-500">{note}</p>}
    </div>
  );
}

function CaseRow({
  item,
  selected,
  onSelect,
}: {
  item: ForensicCase;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <li>
      <button
        onClick={onSelect}
        aria-pressed={selected}
        className={`flex w-full flex-wrap items-center justify-between gap-2 rounded-lg border px-2 py-1 text-left text-xs ${
          selected
            ? "border-sky-600 bg-slate-800"
            : "border-slate-800 bg-slate-900/60 hover:bg-slate-800/60"
        }`}
      >
        <span className="flex flex-wrap items-center gap-2">
          <StatusPill status={item.status} />
          <StatusPill status={item.severity} />
          <span className="font-medium text-slate-200">{item.case_number}</span>
          <span className="text-slate-300">{item.title}</span>
        </span>
        <span className="text-slate-500">
          {item.case_type} · {item.priority} · {item.source} · v{item.version}
        </span>
      </button>
    </li>
  );
}

function FindingRow({
  finding,
  checked,
  onToggle,
}: {
  finding: IntegrityFinding;
  checked: boolean;
  onToggle: () => void;
}) {
  return (
    <li className="rounded-lg border border-slate-800 bg-slate-900/60 px-2 py-2 text-xs">
      <label className="flex items-start gap-2">
        <input
          type="checkbox"
          checked={checked}
          onChange={onToggle}
          aria-label={`select finding ${finding.finding_id}`}
          className="mt-0.5"
        />
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-center justify-between gap-2">
            <span className="flex items-center gap-2">
              <StatusPill status={finding.severity} />
              <span className="font-medium text-slate-200">{finding.reason_code}</span>
            </span>
            <span className="text-slate-500">{finding.detected_at}</span>
          </span>
          <span className="mt-1 block text-slate-300">{finding.explanation}</span>
          <span className="mt-1 block text-slate-500">
            Artifact: {finding.artifact_id ?? "—"} · Run: {finding.audit_run_id}
          </span>
        </span>
      </label>
    </li>
  );
}

function ExportRow({
  item,
  canExport,
  onVerify,
  verifying,
}: {
  item: ForensicExportRecord;
  canExport: boolean;
  onVerify: () => void;
  verifying: boolean;
}) {
  return (
    <li className="rounded-lg border border-slate-800 bg-slate-900/60 px-2 py-2 text-xs">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="flex flex-wrap items-center gap-2">
          <StatusPill status={item.verification_outcome} />
          <span className="font-medium text-slate-200">{item.filename}</span>
          <span className="text-slate-500">
            {item.file_count} file(s) · {item.size_bytes} bytes ·{" "}
            {item.evidence_bytes_included ? "includes evidence bytes" : "references only"}
          </span>
        </span>
        {canExport && (
          <span className="flex gap-2">
            <a
              href={forensicExportDownloadUrl(item.export_id)}
              className="rounded-lg bg-slate-800 px-2 py-1 text-slate-200 hover:bg-slate-700"
            >
              Download
            </a>
            <button
              onClick={onVerify}
              disabled={verifying}
              className="rounded-lg bg-slate-800 px-2 py-1 text-slate-200 hover:bg-slate-700 disabled:opacity-40"
            >
              {verifying ? "Verifying…" : "Verify"}
            </button>
          </span>
        )}
      </div>
      <p className="mt-1 break-all text-slate-500">
        sha256: {item.sha256} · manifest: {item.manifest_digest}
      </p>
      {item.verification_detail && (
        <p className="mt-1 text-slate-400">{item.verification_detail}</p>
      )}
    </li>
  );
}

export default function ForensicsPage() {
  const { hasRole } = useAuth();
  const canWrite = hasRole("ADMIN") || hasRole("OPERATOR");
  const canClose = hasRole("ADMIN");
  const canExport = hasRole("ADMIN");

  const [status, setStatus] = useState<ForensicStatus | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [statusLoading, setStatusLoading] = useState(true);

  const [cases, setCases] = useState<ForensicCase[]>([]);
  const [casesTotal, setCasesTotal] = useState(0);
  const [casesPage, setCasesPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [search, setSearch] = useState("");
  const [casesError, setCasesError] = useState<string | null>(null);
  const [casesLoading, setCasesLoading] = useState(true);

  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);
  const [detail, setDetail] = useState<ForensicCaseDetail | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const [findings, setFindings] = useState<IntegrityFinding[]>([]);
  const [findingsTotal, setFindingsTotal] = useState(0);
  const [findingsAvailable, setFindingsAvailable] = useState(true);
  const [findingsDetail, setFindingsDetail] = useState<string | null>(null);
  const [findingsError, setFindingsError] = useState<string | null>(null);
  const [findingsLoading, setFindingsLoading] = useState(true);
  const [selectedFindingIds, setSelectedFindingIds] = useState<string[]>([]);
  const [correlating, setCorrelating] = useState(false);
  const [correlateError, setCorrelateError] = useState<string | null>(null);
  const [correlateStats, setCorrelateStats] = useState<Record<string, number> | null>(null);

  const [showNewCase, setShowNewCase] = useState(false);
  const [newTitle, setNewTitle] = useState("");
  const [newDescription, setNewDescription] = useState("");
  const [newCaseType, setNewCaseType] = useState<ForensicCaseType>("FORENSIC_REVIEW");
  const [newSeverity, setNewSeverity] = useState("MEDIUM");
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  const [transitionTarget, setTransitionTarget] = useState<ForensicCaseStatus | "">("");
  const [transitionReason, setTransitionReason] = useState("");
  const [transitioning, setTransitioning] = useState(false);
  const [transitionError, setTransitionError] = useState<string | null>(null);

  const [noteType, setNoteType] = useState("OBSERVATION");
  const [noteContent, setNoteContent] = useState("");
  const [noteSubmitting, setNoteSubmitting] = useState(false);
  const [noteError, setNoteError] = useState<string | null>(null);

  const [verifying, setVerifying] = useState(false);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const [verifyReport, setVerifyReport] = useState<ForensicVerificationReport | null>(null);

  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const [verifyingExportId, setVerifyingExportId] = useState<string | null>(null);

  const refreshStatus = useCallback(async () => {
    try {
      setStatus(await fetchForensicStatus());
      setStatusError(null);
    } catch (e) {
      setStatusError(e instanceof Error ? e.message : "API unreachable");
    } finally {
      setStatusLoading(false);
    }
  }, []);

  const refreshCases = useCallback(async () => {
    setCasesLoading(true);
    try {
      const body = await fetchForensicCases({
        status: statusFilter ? [statusFilter] : undefined,
        severity: severityFilter ? [severityFilter] : undefined,
        search: search.trim() || undefined,
        page: casesPage,
        page_size: PAGE_SIZE,
      });
      setCases(body.items);
      setCasesTotal(body.total);
      setCasesError(null);
    } catch (e) {
      setCasesError(e instanceof Error ? e.message : "API unreachable");
    } finally {
      setCasesLoading(false);
    }
  }, [statusFilter, severityFilter, search, casesPage]);

  const refreshFindings = useCallback(async () => {
    setFindingsLoading(true);
    try {
      const body = await fetchForensicFindings({ page: 1, page_size: 50 });
      setFindings(body.items);
      setFindingsTotal(body.total);
      setFindingsAvailable(body.available);
      setFindingsDetail(body.detail ?? null);
      setFindingsError(null);
    } catch (e) {
      setFindingsError(e instanceof Error ? e.message : "API unreachable");
    } finally {
      setFindingsLoading(false);
    }
  }, []);

  const refreshDetail = useCallback(async (caseId: string) => {
    setDetailLoading(true);
    try {
      const body = await fetchForensicCase(caseId);
      setDetail(body);
      setDetailError(null);
    } catch (e) {
      setDetailError(e instanceof Error ? e.message : "API unreachable");
    } finally {
      setDetailLoading(false);
    }
  }, []);

  useEffect(() => {
    void refreshStatus();
    const timer = setInterval(() => void refreshStatus(), 30000);
    return () => clearInterval(timer);
  }, [refreshStatus]);

  useEffect(() => {
    void refreshCases();
  }, [refreshCases]);

  useEffect(() => {
    void refreshFindings();
  }, [refreshFindings]);

  useEffect(() => {
    if (!selectedCaseId) {
      setDetail(null);
      setDetailError(null);
      setVerifyReport(null);
      return;
    }
    setTransitionTarget("");
    setTransitionReason("");
    setVerifyReport(null);
    void refreshDetail(selectedCaseId);
  }, [selectedCaseId, refreshDetail]);

  const toggleFinding = (findingId: string) => {
    setSelectedFindingIds((previous) =>
      previous.includes(findingId)
        ? previous.filter((value) => value !== findingId)
        : [...previous, findingId]
    );
  };

  const submitNewCase = async () => {
    if (!newTitle.trim()) {
      setCreateError("A case title is required.");
      return;
    }
    setCreating(true);
    setCreateError(null);
    try {
      const created = await createForensicCase({
        title: newTitle.trim(),
        description: newDescription.trim(),
        case_type: newCaseType,
        severity: newSeverity,
      });
      setNewTitle("");
      setNewDescription("");
      setShowNewCase(false);
      setSelectedCaseId(created.case_id);
      await Promise.all([refreshCases(), refreshStatus()]);
    } catch (e) {
      setCreateError(e instanceof Error ? e.message : "Case creation failed");
    } finally {
      setCreating(false);
    }
  };

  const correlateSelected = async () => {
    if (selectedFindingIds.length === 0) return;
    setCorrelating(true);
    setCorrelateError(null);
    setCorrelateStats(null);
    try {
      const body = await correlateForensicFindings({ finding_ids: selectedFindingIds });
      setCorrelateStats(body.stats);
      setSelectedFindingIds([]);
      await Promise.all([refreshCases(), refreshStatus(), refreshFindings()]);
    } catch (e) {
      setCorrelateError(e instanceof Error ? e.message : "Correlation failed");
    } finally {
      setCorrelating(false);
    }
  };

  const submitTransition = async () => {
    if (!detail || !transitionTarget) return;
    if (!transitionReason.trim()) {
      setTransitionError("A transition reason is required.");
      return;
    }
    setTransitioning(true);
    setTransitionError(null);
    try {
      await transitionForensicCase(detail.case.case_id, {
        target_status: transitionTarget,
        reason: transitionReason.trim(),
        expected_version: detail.case.version,
      });
      setTransitionReason("");
      setTransitionTarget("");
      await Promise.all([
        refreshDetail(detail.case.case_id),
        refreshCases(),
        refreshStatus(),
      ]);
    } catch (e) {
      setTransitionError(e instanceof Error ? e.message : "Transition failed");
    } finally {
      setTransitioning(false);
    }
  };

  const submitNote = async () => {
    if (!detail || !noteContent.trim()) return;
    setNoteSubmitting(true);
    setNoteError(null);
    try {
      await addForensicNote(detail.case.case_id, {
        note_type: noteType,
        content: noteContent.trim(),
      });
      setNoteContent("");
      await refreshDetail(detail.case.case_id);
    } catch (e) {
      setNoteError(e instanceof Error ? e.message : "Note could not be saved");
    } finally {
      setNoteSubmitting(false);
    }
  };

  const runVerification = async () => {
    if (!detail) return;
    setVerifying(true);
    setVerifyError(null);
    try {
      setVerifyReport(await verifyForensicCase(detail.case.case_id));
      await refreshDetail(detail.case.case_id);
    } catch (e) {
      setVerifyError(e instanceof Error ? e.message : "Verification failed");
    } finally {
      setVerifying(false);
    }
  };

  const generateExport = async () => {
    if (!detail) return;
    setExporting(true);
    setExportError(null);
    try {
      await createForensicExport(detail.case.case_id, false);
      await refreshDetail(detail.case.case_id);
    } catch (e) {
      setExportError(e instanceof Error ? e.message : "Export failed");
    } finally {
      setExporting(false);
    }
  };

  const runExportVerification = async (exportId: string) => {
    setVerifyingExportId(exportId);
    setExportError(null);
    try {
      await verifyForensicExport(exportId);
      if (detail) await refreshDetail(detail.case.case_id);
    } catch (e) {
      setExportError(e instanceof Error ? e.message : "Export verification failed");
    } finally {
      setVerifyingExportId(null);
    }
  };

  const summary = status?.summary ?? null;
  const caseDetail = detail;
  const custodyOutcome = caseDetail?.custody.verification.outcome ?? null;
  const allowedTransitions = caseDetail
    ? [
        ...TRANSITIONS[caseDetail.case.status],
        ...(caseDetail.case.status === "RESOLVED" || caseDetail.case.status === "CLOSED"
          ? (["OPEN"] as ForensicCaseStatus[])
          : []),
      ]
    : [];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h1 className="text-lg font-bold">Integrity Incident Response &amp; Forensics</h1>
          <p className="max-w-3xl text-xs text-slate-400">
            Forensic cases reference V29–V33 artifacts by identifier and hash; they never copy,
            move, repair, or rewrite protected evidence. The custody ledger is an append-only local
            hash chain. External anchoring is never claimed unless a provider is independently
            verified.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <SectionBadge
            state={status?.v33_source === "AVAILABLE" ? "ok" : "unavailable"}
            label={`V33 source: ${status?.v33_source ?? "unknown"}`}
          />
          <SectionBadge state="degraded" label={`assurance: ${status?.assurance ?? "unknown"}`} />
          <button
            onClick={() => {
              void refreshStatus();
              void refreshCases();
              void refreshFindings();
              if (selectedCaseId) void refreshDetail(selectedCaseId);
            }}
            className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm hover:bg-slate-700"
          >
            Refresh
          </button>
        </div>
      </div>

      {statusLoading && !status && (
        <p className="text-sm text-slate-400" role="status">
          Loading forensic status…
        </p>
      )}
      {statusError && (
        <p className="text-sm text-amber-300" role="alert">
          Forensic status unavailable ({statusError}) — lists below keep their own state.
        </p>
      )}

      <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-200">
        <span className="font-semibold">Assurance boundary:</span>{" "}
        {status?.external_anchor_claimed
          ? "An external anchor is claimed."
          : status?.external_anchor_note ??
            "No external transparency provider is configured; the local chain is not anchored."}
      </div>

      <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-5">
        <Metric label="Total cases" value={summary?.total ?? 0} />
        <Metric label="Open" value={summary?.open ?? 0} note="Awaiting triage" />
        <Metric label="Investigating" value={summary?.investigating ?? 0} />
        <Metric
          label="Awaiting review"
          value={summary?.awaiting_review ?? 0}
          note={`${summary?.resolved ?? 0} resolved`}
        />
        <Metric label="Critical" value={summary?.critical ?? 0} note="Unresolved severity" />
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card title={`Cases (${casesTotal})`}>
          <div className="mb-2 flex flex-wrap gap-2 text-xs">
            <label className="text-slate-400">
              Status{" "}
              <select
                value={statusFilter}
                onChange={(e) => {
                  setStatusFilter(e.target.value);
                  setCasesPage(1);
                }}
                className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-slate-200"
                aria-label="case status filter"
              >
                <option value="">all</option>
                {STATUSES.map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
            </label>
            <label className="text-slate-400">
              Severity{" "}
              <select
                value={severityFilter}
                onChange={(e) => {
                  setSeverityFilter(e.target.value);
                  setCasesPage(1);
                }}
                className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-slate-200"
                aria-label="case severity filter"
              >
                <option value="">all</option>
                {SEVERITIES.map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
            </label>
            <label className="text-slate-400">
              Search{" "}
              <input
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value);
                  setCasesPage(1);
                }}
                placeholder="case number or title"
                className="w-44 rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-slate-200"
                aria-label="case search"
              />
            </label>
          </div>
          {canWrite && (
            <div className="mb-2">
              <button
                onClick={() => setShowNewCase((value) => !value)}
                className="rounded-lg bg-sky-700 px-3 py-1.5 text-xs hover:bg-sky-600"
              >
                {showNewCase ? "Cancel new case" : "Open case"}
              </button>
              {showNewCase && (
                <div className="mt-2 space-y-2 rounded-lg border border-slate-800 p-2 text-xs">
                  <input
                    value={newTitle}
                    onChange={(e) => setNewTitle(e.target.value)}
                    placeholder="Case title"
                    className="w-full rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-slate-200"
                    aria-label="new case title"
                  />
                  <textarea
                    value={newDescription}
                    onChange={(e) => setNewDescription(e.target.value)}
                    placeholder="Description (no credentials or evidence bytes)"
                    className="w-full rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-slate-200"
                    aria-label="new case description"
                    rows={2}
                  />
                  <div className="flex flex-wrap gap-2">
                    <select
                      value={newCaseType}
                      onChange={(e) => setNewCaseType(e.target.value as ForensicCaseType)}
                      className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-slate-200"
                      aria-label="new case type"
                    >
                      {CASE_TYPES.map((value) => (
                        <option key={value} value={value}>
                          {value}
                        </option>
                      ))}
                    </select>
                    <select
                      value={newSeverity}
                      onChange={(e) => setNewSeverity(e.target.value)}
                      className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-slate-200"
                      aria-label="new case severity"
                    >
                      {SEVERITIES.map((value) => (
                        <option key={value} value={value}>
                          {value}
                        </option>
                      ))}
                    </select>
                    <button
                      onClick={() => void submitNewCase()}
                      disabled={creating}
                      className="rounded-lg bg-emerald-700 px-3 py-1 text-white hover:bg-emerald-600 disabled:opacity-40"
                    >
                      {creating ? "Creating…" : "Create case"}
                    </button>
                  </div>
                  {createError && (
                    <p className="text-red-300" role="alert">
                      {createError}
                    </p>
                  )}
                </div>
              )}
            </div>
          )}
          <DataState
            state={
              casesError
                ? "error"
                : casesLoading && cases.length === 0
                  ? "loading"
                  : casesTotal === 0
                    ? "empty"
                    : "ready"
            }
            emptyText="No forensic cases recorded — nothing has been correlated or opened."
            error={casesError}
          >
            <ul className="space-y-1">
              {cases.map((item) => (
                <CaseRow
                  key={item.case_id}
                  item={item}
                  selected={selectedCaseId === item.case_id}
                  onSelect={() => setSelectedCaseId(item.case_id)}
                />
              ))}
            </ul>
            <div className="mt-2 flex items-center gap-2 text-xs text-slate-400">
              <button
                disabled={casesPage <= 1}
                onClick={() => setCasesPage((page) => Math.max(1, page - 1))}
                className="rounded-lg bg-slate-800 px-2 py-1 disabled:opacity-40"
              >
                Prev
              </button>
              <span>
                Page {casesPage} · {casesTotal} total
              </span>
              <button
                disabled={casesPage * PAGE_SIZE >= casesTotal}
                onClick={() => setCasesPage((page) => page + 1)}
                className="rounded-lg bg-slate-800 px-2 py-1 disabled:opacity-40"
              >
                Next
              </button>
            </div>
          </DataState>
        </Card>

        <Card title={`V33 findings available for correlation (${findingsTotal})`}>
          <p className="mb-2 text-xs text-slate-400">
            Only confirmed failure reasons can create or update a confirmed security incident.
            Unavailable, not-run, simulated, and operational findings remain review context.
          </p>
          {!findingsAvailable && (
            <p className="mb-2 text-xs text-amber-300" role="alert">
              {findingsDetail ?? "V33 monitoring store is unavailable."}
            </p>
          )}
          <DataState
            state={
              findingsError
                ? "error"
                : findingsLoading && findings.length === 0
                  ? "loading"
                  : !findingsAvailable || findingsTotal === 0
                    ? "empty"
                    : "ready"
            }
            emptyText={
              findingsAvailable
                ? "No V33 findings recorded — genuine quiet, not missing data."
                : "Findings cannot be listed while the V33 source is unavailable."
            }
            error={findingsError}
          >
            <ul className="space-y-1">
              {findings.map((finding) => (
                <FindingRow
                  key={finding.finding_id}
                  finding={finding}
                  checked={selectedFindingIds.includes(finding.finding_id)}
                  onToggle={() => toggleFinding(finding.finding_id)}
                />
              ))}
            </ul>
          </DataState>
          {canWrite && findingsAvailable && findings.length > 0 && (
            <div className="mt-2 flex flex-wrap items-center gap-2 text-xs">
              <button
                onClick={() => void correlateSelected()}
                disabled={correlating || selectedFindingIds.length === 0}
                className="rounded-lg bg-emerald-700 px-3 py-1 text-white hover:bg-emerald-600 disabled:opacity-40"
              >
                {correlating
                  ? "Correlating…"
                  : `Correlate selected (${selectedFindingIds.length})`}
              </button>
              {correlateError && (
                <span className="text-red-300" role="alert">
                  {correlateError}
                </span>
              )}
            </div>
          )}
          {correlateStats && (
            <div className="mt-2 rounded-lg border border-slate-800 px-2 py-1 text-xs">
              <p className="text-slate-300">
                Examined {correlateStats.examined} · confirmed {correlateStats.confirmed} · cases
                created {correlateStats.cases_created} · updated {correlateStats.cases_updated} ·
                incidents created {correlateStats.incidents_created} · linked{" "}
                {correlateStats.incidents_linked}
              </p>
              {(correlateStats.skipped_unavailable > 0 ||
                correlateStats.skipped_not_run > 0 ||
                correlateStats.skipped_simulated > 0 ||
                correlateStats.skipped_operational > 0) && (
                <p className="mt-1 text-amber-300/90">
                  Skipped: {correlateStats.skipped_unavailable} unavailable ·{" "}
                  {correlateStats.skipped_not_run} not run · {correlateStats.skipped_simulated}{" "}
                  simulated · {correlateStats.skipped_operational} operational — none were promoted.
                </p>
              )}
              {correlateStats.failed > 0 && (
                <p className="mt-1 text-red-300">
                  {correlateStats.failed} correlation attempt(s) failed; inspect logs.
                </p>
              )}
            </div>
          )}
        </Card>
      </div>

      <Card title="Case detail">
        {!selectedCaseId ? (
          <p className="text-sm text-slate-400">Select a case to inspect its custody ledger.</p>
        ) : detailError ? (
          <p className="text-sm text-amber-300" role="alert">
            {detailError}
          </p>
        ) : !caseDetail ? (
          <p className="text-sm text-slate-400" role="status">
            {detailLoading ? "Loading…" : "Case detail unavailable."}
          </p>
        ) : (
          <div className="space-y-3 text-xs">
            <div className="flex flex-wrap items-center gap-2">
              <StatusPill status={caseDetail.case.status} />
              <StatusPill status={caseDetail.case.severity} />
              <span className="font-medium text-slate-200">{caseDetail.case.case_number}</span>
              <span className="text-slate-300">{caseDetail.case.title}</span>
              <span className="text-slate-500">
                {caseDetail.case.case_type} · {caseDetail.case.priority} ·{" "}
                {caseDetail.case.source} · v{caseDetail.case.version}
              </span>
            </div>
            <p className="text-slate-400">{caseDetail.case.description || "No description."}</p>
            <p className="text-slate-500">
              Originating incident: {caseDetail.case.originating_incident_id ?? "—"} · audit run:{" "}
              {caseDetail.case.originating_audit_run_id ?? "—"} · assigned:{" "}
              {caseDetail.case.assigned_to ?? "unassigned"}
            </p>
            {caseDetail.case.resolution_summary && (
              <p className="text-slate-300">
                Resolution: {caseDetail.case.resolution_summary}
              </p>
            )}

            <div
              className={`rounded-lg border px-2 py-1 ${
                custodyOutcome === "PASS"
                  ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-200"
                  : "border-red-500/30 bg-red-500/10 text-red-200"
              }`}
            >
              Custody verification: {custodyOutcome ?? "unknown"} ·{" "}
              {caseDetail.custody.verification.event_count} event(s) ·{" "}
              {caseDetail.custody.verification.assurance}
              {custodyOutcome !== "PASS" && (
                <span className="ml-2 font-semibold">
                  Do not treat this case as intact — review reason codes.
                </span>
              )}
              {caseDetail.custody.verification.reason_codes.length > 0 && (
                <span className="ml-2">
                  Reasons: {caseDetail.custody.verification.reason_codes.join(", ")}
                </span>
              )}
            </div>

            <div className="flex flex-wrap items-end gap-2">
              <label className="text-slate-400">
                Target status{" "}
                <select
                  value={transitionTarget}
                  onChange={(e) =>
                    setTransitionTarget(e.target.value as ForensicCaseStatus | "")
                  }
                  className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-slate-200"
                  aria-label="transition target"
                >
                  <option value="">select</option>
                  {allowedTransitions.map((value) => (
                    <option key={value} value={value}>
                      {value}
                    </option>
                  ))}
                </select>
              </label>
              <label className="text-slate-400">
                Reason{" "}
                <input
                  value={transitionReason}
                  onChange={(e) => setTransitionReason(e.target.value)}
                  className="w-56 rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-slate-200"
                  aria-label="transition reason"
                />
              </label>
              {canWrite ? (
                <button
                  onClick={() => void submitTransition()}
                  disabled={
                    transitioning ||
                    !transitionTarget ||
                    (CLOSE_STATUSES.includes(transitionTarget as ForensicCaseStatus) && !canClose)
                  }
                  className="rounded-lg bg-sky-700 px-3 py-1 text-white hover:bg-sky-600 disabled:opacity-40"
                >
                  {transitioning ? "Applying…" : "Apply transition"}
                </button>
              ) : (
                <span className="text-slate-500">Transitions require ADMIN or OPERATOR.</span>
              )}
              {canWrite &&
                transitionTarget &&
                CLOSE_STATUSES.includes(transitionTarget as ForensicCaseStatus) &&
                !canClose && (
                  <span className="text-amber-300">
                    Resolution and closure require the dedicated ADMIN close capability.
                  </span>
                )}
              {transitionError && (
                <span className="text-red-300" role="alert">
                  {transitionError}
                </span>
              )}
            </div>
            {allowedTransitions.length === 0 && (
              <p className="text-slate-500">
                No forward transition is available. Reopening requires an explicit ADMIN operation.
              </p>
            )}

            <div className="flex flex-wrap items-center gap-2">
              {canWrite ? (
                <button
                  onClick={() => void runVerification()}
                  disabled={verifying}
                  className="rounded-lg bg-slate-800 px-3 py-1 text-slate-200 hover:bg-slate-700 disabled:opacity-40"
                >
                  {verifying ? "Verifying…" : "Run read-only verification"}
                </button>
              ) : (
                <span className="text-slate-500">
                  Verification requires ADMIN or OPERATOR.
                </span>
              )}
              {verifyError && (
                <span className="text-red-300" role="alert">
                  {verifyError}
                </span>
              )}
              {verifyReport && (
                <span
                  className={
                    verifyReport.outcome === "PASS" ? "text-emerald-300" : "text-amber-300"
                  }
                >
                  Verification {verifyReport.outcome}: {verifyReport.counts.passed} passed ·{" "}
                  {verifyReport.counts.failed} failed · {verifyReport.counts.unavailable}{" "}
                  unavailable · {verifyReport.counts.not_run} not run
                  {verifyReport.reason_codes.length > 0
                    ? ` · ${verifyReport.reason_codes.join(", ")}`
                    : ""}
                </span>
              )}
            </div>

            <div className="grid gap-2 xl:grid-cols-2">
              <div>
                <p className="mb-1 font-medium text-slate-300">
                  Evidence references ({caseDetail.evidence_references.length})
                </p>
                {caseDetail.evidence_references.length === 0 ? (
                  <p className="text-slate-500">No evidence references recorded.</p>
                ) : (
                  <ul className="space-y-1">
                    {caseDetail.evidence_references.map((reference) => (
                      <li
                        key={reference.reference_id}
                        className="rounded-lg border border-slate-800 px-2 py-1"
                      >
                        <span className="flex flex-wrap items-center justify-between gap-2">
                          <span className="flex items-center gap-2">
                            <StatusPill status={reference.verification_outcome} />
                            <span className="text-slate-200">
                              {reference.artifact_type}: {reference.artifact_id}
                            </span>
                          </span>
                          <span className="text-slate-500">
                            expected {reference.expected_sha256.slice(0, 12) || "—"}
                          </span>
                        </span>
                        {reference.verification_detail && (
                          <p className="mt-1 text-slate-400">{reference.verification_detail}</p>
                        )}
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              <div>
                <p className="mb-1 font-medium text-slate-300">
                  Correlated findings ({caseDetail.correlations.length})
                </p>
                {caseDetail.correlations.length === 0 ? (
                  <p className="text-slate-500">No findings correlated.</p>
                ) : (
                  <ul className="space-y-1">
                    {caseDetail.correlations.map((correlation) => (
                      <li
                        key={correlation.correlation_id}
                        className="rounded-lg border border-slate-800 px-2 py-1"
                      >
                        <span className="flex flex-wrap items-center justify-between gap-2">
                          <span className="flex items-center gap-2">
                            <StatusPill status={correlation.severity} />
                            <span className="text-slate-200">
                              {correlation.reason_code ?? "unknown reason"}
                            </span>
                            <span className="text-slate-500">
                              {correlation.classification}
                            </span>
                          </span>
                          <span className="text-slate-500">
                            run {correlation.audit_run_id ?? "—"}
                          </span>
                        </span>
                        <p className="mt-1 text-slate-500">
                          finding {correlation.finding_id ?? "—"} ·{" "}
                          {correlation.resolved ? "resolved" : "unresolved"}
                        </p>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>

            <div>
              <p className="mb-1 font-medium text-slate-300">
                Linked V10 incidents ({caseDetail.incident_links.length})
              </p>
              {caseDetail.incident_links.length === 0 ? (
                <p className="text-slate-500">No incident linked.</p>
              ) : (
                <ul className="space-y-1">
                  {caseDetail.incident_links.map((link) => (
                    <li key={link.link_id} className="rounded-lg border border-slate-800 px-2 py-1">
                      Incident {link.incident_id} · linked by {link.linked_by ?? "SYSTEM"} ·{" "}
                      {link.linked_at}
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div>
              <p className="mb-1 font-medium text-slate-300">
                Investigation notes ({caseDetail.notes.length})
              </p>
              {caseDetail.notes.length === 0 ? (
                <p className="text-slate-500">No notes recorded.</p>
              ) : (
                <ul className="space-y-1">
                  {caseDetail.notes.map((note) => (
                    <li key={note.note_id} className="rounded-lg border border-slate-800 px-2 py-1">
                      <span className="flex flex-wrap items-center justify-between gap-2">
                        <span className="font-medium text-slate-200">{note.note_type}</span>
                        <span className="text-slate-500">
                          {note.author_id} · v{note.version} · {note.updated_at}
                        </span>
                      </span>
                      <p className="mt-1 whitespace-pre-wrap text-slate-300">{note.content}</p>
                      {note.edited_by && (
                        <p className="mt-1 text-slate-500">
                          Last edited by {note.edited_by}; earlier revisions are retained.
                        </p>
                      )}
                    </li>
                  ))}
                </ul>
              )}
              {canWrite && (
                <div className="mt-2 space-y-1 rounded-lg border border-slate-800 p-2">
                  <div className="flex flex-wrap gap-2">
                    <select
                      value={noteType}
                      onChange={(e) => setNoteType(e.target.value)}
                      className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-slate-200"
                      aria-label="note type"
                    >
                      {["OBSERVATION", "ANALYSIS", "HYPOTHESIS", "ACTION", "CONCLUSION", "HANDOVER"].map(
                        (value) => (
                          <option key={value} value={value}>
                            {value}
                          </option>
                        )
                      )}
                    </select>
                    <input
                      value={noteContent}
                      onChange={(e) => setNoteContent(e.target.value)}
                      placeholder="Investigation note (no credentials)"
                      className="min-w-0 flex-1 rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-slate-200"
                      aria-label="note content"
                    />
                    <button
                      onClick={() => void submitNote()}
                      disabled={noteSubmitting || !noteContent.trim()}
                      className="rounded-lg bg-slate-800 px-3 py-1 text-slate-200 hover:bg-slate-700 disabled:opacity-40"
                    >
                      {noteSubmitting ? "Saving…" : "Add note"}
                    </button>
                  </div>
                  {noteError && (
                    <p className="text-red-300" role="alert">
                      {noteError}
                    </p>
                  )}
                </div>
              )}
            </div>

            <div>
              <p className="mb-1 font-medium text-slate-300">
                Forensic exports ({caseDetail.exports.length})
              </p>
              {caseDetail.exports.length === 0 ? (
                <p className="text-slate-500">
                  No export generated. Exports contain references, hashes, and manifests only.
                </p>
              ) : (
                <ul className="space-y-1">
                  {caseDetail.exports.map((item) => (
                    <ExportRow
                      key={item.export_id}
                      item={item}
                      canExport={canExport}
                      verifying={verifyingExportId === item.export_id}
                      onVerify={() => void runExportVerification(item.export_id)}
                    />
                  ))}
                </ul>
              )}
              {canExport ? (
                <button
                  onClick={() => void generateExport()}
                  disabled={exporting}
                  className="mt-2 rounded-lg bg-slate-800 px-3 py-1 text-slate-200 hover:bg-slate-700 disabled:opacity-40"
                >
                  {exporting ? "Building export…" : "Generate references-only export"}
                </button>
              ) : (
                <p className="mt-1 text-slate-500">
                  Export generation, download, and verification require the dedicated ADMIN export
                  capability.
                </p>
              )}
              {exportError && (
                <p className="mt-1 text-red-300" role="alert">
                  {exportError}
                </p>
              )}
            </div>

            <div>
              <p className="mb-1 font-medium text-slate-300">
                Custody timeline ({caseDetail.custody.events.length})
              </p>
              {caseDetail.custody.events.length === 0 ? (
                <p className="text-slate-500">No custody events recorded.</p>
              ) : (
                <ul className="space-y-1">
                  {caseDetail.custody.events.map((event) => (
                    <li
                      key={event.event_id}
                      className="rounded-lg border border-slate-800 px-2 py-1 text-slate-400"
                    >
                      #{event.sequence} {event.event_type} · {event.actor_id} ({event.actor_role}) ·{" "}
                      {event.timestamp} · hash {event.event_hash.slice(0, 12)}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}
