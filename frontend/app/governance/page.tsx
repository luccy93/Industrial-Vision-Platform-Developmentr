"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { Card } from "../../components/ui/Card";
import { DataState, SectionBadge } from "../../components/operations/primitives";
import { useAuth } from "../../components/auth/AuthProvider";
import {
  actOnGovernanceExport,
  actOnGovernanceHold,
  createGovernanceHold,
  createGovernancePolicy,
  decideGovernanceDisposition,
  downloadGovernanceComplianceCsv,
  evaluateGovernanceRetention,
  fetchGovernanceAudit,
  fetchGovernanceComplianceReport,
  fetchGovernanceDispositions,
  fetchGovernanceExports,
  fetchGovernanceHolds,
  fetchGovernancePolicies,
  fetchGovernanceRetentionQueue,
  fetchGovernanceStatus,
  generateGovernanceExport,
  governanceExportDownloadUrl,
  requestGovernanceDisposition,
  requestGovernanceExport,
  reviewGovernanceRetention,
  setGovernancePolicyState,
  updateGovernancePolicy,
  verifyGovernanceExport,
  withdrawGovernanceDisposition,
} from "../../lib/governance/client";
import type {
  GovernanceAuditEvent,
  GovernanceComplianceReport,
  GovernanceDisposition,
  GovernanceExportApproval,
  GovernanceLegalHold,
  GovernancePolicy,
  GovernanceRetentionEvaluation,
  GovernanceStatus,
} from "../../types";

const PAGE_SIZE = 50;

type PolicyForm = {
  policy_id: string;
  name: string;
  state: string;
  case_type: string;
  evidence_category: string;
  retention_days: string;
  review_interval_days: string;
  export_requires_approval: boolean;
  allow_evidence_bytes: boolean;
  disposition_review_required: boolean;
  reason: string;
};

const EMPTY_POLICY_FORM: PolicyForm = {
  policy_id: "",
  name: "",
  state: "DRAFT",
  case_type: "",
  evidence_category: "",
  retention_days: "",
  review_interval_days: "",
  export_requires_approval: true,
  allow_evidence_bytes: false,
  disposition_review_required: true,
  reason: "",
};

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : "API unreachable";
}

function numberOrNull(value: string): number | null {
  const trimmed = value.trim();
  if (!trimmed) return null;
  const parsed = Number(trimmed);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
}

function statusStyle(status: string): string {
  if (["ACTIVE", "APPROVED", "VERIFIED", "GENERATED", "PASS", "OK", "NO_KNOWN_GAPS"].includes(status)) {
    return "bg-emerald-500/15 text-emerald-300";
  }
  if (["FAIL", "FAILED", "BLOCKED", "REJECTED", "CRITICAL", "REVIEW_REQUIRED"].includes(status)) {
    return "bg-red-500/15 text-red-300";
  }
  if (
    ["PENDING_APPROVAL", "REVIEW_DUE", "APPROVAL_PENDING", "POLICY_AUTO_APPROVED", "PARTIAL", "INCOMPLETE"].includes(
      status
    )
  ) {
    return "bg-amber-500/15 text-amber-300";
  }
  return "bg-slate-500/15 text-slate-300";
}

function StatusPill({ status }: { status: string }) {
  return (
    <span className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${statusStyle(status)}`}>
      {status}
    </span>
  );
}

function Metric({ label, value, note }: { label: string; value: string | number; note?: string }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-3">
      <p className="text-xs text-slate-400">{label}</p>
      <p className="mt-1 text-lg font-semibold text-slate-100">{value}</p>
      {note ? <p className="mt-1 text-xs text-slate-500">{note}</p> : null}
    </div>
  );
}

function ConfirmAction({
  label,
  description,
  confirmLabel,
  onConfirm,
}: {
  label: string;
  description?: string;
  confirmLabel?: string;
  onConfirm: (reason: string) => Promise<void>;
}) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!open) {
    return (
      <button
        type="button"
        className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-200 hover:bg-slate-800"
        onClick={() => setOpen(true)}
      >
        {label}
      </button>
    );
  }

  return (
    <div className="mt-2 rounded-lg border border-amber-500/40 bg-amber-500/5 p-2">
      {description ? <p className="mb-1 text-xs text-amber-200">{description}</p> : null}
      <label className="block text-xs text-slate-300">
        Reason (required)
        <textarea
          aria-label={`${label} reason`}
          className="mt-1 w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs text-slate-100"
          rows={2}
          value={reason}
          onChange={(event) => setReason(event.target.value)}
        />
      </label>
      <div className="mt-2 flex flex-wrap gap-2">
        <button
          type="button"
          className="rounded bg-amber-500 px-2 py-1 text-xs font-semibold text-slate-950 disabled:opacity-50"
          disabled={busy || !reason.trim()}
          onClick={async () => {
            setBusy(true);
            setError(null);
            try {
              await onConfirm(reason.trim());
              setOpen(false);
              setReason("");
            } catch (e) {
              setError(messageOf(e));
            } finally {
              setBusy(false);
            }
          }}
        >
          {busy ? "Working…" : (confirmLabel ?? label)}
        </button>
        <button
          type="button"
          className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-300"
          onClick={() => {
            setOpen(false);
            setReason("");
            setError(null);
          }}
        >
          Cancel
        </button>
      </div>
      {error ? (
        <p className="mt-1 text-xs text-red-300" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}

function CountList({ counts }: { counts: Record<string, number> }) {
  const entries = Object.entries(counts);
  if (entries.length === 0) return <p className="text-xs text-slate-500">No records.</p>;
  return (
    <div className="flex flex-wrap gap-2">
      {entries.map(([key, value]) => (
        <span key={key} className="rounded border border-slate-800 px-2 py-1 text-xs text-slate-300">
          {key}: {value}
        </span>
      ))}
    </div>
  );
}

export default function GovernancePage() {
  const { hasRole } = useAuth();
  const isAdmin = hasRole("ADMIN");
  const canOperate = isAdmin || hasRole("OPERATOR");

  const [status, setStatus] = useState<GovernanceStatus | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [policies, setPolicies] = useState<GovernancePolicy[]>([]);
  const [policiesError, setPoliciesError] = useState<string | null>(null);
  const [retention, setRetention] = useState<GovernanceRetentionEvaluation[]>([]);
  const [retentionError, setRetentionError] = useState<string | null>(null);
  const [holds, setHolds] = useState<GovernanceLegalHold[]>([]);
  const [holdsError, setHoldsError] = useState<string | null>(null);
  const [dispositions, setDispositions] = useState<GovernanceDisposition[]>([]);
  const [dispositionsError, setDispositionsError] = useState<string | null>(null);
  const [exports, setExports] = useState<GovernanceExportApproval[]>([]);
  const [exportsError, setExportsError] = useState<string | null>(null);
  const [audit, setAudit] = useState<GovernanceAuditEvent[] | null>(null);
  const [auditError, setAuditError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState<string | null>(null);

  const [policyForm, setPolicyForm] = useState<PolicyForm>(EMPTY_POLICY_FORM);
  const [editingPolicy, setEditingPolicy] = useState<GovernancePolicy | null>(null);
  const [policyBusy, setPolicyBusy] = useState(false);
  const [policyFormError, setPolicyFormError] = useState<string | null>(null);

  const [retentionCaseId, setRetentionCaseId] = useState("");
  const [retentionBusy, setRetentionBusy] = useState(false);
  const [retentionActionError, setRetentionActionError] = useState<string | null>(null);

  const [holdCaseId, setHoldCaseId] = useState("");
  const [holdEvidenceId, setHoldEvidenceId] = useState("");
  const [holdScope, setHoldScope] = useState("case");
  const [holdReason, setHoldReason] = useState("");
  const [holdBusy, setHoldBusy] = useState(false);
  const [holdActionError, setHoldActionError] = useState<string | null>(null);

  const [dispositionCaseId, setDispositionCaseId] = useState("");
  const [dispositionJustification, setDispositionJustification] = useState("");
  const [dispositionBusy, setDispositionBusy] = useState(false);
  const [dispositionActionError, setDispositionActionError] = useState<string | null>(null);

  const [exportCaseId, setExportCaseId] = useState("");
  const [exportReason, setExportReason] = useState("");
  const [exportIncludeBytes, setExportIncludeBytes] = useState(false);
  const [exportBusy, setExportBusy] = useState(false);
  const [exportActionError, setExportActionError] = useState<string | null>(null);

  const [report, setReport] = useState<GovernanceComplianceReport | null>(null);
  const [reportError, setReportError] = useState<string | null>(null);
  const [reportBusy, setReportBusy] = useState(false);
  const [reportCaseId, setReportCaseId] = useState("");
  const [reportScope, setReportScope] = useState<"SUMMARY" | "DETAIL">("SUMMARY");

  const refresh = useCallback(async () => {
    setLoading(true);
    const requests: Array<Promise<unknown>> = [
      fetchGovernanceStatus(),
      fetchGovernancePolicies({ page: 1, page_size: PAGE_SIZE }),
      fetchGovernanceRetentionQueue({ page: 1, page_size: PAGE_SIZE }),
      fetchGovernanceHolds({ page: 1, page_size: PAGE_SIZE }),
      fetchGovernanceDispositions({ page: 1, page_size: PAGE_SIZE }),
      fetchGovernanceExports({ page: 1, page_size: PAGE_SIZE }),
    ];
    if (isAdmin) requests.push(fetchGovernanceAudit({ page: 1, page_size: PAGE_SIZE }));
    const results = await Promise.allSettled(requests);

    const statusResult = results[0] as PromiseSettledResult<GovernanceStatus>;
    if (statusResult.status === "fulfilled") {
      setStatus(statusResult.value);
      setStatusError(null);
    } else {
      setStatus(null);
      setStatusError(messageOf(statusResult.reason));
    }

    const policiesResult = results[1] as PromiseSettledResult<{
      items: GovernancePolicy[];
    }>;
    if (policiesResult.status === "fulfilled") {
      setPolicies(policiesResult.value.items);
      setPoliciesError(null);
    } else {
      setPolicies([]);
      setPoliciesError(messageOf(policiesResult.reason));
    }

    const retentionResult = results[2] as PromiseSettledResult<{
      items: GovernanceRetentionEvaluation[];
    }>;
    if (retentionResult.status === "fulfilled") {
      setRetention(retentionResult.value.items);
      setRetentionError(null);
    } else {
      setRetention([]);
      setRetentionError(messageOf(retentionResult.reason));
    }

    const holdsResult = results[3] as PromiseSettledResult<{ items: GovernanceLegalHold[] }>;
    if (holdsResult.status === "fulfilled") {
      setHolds(holdsResult.value.items);
      setHoldsError(null);
    } else {
      setHolds([]);
      setHoldsError(messageOf(holdsResult.reason));
    }

    const dispositionsResult = results[4] as PromiseSettledResult<{
      items: GovernanceDisposition[];
    }>;
    if (dispositionsResult.status === "fulfilled") {
      setDispositions(dispositionsResult.value.items);
      setDispositionsError(null);
    } else {
      setDispositions([]);
      setDispositionsError(messageOf(dispositionsResult.reason));
    }

    const exportsResult = results[5] as PromiseSettledResult<{
      items: GovernanceExportApproval[];
    }>;
    if (exportsResult.status === "fulfilled") {
      setExports(exportsResult.value.items);
      setExportsError(null);
    } else {
      setExports([]);
      setExportsError(messageOf(exportsResult.reason));
    }

    if (isAdmin) {
      const auditResult = results[6] as PromiseSettledResult<{ items: GovernanceAuditEvent[] }>;
      if (auditResult.status === "fulfilled") {
        setAudit(auditResult.value.items);
        setAuditError(null);
      } else {
        setAudit(null);
        setAuditError(messageOf(auditResult.reason));
      }
    } else {
      setAudit(null);
      setAuditError(null);
    }

    setLoading(false);
  }, [isAdmin]);

  const loadReport = useCallback(async (scope: "SUMMARY" | "DETAIL", caseId?: string) => {
    setReportBusy(true);
    setReportError(null);
    try {
      const body = await fetchGovernanceComplianceReport({
        scope,
        case_id: caseId?.trim() || undefined,
      });
      setReport(body);
    } catch (e) {
      setReportError(messageOf(e));
    } finally {
      setReportBusy(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    void loadReport("SUMMARY");
  }, [loadReport]);

  const pendingHoldCount = useMemo(
    () => holds.filter((hold) => hold.status === "PENDING_APPROVAL").length,
    [holds]
  );
  const blockingHoldCount = useMemo(
    () => holds.filter((hold) => hold.status === "ACTIVE" || hold.status === "PENDING_APPROVAL").length,
    [holds]
  );
  const openDispositionCount = useMemo(
    () =>
      dispositions.filter(
        (item) => item.status === "REVIEW_REQUIRED" || item.status === "APPROVAL_PENDING"
      ).length,
    [dispositions]
  );
  const pendingExportCount = useMemo(
    () => exports.filter((item) => item.status === "PENDING_APPROVAL").length,
    [exports]
  );

  const startEditPolicy = (policy: GovernancePolicy) => {
    setEditingPolicy(policy);
    setPolicyForm({
      policy_id: policy.policy_id,
      name: policy.name,
      state: policy.state,
      case_type: policy.case_type ?? "",
      evidence_category: policy.evidence_category ?? "",
      retention_days: policy.retention_days === null ? "" : String(policy.retention_days),
      review_interval_days:
        policy.review_interval_days === null ? "" : String(policy.review_interval_days),
      export_requires_approval: policy.export_requires_approval,
      allow_evidence_bytes: policy.allow_evidence_bytes,
      disposition_review_required: policy.disposition_review_required,
      reason: "",
    });
    setPolicyFormError(null);
  };

  const submitPolicy = async () => {
    setPolicyBusy(true);
    setPolicyFormError(null);
    try {
      const base = {
        name: policyForm.name.trim(),
        state: policyForm.state,
        case_type: policyForm.case_type.trim() || null,
        evidence_category: policyForm.evidence_category.trim() || null,
        retention_days: numberOrNull(policyForm.retention_days),
        review_interval_days: numberOrNull(policyForm.review_interval_days),
        export_requires_approval: policyForm.export_requires_approval,
        allow_evidence_bytes: policyForm.allow_evidence_bytes,
        disposition_review_required: policyForm.disposition_review_required,
        reason: policyForm.reason.trim(),
      };
      if (editingPolicy) {
        await updateGovernancePolicy(editingPolicy.policy_id, {
          ...base,
          expected_version: editingPolicy.version,
        });
        setNotice(`Policy ${editingPolicy.policy_id} appended as a new version.`);
      } else {
        await createGovernancePolicy({
          ...base,
          policy_id: policyForm.policy_id.trim() || undefined,
        });
        setNotice("Governance policy created.");
      }
      setEditingPolicy(null);
      setPolicyForm(EMPTY_POLICY_FORM);
      await refresh();
    } catch (e) {
      setPolicyFormError(messageOf(e));
    } finally {
      setPolicyBusy(false);
    }
  };

  const submitRetention = async () => {
    if (!retentionCaseId.trim()) {
      setRetentionActionError("A case ID is required.");
      return;
    }
    setRetentionBusy(true);
    setRetentionActionError(null);
    try {
      await evaluateGovernanceRetention({ case_id: retentionCaseId.trim() });
      setNotice("Retention evaluated. No evidence was deleted.");
      setRetentionCaseId("");
      await refresh();
    } catch (e) {
      setRetentionActionError(messageOf(e));
    } finally {
      setRetentionBusy(false);
    }
  };

  const submitHold = async () => {
    if (!holdCaseId.trim() || !holdReason.trim()) {
      setHoldActionError("A case ID and hold reason are required.");
      return;
    }
    setHoldBusy(true);
    setHoldActionError(null);
    try {
      await createGovernanceHold({
        case_id: holdCaseId.trim(),
        evidence_reference_id: holdEvidenceId.trim() || undefined,
        scope: holdScope.trim() || "case",
        reason: holdReason.trim(),
      });
      setNotice("Legal hold requested. It is pending approval and already blocks disposition/export.");
      setHoldCaseId("");
      setHoldEvidenceId("");
      setHoldReason("");
      await refresh();
    } catch (e) {
      setHoldActionError(messageOf(e));
    } finally {
      setHoldBusy(false);
    }
  };

  const submitDisposition = async () => {
    if (!dispositionCaseId.trim() || !dispositionJustification.trim()) {
      setDispositionActionError("A case ID and justification are required.");
      return;
    }
    setDispositionBusy(true);
    setDispositionActionError(null);
    try {
      await requestGovernanceDisposition({
        case_id: dispositionCaseId.trim(),
        justification: dispositionJustification.trim(),
      });
      setNotice("Disposition review requested. Approval does not delete evidence.");
      setDispositionCaseId("");
      setDispositionJustification("");
      await refresh();
    } catch (e) {
      setDispositionActionError(messageOf(e));
    } finally {
      setDispositionBusy(false);
    }
  };

  const submitExportRequest = async () => {
    if (!exportCaseId.trim() || !exportReason.trim()) {
      setExportActionError("A case ID and export reason are required.");
      return;
    }
    setExportBusy(true);
    setExportActionError(null);
    try {
      await requestGovernanceExport({
        case_id: exportCaseId.trim(),
        include_evidence_bytes: exportIncludeBytes,
        reason: exportReason.trim(),
      });
      setNotice("Export approval requested. No delivery is claimed.");
      setExportCaseId("");
      setExportReason("");
      setExportIncludeBytes(false);
      await refresh();
    } catch (e) {
      setExportActionError(messageOf(e));
    } finally {
      setExportBusy(false);
    }
  };

  const downloadCsv = async () => {
    setReportBusy(true);
    setReportError(null);
    try {
      await downloadGovernanceComplianceCsv(
        reportScope === "DETAIL" && reportCaseId.trim()
          ? { scope: "DETAIL", case_id: reportCaseId.trim() }
          : { scope: "SUMMARY" }
      );
      setNotice("Compliance-readiness CSV download started.");
    } catch (e) {
      setReportError(messageOf(e));
    } finally {
      setReportBusy(false);
    }
  };

  const sections = report?.sections ?? {};

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-lg font-bold">Governance &amp; Compliance Readiness</h1>
        <p className="text-xs text-slate-400">
          Versioned retention policies, legal holds, disposition review, export approvals, and
          append-only access audit. V35 never deletes evidence or certifies regulatory compliance.
        </p>
      </div>

      {notice ? (
        <p className="rounded border border-emerald-500/30 bg-emerald-500/10 p-2 text-xs text-emerald-200" role="status">
          {notice}
        </p>
      ) : null}

      <Card title="Governance overview">
        {statusError ? (
          <DataState state="error" emptyText="" error={statusError} />
        ) : loading && !status ? (
          <DataState state="loading" emptyText="" />
        ) : status ? (
          <div className="space-y-3">
            <div className="flex flex-wrap gap-2">
              <SectionBadge state={status.enabled ? "ok" : "unavailable"} label={status.enabled ? "enabled" : "disabled"} />
              <SectionBadge state="degraded" label={`scheduler: ${status.retention_scheduler}`} />
              <SectionBadge state="degraded" label="automatic deletion: off" />
              <SectionBadge state="degraded" label="external certification: not claimed" />
              <SectionBadge
                state={status.audit_integrity.outcome === "OK" ? "ok" : "degraded"}
                label={`audit integrity: ${status.audit_integrity.outcome}`}
              />
            </div>
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
              <Metric label="Policies" value={status.policy_count} />
              <Metric label="Evaluated cases" value={Object.values(status.evaluation_states).reduce((a, b) => a + b, 0)} />
              <Metric label="Blocking legal holds" value={blockingHoldCount} note={`${pendingHoldCount} pending approval`} />
              <Metric label="Open disposition reviews" value={openDispositionCount} />
              <Metric label="Pending export approvals" value={pendingExportCount} />
              <Metric label="Audit events" value={status.audit_event_count} />
              <Metric
                label="Audit digest check"
                value={`${status.audit_integrity.verified}/${status.audit_integrity.checked}`}
                note={status.audit_integrity.assurance}
              />
              <Metric label="Retention scheduler" value={status.retention_scheduler} note="Manual evaluation only" />
            </div>
            <div className="grid gap-2 md:grid-cols-2">
              <div>
                <p className="mb-1 text-xs font-semibold text-slate-300">Retention states</p>
                <CountList counts={status.evaluation_states} />
              </div>
              <div>
                <p className="mb-1 text-xs font-semibold text-slate-300">Legal-hold states</p>
                <CountList counts={status.hold_states} />
              </div>
            </div>
            <p className="text-xs text-amber-200">
              No automatic deletion, no automatic hold release, and no automatic disposition approval.
              Local audit records do not establish immutable storage.
            </p>
          </div>
        ) : null}
      </Card>

      <Card title="Retention policies">
        {policiesError ? <DataState state="error" emptyText="" error={policiesError} /> : null}
        {!policiesError && policies.length === 0 && !loading ? (
          <DataState state="empty" emptyText="No governance policies are configured." />
        ) : null}
        <div className="space-y-2">
          {policies.map((policy) => (
            <div key={`${policy.policy_id}-${policy.version}`} className="rounded-lg border border-slate-800 p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <p className="font-medium text-slate-100">
                    {policy.name} <span className="text-xs text-slate-400">({policy.policy_id})</span>
                  </p>
                  <p className="text-xs text-slate-400">
                    version {policy.version} · {policy.case_type ?? "all case types"} ·{" "}
                    {policy.evidence_category ?? "all evidence"} · retention{" "}
                    {policy.retention_days ?? "organization-defined (unset)"} days · review{" "}
                    {policy.review_interval_days ?? "unset"} days
                  </p>
                  <p className="text-xs text-slate-500">
                    export approval: {policy.export_requires_approval ? "required" : "not required"} · evidence
                    bytes: {policy.allow_evidence_bytes ? "allowed" : "disallowed"} · disposition review:{" "}
                    {policy.disposition_review_required ? "required" : "not required"}
                  </p>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <StatusPill status={policy.state} />
                  {isAdmin ? (
                    <button
                      type="button"
                      className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-200 hover:bg-slate-800"
                      onClick={() => startEditPolicy(policy)}
                    >
                      Edit policy
                    </button>
                  ) : null}
                  {isAdmin && !policy.is_default && policy.state !== "ENABLED" ? (
                    <ConfirmAction
                      label="Enable policy"
                      confirmLabel="Confirm enable"
                      onConfirm={async (reason) => {
                        await setGovernancePolicyState(policy.policy_id, {
                          state: "ENABLED",
                          reason,
                          expected_version: policy.version,
                        });
                        setNotice(`Policy ${policy.policy_id} enabled.`);
                        await refresh();
                      }}
                    />
                  ) : null}
                  {isAdmin && !policy.is_default && policy.state === "ENABLED" ? (
                    <ConfirmAction
                      label="Disable policy"
                      confirmLabel="Confirm disable"
                      description="Disabling a policy does not rewrite prior evaluations."
                      onConfirm={async (reason) => {
                        await setGovernancePolicyState(policy.policy_id, {
                          state: "DISABLED",
                          reason,
                          expected_version: policy.version,
                        });
                        setNotice(`Policy ${policy.policy_id} disabled.`);
                        await refresh();
                      }}
                    />
                  ) : null}
                </div>
              </div>
              {policy.is_default ? (
                <p className="mt-1 text-xs text-slate-500">
                  Safe default policy: durations remain unset until an administrator configures them.
                </p>
              ) : null}
            </div>
          ))}
        </div>

        {isAdmin ? (
          <div className="mt-4 rounded-lg border border-slate-800 p-3">
            <p className="mb-2 text-xs font-semibold text-slate-200">
              {editingPolicy ? `Append a new version of ${editingPolicy.policy_id}` : "Create a governance policy"}
            </p>
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
              <label className="text-xs text-slate-300">
                Policy ID (optional)
                <input
                  className="mt-1 w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs"
                  value={policyForm.policy_id}
                  disabled={Boolean(editingPolicy)}
                  onChange={(event) => setPolicyForm({ ...policyForm, policy_id: event.target.value })}
                />
              </label>
              <label className="text-xs text-slate-300">
                Name
                <input
                  className="mt-1 w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs"
                  value={policyForm.name}
                  onChange={(event) => setPolicyForm({ ...policyForm, name: event.target.value })}
                />
              </label>
              <label className="text-xs text-slate-300">
                State
                <select
                  className="mt-1 w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs"
                  value={policyForm.state}
                  onChange={(event) => setPolicyForm({ ...policyForm, state: event.target.value })}
                >
                  <option value="DRAFT">DRAFT</option>
                  <option value="ENABLED">ENABLED</option>
                  <option value="DISABLED">DISABLED</option>
                  <option value="ARCHIVED">ARCHIVED</option>
                </select>
              </label>
              <label className="text-xs text-slate-300">
                Case type (optional)
                <input
                  className="mt-1 w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs"
                  value={policyForm.case_type}
                  onChange={(event) => setPolicyForm({ ...policyForm, case_type: event.target.value })}
                />
              </label>
              <label className="text-xs text-slate-300">
                Evidence category (optional)
                <input
                  className="mt-1 w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs"
                  value={policyForm.evidence_category}
                  onChange={(event) =>
                    setPolicyForm({ ...policyForm, evidence_category: event.target.value })
                  }
                />
              </label>
              <label className="text-xs text-slate-300">
                Retention days (organization-defined)
                <input
                  className="mt-1 w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs"
                  inputMode="numeric"
                  value={policyForm.retention_days}
                  onChange={(event) =>
                    setPolicyForm({ ...policyForm, retention_days: event.target.value })
                  }
                />
              </label>
              <label className="text-xs text-slate-300">
                Review interval days
                <input
                  className="mt-1 w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs"
                  inputMode="numeric"
                  value={policyForm.review_interval_days}
                  onChange={(event) =>
                    setPolicyForm({ ...policyForm, review_interval_days: event.target.value })
                  }
                />
              </label>
              <label className="flex items-center gap-2 text-xs text-slate-300">
                <input
                  type="checkbox"
                  checked={policyForm.export_requires_approval}
                  onChange={(event) =>
                    setPolicyForm({ ...policyForm, export_requires_approval: event.target.checked })
                  }
                />
                Export requires approval
              </label>
              <label className="flex items-center gap-2 text-xs text-slate-300">
                <input
                  type="checkbox"
                  checked={policyForm.allow_evidence_bytes}
                  onChange={(event) =>
                    setPolicyForm({ ...policyForm, allow_evidence_bytes: event.target.checked })
                  }
                />
                Allow evidence bytes in exports
              </label>
              <label className="flex items-center gap-2 text-xs text-slate-300">
                <input
                  type="checkbox"
                  checked={policyForm.disposition_review_required}
                  onChange={(event) =>
                    setPolicyForm({
                      ...policyForm,
                      disposition_review_required: event.target.checked,
                    })
                  }
                />
                Disposition review required
              </label>
              <label className="text-xs text-slate-300 sm:col-span-2 lg:col-span-3">
                Change reason (required)
                <input
                  className="mt-1 w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs"
                  value={policyForm.reason}
                  onChange={(event) => setPolicyForm({ ...policyForm, reason: event.target.value })}
                />
              </label>
            </div>
            <div className="mt-2 flex flex-wrap gap-2">
              <button
                type="button"
                className="rounded bg-sky-500 px-2 py-1 text-xs font-semibold text-slate-950 disabled:opacity-50"
                disabled={policyBusy || !policyForm.name.trim() || !policyForm.reason.trim()}
                onClick={() => void submitPolicy()}
              >
                {policyBusy ? "Saving…" : editingPolicy ? "Append policy version" : "Create policy"}
              </button>
              {editingPolicy ? (
                <button
                  type="button"
                  className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-300"
                  onClick={() => {
                    setEditingPolicy(null);
                    setPolicyForm(EMPTY_POLICY_FORM);
                    setPolicyFormError(null);
                  }}
                >
                  Cancel edit
                </button>
              ) : null}
            </div>
            {policyFormError ? (
              <p className="mt-1 text-xs text-red-300" role="alert">
                {policyFormError}
              </p>
            ) : null}
          </div>
        ) : (
          <p className="mt-2 text-xs text-slate-500">Policy changes require an administrator.</p>
        )}
      </Card>

      <Card title="Retention review queue">
        {retentionError ? <DataState state="error" emptyText="" error={retentionError} /> : null}
        {canOperate ? (
          <div className="mb-3 flex flex-wrap items-end gap-2">
            <label className="text-xs text-slate-300">
              Case ID
              <input
                className="mt-1 rounded border border-slate-700 bg-slate-950 p-1 text-xs"
                value={retentionCaseId}
                onChange={(event) => setRetentionCaseId(event.target.value)}
              />
            </label>
            <button
              type="button"
              className="rounded bg-sky-500 px-2 py-1 text-xs font-semibold text-slate-950 disabled:opacity-50"
              disabled={retentionBusy || !retentionCaseId.trim()}
              onClick={() => void submitRetention()}
            >
              {retentionBusy ? "Evaluating…" : "Evaluate retention"}
            </button>
            {retentionActionError ? (
              <p className="text-xs text-red-300" role="alert">
                {retentionActionError}
              </p>
            ) : null}
          </div>
        ) : null}
        {!retentionError && retention.length === 0 && !loading ? (
          <DataState state="empty" emptyText="No retention evaluations exist yet." />
        ) : null}
        <div className="space-y-2">
          {retention.map((item) => (
            <div key={item.evaluation_id} className="rounded-lg border border-slate-800 p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <p className="font-medium text-slate-100">
                    {item.case_id} <span className="text-xs text-slate-400">({item.evaluation_kind})</span>
                  </p>
                  <p className="text-xs text-slate-400">
                    policy {item.policy_id ?? "unavailable"} v{item.policy_version ?? "?"} · deadline{" "}
                    {item.retention_deadline ?? "unavailable"} · next review{" "}
                    {item.next_review_at ?? "unavailable"}
                  </p>
                  <p className="text-xs text-slate-500">
                    evaluated {item.evaluated_at ?? "unknown"} · data {item.data_status} · integrity{" "}
                    {item.integrity_status} · deletion authorized: no
                  </p>
                  {item.reasons.length > 0 ? (
                    <p className="mt-1 text-xs text-amber-200">Reasons: {item.reasons.join(", ")}</p>
                  ) : null}
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <StatusPill status={item.governance_state} />
                  {canOperate ? (
                    <ConfirmAction
                      label="Complete review"
                      confirmLabel="Confirm review"
                      onConfirm={async (reason) => {
                        await reviewGovernanceRetention(item.case_id, { reason });
                        setNotice("Retention review recorded. No evidence was deleted.");
                        await refresh();
                      }}
                    />
                  ) : null}
                </div>
              </div>
            </div>
          ))}
        </div>
      </Card>

      <Card title="Legal holds">
        {holdsError ? <DataState state="error" emptyText="" error={holdsError} /> : null}
        {canOperate ? (
          <div className="mb-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
            <label className="text-xs text-slate-300">
              Case ID
              <input
                className="mt-1 w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs"
                value={holdCaseId}
                onChange={(event) => setHoldCaseId(event.target.value)}
              />
            </label>
            <label className="text-xs text-slate-300">
              Evidence reference ID (optional)
              <input
                className="mt-1 w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs"
                value={holdEvidenceId}
                onChange={(event) => setHoldEvidenceId(event.target.value)}
              />
            </label>
            <label className="text-xs text-slate-300">
              Scope
              <input
                className="mt-1 w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs"
                value={holdScope}
                onChange={(event) => setHoldScope(event.target.value)}
              />
            </label>
            <label className="text-xs text-slate-300">
              Reason
              <input
                className="mt-1 w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs"
                value={holdReason}
                onChange={(event) => setHoldReason(event.target.value)}
              />
            </label>
            <button
              type="button"
              className="rounded bg-sky-500 px-2 py-1 text-xs font-semibold text-slate-950 disabled:opacity-50"
              disabled={holdBusy || !holdCaseId.trim() || !holdReason.trim()}
              onClick={() => void submitHold()}
            >
              {holdBusy ? "Requesting…" : "Request legal hold"}
            </button>
            {holdActionError ? (
              <p className="text-xs text-red-300" role="alert">
                {holdActionError}
              </p>
            ) : null}
          </div>
        ) : null}
        {!holdsError && holds.length === 0 && !loading ? (
          <DataState state="empty" emptyText="No legal holds exist." />
        ) : null}
        <div className="space-y-2">
          {holds.map((hold) => (
            <div key={hold.hold_id} className="rounded-lg border border-slate-800 p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <p className="font-medium text-slate-100">
                    {hold.hold_number} <span className="text-xs text-slate-400">({hold.scope})</span>
                  </p>
                  <p className="text-xs text-slate-400">
                    case {hold.case_id} · requested by {hold.requested_by} · {hold.reason}
                  </p>
                  <p className="text-xs text-slate-500">
                    approved by {hold.approved_by ?? "not approved"} · released by{" "}
                    {hold.released_by ?? "not released"} · no automatic expiry
                  </p>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <StatusPill status={hold.status} />
                  {isAdmin && hold.status === "PENDING_APPROVAL" ? (
                    <>
                      <ConfirmAction
                        label="Approve hold"
                        confirmLabel="Confirm approval"
                        onConfirm={async (reason) => {
                          await actOnGovernanceHold(hold.hold_id, "approve", {
                            reason,
                            expected_version: hold.version,
                          });
                          setNotice("Legal hold approved. It now blocks disposition/export.");
                          await refresh();
                        }}
                      />
                      <ConfirmAction
                        label="Reject hold"
                        confirmLabel="Confirm rejection"
                        onConfirm={async (reason) => {
                          await actOnGovernanceHold(hold.hold_id, "reject", {
                            reason,
                            expected_version: hold.version,
                          });
                          setNotice("Legal hold rejected; history is retained.");
                          await refresh();
                        }}
                      />
                    </>
                  ) : null}
                  {isAdmin && hold.status === "ACTIVE" ? (
                    <ConfirmAction
                      label="Release hold"
                      confirmLabel="Confirm release"
                      description="Release requires an explicit reason and affects only this hold."
                      onConfirm={async (reason) => {
                        await actOnGovernanceHold(hold.hold_id, "release", {
                          reason,
                          expected_version: hold.version,
                        });
                        setNotice("Legal hold released. Other holds remain in effect.");
                        await refresh();
                      }}
                    />
                  ) : null}
                  {canOperate && hold.status === "PENDING_APPROVAL" ? (
                    <ConfirmAction
                      label="Withdraw hold request"
                      confirmLabel="Confirm withdrawal"
                      onConfirm={async (reason) => {
                        await actOnGovernanceHold(hold.hold_id, "withdraw", {
                          reason,
                          expected_version: hold.version,
                        });
                        setNotice("Legal-hold request withdrawn; history is retained.");
                        await refresh();
                      }}
                    />
                  ) : null}
                </div>
              </div>
            </div>
          ))}
        </div>
      </Card>

      <Card title="Disposition review queue">
        {dispositionsError ? <DataState state="error" emptyText="" error={dispositionsError} /> : null}
        {canOperate ? (
          <div className="mb-3 flex flex-wrap items-end gap-2">
            <label className="text-xs text-slate-300">
              Case ID
              <input
                className="mt-1 rounded border border-slate-700 bg-slate-950 p-1 text-xs"
                value={dispositionCaseId}
                onChange={(event) => setDispositionCaseId(event.target.value)}
              />
            </label>
            <label className="text-xs text-slate-300">
              Justification
              <input
                className="mt-1 rounded border border-slate-700 bg-slate-950 p-1 text-xs"
                value={dispositionJustification}
                onChange={(event) => setDispositionJustification(event.target.value)}
              />
            </label>
            <button
              type="button"
              className="rounded bg-sky-500 px-2 py-1 text-xs font-semibold text-slate-950 disabled:opacity-50"
              disabled={dispositionBusy || !dispositionCaseId.trim() || !dispositionJustification.trim()}
              onClick={() => void submitDisposition()}
            >
              {dispositionBusy ? "Requesting…" : "Request disposition review"}
            </button>
            {dispositionActionError ? (
              <p className="text-xs text-red-300" role="alert">
                {dispositionActionError}
              </p>
            ) : null}
          </div>
        ) : null}
        <p className="mb-2 text-xs text-amber-200">
          Approval authorizes only a future, separately scoped disposition process. V35 performs no
          physical deletion and schedules none.
        </p>
        {!dispositionsError && dispositions.length === 0 && !loading ? (
          <DataState state="empty" emptyText="No disposition reviews exist." />
        ) : null}
        <div className="space-y-2">
          {dispositions.map((item) => (
            <div key={item.disposition_id} className="rounded-lg border border-slate-800 p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <p className="font-medium text-slate-100">
                    {item.request_number} <span className="text-xs text-slate-400">case {item.case_id}</span>
                  </p>
                  <p className="text-xs text-slate-400">
                    requested by {item.requested_by} · policy {item.policy_id ?? "unavailable"} v
                    {item.policy_version ?? "?"} · approvals {item.approval_count}/
                    {item.required_approval_level === "DUAL_REVIEWER" ? 2 : 1}
                  </p>
                  <p className="text-xs text-slate-500">{item.justification}</p>
                  {item.blocked_reason_codes.length > 0 ? (
                    <p className="mt-1 text-xs text-red-300">
                      Blocked: {item.blocked_reason_codes.join(", ")}
                    </p>
                  ) : null}
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <StatusPill status={item.status} />
                  {isAdmin &&
                  (item.status === "REVIEW_REQUIRED" || item.status === "APPROVAL_PENDING") ? (
                    <>
                      <ConfirmAction
                        label="Approve disposition"
                        confirmLabel="Confirm approval"
                        description="This records governance approval only; no deletion occurs."
                        onConfirm={async (reason) => {
                          await decideGovernanceDisposition(item.disposition_id, {
                            decision: "APPROVE",
                            reason,
                            expected_version: item.version,
                          });
                          setNotice("Disposition approved. No physical deletion was performed.");
                          await refresh();
                        }}
                      />
                      <ConfirmAction
                        label="Reject disposition"
                        confirmLabel="Confirm rejection"
                        onConfirm={async (reason) => {
                          await decideGovernanceDisposition(item.disposition_id, {
                            decision: "REJECT",
                            reason,
                            expected_version: item.version,
                          });
                          setNotice("Disposition rejected; history is retained.");
                          await refresh();
                        }}
                      />
                    </>
                  ) : null}
                  {canOperate &&
                  (item.status === "REVIEW_REQUIRED" || item.status === "APPROVAL_PENDING") ? (
                    <ConfirmAction
                      label="Withdraw disposition"
                      confirmLabel="Confirm withdrawal"
                      onConfirm={async (reason) => {
                        await withdrawGovernanceDisposition(item.disposition_id, {
                          reason,
                          expected_version: item.version,
                        });
                        setNotice("Disposition request withdrawn; history is retained.");
                        await refresh();
                      }}
                    />
                  ) : null}
                </div>
              </div>
            </div>
          ))}
        </div>
      </Card>

      <Card title="Export approvals">
        {exportsError ? <DataState state="error" emptyText="" error={exportsError} /> : null}
        {canOperate ? (
          <div className="mb-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
            <label className="text-xs text-slate-300">
              Case ID
              <input
                className="mt-1 w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs"
                value={exportCaseId}
                onChange={(event) => setExportCaseId(event.target.value)}
              />
            </label>
            <label className="text-xs text-slate-300">
              Reason
              <input
                className="mt-1 w-full rounded border border-slate-700 bg-slate-950 p-1 text-xs"
                value={exportReason}
                onChange={(event) => setExportReason(event.target.value)}
              />
            </label>
            <label className="flex items-center gap-2 text-xs text-slate-300">
              <input
                type="checkbox"
                checked={exportIncludeBytes}
                onChange={(event) => setExportIncludeBytes(event.target.checked)}
              />
              Include evidence bytes (policy-gated)
            </label>
            <button
              type="button"
              className="rounded bg-sky-500 px-2 py-1 text-xs font-semibold text-slate-950 disabled:opacity-50"
              disabled={exportBusy || !exportCaseId.trim() || !exportReason.trim()}
              onClick={() => void submitExportRequest()}
            >
              {exportBusy ? "Requesting…" : "Request export approval"}
            </button>
            {exportActionError ? (
              <p className="text-xs text-red-300" role="alert">
                {exportActionError}
              </p>
            ) : null}
          </div>
        ) : null}
        <p className="mb-2 text-xs text-amber-200">
          Generation, verification, and download are shown separately. No delivery or external
          recipient validation is claimed.
        </p>
        {!exportsError && exports.length === 0 && !loading ? (
          <DataState state="empty" emptyText="No export approvals exist." />
        ) : null}
        <div className="space-y-2">
          {exports.map((item) => (
            <div key={item.approval_id} className="rounded-lg border border-slate-800 p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <p className="font-medium text-slate-100">
                    {item.request_number} <span className="text-xs text-slate-400">case {item.case_id}</span>
                  </p>
                  <p className="text-xs text-slate-400">
                    requested by {item.requested_by} · policy {item.policy_id ?? "unavailable"} v
                    {item.policy_version ?? "?"} · evidence bytes:{" "}
                    {item.include_evidence_bytes ? "requested" : "no"}
                  </p>
                  <p className="text-xs text-slate-500">
                    export: {item.export_id ?? "not generated"} · sha256:{" "}
                    {item.export_sha256 ? `${item.export_sha256.slice(0, 16)}…` : "unavailable"} ·
                    verification: {item.verification_outcome} · delivery claimed: no
                  </p>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <StatusPill status={item.status} />
                  {isAdmin &&
                  (item.status === "PENDING_APPROVAL" || item.status === "POLICY_AUTO_APPROVED") ? (
                    <>
                      <ConfirmAction
                        label="Approve export"
                        confirmLabel="Confirm approval"
                        onConfirm={async (reason) => {
                          await actOnGovernanceExport(item.approval_id, "approve", {
                            reason,
                            expected_version: item.version,
                          });
                          setNotice("Export approved; generation remains a separate action.");
                          await refresh();
                        }}
                      />
                      <ConfirmAction
                        label="Reject export"
                        confirmLabel="Confirm rejection"
                        onConfirm={async (reason) => {
                          await actOnGovernanceExport(item.approval_id, "reject", {
                            reason,
                            expected_version: item.version,
                          });
                          setNotice("Export rejected; history is retained.");
                          await refresh();
                        }}
                      />
                    </>
                  ) : null}
                  {isAdmin &&
                  (item.status === "APPROVED" || item.status === "POLICY_AUTO_APPROVED") ? (
                    <button
                      type="button"
                      className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-200 hover:bg-slate-800"
                      onClick={async () => {
                        try {
                          await generateGovernanceExport(item.approval_id);
                          setNotice("Export generated. Download is a separate observed event.");
                          await refresh();
                        } catch (e) {
                          setExportsError(messageOf(e));
                        }
                      }}
                    >
                      Generate export
                    </button>
                  ) : null}
                  {isAdmin && (item.status === "GENERATED" || item.status === "VERIFIED") ? (
                    <button
                      type="button"
                      className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-200 hover:bg-slate-800"
                      onClick={async () => {
                        try {
                          await verifyGovernanceExport(item.approval_id);
                          setNotice("Export verification recorded.");
                          await refresh();
                        } catch (e) {
                          setExportsError(messageOf(e));
                        }
                      }}
                    >
                      Verify export
                    </button>
                  ) : null}
                  {isAdmin && item.export_id ? (
                    <a
                      className="rounded border border-slate-700 px-2 py-1 text-xs text-sky-300 hover:bg-slate-800"
                      href={governanceExportDownloadUrl(item.approval_id)}
                    >
                      Download export
                    </a>
                  ) : null}
                  {canOperate &&
                  (item.status === "PENDING_APPROVAL" ||
                    item.status === "POLICY_AUTO_APPROVED" ||
                    item.status === "APPROVED") ? (
                    <ConfirmAction
                      label="Withdraw export request"
                      confirmLabel="Confirm withdrawal"
                      onConfirm={async (reason) => {
                        await actOnGovernanceExport(item.approval_id, "withdraw", {
                          reason,
                          expected_version: item.version,
                        });
                        setNotice("Export request withdrawn; history is retained.");
                        await refresh();
                      }}
                    />
                  ) : null}
                </div>
              </div>
            </div>
          ))}
        </div>
      </Card>

      <Card title="Access audit history">
        {!isAdmin ? (
          <p className="text-xs text-slate-500">Access audit history requires an administrator.</p>
        ) : auditError ? (
          <DataState state="error" emptyText="" error={auditError} />
        ) : !audit || audit.length === 0 ? (
          <DataState state={loading ? "loading" : "empty"} emptyText="No governance audit events." />
        ) : (
          <div className="space-y-2">
            <p className="text-xs text-slate-400">
              Assurance: LOCAL_SELF_DIGEST_ONLY. This is an append-only local audit trail, not an
              external hash chain or trust anchor.
            </p>
            <div className="max-h-96 overflow-auto">
              <table className="w-full text-left text-xs">
                <thead className="sticky top-0 bg-slate-900 text-slate-400">
                  <tr>
                    <th className="p-1">Occurred</th>
                    <th className="p-1">Event</th>
                    <th className="p-1">Actor</th>
                    <th className="p-1">Target</th>
                    <th className="p-1">Outcome</th>
                    <th className="p-1">Digest</th>
                  </tr>
                </thead>
                <tbody>
                  {audit.map((event) => (
                    <tr key={event.event_id} className="border-t border-slate-800">
                      <td className="p-1 text-slate-400">{event.occurred_at}</td>
                      <td className="p-1">{event.event_type}</td>
                      <td className="p-1 text-slate-400">
                        {event.actor_id} ({event.actor_role})
                      </td>
                      <td className="p-1 text-slate-400">
                        {event.target_type}:{event.target_id}
                      </td>
                      <td className="p-1">{event.outcome}</td>
                      <td className="p-1 text-slate-500">{event.event_hash.slice(0, 12)}…</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </Card>

      <Card title="Compliance-readiness reports">
        <div className="mb-2 flex flex-wrap items-end gap-2">
          <label className="text-xs text-slate-300">
            Scope
            <select
              className="mt-1 rounded border border-slate-700 bg-slate-950 p-1 text-xs"
              value={reportScope}
              onChange={(event) => setReportScope(event.target.value as "SUMMARY" | "DETAIL")}
            >
              <option value="SUMMARY">SUMMARY</option>
              <option value="DETAIL">DETAIL</option>
            </select>
          </label>
          {reportScope === "DETAIL" ? (
            <label className="text-xs text-slate-300">
              Case ID
              <input
                className="mt-1 rounded border border-slate-700 bg-slate-950 p-1 text-xs"
                value={reportCaseId}
                onChange={(event) => setReportCaseId(event.target.value)}
              />
            </label>
          ) : null}
          <button
            type="button"
            className="rounded bg-sky-500 px-2 py-1 text-xs font-semibold text-slate-950 disabled:opacity-50"
            disabled={
              reportBusy || (reportScope === "DETAIL" && (!isAdmin || !reportCaseId.trim()))
            }
            onClick={() => void loadReport(reportScope, reportScope === "DETAIL" ? reportCaseId : undefined)}
          >
            {reportBusy ? "Generating…" : "Generate report"}
          </button>
          <button
            type="button"
            className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-200 hover:bg-slate-800 disabled:opacity-50"
            disabled={reportBusy || (reportScope === "DETAIL" && (!isAdmin || !reportCaseId.trim()))}
            onClick={() => void downloadCsv()}
          >
            Download CSV
          </button>
        </div>
        {reportError ? (
          <DataState state="error" emptyText="" error={reportError} />
        ) : !report ? (
          <DataState state={reportBusy ? "loading" : "empty"} emptyText="No report generated yet." />
        ) : (
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <StatusPill status={report.overall_status} />
              <span className="text-xs text-slate-400">
                scope {report.scope} · as of {report.as_of} · generated {report.generated_at}
              </span>
            </div>
            <div className="grid gap-2 md:grid-cols-2 lg:grid-cols-3">
              {Object.entries(sections).map(([name, section]) => (
                <div key={name} className="rounded border border-slate-800 p-2">
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-xs font-semibold text-slate-200">{name}</p>
                    <StatusPill status={String(section.status ?? "UNKNOWN")} />
                  </div>
                  <pre className="mt-1 max-h-32 overflow-auto whitespace-pre-wrap text-[10px] text-slate-500">
                    {JSON.stringify(section, null, 2)}
                  </pre>
                </div>
              ))}
            </div>
            {report.detail ? (
              <div className="overflow-auto">
                <table className="w-full text-left text-xs">
                  <thead className="text-slate-400">
                    <tr>
                      <th className="p-1">Case</th>
                      <th className="p-1">State</th>
                      <th className="p-1">Policy</th>
                      <th className="p-1">Deadline</th>
                      <th className="p-1">Data</th>
                      <th className="p-1">Deletion authorized</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.detail.map((row) => (
                      <tr key={row.case_id} className="border-t border-slate-800">
                        <td className="p-1">{row.case_id}</td>
                        <td className="p-1">{row.governance_state}</td>
                        <td className="p-1">
                          {row.policy_id ?? "unavailable"} v{row.policy_version ?? "?"}
                        </td>
                        <td className="p-1">{row.retention_deadline ?? "unavailable"}</td>
                        <td className="p-1">{row.data_status}</td>
                        <td className="p-1">no</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : null}
            <p className="text-xs text-amber-200">
              Not a regulatory certification or legal compliance attestation. No external immutable
              storage or trust anchor is claimed.
            </p>
            <details className="text-xs text-slate-400">
              <summary>Report limitations and non-claims</summary>
              <ul className="mt-1 list-disc pl-4">
                {report.non_claims.map((item) => (
                  <li key={item}>{item}</li>
                ))}
                {report.limitations.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </details>
          </div>
        )}
      </Card>
    </div>
  );
}
