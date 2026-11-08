"use client";

import { useCallback, useEffect, useState } from "react";
import { Card } from "../../components/ui/Card";
import { DataState, SectionBadge } from "../../components/operations/primitives";
import { useAuth } from "../../components/auth/AuthProvider";
import {
  fetchIntegrityAudit,
  fetchIntegrityAudits,
  fetchIntegrityFindings,
  fetchIntegrityStatus,
  startIntegrityAudit,
} from "../../lib/integrity/client";
import type {
  IntegrityAuditDetail,
  IntegrityAuditStatus,
  IntegrityAuditSummary,
  IntegrityFinding,
  IntegrityScope,
  IntegrityScopeResult,
  IntegrityStatus,
} from "../../types";

const PAGE_SIZE = 20;

const SCOPES: IntegrityScope[] = [
  "EVIDENCE",
  "SIGNED_CHECKPOINTS",
  "TRANSPARENCY_LOG",
  "TREE_HEADS",
  "INCLUSION_PROOFS",
  "CONSISTENCY_PROOFS",
  "TRUST_STATE",
];

const STATUSES: IntegrityAuditStatus[] = ["PASS", "FAIL", "PARTIAL", "UNAVAILABLE", "NOT_RUN"];

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

function statusStyle(status: string): string {
  if (status === "PASS") return "bg-emerald-500/15 text-emerald-300";
  if (status === "FAIL") return "bg-red-500/15 text-red-300";
  if (status === "PARTIAL") return "bg-amber-500/15 text-amber-300";
  return "bg-slate-500/15 text-slate-400";
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

function ScopeResultRow({ result }: { result: IntegrityScopeResult }) {
  return (
    <li className="rounded-lg border border-slate-800 px-2 py-1 text-xs">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="font-medium text-slate-200">{result.scope}</span>
        <span className="flex items-center gap-2">
          <StatusPill status={result.status} />
          <span className="text-slate-500">
            {result.artifacts_checked} artifact(s) · {result.checks_failed}/{result.checks_total} check(s)
            failed
          </span>
        </span>
      </div>
      {result.reason_codes.length > 0 && (
        <p className="mt-1 text-slate-400">Reasons: {result.reason_codes.join(", ")}</p>
      )}
      {result.error_summary && <p className="mt-1 text-amber-300/90">{result.error_summary}</p>}
      {result.truncated && (
        <p className="mt-1 text-amber-300/90">
          Bounded batch reached — this scope result is partial, not complete.
        </p>
      )}
    </li>
  );
}

function FindingRow({ finding }: { finding: IntegrityFinding }) {
  return (
    <li className="rounded-lg border border-slate-800 bg-slate-900/60 px-2 py-2 text-xs">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="flex items-center gap-2">
          <StatusPill status={finding.severity} />
          <span className="font-medium text-slate-200">{finding.reason_code}</span>
        </span>
        <span className="text-slate-500">
          {finding.scope} · {finding.detected_at}
        </span>
      </div>
      <p className="mt-1 text-slate-300">{finding.explanation}</p>
      <p className="mt-1 text-slate-500">
        Artifact: {finding.artifact_id ?? "—"} · Source: {finding.verification_source}
      </p>
      <p className="mt-1 text-slate-400">Recommended: {finding.recommended_action}</p>
      <p className="mt-1 text-slate-600">Run: {finding.audit_run_id}</p>
    </li>
  );
}

function AuditRow({
  audit,
  selected,
  onSelect,
}: {
  audit: IntegrityAuditSummary;
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
        <span className="flex items-center gap-2">
          <StatusPill status={audit.status} />
          <span className="font-medium text-slate-200">{audit.trigger}</span>
          <span className="text-slate-500">{audit.started_at}</span>
        </span>
        <span className="text-slate-500">
          {audit.artifacts_checked} artifact(s) · {audit.finding_counts?.CRITICAL ?? 0} critical ·{" "}
          {audit.duration_ms} ms
        </span>
      </button>
    </li>
  );
}

export default function IntegrityPage() {
  const { hasRole } = useAuth();
  const canRun = hasRole("ADMIN") || hasRole("OPERATOR");

  const [status, setStatus] = useState<IntegrityStatus | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [statusLoading, setStatusLoading] = useState(true);

  const [findings, setFindings] = useState<IntegrityFinding[]>([]);
  const [findingsTotal, setFindingsTotal] = useState(0);
  const [findingsPage, setFindingsPage] = useState(1);
  const [severity, setSeverity] = useState("");
  const [findingScope, setFindingScope] = useState("");
  const [reasonCode, setReasonCode] = useState("");
  const [findingsError, setFindingsError] = useState<string | null>(null);
  const [findingsLoading, setFindingsLoading] = useState(true);

  const [audits, setAudits] = useState<IntegrityAuditSummary[]>([]);
  const [auditsTotal, setAuditsTotal] = useState(0);
  const [auditsPage, setAuditsPage] = useState(1);
  const [auditStatus, setAuditStatus] = useState("");
  const [auditsError, setAuditsError] = useState<string | null>(null);
  const [auditsLoading, setAuditsLoading] = useState(true);

  const [selectedAuditId, setSelectedAuditId] = useState<string | null>(null);
  const [auditDetail, setAuditDetail] = useState<IntegrityAuditDetail | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);

  const [selectedScopes, setSelectedScopes] = useState<IntegrityScope[]>(["FULL"]);
  const [running, setRunning] = useState(false);
  const [runError, setRunError] = useState<string | null>(null);
  const [runResult, setRunResult] = useState<IntegrityAuditSummary | null>(null);

  const refreshStatus = useCallback(async () => {
    try {
      setStatus(await fetchIntegrityStatus());
      setStatusError(null);
    } catch (e) {
      setStatusError(e instanceof Error ? e.message : "API unreachable");
    } finally {
      setStatusLoading(false);
    }
  }, []);

  const refreshFindings = useCallback(async () => {
    setFindingsLoading(true);
    try {
      const body = await fetchIntegrityFindings({
        severity: severity || undefined,
        scope: findingScope || undefined,
        reason_code: reasonCode.trim() || undefined,
        page: findingsPage,
        page_size: PAGE_SIZE,
      });
      setFindings(body.items);
      setFindingsTotal(body.total);
      setFindingsError(null);
    } catch (e) {
      setFindingsError(e instanceof Error ? e.message : "API unreachable");
    } finally {
      setFindingsLoading(false);
    }
  }, [severity, findingScope, reasonCode, findingsPage]);

  const refreshAudits = useCallback(async () => {
    setAuditsLoading(true);
    try {
      const body = await fetchIntegrityAudits({
        status: auditStatus || undefined,
        page: auditsPage,
        page_size: PAGE_SIZE,
      });
      setAudits(body.items);
      setAuditsTotal(body.total);
      setAuditsError(null);
    } catch (e) {
      setAuditsError(e instanceof Error ? e.message : "API unreachable");
    } finally {
      setAuditsLoading(false);
    }
  }, [auditStatus, auditsPage]);

  useEffect(() => {
    void refreshStatus();
    const timer = setInterval(() => void refreshStatus(), 30000);
    return () => clearInterval(timer);
  }, [refreshStatus]);

  useEffect(() => {
    void refreshFindings();
  }, [refreshFindings]);

  useEffect(() => {
    void refreshAudits();
  }, [refreshAudits]);

  useEffect(() => {
    if (!selectedAuditId) {
      setAuditDetail(null);
      setDetailError(null);
      return;
    }
    let cancelled = false;
    void (async () => {
      try {
        const detail = await fetchIntegrityAudit(selectedAuditId);
        if (!cancelled) {
          setAuditDetail(detail);
          setDetailError(null);
        }
      } catch (e) {
        if (!cancelled) setDetailError(e instanceof Error ? e.message : "API unreachable");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [selectedAuditId]);

  const toggleScope = (scope: IntegrityScope) => {
    setSelectedScopes((previous) => {
      if (scope === "FULL") return ["FULL"];
      const next = previous.filter((value) => value !== "FULL");
      if (next.includes(scope)) {
        const without = next.filter((value) => value !== scope);
        return without.length > 0 ? without : ["FULL"];
      }
      return [...next, scope];
    });
  };

  const runAudit = async () => {
    setRunning(true);
    setRunError(null);
    setRunResult(null);
    try {
      const result = await startIntegrityAudit(selectedScopes.length > 0 ? selectedScopes : ["FULL"]);
      setRunResult(result);
      setSelectedAuditId(result.audit_run_id);
      await Promise.all([refreshStatus(), refreshAudits(), refreshFindings()]);
    } catch (e) {
      setRunError(e instanceof Error ? e.message : "Audit failed");
    } finally {
      setRunning(false);
    }
  };

  const latest = status?.latest_audit ?? null;
  const trust = status?.trust ?? null;
  const assurance = status?.assurance ?? trust?.assurance ?? "UNKNOWN";
  const externalAnchor = trust?.external_anchor_status ?? "NOT_CONFIGURED";

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h1 className="text-lg font-bold">Continuous Integrity Monitoring</h1>
          <p className="max-w-3xl text-xs text-slate-400">
            Read-only verification of V30 evidence, V31 signed checkpoints, and V32 transparency
            proofs and trust state. Audit records are written only to the isolated monitoring
            store. This deployment is offline/local: external anchoring is never claimed.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <SectionBadge
            state={status?.store_status === "AVAILABLE" ? "ok" : "unavailable"}
            label={`store: ${status?.store_status ?? "unknown"}`}
          />
          <SectionBadge
            state={status?.scheduler?.state === "RUNNING" ? "ok" : "degraded"}
            label={`scheduler: ${status?.scheduler?.state ?? "unknown"}`}
          />
          <SectionBadge state="degraded" label={`assurance: ${assurance}`} />
          <button
            onClick={() => {
              void refreshStatus();
              void refreshFindings();
              void refreshAudits();
            }}
            className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm hover:bg-slate-700"
          >
            Refresh
          </button>
        </div>
      </div>

      {statusError && (
        <p className="text-sm text-amber-300" role="alert">
          Integrity status unavailable ({statusError}) — lists below keep their own state.
        </p>
      )}
      {status?.store_error && (
        <p className="text-sm text-amber-300" role="alert">
          Monitoring store: {status.store_error}
        </p>
      )}

      <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-200">
        <span className="font-semibold">Assurance boundary:</span> {externalAnchor}.{" "}
        {trust?.external_anchor_detail ??
          "No external transparency provider is configured; all verification is local."}
      </div>

      <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
        <Metric
          label="Latest audit"
          value={latest ? latest.status : "—"}
          note={latest ? `${latest.trigger} · ${latest.started_at}` : "No audit has run yet"}
        />
        <Metric
          label="Last success"
          value={status?.last_success?.status ?? "—"}
          note={status?.last_success?.started_at ?? "No PASS audit recorded"}
        />
        <Metric label="Audits recorded" value={status?.total_audits ?? 0} note="Bounded retention applies" />
        <Metric
          label="Open findings"
          value={status?.open_findings ?? 0}
          note={`${status?.running_audits ?? 0} audit(s) running`}
        />
        <Metric label="Artifacts checked" value={status?.total_audited_artifacts ?? 0} />
        <Metric label="Verified evidence" value={status?.verified_evidence_count ?? 0} />
        <Metric label="Verified checkpoints" value={status?.verified_checkpoint_count ?? 0} />
        <Metric label="Verified tree heads" value={status?.verified_tree_head_count ?? 0} />
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="Trust overview">
          {!trust ? (
            <p className="text-sm text-slate-400" role="status">
              {statusLoading ? "Loading…" : "Trust material unavailable."}
            </p>
          ) : (
            <div className="space-y-2 text-xs">
              <div className="flex flex-wrap gap-1">
                <span className="rounded bg-slate-800 px-2 py-0.5 text-slate-300">
                  trusted keys: {trust.trusted_key_count}
                </span>
                <span className="rounded bg-slate-800 px-2 py-0.5 text-slate-300">
                  active: {trust.active_key_count}
                </span>
                <span className="rounded bg-slate-800 px-2 py-0.5 text-slate-300">
                  expired: {trust.expired_key_count}
                </span>
                <span className="rounded bg-slate-800 px-2 py-0.5 text-slate-300">
                  revoked: {trust.revoked_key_count}
                </span>
              </div>
              <p className="text-slate-400">
                Evidence trust state: {trust.evidence_trust_state} · Transparency trust state:{" "}
                {trust.transparency_trust_state}
              </p>
              <p className="text-slate-400">
                Latest tree head:{" "}
                {trust.latest_tree_head_size === null
                  ? "not available"
                  : `size ${trust.latest_tree_head_size} · ${trust.latest_tree_head_digest ?? "digest unavailable"}`}
              </p>
              <p className="text-slate-400">Assurance: {trust.assurance}</p>
              {trust.limitations.length > 0 && (
                <ul className="list-inside list-disc text-amber-300/90">
                  {trust.limitations.map((limitation) => (
                    <li key={limitation}>{limitation}</li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </Card>

        <Card title="Run a bounded audit">
          <p className="text-xs text-slate-400">
            Runs synchronously within the configured timeout. Scopes not configured are reported
            as unavailable — never as a pass.
          </p>
          <div className="mt-2 flex flex-wrap gap-1">
            <button
              onClick={() => toggleScope("FULL")}
              aria-pressed={selectedScopes.includes("FULL")}
              className={`rounded-full px-2 py-0.5 text-xs ${
                selectedScopes.includes("FULL")
                  ? "bg-sky-600 text-white"
                  : "bg-slate-800 text-slate-300"
              }`}
            >
              FULL
            </button>
            {SCOPES.map((scope) => (
              <button
                key={scope}
                onClick={() => toggleScope(scope)}
                aria-pressed={selectedScopes.includes(scope)}
                className={`rounded-full px-2 py-0.5 text-xs ${
                  selectedScopes.includes(scope)
                    ? "bg-sky-600 text-white"
                    : "bg-slate-800 text-slate-300"
                }`}
              >
                {scope}
              </button>
            ))}
          </div>
          {canRun ? (
            <button
              onClick={() => void runAudit()}
              disabled={running}
              className="mt-3 rounded-lg bg-emerald-700 px-3 py-1.5 text-sm hover:bg-emerald-600 disabled:opacity-40"
            >
              {running ? "Running…" : "Run audit"}
            </button>
          ) : (
            <p className="mt-3 text-xs text-slate-500">
              Starting an audit requires the ADMIN or OPERATOR role.
            </p>
          )}
          {runError && (
            <p className="mt-2 text-sm text-red-300" role="alert">
              {runError}
            </p>
          )}
          {runResult && (
            <div className="mt-2 rounded-lg border border-slate-800 px-2 py-1 text-xs">
              <p className="flex items-center gap-2">
                Result: <StatusPill status={runResult.status} />
                <span className="text-slate-500">
                  {runResult.artifacts_checked} artifact(s) · {runResult.duration_ms} ms
                </span>
              </p>
              {runResult.status !== "PASS" && (
                <p className="mt-1 text-amber-300/90">
                  Not a clean pass — inspect the scope results and findings below.
                </p>
              )}
            </div>
          )}
        </Card>
      </div>

      <Card title={`Findings (${findingsTotal})`}>
        <div className="mb-2 flex flex-wrap gap-2 text-xs">
          <label className="text-slate-400">
            Severity{" "}
            <select
              value={severity}
              onChange={(e) => {
                setSeverity(e.target.value);
                setFindingsPage(1);
              }}
              className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-slate-200"
              aria-label="finding severity filter"
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
            Scope{" "}
            <select
              value={findingScope}
              onChange={(e) => {
                setFindingScope(e.target.value);
                setFindingsPage(1);
              }}
              className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-slate-200"
              aria-label="finding scope filter"
            >
              <option value="">all</option>
              {SCOPES.map((scope) => (
                <option key={scope} value={scope}>
                  {scope}
                </option>
              ))}
            </select>
          </label>
          <label className="text-slate-400">
            Reason{" "}
            <input
              value={reasonCode}
              onChange={(e) => {
                setReasonCode(e.target.value);
                setFindingsPage(1);
              }}
              placeholder="EVIDENCE_MISSING"
              className="w-44 rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-slate-200"
              aria-label="finding reason filter"
            />
          </label>
        </div>
        <DataState
          state={
            findingsError
              ? "error"
              : findingsLoading && findings.length === 0
                ? "loading"
                : findingsTotal === 0
                  ? "empty"
                  : "ready"
          }
          emptyText="No findings recorded — genuine quiet, not missing data."
          error={findingsError}
        >
          <ul className="space-y-1">
            {findings.map((finding) => (
              <FindingRow key={finding.finding_id} finding={finding} />
            ))}
          </ul>
          <div className="mt-2 flex items-center gap-2 text-xs text-slate-400">
            <button
              disabled={findingsPage <= 1}
              onClick={() => setFindingsPage((page) => Math.max(1, page - 1))}
              className="rounded-lg bg-slate-800 px-2 py-1 disabled:opacity-40"
            >
              Prev
            </button>
            <span>
              Page {findingsPage} · {findingsTotal} total
            </span>
            <button
              disabled={findingsPage * PAGE_SIZE >= findingsTotal}
              onClick={() => setFindingsPage((page) => page + 1)}
              className="rounded-lg bg-slate-800 px-2 py-1 disabled:opacity-40"
            >
              Next
            </button>
          </div>
        </DataState>
      </Card>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card title={`Audit history (${auditsTotal})`}>
          <label className="text-xs text-slate-400">
            Status{" "}
            <select
              value={auditStatus}
              onChange={(e) => {
                setAuditStatus(e.target.value);
                setAuditsPage(1);
              }}
              className="mb-2 rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-slate-200"
              aria-label="audit status filter"
            >
              <option value="">all</option>
              {STATUSES.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </label>
          <DataState
            state={
              auditsError
                ? "error"
                : auditsLoading && audits.length === 0
                  ? "loading"
                  : auditsTotal === 0
                    ? "empty"
                    : "ready"
            }
            emptyText="No audits recorded yet. Run one above or enable the scheduler."
            error={auditsError}
          >
            <ul className="space-y-1">
              {audits.map((audit) => (
                <AuditRow
                  key={audit.audit_run_id}
                  audit={audit}
                  selected={selectedAuditId === audit.audit_run_id}
                  onSelect={() => setSelectedAuditId(audit.audit_run_id)}
                />
              ))}
            </ul>
            <div className="mt-2 flex items-center gap-2 text-xs text-slate-400">
              <button
                disabled={auditsPage <= 1}
                onClick={() => setAuditsPage((page) => Math.max(1, page - 1))}
                className="rounded-lg bg-slate-800 px-2 py-1 disabled:opacity-40"
              >
                Prev
              </button>
              <span>
                Page {auditsPage} · {auditsTotal} total
              </span>
              <button
                disabled={auditsPage * PAGE_SIZE >= auditsTotal}
                onClick={() => setAuditsPage((page) => page + 1)}
                className="rounded-lg bg-slate-800 px-2 py-1 disabled:opacity-40"
              >
                Next
              </button>
            </div>
          </DataState>
        </Card>

        <Card title="Audit detail">
          {!selectedAuditId ? (
            <p className="text-sm text-slate-400">Select an audit to inspect scope results.</p>
          ) : detailError ? (
            <p className="text-sm text-amber-300" role="alert">
              {detailError}
            </p>
          ) : !auditDetail ? (
            <p className="text-sm text-slate-400" role="status">
              Loading…
            </p>
          ) : (
            <div className="space-y-2 text-xs">
              <div className="flex flex-wrap items-center gap-2">
                <StatusPill status={auditDetail.audit.status} />
                <span className="text-slate-400">
                  {auditDetail.audit.trigger} · {auditDetail.audit.started_at}
                </span>
                <span className="text-slate-500">
                  assurance {auditDetail.audit.assurance} · external anchor{" "}
                  {auditDetail.audit.external_anchor_configured ? "configured" : "not configured"}
                </span>
              </div>
              {auditDetail.audit.error_summary && (
                <p className="text-amber-300/90">{auditDetail.audit.error_summary}</p>
              )}
              <ul className="space-y-1">
                {auditDetail.scope_results.map((result) => (
                  <ScopeResultRow key={result.scope} result={result} />
                ))}
              </ul>
              {auditDetail.findings_total > 0 && (
                <div>
                  <p className="mb-1 font-medium text-slate-300">
                    Findings in this run ({auditDetail.findings_total})
                  </p>
                  <ul className="space-y-1">
                    {auditDetail.findings.map((finding) => (
                      <FindingRow key={finding.finding_id} finding={finding} />
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
