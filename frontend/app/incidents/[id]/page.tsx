"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { Card } from "../../../components/ui/Card";
import { PriorityBadge, RiskBadge } from "../../../components/intelligence/RiskBadge";
import { appConfig } from "../../../lib/config";
import type { IncidentDetail, IncidentPriority } from "../../../types";

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${appConfig.apiUrl}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    let detail = `${path} → ${res.status}`;
    try {
      const body = (await res.json()) as {
        error?: {
          message?: string;
          code?: string;
          details?: { current_status?: string; attempted_status?: string };
        };
        detail?: unknown;
      };
      if (body?.error?.message) {
        detail = `${body.error.code ?? res.status}: ${body.error.message}`;
        const d = body.error.details;
        if (d?.current_status) detail += ` (${d.current_status} → ${d.attempted_status})`;
      } else if (typeof body?.detail === "string") detail = body.detail;
    } catch {
      /* keep the status fallback */
    }
    throw new Error(detail);
  }
  return (await res.json()) as T;
}

const RESOLUTIONS = [
  "FALSE_ALARM",
  "HAZARD_REMOVED",
  "OPERATOR_ACTION",
  "AUTOMATIC_CLEAR",
  "QUALITY_REWORKED",
  "OTHER",
];
const NOTE_KINDS = ["NOTE", "FINDING", "ACTION", "OBSERVATION"];
const EVIDENCE_TYPES = ["FRAME", "IMAGE", "VIDEO", "SNAPSHOT", "LINK", "OTHER"];
const PRIORITIES: IncidentPriority[] = ["P0", "P1", "P2", "P3", "P4"];

const btn =
  "rounded-lg bg-slate-800 px-3 py-1.5 text-sm hover:bg-slate-700 disabled:opacity-40";
const input =
  "mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm text-slate-200";

/**
 * Incident detail — V10.
 *
 * Summary, risk, timeline, linked events, evidence, and assignment.
 * Every action button is gated by the backend's `allowed_actions`
 * (single source of truth — the UI never second-guesses the state machine).
 */
export default function IncidentDetailPage({ params }: { params: { id: string } }) {
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [actor, setActor] = useState("operator");
  const [reason, setReason] = useState("");
  const [assignee, setAssignee] = useState("");
  const [note, setNote] = useState("");
  const [noteKind, setNoteKind] = useState("NOTE");
  const [resolution, setResolution] = useState(RESOLUTIONS[0]);
  const [closureReason, setClosureReason] = useState("");
  const [escalateTo, setEscalateTo] = useState<IncidentPriority>("P1");
  const [escalateReason, setEscalateReason] = useState("");
  const [editTitle, setEditTitle] = useState("");
  const [editDescription, setEditDescription] = useState("");
  const [evidenceUri, setEvidenceUri] = useState("");
  const [evidenceType, setEvidenceType] = useState("FRAME");
  const [evidenceFrame, setEvidenceFrame] = useState("");

  const refresh = useCallback(async () => {
    try {
      const d = await api<IncidentDetail>(`/api/v1/incidents/${params.id}`);
      setDetail(d);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "API unreachable");
    }
  }, [params.id]);

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), 10000);
    return () => clearInterval(timer);
  }, [refresh]);

  useEffect(() => {
    if (detail) {
      setEditTitle(detail.incident.title);
      setEditDescription(detail.incident.description ?? "");
    }
  }, [detail?.incident.id]); // eslint-disable-line react-hooks/exhaustive-deps

  const run = async (path: string, payload: Record<string, unknown>) => {
    setBusy(true);
    setActionError(null);
    try {
      await api(`/api/v1/incidents/${params.id}${path}`, {
        method: "POST",
        body: JSON.stringify({ actor_id: actor.trim() || null, ...payload }),
      });
      setReason("");
      await refresh();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Action failed");
    } finally {
      setBusy(false);
    }
  };

  const can = (action: string) => detail?.allowed_actions.includes(action) ?? false;
  const incident = detail?.incident;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-bold">
          <Link href="/incidents" className="text-sky-400 hover:underline">
            Incidents
          </Link>
          {incident ? ` / ${incident.incident_number}` : " / …"}
        </h1>
        <button onClick={() => void refresh()} className={btn}>
          Refresh
        </button>
      </div>
      {error && (
        <p className="text-sm text-amber-300">API unreachable ({error}) — start the backend on :8000.</p>
      )}
      {actionError && <p className="text-sm text-red-300">{actionError}</p>}

      <Card title="Summary">
        {incident ? (
          <div className="space-y-2">
            <p className="text-base font-medium">{incident.title}</p>
            {incident.description && <p className="text-sm text-slate-400">{incident.description}</p>}
            <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
              <RiskBadge level={incident.risk_level} score={incident.risk_score} />
              <PriorityBadge priority={incident.priority} />
              <span className="rounded-full bg-slate-800 px-2 py-0.5">{incident.status}</span>
              <span>{incident.category}</span>
              <span>{incident.source}</span>
              <span>camera: {incident.camera_id}</span>
              {incident.assigned_to && <span>→ {incident.assigned_to}</span>}
            </div>
            <div className="grid gap-1 text-xs text-slate-500 md:grid-cols-2">
              <span>First seen: {incident.first_seen}</span>
              <span>Last seen: {incident.last_seen}</span>
              <span>Acknowledged: {incident.acknowledged_at ?? "—"}</span>
              <span>Resolved: {incident.resolved_at ?? "—"}</span>
              <span>Closed: {incident.closed_at ?? "—"}</span>
              <span>Cluster: {incident.source_cluster_id ?? "—"}</span>
            </div>
            <div className="text-xs text-slate-500">
              Risk: {detail?.risk_summary.risk_level} ({detail?.risk_summary.risk_score}) · severity{" "}
              {detail?.risk_summary.severity}
            </div>
          </div>
        ) : (
          <p className="text-sm text-slate-400">Loading…</p>
        )}
      </Card>

      {detail && (
        <Card title="Actions">
          <div className="mb-2 flex items-center gap-2 text-xs text-slate-400">
            <label>
              Actor
              <input
                value={actor}
                onChange={(e) => setActor(e.target.value)}
                className="ml-1 w-32 rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-sm text-slate-200"
                placeholder="operator"
              />
            </label>
          </div>
          <div className="flex flex-wrap gap-2">
            {can("acknowledge") && (
              <button disabled={busy} onClick={() => void run("/acknowledge", { reason })} className={btn}>
                Acknowledge
              </button>
            )}
            {can("investigate") && (
              <button disabled={busy} onClick={() => void run("/investigate", { reason })} className={btn}>
                Start investigating
              </button>
            )}
            {can("mitigate") && (
              <button
                disabled={busy || !reason.trim()}
                title="Mitigation requires a reason"
                onClick={() => void run("/mitigate", { reason })}
                className={btn}
              >
                Mitigate
              </button>
            )}
            {can("resolve") && (
              <span className="flex items-center gap-1">
                <select
                  value={resolution}
                  onChange={(e) => setResolution(e.target.value)}
                  className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm"
                >
                  {RESOLUTIONS.map((r) => (
                    <option key={r} value={r}>
                      {r}
                    </option>
                  ))}
                </select>
                <button
                  disabled={busy}
                  onClick={() => void run("/resolve", { reason: resolution, detail: reason })}
                  className={btn}
                >
                  Resolve
                </button>
              </span>
            )}
            {(can("acknowledge") || can("investigate") || can("mitigate")) && (
              <input
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="reason / detail (optional, required for mitigate)"
                className="min-w-64 flex-1 rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm"
              />
            )}
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            {can("assign") && (
              <span className="flex items-center gap-1">
                <input
                  value={assignee}
                  onChange={(e) => setAssignee(e.target.value)}
                  placeholder="assignee"
                  className="w-36 rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm"
                />
                <button
                  disabled={busy || !assignee.trim()}
                  onClick={() => void run("/assign", { assignee: assignee.trim() })}
                  className={btn}
                >
                  Assign
                </button>
              </span>
            )}
            {can("unassign") && (
              <button disabled={busy} onClick={() => void run("/unassign", {})} className={btn}>
                Unassign
              </button>
            )}
            {can("escalate") && (
              <span className="flex items-center gap-1">
                <select
                  value={escalateTo}
                  onChange={(e) => setEscalateTo(e.target.value as IncidentPriority)}
                  className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm"
                >
                  {PRIORITIES.map((p) => (
                    <option key={p} value={p}>
                      {p}
                    </option>
                  ))}
                </select>
                <input
                  value={escalateReason}
                  onChange={(e) => setEscalateReason(e.target.value)}
                  placeholder="escalation reason (required)"
                  className="w-52 rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm"
                />
                <button
                  disabled={busy || !escalateReason.trim()}
                  onClick={() =>
                    void run("/escalate", {
                      priority: escalateTo,
                      reason: escalateReason.trim(),
                    }).then(() => setEscalateReason(""))
                  }
                  className={btn}
                >
                  Escalate
                </button>
              </span>
            )}
          </div>
          {can("close") && incident?.status === "RESOLVED" && (
            <div className="mt-2 flex items-center gap-2">
              <input
                value={closureReason}
                onChange={(e) => setClosureReason(e.target.value)}
                placeholder="closure reason (required, terminal)"
                className="min-w-64 flex-1 rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm"
              />
              <button
                disabled={busy || !closureReason.trim()}
                onClick={() =>
                  void run("/close", { closure_reason: closureReason.trim() }).then(() =>
                    setClosureReason("")
                  )
                }
                className="rounded-lg bg-red-800 px-3 py-1.5 text-sm hover:bg-red-700 disabled:opacity-40"
              >
                Close (terminal)
              </button>
            </div>
          )}
          {!detail.allowed_actions.length && (
            <p className="text-xs text-slate-500">Closed — no further actions available.</p>
          )}
        </Card>
      )}

      {detail && can("note") && (
        <Card title="Add note">
          <div className="flex flex-wrap items-center gap-2">
            <input
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="note message"
              className="min-w-64 flex-1 rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm"
            />
            <select
              value={noteKind}
              onChange={(e) => setNoteKind(e.target.value)}
              className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm"
            >
              {NOTE_KINDS.map((k) => (
                <option key={k} value={k}>
                  {k}
                </option>
              ))}
            </select>
            <button
              disabled={busy || !note.trim()}
              onClick={() =>
                void run("/notes", { message: note.trim(), kind: noteKind }).then(() => setNote(""))
              }
              className={btn}
            >
              Add
            </button>
          </div>
        </Card>
      )}

      {detail && (
        <Card title="Edit details">
          <div className="grid gap-2">
            <label className="text-xs text-slate-400">
              Title
              <input value={editTitle} onChange={(e) => setEditTitle(e.target.value)} className={input} />
            </label>
            <label className="text-xs text-slate-400">
              Description
              <textarea
                value={editDescription}
                onChange={(e) => setEditDescription(e.target.value)}
                className={input}
                rows={2}
              />
            </label>
            <div>
              <button
                disabled={busy || !editTitle.trim()}
                onClick={() => {
                  setBusy(true);
                  setActionError(null);
                  api(`/api/v1/incidents/${params.id}`, {
                    method: "PATCH",
                    body: JSON.stringify({ title: editTitle.trim(), description: editDescription }),
                  })
                    .then(() => refresh())
                    .catch((e: unknown) =>
                      setActionError(e instanceof Error ? e.message : "Patch failed")
                    )
                    .finally(() => setBusy(false));
                }}
                className={btn}
              >
                Save
              </button>
            </div>
          </div>
        </Card>
      )}

      <Card title={`Timeline (${detail?.timeline.length ?? 0})`}>
        {!detail ? (
          <p className="text-sm text-slate-400">Loading…</p>
        ) : detail.timeline.length === 0 ? (
          <p className="text-sm text-slate-400">No timeline entries.</p>
        ) : (
          <ol className="space-y-1">
            {detail.timeline.map((t) => (
              <li key={t.id} className="rounded-lg border border-slate-800 px-2 py-1 text-xs">
                <span className="font-medium text-slate-200">{t.event_type}</span>
                <span className="text-slate-400"> · {t.message}</span>
                <span className="block text-slate-500">
                  {t.timestamp} · {t.actor_type}:{t.actor_id ?? "—"}
                  {t.previous_state ? ` · ${t.previous_state} → ${t.new_state ?? "—"}` : ""}
                </span>
              </li>
            ))}
          </ol>
        )}
      </Card>

      <Card title={`Linked events (${detail?.linked_events.length ?? 0})`}>
        {!detail?.linked_events.length ? (
          <p className="text-sm text-slate-400">
            {detail ? "No linked V09 events (manual incident)." : "Loading…"}
          </p>
        ) : (
          <ul className="space-y-1 text-xs">
            {detail.linked_events.map((e) => (
              <li key={e.event_id} className="rounded-lg border border-slate-800 px-2 py-1">
                <span className="font-medium text-slate-200">{e.event_type}</span>
                <span className="text-slate-400">
                  {" "}
                  · {e.source_domain}
                  {e.is_primary ? " · primary" : ""} · {e.created_at}
                </span>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card title={`Evidence (${detail?.evidence.length ?? 0})`}>
        {detail && detail.evidence.length > 0 && (
          <ul className="mb-2 space-y-1 text-xs">
            {detail.evidence.map((e) => (
              <li
                key={e.id}
                className="flex items-center justify-between gap-2 rounded-lg border border-slate-800 px-2 py-1"
              >
                <span>
                  <span className="font-medium text-slate-200">{e.evidence_type}</span>
                  <span className="text-slate-400"> · {e.uri}</span>
                  {e.frame_id && <span className="text-slate-500"> · frame {e.frame_id}</span>}
                </span>
                <button
                  disabled={busy}
                  onClick={() => {
                    setBusy(true);
                    setActionError(null);
                    api(`/api/v1/incidents/${params.id}/evidence/${e.id}`, { method: "DELETE" })
                      .then(() => refresh())
                      .catch((err: unknown) =>
                        setActionError(err instanceof Error ? err.message : "Delete failed")
                      )
                      .finally(() => setBusy(false));
                  }}
                  className="rounded bg-slate-800 px-2 py-0.5 hover:bg-red-800"
                >
                  Delete
                </button>
              </li>
            ))}
          </ul>
        )}
        {detail && can("evidence") && (
          <div className="flex flex-wrap items-center gap-2">
            <select
              value={evidenceType}
              onChange={(e) => setEvidenceType(e.target.value)}
              className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm"
            >
              {EVIDENCE_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
            <input
              value={evidenceUri}
              onChange={(e) => setEvidenceUri(e.target.value)}
              placeholder="uri (required)"
              className="min-w-48 flex-1 rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm"
            />
            <input
              value={evidenceFrame}
              onChange={(e) => setEvidenceFrame(e.target.value)}
              placeholder="frame_id (optional)"
              className="w-36 rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm"
            />
            <button
              disabled={busy || !evidenceUri.trim()}
              onClick={() => {
                setBusy(true);
                setActionError(null);
                api(`/api/v1/incidents/${params.id}/evidence`, {
                  method: "POST",
                  body: JSON.stringify({
                    evidence_type: evidenceType,
                    uri: evidenceUri.trim(),
                    frame_id: evidenceFrame.trim() || null,
                  }),
                })
                  .then(() => {
                    setEvidenceUri("");
                    setEvidenceFrame("");
                    return refresh();
                  })
                  .catch((err: unknown) =>
                    setActionError(err instanceof Error ? err.message : "Add failed")
                  )
                  .finally(() => setBusy(false));
              }}
              className={btn}
            >
              Add evidence
            </button>
          </div>
        )}
        {!detail && <p className="text-sm text-slate-400">Loading…</p>}
      </Card>

      {detail && (
        <Card title="Assignment history">
          {detail.assignment.history.length === 0 ? (
            <p className="text-sm text-slate-400">Never assigned.</p>
          ) : (
            <ul className="space-y-1 text-xs text-slate-400">
              {detail.assignment.history.map((h, i) => (
                <li key={i}>
                  {h.previous_assignee ?? "—"} → {h.assignee ?? "—"} · {h.actor_id ?? "system"} ·{" "}
                  {h.timestamp}
                </li>
              ))}
            </ul>
          )}
        </Card>
      )}
    </div>
  );
}
