"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { Card } from "../../components/ui/Card";
import { DataState, SectionBadge } from "../../components/operations/primitives";
import { useOperationsSocket } from "../../lib/websocket/useOperationsSocket";
import { useAuth } from "../../components/auth/AuthProvider";
import {
  createRule,
  emptyRuleForm,
  fetchAlertingStatus,
  fetchNotificationDetail,
  fetchNotifications,
  fetchRules,
  patchRule,
  retryDelivery,
  validateRuleForm,
  type RuleForm,
} from "../../lib/alerting/client";
import type {
  AlertRule,
  AlertingStatus,
  DeliveryItem,
  NotificationDetail,
  NotificationItem,
} from "../../types";

const DOMAINS = ["SAFETY", "SPATIAL", "QUALITY", "AUTONOMOUS", "INTELLIGENCE", "INCIDENT"];
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const STATUSES = ["OPEN", "ACKNOWLEDGED", "INVESTIGATING", "MITIGATED", "RESOLVED", "CLOSED"];
const CHANNELS = ["in_app", "email", "webhook"];

function toggle(list: string[], value: string): string[] {
  return list.includes(value) ? list.filter((v) => v !== value) : [...list, value];
}

function DeliveryBadge({ status }: { status: string }) {
  const style =
    status === "sent"
      ? "bg-emerald-500/15 text-emerald-300"
      : status === "failed"
        ? "bg-red-500/15 text-red-300"
        : "bg-amber-500/15 text-amber-300";
  return (
    <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${style}`}>{status}</span>
  );
}

const NOTIFICATION_TYPES = new Set(["notification_created"]);

/**
 * Notifications & alert rules — V15.
 *
 * System-wide notification history (no per-user inbox; V16 owns identity).
 * REST is authoritative; the shared operations socket applies increments.
 */
export default function NotificationsPage() {
  const { getTicket } = useAuth();
  const [tab, setTab] = useState<"notifications" | "rules" | "status">("notifications");
  const [status, setStatus] = useState<AlertingStatus | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);

  const [items, setItems] = useState<NotificationItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [severity, setSeverity] = useState("");
  const [domain, setDomain] = useState("");
  const [cameraId, setCameraId] = useState("");
  const [listError, setListError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<NotificationDetail | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [retrying, setRetrying] = useState<string | null>(null);
  const [retryError, setRetryError] = useState<string | null>(null);

  const [rules, setRules] = useState<AlertRule[]>([]);
  const [rulesTotal, setRulesTotal] = useState(0);
  const [rulesError, setRulesError] = useState<string | null>(null);
  const [formOpen, setFormOpen] = useState(false);
  const [form, setForm] = useState<RuleForm>(emptyRuleForm());
  const [formError, setFormError] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);

  const refreshStatus = useCallback(async () => {
    try {
      setStatus(await fetchAlertingStatus());
      setStatusError(null);
    } catch (e) {
      setStatusError(e instanceof Error ? e.message : "API unreachable");
    }
  }, []);

  const refreshList = useCallback(async () => {
    try {
      const body = await fetchNotifications({
        severity: severity || undefined,
        domain: domain || undefined,
        camera_id: cameraId.trim() || undefined,
        page,
        page_size: 20,
      });
      setItems(body.notifications);
      setTotal(body.total);
      setListError(null);
    } catch (e) {
      setListError(e instanceof Error ? e.message : "API unreachable");
    }
  }, [severity, domain, cameraId, page]);

  const refreshRules = useCallback(async () => {
    try {
      const body = await fetchRules(1);
      setRules(body.rules);
      setRulesTotal(body.total);
      setRulesError(null);
    } catch (e) {
      setRulesError(e instanceof Error ? e.message : "API unreachable");
    }
  }, []);

  const refreshDetail = useCallback(async (id: string) => {
    try {
      setDetail(await fetchNotificationDetail(id));
      setDetailError(null);
    } catch (e) {
      setDetailError(e instanceof Error ? e.message : "API unreachable");
    }
  }, []);

  useEffect(() => {
    void refreshStatus();
    void refreshList();
    void refreshRules();
    const timer = setInterval(() => {
      void refreshStatus();
      void refreshList();
      void refreshRules();
    }, 15000);
    return () => clearInterval(timer);
  }, [refreshStatus, refreshList, refreshRules]);

  useEffect(() => {
    if (selectedId) void refreshDetail(selectedId);
    else setDetail(null);
  }, [selectedId, refreshDetail]);

  const handleSocketMessage = useCallback(
    (message: { type?: string; event_type?: string }) => {
      const kind = String(message.type ?? message.event_type ?? "");
      if (kind === "notification_created") {
        void refreshList();
        if (selectedId) void refreshDetail(selectedId);
      }
    },
    [refreshList, refreshDetail, selectedId]
  );
  const handlerRef = useRef(handleSocketMessage);
  handlerRef.current = handleSocketMessage;
  const stableHandler = useCallback(
    (message: { type?: string; event_type?: string }) => handlerRef.current(message),
    []
  );
  const feedStatus = useOperationsSocket(true, NOTIFICATION_TYPES, stableHandler, getTicket);

  const submitRule = async () => {
    const problem = validateRuleForm(form);
    if (problem) {
      setFormError(problem);
      return;
    }
    setFormError(null);
    try {
      if (editingId) {
        await patchRule(editingId, {
          name: form.name.trim(),
          description: form.description,
          enabled: form.enabled,
          domains: form.domains,
          event_types: form.event_types,
          min_severity: form.min_severity || null,
          min_priority: form.min_priority || null,
          camera_ids: form.camera_ids
            .split(",")
            .map((part) => part.trim())
            .filter(Boolean),
          incident_statuses: form.incident_statuses,
          channels: form.channels,
          cooldown_seconds: form.cooldown_seconds,
        });
      } else {
        await createRule(form);
      }
      setForm(emptyRuleForm());
      setEditingId(null);
      setFormOpen(false);
      await refreshRules();
    } catch (e) {
      setFormError(e instanceof Error ? e.message : "Save failed");
    }
  };

  const doRetry = async (delivery: DeliveryItem) => {
    setRetrying(delivery.id);
    setRetryError(null);
    try {
      await retryDelivery(delivery.id);
      if (selectedId) await refreshDetail(selectedId);
    } catch (e) {
      setRetryError(e instanceof Error ? e.message : "Retry failed");
    } finally {
      setRetrying(null);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="text-lg font-bold">Notifications & Alert Rules</h1>
          <p className="text-xs text-slate-400">
            System-wide notification history. No per-user inbox — identity arrives with V16.
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <SectionBadge state={status?.enabled ? "ok" : "degraded"} label={status?.enabled ? "alerting on" : "alerting off"} />
          <span
            className={`rounded-full px-2 py-0.5 ${
              feedStatus === "live"
                ? "bg-emerald-500/15 text-emerald-300"
                : "bg-slate-500/15 text-slate-400"
            }`}
            role="status"
            aria-label={`event stream: ${feedStatus}`}
          >
            stream: {feedStatus}
          </span>
          <button
            onClick={() => {
              void refreshStatus();
              void refreshList();
              void refreshRules();
            }}
            className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm hover:bg-slate-700"
          >
            Refresh
          </button>
        </div>
      </div>

      {statusError && (
        <p className="text-sm text-amber-300">
          Status unavailable ({statusError}) — lists below keep their own state.
        </p>
      )}

      <div className="flex gap-2" role="tablist" aria-label="notifications views">
        {(["notifications", "rules", "status"] as const).map((name) => (
          <button
            key={name}
            role="tab"
            aria-selected={tab === name}
            onClick={() => setTab(name)}
            className={`rounded-lg px-3 py-1.5 text-sm capitalize ${
              tab === name ? "bg-sky-600 text-white" : "bg-slate-800 text-slate-300 hover:bg-slate-700"
            }`}
          >
            {name}
          </button>
        ))}
      </div>

      {tab === "notifications" && (
        <div className="grid gap-4 xl:grid-cols-2">
          <Card title={`Notifications (${total})`}>
            <div className="mb-2 flex flex-wrap gap-2 text-xs">
              <label className="text-slate-400">
                Severity{" "}
                <select
                  value={severity}
                  onChange={(e) => {
                    setSeverity(e.target.value);
                    setPage(1);
                  }}
                  className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-slate-200"
                  aria-label="severity filter"
                >
                  <option value="">all</option>
                  {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </select>
              </label>
              <label className="text-slate-400">
                Domain{" "}
                <select
                  value={domain}
                  onChange={(e) => {
                    setDomain(e.target.value);
                    setPage(1);
                  }}
                  className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-slate-200"
                  aria-label="domain filter"
                >
                  <option value="">all</option>
                  {["SAFETY", "SPATIAL", "QUALITY", "AUTONOMOUS", "INTELLIGENCE", "INCIDENT"].map(
                    (d) => (
                      <option key={d} value={d}>
                        {d}
                      </option>
                    )
                  )}
                </select>
              </label>
              <label className="text-slate-400">
                Camera{" "}
                <input
                  value={cameraId}
                  onChange={(e) => {
                    setCameraId(e.target.value);
                    setPage(1);
                  }}
                  placeholder="camera_id"
                  className="w-32 rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-slate-200"
                  aria-label="camera filter"
                />
              </label>
            </div>
            <DataState
              state={listError ? "error" : items.length === 0 && total === 0 ? "empty" : "ready"}
              emptyText="No notifications yet — genuine quiet, not missing data."
              error={listError}
            >
              <ul className="space-y-1">
                {items.map((item) => (
                  <li key={item.id}>
                    <button
                      onClick={() => setSelectedId(item.id)}
                      aria-pressed={selectedId === item.id}
                      className={`flex w-full flex-wrap items-center justify-between gap-2 rounded-lg border px-2 py-1 text-left text-xs ${
                        selectedId === item.id
                          ? "border-sky-600 bg-slate-800"
                          : "border-slate-800 bg-slate-900/60 hover:bg-slate-800/60"
                      }`}
                    >
                      <span className="font-medium text-slate-200">{item.title}</span>
                      <span className="flex items-center gap-2 text-slate-400">
                        <span>{item.severity}</span>
                        <span>{item.event_type}</span>
                        <span>{item.camera_id ?? "—"}</span>
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
              <div className="mt-2 flex items-center gap-2 text-xs text-slate-400">
                <button
                  disabled={page <= 1}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  className="rounded-lg bg-slate-800 px-2 py-1 disabled:opacity-40"
                >
                  Prev
                </button>
                <span>
                  Page {page} · {total} total
                </span>
                <button
                  disabled={page * 20 >= total}
                  onClick={() => setPage((p) => p + 1)}
                  className="rounded-lg bg-slate-800 px-2 py-1 disabled:opacity-40"
                >
                  Next
                </button>
              </div>
            </DataState>
          </Card>

          <Card title="Notification detail">
            {!selectedId ? (
              <p className="text-sm text-slate-400">Select a notification to inspect deliveries.</p>
            ) : detailError ? (
              <p className="text-sm text-amber-300" role="alert">
                {detailError}
              </p>
            ) : !detail ? (
              <p className="text-sm text-slate-400">Loading…</p>
            ) : (
              <div className="space-y-2 text-xs">
                <p className="text-sm font-medium text-slate-200">{detail.message}</p>
                <p className="text-slate-400">
                  Rule {detail.rule_id} · {detail.created_at ?? "time unknown"}
                  {detail.incident_id && (
                    <>
                      {" · "}
                      <Link
                        href={`/incidents/${detail.incident_id}`}
                        className="text-sky-400 hover:underline"
                      >
                        Open incident
                      </Link>
                    </>
                  )}
                </p>
                {retryError && (
                  <p className="text-red-300" role="alert">
                    {retryError}
                  </p>
                )}
                <ul className="space-y-1">
                  {detail.deliveries.map((delivery) => (
                    <li
                      key={delivery.id}
                      className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-800 px-2 py-1"
                    >
                      <span>
                        <span className="font-medium text-slate-200">{delivery.channel}</span>
                        <span className="text-slate-500">
                          {" "}
                          · attempts {delivery.attempts}
                          {delivery.last_error ? ` · ${delivery.last_error}` : ""}
                          {delivery.delivered_at ? ` · delivered ${delivery.delivered_at}` : ""}
                          {delivery.next_retry_at && delivery.status === "pending"
                            ? ` · retry ${delivery.next_retry_at}`
                            : ""}
                        </span>
                      </span>
                      <span className="flex items-center gap-2">
                        <DeliveryBadge status={delivery.status} />
                        {delivery.status === "failed" && (
                          <button
                            disabled={retrying === delivery.id}
                            onClick={() => void doRetry(delivery)}
                            className="rounded bg-slate-800 px-2 py-0.5 disabled:opacity-40 hover:bg-slate-700"
                            aria-label={`Retry ${delivery.channel} delivery`}
                          >
                            {retrying === delivery.id ? "Retrying…" : "Retry"}
                          </button>
                        )}
                      </span>
                    </li>
                  ))}
                </ul>
                {detail.deliveries.length === 0 && (
                  <p className="text-slate-500">No delivery records yet.</p>
                )}
              </div>
            )}
          </Card>
        </div>
      )}

      {tab === "rules" && (
        <div className="grid gap-4 xl:grid-cols-2">
          <Card title={`Alert rules (${rulesTotal})`}>
            {rulesError ? (
              <p className="text-sm text-amber-300" role="alert">
                {rulesError}
              </p>
            ) : rules.length === 0 ? (
              <p className="text-sm text-slate-400">
                No rules yet. Create one to start receiving notifications — nothing sends until
                an operator enables a rule.
              </p>
            ) : (
              <ul className="space-y-1">
                {rules.map((rule) => (
                  <li
                    key={rule.id}
                    className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-800 px-2 py-1 text-xs"
                  >
                    <span>
                      <span className="font-medium text-slate-200">{rule.name}</span>{" "}
                      <span className="text-slate-500">
                        · {rule.enabled ? "enabled" : "disabled"} · {rule.channels.join(", ")} ·
                        fired {rule.trigger_count} · suppressed {rule.suppressed_count}
                      </span>
                    </span>
                    <span className="flex gap-1">
                      <button
                        onClick={() => {
                          setEditingId(rule.id);
                          setForm({
                            name: rule.name,
                            description: rule.description,
                            enabled: rule.enabled,
                            domains: rule.domains,
                            event_types: rule.event_types,
                            min_severity: rule.min_severity ?? "",
                            min_priority: rule.min_priority ?? "",
                            camera_ids: rule.camera_ids.join(", "),
                            incident_statuses: rule.incident_statuses,
                            channels: rule.channels,
                            cooldown_seconds: rule.cooldown_seconds,
                          });
                          setFormOpen(true);
                        }}
                        className="rounded bg-slate-800 px-2 py-0.5 hover:bg-slate-700"
                      >
                        Edit
                      </button>
                      <button
                        onClick={() =>
                          void patchRule(rule.id, { enabled: !rule.enabled }).then(
                            () => void refreshRules(),
                            (e: unknown) =>
                              setRulesError(e instanceof Error ? e.message : "Update failed")
                          )
                        }
                        className="rounded bg-slate-800 px-2 py-0.5 hover:bg-slate-700"
                        aria-label={`${rule.enabled ? "Disable" : "Enable"} rule ${rule.name}`}
                      >
                        {rule.enabled ? "Disable" : "Enable"}
                      </button>
                    </span>
                  </li>
                ))}
              </ul>
            )}
            <button
              onClick={() => {
                setEditingId(null);
                setForm({
                  name: "",
                  description: "",
                  enabled: true,
                  domains: [],
                  event_types: [],
                  min_severity: "",
                  min_priority: "",
                  camera_ids: "",
                  incident_statuses: [],
                  channels: ["in_app"],
                  cooldown_seconds: 0,
                });
                setFormError(null);
                setFormOpen((v) => !v);
              }}
              className="mt-2 rounded-lg bg-emerald-700 px-3 py-1.5 text-sm hover:bg-emerald-600"
            >
              {formOpen ? "Cancel" : "New rule"}
            </button>
          </Card>

          {formOpen && (
            <Card title={editingId ? "Edit rule" : "New rule"}>
              <div className="grid gap-2 text-xs">
                <label className="text-slate-400">
                  Name (required)
                  <input
                    value={form.name}
                    onChange={(e) => setForm({ ...form, name: e.target.value })}
                    className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm text-slate-200"
                    aria-label="rule name"
                  />
                </label>
                <label className="text-slate-400">
                  Description
                  <input
                    value={form.description}
                    onChange={(e) => setForm({ ...form, description: e.target.value })}
                    className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm text-slate-200"
                    aria-label="rule description"
                  />
                </label>
                <div>
                  <p className="text-slate-400">Domains (empty = all)</p>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {["SAFETY", "SPATIAL", "QUALITY", "AUTONOMOUS", "INTELLIGENCE", "INCIDENT"].map(
                      (d) => (
                        <button
                          key={d}
                          onClick={() => setForm({ ...form, domains: toggle(form.domains, d) })}
                          aria-pressed={form.domains.includes(d)}
                          className={`rounded-full px-2 py-0.5 ${
                            form.domains.includes(d)
                              ? "bg-sky-600 text-white"
                              : "bg-slate-800 text-slate-300"
                          }`}
                        >
                          {d}
                        </button>
                      )
                    )}
                  </div>
                </div>
                <label className="text-slate-400">
                  Event types, comma-separated (empty = all; unknown types rejected)
                  <input
                    value={form.event_types.join(", ")}
                    onChange={(e) =>
                      setForm({
                        ...form,
                        event_types: e.target.value.split(",").map((p) => p.trim()).filter(Boolean),
                      })
                    }
                    placeholder="CROWD_WARNING, RESOLVED"
                    className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm text-slate-200"
                    aria-label="event types"
                  />
                </label>
                <div className="flex gap-2">
                  <label className="text-slate-400">
                    Min severity{" "}
                    <select
                      value={form.min_severity}
                      onChange={(e) => setForm({ ...form, min_severity: e.target.value })}
                      className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-slate-200"
                      aria-label="minimum severity"
                    >
                      <option value="">none</option>
                      {["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].map((s) => (
                        <option key={s} value={s}>
                          {s}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="text-slate-400">
                    Min priority{" "}
                    <select
                      value={form.min_priority}
                      onChange={(e) => setForm({ ...form, min_priority: e.target.value })}
                      className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-slate-200"
                      aria-label="minimum priority"
                    >
                      <option value="">none</option>
                      {["P0", "P1", "P2", "P3", "P4"].map((p) => (
                        <option key={p} value={p}>
                          {p}
                        </option>
                      ))}
                    </select>
                  </label>
                </div>
                <label className="text-slate-400">
                  Cameras, comma-separated (empty = all)
                  <input
                    value={form.camera_ids}
                    onChange={(e) => setForm({ ...form, camera_ids: e.target.value })}
                    placeholder="cam-01, cam-02"
                    className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm text-slate-200"
                    aria-label="camera filter"
                  />
                </label>
                <div>
                  <p className="text-slate-400">Incident statuses (empty = n/a for events)</p>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {["OPEN", "ACKNOWLEDGED", "INVESTIGATING", "MITIGATED", "RESOLVED", "CLOSED"].map(
                      (s) => (
                        <button
                          key={s}
                          onClick={() =>
                            setForm({ ...form, incident_statuses: toggle(form.incident_statuses, s) })
                          }
                          aria-pressed={form.incident_statuses.includes(s)}
                          className={`rounded-full px-2 py-0.5 ${
                            form.incident_statuses.includes(s)
                              ? "bg-sky-600 text-white"
                              : "bg-slate-800 text-slate-300"
                          }`}
                        >
                          {s}
                        </button>
                      )
                    )}
                  </div>
                </div>
                <div>
                  <p className="text-slate-400">Channels (at least one)</p>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {["in_app", "email", "webhook"].map((c) => (
                      <button
                        key={c}
                        onClick={() => setForm({ ...form, channels: toggle(form.channels, c) })}
                        aria-pressed={form.channels.includes(c)}
                        className={`rounded-full px-2 py-0.5 ${
                          form.channels.includes(c)
                            ? "bg-sky-600 text-white"
                            : "bg-slate-800 text-slate-300"
                        }`}
                      >
                        {c}
                      </button>
                    ))}
                  </div>
                </div>
                <label className="text-slate-400">
                  Cooldown seconds (0 = none; suppressions are recorded, not silent)
                  <input
                    type="number"
                    min={0}
                    max={86400}
                    value={form.cooldown_seconds}
                    onChange={(e) =>
                      setForm({ ...form, cooldown_seconds: Number(e.target.value) || 0 })
                    }
                    className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm text-slate-200"
                    aria-label="cooldown seconds"
                  />
                </label>
                <label className="flex items-center gap-2 text-slate-300">
                  <input
                    type="checkbox"
                    checked={form.enabled}
                    onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
                    aria-label="rule enabled"
                  />
                  Enabled
                </label>
              </div>
              {formError && (
                <p className="mt-2 text-sm text-red-300" role="alert">
                  {formError}
                </p>
              )}
              <button
                onClick={() => void submitRule()}
                className="mt-3 rounded-lg bg-emerald-700 px-3 py-1.5 text-sm hover:bg-emerald-600"
              >
                {editingId ? "Save changes" : "Create rule"}
              </button>
            </Card>
          )}
        </div>
      )}

      {tab === "status" && (
        <Card title="Alerting engine status">
          {!status ? (
            <p className="text-sm text-slate-400">Loading…</p>
          ) : (
            <div className="space-y-2 text-sm">
              <p>
                Engine:{" "}
                <span className={status.enabled ? "text-emerald-300" : "text-slate-400"}>
                  {status.enabled ? "enabled" : "disabled"}
                </span>
              </p>
              <p className="text-slate-400">
                Evaluator: {status.evaluator?.state ?? "—"} · Delivery:{" "}
                {status.delivery_worker?.state ?? "—"}
              </p>
              <div className="flex flex-wrap gap-1 text-xs">
                {Object.entries(status.channels).map(([name, info]) => (
                  <span key={name} className="rounded bg-slate-800 px-2 py-0.5 text-slate-300">
                    {name}: {info.available ? "configured" : "unavailable"}
                    {info.destinations !== undefined ? ` (${info.destinations})` : ""}
                  </span>
                ))}
              </div>
              <div className="flex flex-wrap gap-1 text-xs">
                {Object.entries(status.deliveries).map(([state, count]) => (
                  <span key={state} className="rounded bg-slate-800 px-2 py-0.5 text-slate-300">
                    {state}: {count}
                  </span>
                ))}
              </div>
              <p className="text-xs text-amber-300/80">{status.security_note}</p>
            </div>
          )}
        </Card>
      )}
    </div>
  );
}
