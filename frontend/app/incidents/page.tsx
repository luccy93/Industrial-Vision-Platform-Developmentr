"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { Card } from "../../components/ui/Card";
import { PriorityBadge, RiskBadge } from "../../components/intelligence/RiskBadge";
import { appConfig } from "../../lib/config";
import type {
  IncidentCategory,
  IncidentListResponse,
  IncidentPriority,
  IncidentStatus,
} from "../../types";

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${appConfig.apiUrl}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    let detail = `${path} → ${res.status}`;
    try {
      const body = (await res.json()) as {
        error?: { message?: string; code?: string };
        detail?: unknown;
      };
      if (body?.error?.message) detail = `${body.error.code ?? res.status}: ${body.error.message}`;
      else if (typeof body?.detail === "string") detail = body.detail;
    } catch {
      /* keep the status fallback */
    }
    throw new Error(detail);
  }
  return (await res.json()) as T;
}

const STATUSES: IncidentStatus[] = [
  "OPEN",
  "ACKNOWLEDGED",
  "INVESTIGATING",
  "MITIGATED",
  "RESOLVED",
  "CLOSED",
];
const PRIORITIES: IncidentPriority[] = ["P0", "P1", "P2", "P3", "P4"];
const CATEGORIES: IncidentCategory[] = [
  "SAFETY",
  "SECURITY",
  "QUALITY",
  "COLLISION",
  "SPATIAL",
  "OPERATIONAL",
  "SYSTEM",
  "UNKNOWN",
];

function toggle<T>(list: T[], value: T): T[] {
  return list.includes(value) ? list.filter((v) => v !== value) : [...list, value];
}

/**
 * Incident Management — V10.
 *
 * Filterable, paginated operator queue with manual incident creation.
 * State-gated lifecycle work happens on the detail page.
 */
export default function IncidentsPage() {
  const [data, setData] = useState<IncidentListResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [statuses, setStatuses] = useState<IncidentStatus[]>([]);
  const [priorities, setPriorities] = useState<IncidentPriority[]>([]);
  const [categories, setCategories] = useState<IncidentCategory[]>([]);
  const [cameraId, setCameraId] = useState("");
  const [assignedTo, setAssignedTo] = useState("");
  const [page, setPage] = useState(1);
  const [formOpen, setFormOpen] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [form, setForm] = useState({
    title: "",
    description: "",
    category: "OPERATIONAL" as IncidentCategory,
    priority: "P4" as IncidentPriority,
    camera_id: "",
  });

  const refresh = useCallback(async () => {
    const query = new URLSearchParams();
    for (const s of statuses) query.append("status", s);
    for (const p of priorities) query.append("priority", p);
    for (const c of categories) query.append("category", c);
    if (cameraId.trim()) query.set("camera_id", cameraId.trim());
    if (assignedTo.trim()) query.set("assigned_to", assignedTo.trim());
    query.set("page", String(page));
    query.set("page_size", "20");
    try {
      setData(await api<IncidentListResponse>(`/api/v1/incidents?${query.toString()}`));
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "API unreachable");
    }
  }, [statuses, priorities, categories, cameraId, assignedTo, page]);

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), 10000);
    return () => clearInterval(timer);
  }, [refresh]);

  const applyFilters = () => {
    setPage(1);
    void refresh();
  };

  const clearFilters = () => {
    setStatuses([]);
    setPriorities([]);
    setCategories([]);
    setCameraId("");
    setAssignedTo("");
    setPage(1);
  };

  const createIncident = async () => {
    setFormError(null);
    try {
      await api("/api/v1/incidents", {
        method: "POST",
        body: JSON.stringify({
          title: form.title.trim(),
          description: form.description,
          category: form.category,
          priority: form.priority,
          camera_id: form.camera_id.trim() || null,
        }),
      });
      setForm({ title: "", description: "", category: "OPERATIONAL", priority: "P4", camera_id: "" });
      setFormOpen(false);
      setPage(1);
      await refresh();
    } catch (e) {
      setFormError(e instanceof Error ? e.message : "Create failed");
    }
  };

  const totalPages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-bold">Incident Management — V10</h1>
        <div className="flex gap-2">
          <button
            onClick={() => setFormOpen((v) => !v)}
            className="rounded-lg bg-emerald-700 px-3 py-1.5 text-sm hover:bg-emerald-600"
          >
            {formOpen ? "Cancel" : "New incident"}
          </button>
          <button
            onClick={() => void refresh()}
            className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm hover:bg-slate-700"
          >
            Refresh
          </button>
        </div>
      </div>
      {error && (
        <p className="text-sm text-amber-300">API unreachable ({error}) — start the backend on :8000.</p>
      )}

      {formOpen && (
        <Card title="Create manual incident">
          <div className="grid gap-2 md:grid-cols-2">
            <label className="text-xs text-slate-400">
              Title (required)
              <input
                value={form.title}
                onChange={(e) => setForm({ ...form, title: e.target.value })}
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm text-slate-200"
                placeholder="e.g. Conveyor jam at station 3"
              />
            </label>
            <label className="text-xs text-slate-400">
              Camera (optional — must already exist)
              <input
                value={form.camera_id}
                onChange={(e) => setForm({ ...form, camera_id: e.target.value })}
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm text-slate-200"
                placeholder="cam-01"
              />
            </label>
            <label className="text-xs text-slate-400 md:col-span-2">
              Description
              <textarea
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm text-slate-200"
                rows={2}
              />
            </label>
            <label className="text-xs text-slate-400">
              Category
              <select
                value={form.category}
                onChange={(e) => setForm({ ...form, category: e.target.value as IncidentCategory })}
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm text-slate-200"
              >
                {CATEGORIES.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </select>
            </label>
            <label className="text-xs text-slate-400">
              Priority
              <select
                value={form.priority}
                onChange={(e) => setForm({ ...form, priority: e.target.value as IncidentPriority })}
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm text-slate-200"
              >
                {PRIORITIES.map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </select>
            </label>
          </div>
          {formError && <p className="mt-2 text-sm text-red-300">{formError}</p>}
          <button
            onClick={() => void createIncident()}
            disabled={!form.title.trim()}
            className="mt-3 rounded-lg bg-emerald-700 px-3 py-1.5 text-sm disabled:opacity-40 hover:bg-emerald-600"
          >
            Create
          </button>
        </Card>
      )}

      <Card title="Filters">
        <div className="space-y-2">
          <div>
            <p className="text-xs text-slate-400">Status</p>
            <div className="mt-1 flex flex-wrap gap-1">
              {STATUSES.map((s) => (
                <button
                  key={s}
                  onClick={() => setStatuses((prev) => toggle(prev, s))}
                  className={`rounded-full px-2 py-0.5 text-xs ${
                    statuses.includes(s) ? "bg-sky-600 text-white" : "bg-slate-800 text-slate-300"
                  }`}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
          <div>
            <p className="text-xs text-slate-400">Priority</p>
            <div className="mt-1 flex flex-wrap gap-1">
              {PRIORITIES.map((p) => (
                <button
                  key={p}
                  onClick={() => setPriorities((prev) => toggle(prev, p))}
                  className={`rounded-full px-2 py-0.5 text-xs ${
                    priorities.includes(p) ? "bg-sky-600 text-white" : "bg-slate-800 text-slate-300"
                  }`}
                >
                  {p}
                </button>
              ))}
            </div>
          </div>
          <div>
            <p className="text-xs text-slate-400">Category</p>
            <div className="mt-1 flex flex-wrap gap-1">
              {CATEGORIES.map((c) => (
                <button
                  key={c}
                  onClick={() => setCategories((prev) => toggle(prev, c))}
                  className={`rounded-full px-2 py-0.5 text-xs ${
                    categories.includes(c) ? "bg-sky-600 text-white" : "bg-slate-800 text-slate-300"
                  }`}
                >
                  {c}
                </button>
              ))}
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <input
              value={cameraId}
              onChange={(e) => setCameraId(e.target.value)}
              placeholder="camera_id"
              className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm text-slate-200"
            />
            <input
              value={assignedTo}
              onChange={(e) => setAssignedTo(e.target.value)}
              placeholder="assigned_to"
              className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm text-slate-200"
            />
            <button
              onClick={applyFilters}
              className="rounded-lg bg-sky-700 px-3 py-1.5 text-sm hover:bg-sky-600"
            >
              Apply
            </button>
            <button
              onClick={clearFilters}
              className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm hover:bg-slate-700"
            >
              Clear
            </button>
          </div>
        </div>
      </Card>

      <Card title={`Incidents (${data?.total ?? 0})`}>
        {!data || data.incidents.length === 0 ? (
          <p className="text-sm text-slate-400">
            No incidents match. Automatic incidents appear here once a cluster reaches the
            configured minimum priority.
          </p>
        ) : (
          <div className="space-y-2">
            {data.incidents.map((incident) => (
              <Link
                key={incident.id}
                href={`/incidents/${incident.id}`}
                className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2 hover:bg-slate-800/60"
              >
                <span className="text-sm font-medium">
                  {incident.incident_number} · {incident.title}
                </span>
                <span className="flex items-center gap-2 text-xs text-slate-400">
                  <RiskBadge level={incident.risk_level} score={incident.risk_score} />
                  <PriorityBadge priority={incident.priority} />
                  <span>{incident.status}</span>
                  <span>{incident.category}</span>
                  {incident.assigned_to && <span>→ {incident.assigned_to}</span>}
                </span>
              </Link>
            ))}
          </div>
        )}
        {data && totalPages > 1 && (
          <div className="mt-3 flex items-center gap-2 text-sm">
            <button
              disabled={page <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              className="rounded-lg bg-slate-800 px-3 py-1 disabled:opacity-40 hover:bg-slate-700"
            >
              Prev
            </button>
            <span className="text-slate-400">
              Page {page} of {totalPages}
            </span>
            <button
              disabled={page >= totalPages}
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              className="rounded-lg bg-slate-800 px-3 py-1 disabled:opacity-40 hover:bg-slate-700"
            >
              Next
            </button>
          </div>
        )}
      </Card>
    </div>
  );
}
