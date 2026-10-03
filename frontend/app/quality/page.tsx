"use client";

import { useCallback, useEffect, useState } from "react";
import { Card } from "../../components/ui/Card";
import { StatusCard } from "../../components/system/StatusCard";
import { DecisionBadge } from "../../components/quality/DecisionBadge";
import { ResultCard } from "../../components/quality/ResultCard";
import { InspectionCanvas } from "../../components/quality/InspectionCanvas";
import { RegionEditor, validateRegionDraft, type RegionDraft } from "../../components/quality/RegionEditor";
import { appConfig } from "../../lib/config";
import type {
  CameraItem,
  DefectCategory,
  DefectSeverity,
  InspectionProfile,
  InspectionResult,
  InspectionType,
  QualityEvent,
  QualityStatus,
  RegionType,
} from "../../types";

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${appConfig.apiUrl}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) throw new Error(`${path} → ${res.status}`);
  return (await res.json()) as T;
}

const SEVERITIES: DefectSeverity[] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
const INSPECTION_TYPES: InspectionType[] = [
  "GENERAL",
  "SURFACE",
  "ASSEMBLY",
  "COMPONENT",
  "DIMENSION",
  "CUSTOM",
];

const SEVERITY_STYLE: Record<string, string> = {
  CRITICAL: "bg-red-500/15 text-red-300",
  HIGH: "bg-orange-500/15 text-orange-300",
  MEDIUM: "bg-amber-500/15 text-amber-300",
  LOW: "bg-sky-500/15 text-sky-300",
  INFO: "bg-slate-500/15 text-slate-300",
};

type ProfileForm = {
  name: string;
  inspection_type: InspectionType;
  enabled: boolean;
  confidence_threshold: string;
  review_threshold: string;
  fail_severities: DefectSeverity[];
  required_region_ids: string;
  missing_evidence_behavior: "REVIEW" | "FAIL" | "IGNORE";
  defect_codes: string[];
};

const EMPTY_FORM: ProfileForm = {
  name: "",
  inspection_type: "GENERAL",
  enabled: true,
  confidence_threshold: "0.6",
  review_threshold: "0.35",
  fail_severities: ["HIGH", "CRITICAL"],
  required_region_ids: "",
  missing_evidence_behavior: "REVIEW",
  defect_codes: [],
};

function formFromProfile(profile: InspectionProfile): ProfileForm {
  return {
    name: profile.name,
    inspection_type: profile.inspection_type,
    enabled: profile.enabled,
    confidence_threshold: String(profile.confidence_threshold),
    review_threshold: String(profile.review_threshold),
    fail_severities: [...profile.decision_policy.fail_severities],
    required_region_ids: profile.decision_policy.required_region_ids.join(", "),
    missing_evidence_behavior: profile.decision_policy.missing_evidence_behavior,
    defect_codes: [],
  };
}

export default function QualityPage() {
  const [status, setStatus] = useState<QualityStatus | null>(null);
  const [cameras, setCameras] = useState<CameraItem[]>([]);
  const [cameraId, setCameraId] = useState<string>("");
  const [profiles, setProfiles] = useState<InspectionProfile[]>([]);
  const [categories, setCategories] = useState<DefectCategory[]>([]);
  const [latest, setLatest] = useState<InspectionResult | null>(null);
  const [events, setEvents] = useState<QualityEvent[]>([]);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<ProfileForm>(EMPTY_FORM);
  const [formRegions, setFormRegions] = useState<RegionDraft[]>([]);
  const [regionDraft, setRegionDraft] = useState<RegionDraft | null>(null);
  const [regionErrors, setRegionErrors] = useState<string[]>([]);
  const [editingRegion, setEditingRegion] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const [s, cams, cats] = await Promise.all([
        api<QualityStatus>("/api/v1/quality/status"),
        api<{ items: CameraItem[] }>("/api/v1/cameras"),
        api<{ categories: DefectCategory[] }>("/api/v1/quality/defect-categories"),
      ]);
      setStatus(s);
      setCameras(cams.items);
      setCategories(cats.categories);
      setError(null);
      const selected = cameraId || cams.items[0]?.camera_id || "";
      if (selected) {
        if (!cameraId) setCameraId(selected);
        const [plist, l, ev] = await Promise.all([
          api<{ profiles: InspectionProfile[] }>(
            `/api/v1/cameras/${selected}/inspection-profiles`
          ),
          api<{ result: InspectionResult | null }>(
            `/api/v1/cameras/${selected}/quality/latest`
          ),
          api<{ events: QualityEvent[] }>(
            `/api/v1/cameras/${selected}/quality/events?status=all&limit=50`
          ),
        ]);
        setProfiles(plist.profiles);
        setLatest(l.result);
        setEvents(ev.events);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "API unreachable");
    }
  }, [cameraId]);

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), 5000);
    return () => clearInterval(timer);
  }, [refresh]);

  const startCreate = () => {
    setEditingId(null);
    setForm(EMPTY_FORM);
    setFormRegions([]);
    setRegionDraft(null);
    setRegionErrors([]);
    setEditingRegion(null);
  };

  const startEdit = (profile: InspectionProfile) => {
    setEditingId(profile.profile_id);
    setForm(formFromProfile(profile));
    setFormRegions([]);
    setRegionDraft(null);
    setRegionErrors([]);
    setEditingRegion(null);
  };

  const toggleSeverity = (severity: DefectSeverity) => {
    setForm((f) => ({
      ...f,
      fail_severities: f.fail_severities.includes(severity)
        ? f.fail_severities.filter((s) => s !== severity)
        : [...f.fail_severities, severity],
    }));
  };

  const toggleCode = (code: string) => {
    setForm((f) => ({
      ...f,
      defect_codes: f.defect_codes.includes(code)
        ? f.defect_codes.filter((c) => c !== code)
        : [...f.defect_codes, code],
    }));
  };

  const addRegion = () => {
    if (!regionDraft || regionErrors.length > 0) return;
    if (editingRegion !== null) {
      setFormRegions((rs) => rs.map((r, i) => (i === editingRegion ? regionDraft : r)));
      setEditingRegion(null);
    } else {
      setFormRegions((rs) => [...rs, regionDraft]);
    }
    setRegionDraft(null);
    setRegionErrors([]);
  };

  const save = async () => {
    if (!cameraId || !form.name.trim() || saving) return;
    setSaving(true);
    try {
      const fail = Number(form.confidence_threshold);
      const review = Number(form.review_threshold);
      const payload = {
        name: form.name.trim(),
        inspection_type: form.inspection_type,
        enabled: form.enabled,
        confidence_threshold: fail,
        review_threshold: review,
        decision_policy: {
          fail_threshold: fail,
          review_threshold: review,
          fail_severities: form.fail_severities,
          required_region_ids: form.required_region_ids
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean),
          missing_evidence_behavior: form.missing_evidence_behavior,
          error_behavior: "RECORD_ERROR",
        },
        regions: formRegions.map((r) => ({
          name: r.name,
          region_type: r.region_type,
          geometry: r.geometry,
          enabled: r.enabled,
          required: r.required,
        })),
        defect_codes: form.defect_codes,
      };
      if (editingId) {
        await api(`/api/v1/cameras/${cameraId}/inspection-profiles/${editingId}`, {
          method: "PUT",
          body: JSON.stringify(payload),
        });
      } else {
        await api(`/api/v1/cameras/${cameraId}/inspection-profiles`, {
          method: "POST",
          body: JSON.stringify(payload),
        });
      }
      setEditingId(null);
      setForm(EMPTY_FORM);
      setFormRegions([]);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
    }
  };

  const removeProfile = async (profileId: string) => {
    try {
      await api(`/api/v1/cameras/${cameraId}/inspection-profiles/${profileId}`, {
        method: "DELETE",
      });
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Delete failed");
    }
  };

  const suppressEvent = async (eventId: string) => {
    try {
      await api(`/api/v1/cameras/${cameraId}/quality/suppress/${eventId}`, { method: "POST" });
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Suppress failed");
    }
  };

  const formValid =
    form.name.trim().length > 0 &&
    form.fail_severities.length > 0 &&
    Number.isFinite(Number(form.confidence_threshold)) &&
    Number.isFinite(Number(form.review_threshold)) &&
    Number(form.review_threshold) <= Number(form.confidence_threshold);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-bold">Quality Inspection — V07</h1>
        <button
          onClick={() => void refresh()}
          className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm hover:bg-slate-700"
        >
          Refresh
        </button>
      </div>
      {error && (
        <p className="text-sm text-amber-300">API unreachable ({error}) — start the backend on :8000.</p>
      )}

      <Card title="Engine">
        {status ? (
          <div className="grid grid-cols-2 gap-2 md:grid-cols-3">
            <StatusCard label="Status" status={status.engine_status} />
            <StatusCard label="Model" status={`${status.model_status}${status.model_name ? ` (${status.model_name})` : ""}`} />
            <StatusCard label="Active profiles" status={String(status.active_profiles)} />
            <StatusCard label="Inspections" status={String(status.inspection_count)} />
            <StatusCard
              label="Pass / Fail / Review / Error"
              status={`${status.pass_count} / ${status.fail_count} / ${status.review_count} / ${status.error_count}`}
            />
            <StatusCard label="Avg latency ms" status={String(status.average_inspection_ms)} />
            <StatusCard label="Frames skipped" status={String(status.frames_skipped)} />
            <StatusCard label="Inspection FPS" status={String(status.inspection_fps)} />
          </div>
        ) : (
          <p className="text-sm text-slate-400">Loading…</p>
        )}
      </Card>

      <Card title="Camera">
        <select
          value={cameraId}
          onChange={(e) => setCameraId(e.target.value)}
          className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm"
        >
          <option value="">Select a camera</option>
          {cameras.map((c) => (
            <option key={c.camera_id} value={c.camera_id}>
              {c.name} ({c.camera_id})
            </option>
          ))}
        </select>
      </Card>

      <Card title={`Profiles (${profiles.length})`}>
        {profiles.length === 0 && (
          <p className="mb-2 text-sm text-slate-400">No inspection profiles for this camera yet.</p>
        )}
        <div className="mb-3 space-y-2">
          {profiles.map((p) => (
            <div
              key={p.profile_id}
              className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2"
            >
              <div>
                <p className="text-sm font-medium">
                  {p.name}
                  <span className="ml-2 text-xs text-slate-400">
                    {p.inspection_type} · {p.enabled ? "enabled" : "disabled"}
                  </span>
                </p>
                <p className="text-xs text-slate-500">
                  fail ≥ {p.confidence_threshold} · review ≥ {p.review_threshold} ·
                  severities {p.decision_policy.fail_severities.join(", ")}
                </p>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => startEdit(p)}
                  className="rounded-lg bg-slate-800 px-3 py-1.5 text-xs hover:bg-slate-700"
                >
                  Edit
                </button>
                <button
                  onClick={() => void removeProfile(p.profile_id)}
                  className="rounded-lg bg-red-900/60 px-3 py-1.5 text-xs hover:bg-red-800/60"
                >
                  Delete
                </button>
              </div>
            </div>
          ))}
        </div>
        <button
          onClick={startCreate}
          className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm hover:bg-slate-700"
        >
          New profile
        </button>
      </Card>

      <Card title={editingId ? "Edit profile" : "New profile"}>
        <div className="grid gap-2 md:grid-cols-2">
          <input
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            placeholder="Profile name"
            className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm"
          />
          <select
            value={form.inspection_type}
            onChange={(e) => setForm({ ...form, inspection_type: e.target.value as InspectionType })}
            className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm"
          >
            {INSPECTION_TYPES.map((t) => (
              <option key={t}>{t}</option>
            ))}
          </select>
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input
              type="checkbox"
              checked={form.enabled}
              onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
            />
            Enabled
          </label>
          <div className="flex gap-2">
            <label className="flex flex-1 flex-col gap-1 text-xs text-slate-400">
              Fail threshold
              <input
                type="number"
                step={0.05}
                min={0}
                max={1}
                value={form.confidence_threshold}
                onChange={(e) => setForm({ ...form, confidence_threshold: e.target.value })}
                className="rounded-lg bg-slate-800 px-2 py-1"
              />
            </label>
            <label className="flex flex-1 flex-col gap-1 text-xs text-slate-400">
              Review threshold
              <input
                type="number"
                step={0.05}
                min={0}
                max={1}
                value={form.review_threshold}
                onChange={(e) => setForm({ ...form, review_threshold: e.target.value })}
                className="rounded-lg bg-slate-800 px-2 py-1"
              />
            </label>
          </div>
        </div>

        <div className="mt-3">
          <p className="mb-1 text-xs text-slate-400">Fail severities</p>
          <div className="flex flex-wrap gap-2">
            {SEVERITIES.map((s) => (
              <button
                key={s}
                onClick={() => toggleSeverity(s)}
                className={`rounded-full px-2 py-0.5 text-xs ${
                  form.fail_severities.includes(s)
                    ? "bg-slate-100 text-slate-900"
                    : "bg-slate-800 text-slate-300"
                }`}
              >
                {s}
              </button>
            ))}
          </div>
        </div>

        <div className="mt-3 grid gap-2 md:grid-cols-2">
          <label className="flex flex-col gap-1 text-xs text-slate-400">
            Required region IDs (comma-separated)
            <input
              value={form.required_region_ids}
              onChange={(e) => setForm({ ...form, required_region_ids: e.target.value })}
              placeholder="region-01, region-02"
              className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm"
            />
          </label>
          <label className="flex flex-col gap-1 text-xs text-slate-400">
            Missing evidence behavior
            <select
              value={form.missing_evidence_behavior}
              onChange={(e) =>
                setForm({
                  ...form,
                  missing_evidence_behavior: e.target.value as "REVIEW" | "FAIL" | "IGNORE",
                })
              }
              className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm"
            >
              <option value="REVIEW">REVIEW</option>
              <option value="FAIL">FAIL</option>
              <option value="IGNORE">IGNORE</option>
            </select>
          </label>
        </div>

        <div className="mt-3">
          <p className="mb-1 text-xs text-slate-400">Defect categories</p>
          {categories.length === 0 && (
            <p className="text-xs text-slate-500">No defect categories in the catalog yet.</p>
          )}
          <div className="flex flex-wrap gap-2">
            {categories.map((c) => (
              <button
                key={c.code}
                onClick={() => toggleCode(c.code)}
                title={`${c.name} (${c.severity})`}
                className={`rounded-full px-2 py-0.5 text-xs ${
                  form.defect_codes.includes(c.code)
                    ? "bg-slate-100 text-slate-900"
                    : "bg-slate-800 text-slate-300"
                }`}
              >
                {c.code}
              </button>
            ))}
          </div>
        </div>

        <div className="mt-3">
          <p className="mb-1 text-xs text-slate-400">
            Regions ({formRegions.length})
          </p>
          {formRegions.map((r, i) => (
            <div
              key={i}
              className="mb-1 flex items-center justify-between rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-1.5 text-xs"
            >
              <span>
                {r.name} · {r.region_type}
                {r.required ? " · required" : ""}
                {r.enabled ? "" : " · disabled"}
              </span>
              <div className="flex gap-2">
                <button
                  onClick={() => {
                    setEditingRegion(i);
                    setRegionDraft(r);
                    setRegionErrors(validateRegionDraft(r));
                  }}
                  className="rounded bg-slate-800 px-2 py-0.5 hover:bg-slate-700"
                >
                  Edit
                </button>
                <button
                  onClick={() => setFormRegions((rs) => rs.filter((_, j) => j !== i))}
                  className="rounded bg-red-900/60 px-2 py-0.5 hover:bg-red-800/60"
                >
                  Remove
                </button>
              </div>
            </div>
          ))}
          <div className="mt-2 rounded-lg border border-slate-800 p-3">
            <RegionEditor
              key={editingRegion ?? `new-${formRegions.length}`}
              initial={
                editingRegion !== null
                  ? formRegions[editingRegion]
                  : { name: "", region_type: "RECTANGLE" as RegionType, geometry: {}, enabled: true, required: false }
              }
              onChange={(draft, errors) => {
                setRegionDraft(draft);
                setRegionErrors(errors);
              }}
            />
            <button
              onClick={addRegion}
              disabled={!regionDraft || regionErrors.length > 0}
              className="mt-2 rounded-lg bg-emerald-700 px-3 py-1.5 text-sm disabled:opacity-40"
            >
              {editingRegion !== null ? "Save region" : "Add region"}
            </button>
          </div>
        </div>

        <div className="mt-3 flex gap-2">
          <button
            onClick={() => void save()}
            disabled={!formValid || saving || !cameraId}
            className="rounded-lg bg-emerald-700 px-3 py-1.5 text-sm disabled:opacity-40"
          >
            {editingId ? "Save changes" : "Create profile"}
          </button>
          <button
            onClick={() => {
              setEditingId(null);
              setForm(EMPTY_FORM);
              setFormRegions([]);
            }}
            className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm hover:bg-slate-700"
          >
            Cancel
          </button>
        </div>
      </Card>

      <Card title="Latest result">
        {!cameraId && <p className="text-sm text-slate-400">Select a camera to see inspection results.</p>}
        {cameraId && !latest && <p className="text-sm text-slate-400">No inspection results yet.</p>}
        {latest && (
          <div className="space-y-3">
            <div className="flex items-center gap-2 text-sm">
              <DecisionBadge decision={latest.decision} />
              <span className="text-xs text-slate-400">{latest.profile_id}</span>
            </div>
            <ResultCard result={latest} />
            <InspectionCanvas regions={[]} observations={latest.observations} frame={null} />
          </div>
        )}
      </Card>

      <Card title={`Quality events (${events.length})`}>
        {events.length === 0 && (
          <p className="text-sm text-slate-400">No quality events yet.</p>
        )}
        <div className="space-y-2">
          {events.slice(0, 20).map((e) => (
            <div
              key={e.event_id}
              className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2"
            >
              <div>
                <p className="text-sm font-medium">
                  {e.event_type}
                  {e.defect_code && <span className="ml-2 text-xs text-slate-400">{e.defect_code}</span>}
                </p>
                <p className="text-xs text-slate-500">
                  {e.decision} · {new Date(e.timestamp).toLocaleString()} · duration{" "}
                  {(e.duration_ms / 1000).toFixed(1)}s
                </p>
              </div>
              <div className="flex items-center gap-2">
                <span
                  className={`rounded-full px-2 py-0.5 text-xs ${SEVERITY_STYLE[e.severity] ?? SEVERITY_STYLE.INFO}`}
                >
                  {e.severity}
                </span>
                <span className="rounded-full bg-slate-500/15 px-2 py-0.5 text-xs text-slate-300">
                  {e.status}
                </span>
                {e.status === "ACTIVE" && (
                  <button
                    onClick={() => void suppressEvent(e.event_id)}
                    className="rounded-lg bg-slate-800 px-2 py-0.5 text-xs hover:bg-slate-700"
                  >
                    Suppress
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
