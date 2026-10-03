"use client";

import { useCallback, useEffect, useState } from "react";
import { Card } from "../../components/ui/Card";
import { StatusCard } from "../../components/system/StatusCard";
import { AvailabilityBadge } from "../../components/autonomous/AvailabilityBadge";
import { LaneOverlay } from "../../components/autonomous/LaneOverlay";
import { BevCanvas } from "../../components/autonomous/BevCanvas";
import { appConfig } from "../../lib/config";
import type {
  AutonomousProfile,
  AutonomousResult,
  AutonomousStatus,
  Availability,
  CameraItem,
  PerceptionEvent,
  RiskLevel,
  SceneType,
} from "../../types";

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${appConfig.apiUrl}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) throw new Error(`${path} → ${res.status}`);
  return (await res.json()) as T;
}

const SCENE_TYPES: SceneType[] = [
  "ROAD",
  "PARKING",
  "WAREHOUSE",
  "INDUSTRIAL_YARD",
  "INDOOR_MOBILE_ROBOT",
  "UNKNOWN",
];

const RISK_STYLE: Record<string, string> = {
  CRITICAL: "bg-red-500/15 text-red-300",
  HIGH: "bg-orange-500/15 text-orange-300",
  MEDIUM: "bg-amber-500/15 text-amber-300",
  LOW: "bg-sky-500/15 text-sky-300",
  NONE: "bg-slate-500/15 text-slate-300",
  UNKNOWN: "bg-rose-500/15 text-rose-300",
};

const STATE_STYLE: Record<string, string> = {
  MOVING: "bg-sky-500/15 text-sky-300",
  STATIONARY: "bg-slate-500/15 text-slate-300",
  APPROACHING: "bg-orange-500/15 text-orange-300",
  RECEDING: "bg-emerald-500/15 text-emerald-300",
  CROSSING: "bg-amber-500/15 text-amber-300",
  UNKNOWN: "bg-rose-500/15 text-rose-300",
};

function availabilityOf(status: string): Availability {
  if (status === "READY") return "AVAILABLE";
  if (status === "NOT_CONFIGURED" || status === "DISABLED") return "NOT_CONFIGURED";
  return "UNKNOWN";
}

type ProfileForm = {
  name: string;
  enabled: boolean;
  scene_type: SceneType;
  lane_detection_enabled: boolean;
  depth_enabled: boolean;
  trajectory_enabled: boolean;
  collision_risk_enabled: boolean;
  bev_enabled: boolean;
  trajectory_horizon_seconds: string;
  collision_risk_threshold: string;
  collision_grace_seconds: string;
};

const EMPTY_FORM: ProfileForm = {
  name: "",
  enabled: true,
  scene_type: "UNKNOWN",
  lane_detection_enabled: true,
  depth_enabled: false,
  trajectory_enabled: true,
  collision_risk_enabled: true,
  bev_enabled: true,
  trajectory_horizon_seconds: "2.0",
  collision_risk_threshold: "0.5",
  collision_grace_seconds: "0.5",
};

function formFromProfile(profile: AutonomousProfile): ProfileForm {
  return {
    name: profile.name,
    enabled: profile.enabled,
    scene_type: profile.scene_type,
    lane_detection_enabled: profile.lane_detection_enabled,
    depth_enabled: profile.depth_enabled,
    trajectory_enabled: profile.trajectory_enabled,
    collision_risk_enabled: profile.collision_risk_enabled,
    bev_enabled: profile.bev_enabled,
    trajectory_horizon_seconds: String(profile.trajectory_horizon_seconds),
    collision_risk_threshold: String(profile.collision_risk_threshold),
    collision_grace_seconds: String(profile.collision_grace_seconds),
  };
}

export default function AutonomousPage() {
  const [status, setStatus] = useState<AutonomousStatus | null>(null);
  const [cameras, setCameras] = useState<CameraItem[]>([]);
  const [cameraId, setCameraId] = useState<string>("");
  const [profiles, setProfiles] = useState<AutonomousProfile[]>([]);
  const [latest, setLatest] = useState<AutonomousResult | null>(null);
  const [events, setEvents] = useState<PerceptionEvent[]>([]);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<ProfileForm>(EMPTY_FORM);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const [s, cams] = await Promise.all([
        api<AutonomousStatus>("/api/v1/autonomous/status"),
        api<{ items: CameraItem[] }>("/api/v1/cameras"),
      ]);
      setStatus(s);
      setCameras(cams.items);
      setError(null);
      const selected = cameraId || cams.items[0]?.camera_id || "";
      if (selected) {
        if (!cameraId) setCameraId(selected);
        const [plist, l, ev] = await Promise.all([
          api<{ profiles: AutonomousProfile[] }>(
            `/api/v1/cameras/${selected}/autonomous-profiles`
          ),
          api<{ result: AutonomousResult | null }>(
            `/api/v1/cameras/${selected}/autonomous/latest`
          ),
          api<{ events: PerceptionEvent[] }>(
            `/api/v1/cameras/${selected}/autonomous/events?status=all&limit=50`
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
  };

  const startEdit = (profile: AutonomousProfile) => {
    setEditingId(profile.profile_id);
    setForm(formFromProfile(profile));
  };

  const save = async () => {
    if (!cameraId || !form.name.trim() || saving) return;
    setSaving(true);
    try {
      const payload = {
        name: form.name.trim(),
        enabled: form.enabled,
        scene_type: form.scene_type,
        lane_detection_enabled: form.lane_detection_enabled,
        depth_enabled: form.depth_enabled,
        trajectory_enabled: form.trajectory_enabled,
        collision_risk_enabled: form.collision_risk_enabled,
        bev_enabled: form.bev_enabled,
        trajectory_horizon_seconds: Number(form.trajectory_horizon_seconds),
        collision_risk_threshold: Number(form.collision_risk_threshold),
        collision_grace_seconds: Number(form.collision_grace_seconds),
      };
      if (editingId) {
        await api(`/api/v1/cameras/${cameraId}/autonomous-profiles/${editingId}`, {
          method: "PUT",
          body: JSON.stringify(payload),
        });
      } else {
        await api(`/api/v1/cameras/${cameraId}/autonomous-profiles`, {
          method: "POST",
          body: JSON.stringify(payload),
        });
      }
      setEditingId(null);
      setForm(EMPTY_FORM);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
    }
  };

  const removeProfile = async (profileId: string) => {
    try {
      await api(`/api/v1/cameras/${cameraId}/autonomous-profiles/${profileId}`, {
        method: "DELETE",
      });
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Delete failed");
    }
  };

  const formValid =
    form.name.trim().length > 0 &&
    Number.isFinite(Number(form.trajectory_horizon_seconds)) &&
    Number(form.trajectory_horizon_seconds) >= 0.1 &&
    Number.isFinite(Number(form.collision_risk_threshold)) &&
    Number(form.collision_risk_threshold) >= 0 &&
    Number(form.collision_risk_threshold) <= 1;

  const trajectoryMap: Record<string, Array<{ x: number; y: number }>> = {};
  if (latest) {
    for (const t of latest.trajectories) trajectoryMap[t.object_id] = t.points;
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-bold">Autonomous Perception — V08</h1>
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
          <div className="space-y-2">
            <div className="grid grid-cols-2 gap-2 md:grid-cols-3">
              <StatusCard label="Status" status={status.engine_status} />
              <StatusCard label="Active profiles" status={String(status.active_profiles)} />
              <StatusCard label="Perceptions" status={String(status.perception_count)} />
              <StatusCard label="Avg latency ms" status={String(status.average_perception_ms)} />
              <StatusCard label="Frames skipped" status={String(status.frames_skipped)} />
              <StatusCard label="Perception FPS" status={String(status.perception_fps)} />
            </div>
            <div className="flex flex-wrap gap-3 rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2">
              <AvailabilityBadge label="Scene" availability={availabilityOf(status.scene_classifier_status)} />
              <AvailabilityBadge label="Lanes" availability={availabilityOf(status.lane_detector_status)} />
              <AvailabilityBadge label="Depth" availability={availabilityOf(status.depth_status)} />
              <AvailabilityBadge label="Trajectory" availability={availabilityOf(status.trajectory_status)} />
              <AvailabilityBadge label="Collision" availability={availabilityOf(status.collision_status)} />
              <AvailabilityBadge label="BEV" availability={availabilityOf(status.bev_status)} />
            </div>
            {status.depth_status === "NOT_CONFIGURED" && (
              <p className="text-xs text-slate-500">
                Depth unavailable — relative depth reports as unavailable and risk analysis
                continues without it. Configure AUTONOMOUS_DEPTH_MODEL for estimates.
              </p>
            )}
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
          <p className="mb-2 text-sm text-slate-400">
            No perception profiles — the engine runs on global defaults.
          </p>
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
                    {p.scene_type} · {p.enabled ? "enabled" : "disabled"}
                  </span>
                </p>
                <p className="text-xs text-slate-500">
                  lanes {p.lane_detection_enabled ? "on" : "off"} · depth{" "}
                  {p.depth_enabled ? "on" : "off"} · trajectory{" "}
                  {p.trajectory_enabled ? "on" : "off"} · collision{" "}
                  {p.collision_risk_enabled ? "on" : "off"} · horizon {p.trajectory_horizon_seconds}s
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
            value={form.scene_type}
            onChange={(e) => setForm({ ...form, scene_type: e.target.value as SceneType })}
            className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm"
          >
            {SCENE_TYPES.map((t) => (
              <option key={t} value={t}>
                {t === "UNKNOWN" ? "UNKNOWN (auto)" : t}
              </option>
            ))}
          </select>
        </div>
        <div className="mt-2 flex flex-wrap gap-3 text-sm text-slate-300">
          {(
            [
              ["enabled", "Enabled"],
              ["lane_detection_enabled", "Lanes"],
              ["depth_enabled", "Depth"],
              ["trajectory_enabled", "Trajectory"],
              ["collision_risk_enabled", "Collision"],
              ["bev_enabled", "BEV"],
            ] as const
          ).map(([key, label]) => (
            <label key={key} className="flex items-center gap-1">
              <input
                type="checkbox"
                checked={form[key]}
                onChange={(e) => setForm({ ...form, [key]: e.target.checked })}
              />
              {label}
            </label>
          ))}
        </div>
        <div className="mt-2 grid gap-2 md:grid-cols-3">
          <label className="flex flex-col gap-1 text-xs text-slate-400">
            Trajectory horizon (s)
            <input
              type="number"
              step={0.5}
              min={0.1}
              max={10}
              value={form.trajectory_horizon_seconds}
              onChange={(e) => setForm({ ...form, trajectory_horizon_seconds: e.target.value })}
              className="rounded-lg bg-slate-800 px-2 py-1"
            />
          </label>
          <label className="flex flex-col gap-1 text-xs text-slate-400">
            Risk threshold
            <input
              type="number"
              step={0.05}
              min={0}
              max={1}
              value={form.collision_risk_threshold}
              onChange={(e) => setForm({ ...form, collision_risk_threshold: e.target.value })}
              className="rounded-lg bg-slate-800 px-2 py-1"
            />
          </label>
          <label className="flex flex-col gap-1 text-xs text-slate-400">
            Collision grace (s)
            <input
              type="number"
              step={0.1}
              min={0}
              value={form.collision_grace_seconds}
              onChange={(e) => setForm({ ...form, collision_grace_seconds: e.target.value })}
              className="rounded-lg bg-slate-800 px-2 py-1"
            />
          </label>
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
            }}
            className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm hover:bg-slate-700"
          >
            Cancel
          </button>
        </div>
      </Card>

      <Card title="Latest scene">
        {!cameraId && <p className="text-sm text-slate-400">Select a camera to see perception output.</p>}
        {cameraId && !latest && <p className="text-sm text-slate-400">No perceived scenes yet.</p>}
        {latest && (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <span className="rounded-full bg-indigo-500/15 px-2 py-0.5 text-xs text-indigo-300">
                {latest.scene_type}
              </span>
              <span className="text-xs text-slate-400">
                {latest.objects.length} object(s) · {latest.lanes.length} lane(s) ·{" "}
                {latest.processing_time_ms.toFixed(1)} ms
              </span>
            </div>
            {latest.objects.length > 0 && (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="text-slate-500">
                      <th className="py-1 pr-3">Object</th>
                      <th className="py-1 pr-3">Class</th>
                      <th className="py-1 pr-3">State</th>
                      <th className="py-1 pr-3">Velocity</th>
                      <th className="py-1 pr-3">Depth</th>
                    </tr>
                  </thead>
                  <tbody>
                    {latest.objects.map((o) => (
                      <tr key={o.object_id} className="border-t border-slate-800">
                        <td className="py-1 pr-3 font-medium">{o.object_id}</td>
                        <td className="py-1 pr-3 text-slate-400">{o.class_name}</td>
                        <td className="py-1 pr-3">
                          <span
                            className={`rounded-full px-2 py-0.5 ${STATE_STYLE[o.object_state] ?? STATE_STYLE.UNKNOWN}`}
                          >
                            {o.object_state}
                          </span>
                        </td>
                        <td className="py-1 pr-3 text-slate-400">
                          {o.velocity
                            ? `(${(o.velocity[0] * 100).toFixed(1)}, ${(o.velocity[1] * 100).toFixed(1)}) %/s`
                            : "—"}
                        </td>
                        <td className="py-1 pr-3 text-slate-400">
                          {o.relative_depth != null ? (
                            `${(o.relative_depth * 100).toFixed(0)}% rel.`
                          ) : (
                            <span title="No depth estimator configured">unavailable</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <LaneOverlay objects={latest.objects} lanes={latest.lanes} />
            <BevCanvas
              objects={latest.objects}
              lanes={latest.lanes}
              trajectories={trajectoryMap}
              risks={latest.collision_risks}
            />
            {latest.collision_risks.length > 0 && (
              <div className="space-y-1">
                {latest.collision_risks.map((r, i) => (
                  <p key={i} className="text-xs text-slate-300">
                    <span
                      className={`mr-2 rounded-full px-2 py-0.5 ${RISK_STYLE[r.risk_level as RiskLevel] ?? RISK_STYLE.UNKNOWN}`}
                    >
                      {r.risk_level}
                    </span>
                    {r.object_ids.join(" ↔ ")} · score {(r.risk_score * 100).toFixed(0)}% ·{" "}
                    {r.time_to_collision != null
                      ? `TTC ~${r.time_to_collision.toFixed(1)}s (estimate)`
                      : "TTC unavailable"}{" "}
                    · {r.reason}
                  </p>
                ))}
              </div>
            )}
          </div>
        )}
      </Card>

      <Card title={`Perception events (${events.length})`}>
        {events.length === 0 && <p className="text-sm text-slate-400">No perception events yet.</p>}
        <div className="space-y-2">
          {events.slice(0, 20).map((e) => (
            <div
              key={e.event_id}
              className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2"
            >
              <div>
                <p className="text-sm font-medium">
                  {e.event_type}
                  {e.object_ids.length > 0 && (
                    <span className="ml-2 text-xs text-slate-400">{e.object_ids.join(", ")}</span>
                  )}
                </p>
                <p className="text-xs text-slate-500">
                  {new Date(e.timestamp).toLocaleString()} · duration{" "}
                  {(e.duration_ms / 1000).toFixed(1)}s · {e.message}
                </p>
              </div>
              <div className="flex items-center gap-2">
                <span
                  className={`rounded-full px-2 py-0.5 text-xs ${RISK_STYLE[e.risk_level] ?? RISK_STYLE.UNKNOWN}`}
                >
                  {e.risk_level}
                </span>
                <span className="rounded-full bg-slate-500/15 px-2 py-0.5 text-xs text-slate-300">
                  {e.status}
                </span>
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
