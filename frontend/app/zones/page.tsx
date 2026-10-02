"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { Card } from "../../components/ui/Card";
import { StatusCard } from "../../components/system/StatusCard";
import { appConfig } from "../../lib/config";
import type {
  CameraItem,
  SafetyEventItem,
  SpatialStatus,
  ZoneItem,
  ZoneMembership,
  ZonePoint,
  ZoneType
} from "../../types";

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${appConfig.apiUrl}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json" }
  });
  if (!res.ok) throw new Error(`${path} → ${res.status}`);
  return (await res.json()) as T;
}

const ZONE_TYPES: ZoneType[] = ["RESTRICTED", "DANGER", "WARNING", "SAFE", "CUSTOM"];
const SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
const ZONE_FILL: Record<ZoneType, string> = {
  RESTRICTED: "rgba(239,68,68,0.18)",
  DANGER: "rgba(249,115,22,0.18)",
  WARNING: "rgba(250,204,21,0.18)",
  SAFE: "rgba(34,197,94,0.18)",
  CUSTOM: "rgba(99,102,241,0.18)"
};
const SPATIAL_EVENT_TYPES = new Set([
  "RESTRICTED_ZONE_ENTRY",
  "RESTRICTED_ZONE_EXIT",
  "ZONE_DWELL",
  "PERSON_VEHICLE_PROXIMITY",
  "PERSON_PERSON_PROXIMITY",
  "VEHICLE_VEHICLE_PROXIMITY"
]);
// Editor canvas works in normalized [0,1] coordinates rendered on a fixed viewBox.
const VIEW = 400;

export default function ZonesPage() {
  const [status, setStatus] = useState<SpatialStatus | null>(null);
  const [cameras, setCameras] = useState<CameraItem[]>([]);
  const [cameraId, setCameraId] = useState<string>("");
  const [zones, setZones] = useState<ZoneItem[]>([]);
  const [members, setMembers] = useState<ZoneMembership[]>([]);
  const [spatialEvents, setSpatialEvents] = useState<SafetyEventItem[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [points, setPoints] = useState<ZonePoint[]>([]);
  const [name, setName] = useState<string>("");
  const [zoneType, setZoneType] = useState<ZoneType>("RESTRICTED");
  const [severity, setSeverity] = useState<string>("HIGH");
  const [dwell, setDwell] = useState<string>("");
  const [error, setError] = useState<string | null>(null);

  const loadZones = useCallback(async (id: string) => {
    if (!id) {
      setZones([]);
      return;
    }
    try {
      const body = await api<{ zones: ZoneItem[] }>(`/api/v1/cameras/${id}/zones`);
      setZones(body.zones);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "API unreachable");
    }
  }, []);

  const refresh = useCallback(async () => {
    try {
      const [s, cams] = await Promise.all([
        api<SpatialStatus>("/api/v1/spatial/status"),
        api<{ items: CameraItem[] }>("/api/v1/cameras")
      ]);
      setStatus(s);
      setCameras(cams.items);
      setCameraId((current) => current || cams.items[0]?.camera_id || "");
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "API unreachable");
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), 5000);
    return () => clearInterval(timer);
  }, [refresh]);

  useEffect(() => {
    void loadZones(cameraId);
    setSelected(null);
    setPoints([]);
  }, [cameraId, loadZones]);

  // Runtime membership + spatial events for the selected camera.
  useEffect(() => {
    if (!cameraId) return;
    let cancelled = false;
    const poll = async () => {
      try {
        const [state, events] = await Promise.all([
          api<{ members: ZoneMembership[] }>(`/api/v1/cameras/${cameraId}/zones/state`),
          api<{ events: SafetyEventItem[] }>(
            `/api/v1/cameras/${cameraId}/safety/events?status=all&limit=50`
          )
        ]);
        if (cancelled) return;
        setMembers(state.members);
        setSpatialEvents(events.events.filter((e) => SPATIAL_EVENT_TYPES.has(e.event_type)));
        setError(null);
      } catch {
        if (!cancelled) setMembers([]);
      }
    };
    void poll();
    const timer = setInterval(() => void poll(), 5000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [cameraId]);

  const editing = useMemo(() => zones.find((z) => z.zone_id === selected) ?? null, [zones, selected]);

  const startEdit = (zone: ZoneItem) => {
    setSelected(zone.zone_id);
    setPoints(zone.polygon);
    setName(zone.name);
    setZoneType(zone.zone_type);
    setSeverity(zone.severity);
    setDwell(zone.dwell_threshold_seconds === null ? "" : String(zone.dwell_threshold_seconds));
  };

  const startCreate = () => {
    setSelected(null);
    setPoints([]);
    setName("");
    setZoneType("RESTRICTED");
    setSeverity("HIGH");
    setDwell("");
  };

  const valid = points.length >= 3 && name.trim().length > 0;

  const save = async () => {
    if (!cameraId || !valid) return;
    const body = {
      name: name.trim(),
      zone_type: zoneType,
      polygon: points,
      severity,
      dwell_threshold_seconds: dwell.trim() === "" ? null : Number(dwell)
    };
    const path = editing
      ? `/api/v1/cameras/${cameraId}/zones/${editing.zone_id}`
      : `/api/v1/cameras/${cameraId}/zones`;
    await api<ZoneItem>(path, {
      method: editing ? "PUT" : "POST",
      body: JSON.stringify(body)
    });
    startCreate();
    await loadZones(cameraId);
  };

  const remove = async (zone: ZoneItem) => {
    await api(`/api/v1/cameras/${cameraId}/zones/${zone.zone_id}`, { method: "DELETE" });
    if (selected === zone.zone_id) startCreate();
    await loadZones(cameraId);
  };

  const toggle = async (zone: ZoneItem) => {
    await api(`/api/v1/cameras/${cameraId}/zones/${zone.zone_id}`, {
      method: "PUT",
      body: JSON.stringify({ enabled: !zone.enabled })
    });
    await loadZones(cameraId);
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-bold">Spatial Zones — V06</h1>
        <div className="flex items-center gap-2">
          <select
            value={cameraId}
            onChange={(e) => setCameraId(e.target.value)}
            className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm"
          >
            {cameras.length === 0 && <option value="">No cameras</option>}
            {cameras.map((c) => (
              <option key={c.camera_id} value={c.camera_id}>
                {c.name} ({c.camera_id})
              </option>
            ))}
          </select>
          <button
            onClick={() => startCreate()}
            className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm hover:bg-slate-700"
          >
            New zone
          </button>
        </div>
      </div>

      {error && (
        <p className="text-sm text-amber-300">API unreachable ({error}) — start the backend on :8000.</p>
      )}

      <Card title="Spatial engine (image-space)">
        {status ? (
          <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
            <StatusCard label="Status" status={status.engine_status} />
            <StatusCard label="Zones" status={String(status.zone_count)} />
            <StatusCard label="Proximity" status={status.proximity_strategy} />
            <StatusCard label="Dwell s" status={String(status.default_dwell_seconds)} />
            <StatusCard label="Active states" status={String(status.active_state_count)} />
            <StatusCard label="Cameras" status={String(status.camera_count)} />
            <StatusCard
              label="Relationships"
              status={status.relationships.map((r) => `${r.relationship.replace(/_/g, " ").toLowerCase()}:${r.enabled ? "on" : "off"}`).join(" ")}
            />
            <StatusCard label="Coordinate space" status={status.coordinate_space} />
          </div>
        ) : (
          <p className="text-sm text-slate-400">Loading…</p>
        )}
        <p className="mt-2 text-xs text-slate-500">
          {status?.membership_heuristic.replace(/_/g, " ")} is an image-space approximation — not physical
          distance. No video transport is used on this page.
        </p>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title={editing ? `Edit zone — ${editing.zone_id}` : "New zone (click the canvas to add points)"}>
          <svg
            viewBox={`0 0 ${VIEW} ${VIEW}`}
            className="h-64 w-full cursor-crosshair rounded-lg border border-slate-800 bg-slate-950"
            onClick={(e) => {
              const rect = e.currentTarget.getBoundingClientRect();
              const x = (e.clientX - rect.left) / rect.width;
              const y = (e.clientY - rect.top) / rect.height;
              if (x < 0 || x > 1 || y < 0 || y > 1) return;
              setPoints((prev) => [...prev, { x: Number(x.toFixed(4)), y: Number(y.toFixed(4)) }]);
            }}
          >
            <polygon
              points={points.map((p) => `${p.x * VIEW},${p.y * VIEW}`).join(" ")}
              fill={ZONE_FILL[zoneType]}
              stroke="rgb(148 163 184)"
              strokeWidth={2}
            />
            {points.map((p, i) => (
              <circle key={i} cx={p.x * VIEW} cy={p.y * VIEW} r={5} fill="rgb(226 232 240)" />
            ))}
            {members.map((m) => (
              <text
                key={`${m.zone_id}-${m.track_id}`}
                x={12}
                y={20 + members.findIndex((x) => x === m) * 14}
                fill="rgb(125 211 252)"
                fontSize={12}
              >
                #{m.track_id} in {m.zone_id} ({m.dwell_seconds.toFixed(1)}s)
              </text>
            ))}
          </svg>

          <div className="mt-3 grid gap-2 md:grid-cols-2">
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Zone name"
              className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm"
            />
            <select
              value={zoneType}
              onChange={(e) => setZoneType(e.target.value as ZoneType)}
              className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm"
            >
              {ZONE_TYPES.map((t) => (
                <option key={t}>{t}</option>
              ))}
            </select>
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm"
            >
              {SEVERITIES.map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
            <input
              value={dwell}
              onChange={(e) => setDwell(e.target.value)}
              placeholder="Dwell seconds (blank = default)"
              inputMode="decimal"
              className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm"
            />
          </div>

          <div className="mt-3 flex gap-2">
            <button
              onClick={() => void save()}
              disabled={!valid}
              className="rounded-lg bg-emerald-700 px-3 py-1.5 text-sm disabled:opacity-40"
            >
              {editing ? "Save changes" : "Create zone"}
            </button>
            <button
              onClick={() => setPoints((prev) => prev.slice(0, -1))}
              disabled={points.length === 0}
              className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm disabled:opacity-40"
            >
              Undo point
            </button>
            <button
              onClick={() => setPoints([])}
              disabled={points.length === 0}
              className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm disabled:opacity-40"
            >
              Clear
            </button>
            {editing && (
              <button
                onClick={startCreate}
                className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm hover:bg-slate-700"
              >
                Cancel
              </button>
            )}
          </div>
          <p className="mt-2 text-xs text-slate-500">
            {points.length} point(s) · minimum 3 · coordinates normalized [0,1] ·{" "}
            {valid ? "ready to save" : "add at least 3 points and a name"}
          </p>
        </Card>

        <Card title={`Configured zones (${zones.length})`}>
          {zones.length === 0 ? (
            <p className="text-sm text-slate-400">No zones for this camera yet.</p>
          ) : (
            <ul className="space-y-2">
              {zones.map((z) => (
                <li key={z.zone_id} className="rounded-lg border border-slate-800 p-2">
                  <div className="flex items-center justify-between">
                    <p className="font-semibold">{z.name}</p>
                    <div className="flex gap-1 text-xs">
                      <span className="rounded-full bg-slate-500/15 px-2 py-0.5">{z.zone_type}</span>
                      <span className="rounded-full bg-slate-500/15 px-2 py-0.5">{z.severity}</span>
                      <span
                        className={`rounded-full px-2 py-0.5 ${z.enabled ? "bg-emerald-500/15 text-emerald-300" : "bg-slate-500/15 text-slate-400"}`}
                      >
                        {z.enabled ? "enabled" : "disabled"}
                      </span>
                    </div>
                  </div>
                  <p className="text-xs text-slate-400">
                    {z.zone_id} · {z.polygon.length} points · dwell{" "}
                    {z.dwell_threshold_seconds === null ? "default" : `${z.dwell_threshold_seconds}s`}
                  </p>
                  <div className="mt-1 flex gap-2 text-xs">
                    <button onClick={() => startEdit(z)} className="rounded bg-slate-800 px-2 py-1 hover:bg-slate-700">
                      Edit
                    </button>
                    <button onClick={() => void toggle(z)} className="rounded bg-slate-800 px-2 py-1 hover:bg-slate-700">
                      {z.enabled ? "Disable" : "Enable"}
                    </button>
                    <button
                      onClick={() => void remove(z)}
                      className="rounded bg-red-900/60 px-2 py-1 hover:bg-red-800/60"
                    >
                      Delete
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <Card title={`Spatial events (${spatialEvents.length})`}>
        {spatialEvents.length === 0 ? (
          <p className="text-sm text-slate-400">
            No zone or proximity events yet. Start the camera stream to generate spatial reasoning.
          </p>
        ) : (
          <ul className="space-y-1 text-xs">
            {spatialEvents.slice(0, 12).map((e) => (
              <li key={e.event_id} className="flex items-center justify-between gap-2">
                <span className="truncate">{e.message}</span>
                <span className="shrink-0 text-slate-400">
                  {e.event_type} · {e.severity} · {e.status}
                </span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
