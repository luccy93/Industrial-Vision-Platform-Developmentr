export type HealthState = {
  status: string;
  service?: string;
  env?: string;
  checks?: Record<string, { status: string } & Record<string, unknown>>;
};

export type NavItem = {
  href: string;
  label: string;
  note: string;
};

export type CameraItem = {
  camera_id: string;
  name: string;
  source_type: string;
  source: string;
  enabled: boolean;
  width?: number | null;
  height?: number | null;
  target_fps?: number | null;
};

export type StreamStatus = {
  camera_id: string;
  configured: boolean;
  enabled: boolean;
  state: string;
  metrics?: {
    state: string;
    source_fps: number;
    processing_fps: number;
    frames_received: number;
    frames_processed: number;
    frames_dropped: number;
    latency_ms: number;
    width?: number | null;
    height?: number | null;
    uptime_seconds: number;
    reconnect_count: number;
  };
  last_error?: string;
};

export const NAV_ITEMS: NavItem[] = [
  { href: "/", label: "Overview", note: "V01 foundation" },
  { href: "/cameras", label: "Cameras", note: "V02 ingestion" },
  { href: "/dashboard", label: "Dashboard", note: "Shell — live views in later volumes" },
  { href: "/system", label: "System", note: "API / DB / Redis status" }
];
