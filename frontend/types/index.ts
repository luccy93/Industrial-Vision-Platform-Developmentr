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

export type InferenceStatus = {
  loaded: boolean;
  state: string;
  model_name: string;
  device: string;
  class_count: number;
  confidence_threshold: number;
  inference_fps: number;
  average_latency_ms: number;
  detections_per_frame: number;
  active_workers: number;
};

export type DetectionSummary = {
  camera_id: string;
  inference_running: boolean;
  count: number;
  results: Array<{
    frame_id: string;
    timestamp: string;
    inference_time_ms: number;
    model_name: string;
    device: string;
    detections: Array<{
      class_id: number;
      class_name: string;
      confidence: number;
      bounding_box: { x1: number; y1: number; x2: number; y2: number };
    }>;
  }>;
};

export type TrackSummary = {
  camera_id: string;
  tracking_running: boolean;
  count: number;
  tracks: Array<{
    track_id: number;
    class_id: number;
    class_name: string;
    confidence: number;
    bounding_box: { x1: number; y1: number; x2: number; y2: number };
    state: string;
    age: number;
    hits: number;
    time_since_update: number;
    velocity: { x: number; y: number; speed: number };
  }>;
};

export type SafetyEventItem = {
  event_id: string;
  camera_id: string;
  event_type: string;
  severity: string;
  status: string;
  track_ids: number[];
  confidence: number;
  timestamp: string;
  first_seen: string;
  last_seen: string;
  duration_ms: number;
  message: string;
};

export type SafetyStatus = {
  enabled: boolean;
  engine_status: string;
  rules_loaded: string[];
  active_camera_count: number;
  active_event_count: number;
  average_latency_ms: number;
};

export const NAV_ITEMS: NavItem[] = [
  { href: "/", label: "Overview", note: "V01 foundation" },
  { href: "/cameras", label: "Cameras", note: "V03 detection" },
  { href: "/safety", label: "Safety", note: "V05 intelligence" },
  { href: "/dashboard", label: "Dashboard", note: "Shell — live views in later volumes" },
  { href: "/system", label: "System", note: "API / DB / Redis status" }
];
