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
  spatial?: boolean;
};

export type SafetyStatus = {
  enabled: boolean;
  engine_status: string;
  rules_loaded: string[];
  active_camera_count: number;
  active_event_count: number;
  average_latency_ms: number;
};

export type ZoneType = "RESTRICTED" | "DANGER" | "WARNING" | "SAFE" | "CUSTOM";

export type ZonePoint = {
  x: number;
  y: number;
};

export type ZoneItem = {
  zone_id: string;
  camera_id: string;
  name: string;
  zone_type: ZoneType;
  polygon: ZonePoint[];
  enabled: boolean;
  severity: string;
  dwell_threshold_seconds: number | null;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
};

export type ZoneMembership = {
  camera_id: string;
  zone_id: string;
  track_id: number;
  inside: boolean;
  entered_at: string | null;
  dwell_seconds: number;
};

export type SpatialStatus = {
  enabled: boolean;
  engine_status: string;
  coordinate_space: string;
  membership_heuristic: string;
  default_dwell_seconds: number;
  state_grace_seconds: number;
  proximity_strategy: string;
  proximity_iou_threshold: number;
  relationships: Array<{
    relationship: string;
    enabled: boolean;
    threshold: number;
    severity: string;
  }>;
  zone_count: number;
  camera_count: number;
  active_state_count: number;
};

// --- V07 quality inspection ---

export type InspectionType =
  | "GENERAL"
  | "SURFACE"
  | "ASSEMBLY"
  | "COMPONENT"
  | "DIMENSION"
  | "CUSTOM";

export type RegionType = "RECTANGLE" | "POLYGON";

export type DefectSeverity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type QualityDecision = "PASS" | "FAIL" | "REVIEW" | "ERROR";

export type QualityEventType =
  | "QUALITY_FAIL"
  | "QUALITY_REVIEW"
  | "QUALITY_ERROR"
  | "DEFECT_DETECTED";

export type QualityEventStatus = "ACTIVE" | "RESOLVED" | "SUPPRESSED";

export type DecisionPolicy = {
  fail_threshold: number;
  review_threshold: number;
  fail_severities: DefectSeverity[];
  review_severities: DefectSeverity[];
  required_region_ids: string[];
  missing_evidence_behavior: "REVIEW" | "FAIL" | "IGNORE";
  error_behavior: "RECORD_ERROR" | "SKIP";
};

export type InspectionRegion = {
  region_id: string;
  camera_id: string;
  profile_id: string;
  name: string;
  region_type: RegionType;
  geometry: Record<string, unknown>;
  enabled: boolean;
  required: boolean;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
};

export type DefectCategory = {
  defect_id: string;
  code: string;
  name: string;
  description: string;
  severity: DefectSeverity;
  enabled: boolean;
  confidence_threshold: number;
  review_threshold: number;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
};

export type InspectionProfile = {
  profile_id: string;
  camera_id: string;
  name: string;
  enabled: boolean;
  inspection_type: InspectionType;
  confidence_threshold: number;
  review_threshold: number;
  decision_policy: DecisionPolicy;
  product_correlation: {
    product_id: string | null;
    batch_id: string | null;
    work_order_id: string | null;
    unit_id: string | null;
  } | null;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
};

export type DefectObservation = {
  observation_id: string;
  defect_code: string;
  defect_name: string;
  severity: DefectSeverity;
  confidence: number;
  bounding_box: [number, number, number, number] | null;
  region_id: string | null;
  track_id: number | null;
};

export type InspectionResult = {
  inspection_id: string;
  camera_id: string;
  profile_id: string;
  frame_id: string | null;
  decision: QualityDecision;
  decision_reason: string;
  severity: DefectSeverity;
  observations: DefectObservation[];
  inspection_time_ms: number;
  model_name: string | null;
  model_version: string | null;
  regions_evaluated: string[];
  error_code: string | null;
  timestamp: string;
};

export type QualityEvent = {
  event_id: string;
  inspection_id: string | null;
  event_type: QualityEventType;
  decision: QualityDecision;
  severity: DefectSeverity;
  status: QualityEventStatus;
  confidence: number;
  defect_code: string | null;
  region_id: string | null;
  track_id: number | null;
  timestamp: string;
  first_seen: string;
  last_seen: string;
  duration_ms: number;
  message: string;
  observations: number;
};

export type QualityStatus = {
  enabled: boolean;
  engine_status: string;
  model_status: string;
  model_name: string | null;
  model_version: string | null;
  active_profiles: number;
  active_sessions: number;
  inspection_count: number;
  pass_count: number;
  fail_count: number;
  review_count: number;
  error_count: number;
  defect_count: number;
  average_inspection_ms: number;
  last_inspection_timestamp: string | null;
  frames_skipped: number;
  inspection_fps: number;
  cameras: Record<
    string,
    {
      profiles: number;
      sessions: number;
      inspections: number;
      last_decision: QualityDecision | null;
      last_inspection_at: string | null;
    }
  >;
};

export const NAV_ITEMS: NavItem[] = [
  { href: "/", label: "Overview", note: "V01 foundation" },
  { href: "/cameras", label: "Cameras", note: "V03 detection" },
  { href: "/safety", label: "Safety", note: "V05 intelligence" },
  { href: "/zones", label: "Zones", note: "V06 spatial engine" },
  { href: "/quality", label: "Quality", note: "V07 inspection" },
  { href: "/autonomous", label: "Autonomous", note: "V08 perception" },
  { href: "/dashboard", label: "Dashboard", note: "Shell — live views in later volumes" },
  { href: "/system", label: "System", note: "API / DB / Redis status" }
];

// --- V08 autonomous perception ---

export type SceneType =
  | "ROAD"
  | "PARKING"
  | "WAREHOUSE"
  | "INDUSTRIAL_YARD"
  | "INDOOR_MOBILE_ROBOT"
  | "UNKNOWN";

export type PerceivedObjectState =
  | "MOVING"
  | "STATIONARY"
  | "APPROACHING"
  | "RECEDING"
  | "CROSSING"
  | "UNKNOWN";

export type LaneType = "SOLID" | "DASHED" | "DOUBLE_SOLID" | "UNKNOWN";

export type RiskLevel = "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "UNKNOWN";

export type PerceptionEventType =
  | "COLLISION_RISK"
  | "LANE_DEPARTURE_RISK"
  | "OBJECT_APPROACH"
  | "OBJECT_CROSSING"
  | "SCENE_CHANGE";

export type Availability = "AVAILABLE" | "NOT_CONFIGURED" | "ESTIMATED" | "UNKNOWN";

export type PerceivedObject = {
  object_id: string;
  track_id: number | null;
  class_name: string;
  confidence: number;
  bounding_box: [number, number, number, number] | null;
  velocity: [number, number] | null;
  relative_depth: number | null;
  depth_source: string;
  object_state: PerceivedObjectState;
};

export type LaneItem = {
  lane_id: string;
  points: Array<{ x: number; y: number }>;
  confidence: number;
  lane_type: LaneType;
  side: string | null;
};

export type CollisionRiskItem = {
  object_ids: [string, string];
  risk_level: RiskLevel;
  risk_score: number;
  time_to_collision: number | null;
  confidence: number;
  reason: string;
};

export type PerceptionEvent = {
  event_id: string;
  event_type: PerceptionEventType;
  risk_level: RiskLevel;
  object_ids: string[];
  confidence: number;
  status: "ACTIVE" | "RESOLVED";
  timestamp: string;
  duration_ms: number;
  message: string;
};

export type AutonomousResult = {
  scene_id: string;
  camera_id: string;
  frame_id: string | null;
  timestamp: string;
  scene_type: SceneType;
  objects: PerceivedObject[];
  lanes: LaneItem[];
  trajectories: Array<{
    object_id: string;
    points: Array<{ x: number; y: number }>;
    horizon_seconds: number;
    confidence: number;
  }>;
  collision_risks: CollisionRiskItem[];
  processing_time_ms: number;
};

export type AutonomousProfile = {
  profile_id: string;
  camera_id: string;
  name: string;
  enabled: boolean;
  scene_type: SceneType;
  lane_detection_enabled: boolean;
  depth_enabled: boolean;
  trajectory_enabled: boolean;
  collision_risk_enabled: boolean;
  bev_enabled: boolean;
  trajectory_horizon_seconds: number;
  collision_risk_threshold: number;
  collision_grace_seconds: number;
  configuration: Record<string, unknown>;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
};

export type AutonomousStatus = {
  enabled: boolean;
  engine_status: string;
  scene_classifier_status: string;
  lane_detector_status: string;
  depth_status: string;
  trajectory_status: string;
  collision_status: string;
  bev_status: string;
  active_profiles: number;
  active_cameras: number;
  tracked_objects: number;
  perception_count: number;
  average_perception_ms: number;
  last_perception_timestamp: string | null;
  frames_skipped: number;
  perception_fps: number;
  cameras: Record<
    string,
    {
      profiles: number;
      perceptions: number;
      last_scene_type: SceneType | null;
      last_perception_at: string | null;
    }
  >;
};
