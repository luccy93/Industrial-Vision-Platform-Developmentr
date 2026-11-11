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
  /** Roles allowed to see this entry. Omitted = any authenticated role. */
  roles?: AuthRole[];
};

export type AuthRole = "ADMIN" | "OPERATOR" | "VIEWER";

export type AuthUser = {
  id: string;
  email: string;
  role: AuthRole;
  is_active: boolean;
  must_change_password: boolean;
  last_login_at: string | null;
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
  { href: "/intelligence", label: "Intelligence", note: "V09 event & risk" },
  { href: "/incidents", label: "Incidents", note: "V10 management" },
  { href: "/dashboard", label: "Dashboard", note: "Shell — live views in later volumes" },
  { href: "/analytics", label: "Analytics", note: "V14 historical reporting" },
  { href: "/notifications", label: "Notifications", note: "V15 alerting" },
  { href: "/integrity", label: "Integrity", note: "V33 continuous audit" },
  { href: "/forensics", label: "Forensics", note: "V34 incident response" },
  { href: "/governance", label: "Governance", note: "V35 retention & compliance" },
  { href: "/users", label: "Users", note: "V16 administration", roles: ["ADMIN"] },
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

// --- V09 event & risk intelligence ---

export type UnifiedEvent = {
  event_id: string;
  source_event_id: string;
  camera_id: string;
  source_domain: string;
  event_type: string;
  severity: string;
  status: string;
  confidence: number;
  risk_score: number;
  priority: string;
  timestamp: string;
  first_seen: string;
  last_seen: string;
  track_ids: number[];
  object_ids: string[];
  related_event_ids: string[];
  location: string | null;
  message: string;
  reason: string;
};

export type RiskFactorView = {
  name: string;
  value: number;
  weight: number;
  contribution: number;
  reason: string;
};

export type RiskClusterView = {
  cluster_id: string;
  camera_id: string;
  event_ids: string[];
  track_ids: number[];
  object_ids: string[];
  source_domains: string[];
  first_seen: string;
  last_seen: string;
  event_count: number;
  risk_level: string;
  risk_score: number;
  priority: string;
  status: string;
  factors: RiskFactorView[];
};

export type IntelligenceStatus = {
  engine_status: string;
  active_events: number;
  active_clusters: number;
  highest_risk: {
    risk_score: number;
    risk_level: string;
    confidence: number;
  };
  highest_priority: string;
  metrics: Record<string, number>;
  configuration: Record<string, number | string | boolean>;
  domains: Record<string, { available: boolean; active_events: number }>;
};

// --- V10 incident management ---

export type IncidentStatus =
  | "OPEN"
  | "ACKNOWLEDGED"
  | "INVESTIGATING"
  | "MITIGATED"
  | "RESOLVED"
  | "CLOSED";

export type IncidentCategory =
  | "SAFETY"
  | "SECURITY"
  | "QUALITY"
  | "COLLISION"
  | "SPATIAL"
  | "OPERATIONAL"
  | "SYSTEM"
  | "UNKNOWN";

export type IncidentPriority = "P0" | "P1" | "P2" | "P3" | "P4";

export type IncidentSummary = {
  id: string;
  incident_number: string;
  camera_id: string;
  title: string;
  status: IncidentStatus;
  category: IncidentCategory;
  priority: IncidentPriority;
  severity: string;
  risk_level: string;
  risk_score: number;
  assigned_to: string | null;
  source: string;
  first_seen: string;
  last_seen: string;
  created_at: string;
};

export type TimelineEntryView = {
  id: string;
  event_type: string;
  actor_id: string | null;
  actor_type: string;
  message: string;
  previous_state: string | null;
  new_state: string | null;
  timestamp: string;
};

export type EvidenceView = {
  id: string;
  camera_id: string;
  evidence_type: string;
  uri: string;
  timestamp: string;
  frame_id: string | null;
  description: string;
  checksum: string | null;
  created_at: string;
};

export type LinkedEventView = {
  event_id: string;
  event_type: string;
  source_domain: string;
  is_primary: boolean;
  created_at: string;
};

export type IncidentDetail = {
  incident: IncidentSummary & {
    description: string;
    source_cluster_id: string | null;
    primary_event_id: string | null;
    updated_at: string;
    acknowledged_at: string | null;
    resolved_at: string | null;
    closed_at: string | null;
    metadata: Record<string, unknown>;
  };
  timeline: TimelineEntryView[];
  linked_events: LinkedEventView[];
  evidence: EvidenceView[];
  assignment: {
    assigned_to: string | null;
    history: Array<{
      assignee: string | null;
      previous_assignee: string | null;
      actor_id: string | null;
      timestamp: string;
    }>;
  };
  risk_summary: {
    risk_level: string;
    risk_score: number;
    priority: string;
    severity: string;
  };
  allowed_actions: string[];
};

export type IncidentListResponse = {
  incidents: IncidentSummary[];
  total: number;
  page: number;
  page_size: number;
};

// --- V13 operations dashboard ---

export type SectionState = "ok" | "degraded" | "unavailable";

export type SectionMeta = {
  status: SectionState;
  message: string;
  updated_at: string;
};

export type CamerasSection = SectionMeta & {
  configured: number;
  enabled: number;
  by_state: Record<string, number>;
};

export type SafetySection = SectionMeta & {
  total_active: number;
  by_severity: Record<string, number>;
  cameras_with_events: number;
  truncated: boolean;
};

export type IncidentsSection = SectionMeta & {
  total: number;
  open_total: number;
  by_status: Record<string, number>;
  by_priority: Record<string, number>;
};

export type QualitySection = SectionMeta & {
  model_status: string;
  outcomes: Record<string, number>;
  active_profiles: number;
};

export type RiskSection = SectionMeta & {
  risk_level: string;
  risk_score: number;
  priority: string;
  active_events: number;
  active_clusters: number;
};

export type HealthSection = SectionMeta & {
  ready: boolean;
  readiness: string;
  checks: Record<string, string>;
};

export type OperationsSummary = {
  timestamp: string;
  cameras: CamerasSection;
  safety: SafetySection;
  incidents: IncidentsSection;
  quality: QualitySection;
  risk: RiskSection;
  health: HealthSection;
};

export type OperationsWsMessage = {
  type?: string;
  event_type?: string;
  camera_id?: string;
  timestamp?: string;
  [key: string]: unknown;
};

export type TimelineKind =
  | "safety"
  | "spatial"
  | "quality"
  | "autonomous"
  | "intelligence"
  | "incident";

export type TimelineItem = {
  /** Stable identity for dedup (event_id / cluster_id / incident timeline id). */
  id: string;
  kind: TimelineKind;
  /** Wire or envelope event type, e.g. safety_event, incident_created. */
  eventType: string;
  severity: string;
  cameraId: string;
  timestamp: string;
  title: string;
  /** Existing detail destination, when one exists. */
  href: string | null;
  source: "rest" | "socket";
};

// --- V14 historical analytics & reporting ---

export type AnalyticsSectionState = "ok" | "degraded" | "unavailable";

export type AnalyticsSectionMeta = {
  status: AnalyticsSectionState;
  message: string;
};

export type AnalyticsPreset = "24h" | "7d" | "30d" | "custom";

export type AnalyticsFilters = {
  preset: AnalyticsPreset;
  /** ISO-8601 UTC bounds; required when preset is custom. */
  startAt: string | null;
  endAt: string | null;
  bucket: "hour" | "day" | "week";
  domains: string[];
  severities: string[];
  cameras: string[];
  statuses: string[];
  priorities: string[];
};

/** Query params actually sent (validated: start < end, bounded window). */
export type AnalyticsQuery = {
  start_at: string;
  end_at: string;
  bucket: "hour" | "day" | "week";
  domain?: string[];
  severity?: string[];
  camera_id?: string;
  status?: string[];
  priority?: string[];
};

export type AnalyticsBucket = {
  bucket_start: string;
  count: number;
};

export type AnalyticsTrend = {
  metric: string;
  bucket: "hour" | "day" | "week";
  buckets: AnalyticsBucket[];
  truncated: boolean;
};

export type AnalyticsBreakdown = {
  dataset: string;
  group_by: string;
  groups: Array<{ key: string; label: string; count: number }>;
  truncated: boolean;
};

export type QualityAvailability = AnalyticsSectionMeta & {
  reason: string;
};

export type AnalyticsOverview = {
  start_at: string;
  end_at: string;
  generated_at: string;
  events: AnalyticsSectionMeta & {
    total: number;
    by_domain: Record<string, number>;
    by_severity: Record<string, number>;
    truncated: boolean;
  };
  incidents: AnalyticsSectionMeta & {
    created_total: number;
    open_total: number;
    resolved_total: number;
    closed_total: number;
    by_status: Record<string, number>;
    by_priority: Record<string, number>;
    resolution: {
      count: number;
      average_seconds: number | null;
      median_seconds: number | null;
      min_seconds: number | null;
      max_seconds: number | null;
    };
  };
  quality: QualityAvailability;
  cameras: AnalyticsSectionMeta & {
    by_camera: Record<string, number>;
  };
};

export type ExportReportType =
  | "events"
  | "incidents"
  | "safety"
  | "camera_activity"
  | "quality_events";

// --- V15 alerting & notifications ---

export type AlertChannel = "in_app" | "email" | "webhook";

export type AlertRule = {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  domains: string[];
  event_types: string[];
  min_severity: string | null;
  min_priority: string | null;
  camera_ids: string[];
  incident_statuses: string[];
  channels: AlertChannel[];
  cooldown_seconds: number;
  suppression_scope: string;
  trigger_count: number;
  suppressed_count: number;
  last_triggered_at: string | null;
  created_at: string | null;
  updated_at: string | null;
};

export type AlertRuleListResponse = {
  rules: AlertRule[];
  total: number;
  page: number;
  page_size: number;
};

export type NotificationItem = {
  id: string;
  rule_id: string;
  source_event_id: string;
  source_domain: string;
  event_type: string;
  camera_id: string | null;
  incident_id: string | null;
  title: string;
  message: string;
  severity: string;
  priority: string;
  context: Record<string, unknown>;
  created_at: string | null;
};

export type NotificationListResponse = {
  notifications: NotificationItem[];
  total: number;
  page: number;
  page_size: number;
};

export type DeliveryItem = {
  id: string;
  notification_id: string;
  channel: string;
  destination: string;
  status: string;
  attempts: number;
  next_retry_at: string | null;
  last_attempt_at: string | null;
  delivered_at: string | null;
  last_error: string | null;
  created_at: string | null;
};

export type DeliveryListResponse = {
  deliveries: DeliveryItem[];
  total: number;
  page: number;
  page_size: number;
};

export type NotificationDetail = NotificationItem & {
  deliveries: DeliveryItem[];
};

export type AlertingStatus = {
  enabled: boolean;
  evaluator: { state: string } | null;
  delivery_worker: { state: string } | null;
  channels: Record<string, { available: boolean; destinations?: number }>;
  deliveries: Record<string, number>;
  security_note: string;
};

// --- V33 continuous integrity monitoring ---

export type IntegrityScope =
  | "EVIDENCE"
  | "SIGNED_CHECKPOINTS"
  | "TRANSPARENCY_LOG"
  | "TREE_HEADS"
  | "INCLUSION_PROOFS"
  | "CONSISTENCY_PROOFS"
  | "TRUST_STATE"
  | "FULL";

export type IntegrityAuditStatus = "PASS" | "FAIL" | "PARTIAL" | "UNAVAILABLE" | "NOT_RUN" | "RUNNING";

export type IntegritySeverity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type IntegrityFinding = {
  finding_id: string;
  audit_run_id: string;
  scope: IntegrityScope;
  severity: IntegritySeverity;
  reason_code: string;
  artifact_id: string | null;
  detected_at: string;
  explanation: string;
  verification_source: string;
  recommended_action: string;
};

export type IntegrityScopeResult = {
  audit_run_id: string;
  scope: IntegrityScope;
  status: Exclude<IntegrityAuditStatus, "RUNNING">;
  started_at: string;
  completed_at: string;
  duration_ms: number;
  artifacts_checked: number;
  checks_total: number;
  checks_failed: number;
  findings_count: number;
  reason_codes: string[];
  error_summary: string | null;
  truncated: boolean;
  details: Record<string, unknown>;
};

export type IntegrityAuditSummary = {
  audit_run_id: string;
  trigger: "MANUAL" | "SCHEDULED";
  requested_scopes: IntegrityScope[];
  completed_scopes: IntegrityScope[];
  status: IntegrityAuditStatus;
  started_at: string;
  completed_at: string | null;
  duration_ms: number;
  cancelled: boolean;
  timed_out: boolean;
  retry_count: number;
  artifacts_checked: number;
  finding_counts: Record<string, number>;
  reason_code_counts: Record<string, number>;
  error_summary: string | null;
  external_anchor_configured: boolean;
  assurance: string;
  requested_by: string | null;
  created_at: string;
  schedule_slot?: string | null;
};

export type IntegrityTrustOverview = {
  trusted_key_count: number;
  active_key_count: number;
  expired_key_count: number;
  revoked_key_count: number;
  unknown_key_count: number;
  evidence_trust_state: string;
  transparency_trust_state: string;
  latest_tree_head_size: number | null;
  latest_tree_head_digest: string | null;
  latest_tree_head_id: string | null;
  external_anchor_status: string;
  external_anchor_detail: string;
  assurance: string;
  limitations: string[];
};

export type IntegritySchedulerStatus = {
  enabled: boolean;
  state: string;
  interval_seconds: number;
  stale_run_seconds?: number;
  last_heartbeat?: string | null;
  last_cycle_at?: string | null;
  last_success_at?: string | null;
  last_error?: string | null;
  cycles?: number;
  runs_started?: number;
};

export type IntegrityStatus = {
  enabled: boolean;
  store_status: string;
  store_error: string | null;
  latest_audit: IntegrityAuditSummary | null;
  last_success: IntegrityAuditSummary | null;
  last_failure: IntegrityAuditSummary | null;
  running_audits: number;
  total_audits: number;
  total_audited_artifacts: number;
  verified_evidence_count: number;
  verified_checkpoint_count: number;
  verified_tree_head_count: number;
  open_findings: number;
  findings_by_severity: Record<string, number>;
  trust: IntegrityTrustOverview;
  scheduler: IntegritySchedulerStatus;
  external_anchor_configured: boolean;
  assurance: string;
  generated_at: string;
};

export type IntegritySummary = {
  total_runs: number;
  by_status: Record<string, number>;
  by_trigger: Record<string, number>;
  by_severity: Record<string, number>;
  by_reason_code: Record<string, number>;
  by_scope: Record<string, number>;
  total_findings: number;
  total_audited_artifacts: number;
  verified: Record<string, number>;
  last_success: IntegrityAuditSummary | null;
  last_failure: IntegrityAuditSummary | null;
  latest_audit: IntegrityAuditSummary | null;
  running_audits: number;
  open_findings: number;
  scheduler: IntegritySchedulerStatus;
  retention_days: number;
  page_size_default: number;
  page_size_max: number;
  external_anchor_configured: boolean;
  assurance: string;
  generated_at: string;
};

export type IntegrityAuditListResponse = {
  items: IntegrityAuditSummary[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
};

export type IntegrityFindingListResponse = {
  items: IntegrityFinding[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
};

export type IntegrityAuditDetail = {
  audit: IntegrityAuditSummary;
  scope_results: IntegrityScopeResult[];
  findings: IntegrityFinding[];
  findings_total: number;
};

export type IntegrityAuditRunResponse = IntegrityAuditSummary & {
  scope_results?: IntegrityScopeResult[];
  findings?: IntegrityFinding[];
  findings_total?: number;
};
// --- V34 integrity incident response & forensics ---

export type ForensicCaseType =
  | "EVIDENCE_TAMPERING"
  | "CHECKPOINT_COMPROMISE"
  | "SIGNATURE_FAILURE"
  | "TRANSPARENCY_CONFLICT"
  | "TRUST_KEY_COMPROMISE"
  | "CHAIN_OF_CUSTODY_FAILURE"
  | "FORENSIC_REVIEW"
  | "OTHER";

export type ForensicCaseStatus =
  | "OPEN"
  | "TRIAGED"
  | "INVESTIGATING"
  | "CONTAINMENT_RECOMMENDED"
  | "AWAITING_REVIEW"
  | "RESOLVED"
  | "CLOSED";

export type ForensicCaseSource = "MANUAL" | "CORRELATION" | "SYSTEM";

export type ForensicVerificationOutcome = "PASS" | "FAIL" | "PARTIAL" | "UNAVAILABLE" | "NOT_RUN";

export type ForensicFindingClassification =
  | "CONFIRMED_FAILURE"
  | "SUSPICIOUS"
  | "UNAVAILABLE"
  | "NOT_RUN"
  | "SIMULATED"
  | "OPERATIONAL";

export type ForensicArtifactType =
  | "V33_FINDING"
  | "V33_AUDIT_RUN"
  | "EVIDENCE_FILE"
  | "EVIDENCE_SIDECAR"
  | "EVIDENCE_AUDIT_CHAIN"
  | "SIGNED_CHECKPOINT"
  | "TRUST_STATE"
  | "TRUST_STORE"
  | "TRANSPARENCY_LOG"
  | "TREE_HEAD"
  | "INCLUSION_PROOF"
  | "CONSISTENCY_PROOF"
  | "RECEIPT"
  | "INCIDENT"
  | "OPERATIONAL_LOG"
  | "OTHER";

export type ForensicNoteType =
  | "OBSERVATION"
  | "ANALYSIS"
  | "HYPOTHESIS"
  | "ACTION"
  | "CONCLUSION"
  | "HANDOVER";

export type ForensicCase = {
  case_id: string;
  case_number: string;
  title: string;
  description: string;
  case_type: ForensicCaseType;
  severity: IntegritySeverity;
  status: ForensicCaseStatus;
  priority: string;
  source: ForensicCaseSource;
  originating_incident_id: string | null;
  originating_audit_run_id: string | null;
  created_by: string | null;
  assigned_to: string | null;
  version: number;
  resolution_summary: string | null;
  correlation_key: string | null;
  custody_event_count: number;
  custody_head_hash: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  closed_at: string | null;
};

export type ForensicCorrelation = {
  correlation_id: string;
  case_id: string;
  correlation_key: string;
  finding_id: string | null;
  audit_run_id: string | null;
  artifact_id: string | null;
  evidence_identifier: string | null;
  reason_code: string | null;
  classification: ForensicFindingClassification;
  severity: IntegritySeverity;
  resolved: boolean;
  metadata: Record<string, unknown>;
  created_at: string;
};

export type ForensicIncidentLink = {
  link_id: string;
  case_id: string;
  incident_id: string;
  linked_by: string | null;
  linked_at: string;
  metadata: Record<string, unknown>;
};

export type ForensicEvidenceReference = {
  reference_id: string;
  case_id: string;
  artifact_type: ForensicArtifactType;
  artifact_id: string;
  original_relative_path: string;
  expected_sha256: string;
  observed_sha256: string;
  source_audit_run_id: string | null;
  source_finding_id: string | null;
  capture_timestamp: string | null;
  verification_status: ForensicVerificationOutcome;
  verification_outcome: ForensicVerificationOutcome;
  verification_detail: string;
  reference_created_at: string;
  metadata: Record<string, unknown>;
};

export type ForensicCustodyEvent = {
  event_id: string;
  case_id: string;
  sequence: number;
  event_type: string;
  timestamp: string;
  actor_id: string;
  actor_role: string;
  artifact_id: string | null;
  previous_hash: string;
  event_hash: string;
  metadata: Record<string, unknown>;
};

export type ForensicCustodyVerification = {
  outcome: ForensicVerificationOutcome;
  event_count: number;
  head_hash: string | null;
  expected_head_hash: string | null;
  checks: Array<{ name: string; outcome: ForensicVerificationOutcome; detail: string; reason_code?: string }>;
  reason_codes: string[];
  limitations: string[];
  assurance: string;
  external_anchor_claimed: false;
  external_anchor_note: string;
};

export type ForensicNote = {
  note_id: string;
  case_id: string;
  author_id: string;
  note_type: ForensicNoteType;
  content: string;
  visibility: "INTERNAL" | "RESTRICTED";
  related_evidence_ids: string[];
  version: number;
  edited_by: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
};

export type ForensicNoteRevision = {
  revision_id: string;
  note_id: string;
  case_id: string;
  revision: number;
  content: string;
  editor_id: string;
  edited_at: string;
  metadata: Record<string, unknown>;
};

export type ForensicAction = {
  action_id: string;
  case_id: string;
  actor_id: string;
  action_type: string;
  description: string;
  related_finding_ids: string[];
  action_timestamp: string;
  result: string;
  approval_reference: string | null;
  metadata: Record<string, unknown>;
};

export type ForensicAssignment = {
  assignment_id: string;
  case_id: string;
  assignee: string | null;
  previous_assignee: string | null;
  actor_id: string;
  reason: string;
  timestamp: string;
  metadata: Record<string, unknown>;
};

export type ForensicExportRecord = {
  export_id: string;
  case_id: string;
  filename: string;
  storage_relative_path: string;
  sha256: string;
  size_bytes: number;
  file_count: number;
  schema_version: string;
  policy_version: string;
  created_by: string;
  created_at: string;
  verified_at: string | null;
  verification_outcome: ForensicVerificationOutcome;
  verification_detail: string;
  manifest_digest: string;
  root_digest: string;
  evidence_bytes_included: boolean;
  metadata: Record<string, unknown>;
};

export type ForensicVerificationRun = {
  verification_id: string;
  case_id: string;
  actor_id: string;
  outcome: ForensicVerificationOutcome;
  report: ForensicVerificationReport;
  created_at: string;
  metadata: Record<string, unknown>;
};

export type ForensicVerificationCheck = {
  reference_id: string | null;
  artifact_type: string | null;
  artifact_id: string | null;
  outcome: ForensicVerificationOutcome;
  detail: string;
  reason_code?: string;
  observed_sha256?: string;
  size_bytes?: number;
};

export type ForensicVerificationReport = {
  outcome: ForensicVerificationOutcome;
  checks: ForensicVerificationCheck[];
  observations: Array<Record<string, unknown>>;
  reason_codes: string[];
  limitations: string[];
  custody: ForensicCustodyVerification;
  verified_at: string;
  external_anchor_claimed: false;
  external_anchor_note: string;
  assurance: string;
  counts: {
    checks: number;
    passed: number;
    failed: number;
    unavailable: number;
    not_run: number;
  };
};

export type ForensicCaseDetail = {
  case: ForensicCase;
  correlations: ForensicCorrelation[];
  incident_links: ForensicIncidentLink[];
  evidence_references: ForensicEvidenceReference[];
  custody: { events: ForensicCustodyEvent[]; verification: ForensicCustodyVerification };
  notes: ForensicNote[];
  actions: ForensicAction[];
  assignments: ForensicAssignment[];
  exports: ForensicExportRecord[];
  latest_verification: ForensicVerificationRun | null;
  assurance: string;
  external_anchor_claimed: false;
  external_anchor_note: string;
};

export type ForensicCaseSummary = {
  total: number;
  open: number;
  triaged: number;
  investigating: number;
  containment_recommended: number;
  awaiting_review: number;
  resolved: number;
  closed: number;
  critical: number;
  by_status: Record<string, number>;
  by_severity: Record<string, number>;
  by_type: Record<string, number>;
  recent: ForensicCase[];
};

export type ForensicStatus = {
  enabled: boolean;
  summary: ForensicCaseSummary;
  v33_source: "AVAILABLE" | "UNAVAILABLE" | "DISABLED";
  alerting_enabled: boolean;
  export_evidence_bytes_enabled: boolean;
  assurance: string;
  external_anchor_claimed: false;
  external_anchor_note: string;
};

export type ForensicCaseListResponse = {
  items: ForensicCase[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
};

export type ForensicFindingsResponse = {
  items: IntegrityFinding[];
  total: number;
  available: boolean;
  detail?: string;
};

export type ForensicCorrelationResponse = {
  stats: {
    examined: number;
    confirmed: number;
    suspicious: number;
    skipped_unavailable: number;
    skipped_not_run: number;
    skipped_simulated: number;
    skipped_operational: number;
    duplicates: number;
    conflicts: number;
    cases_created: number;
    cases_updated: number;
    incidents_created: number;
    incidents_linked: number;
    failed: number;
  };
};

export type ForensicExportListResponse = { items: ForensicExportRecord[] };

export type ForensicExportVerifyResponse = {
  export: ForensicExportRecord;
  verification: ForensicVerificationReport;
};

// --- V35 forensic governance, retention & compliance readiness ---

export type GovernancePolicyState = "DRAFT" | "ENABLED" | "DISABLED" | "ARCHIVED";

export type GovernancePolicy = {
  policy_id: string;
  version: number;
  name: string;
  state: GovernancePolicyState;
  case_type: string | null;
  evidence_category: string | null;
  retention_days: number | null;
  review_interval_days: number | null;
  required_approval_level: "SINGLE_REVIEWER" | "DUAL_REVIEWER";
  export_allowed: boolean;
  export_requires_approval: boolean;
  allow_evidence_bytes: boolean;
  export_expiry_days: number | null;
  export_review_days: number | null;
  legal_hold_eligible: boolean;
  disposition_review_required: boolean;
  actor_id: string;
  actor_role: string;
  reason: string;
  idempotency_key: string | null;
  created_at: string | null;
  is_default: boolean;
};

export type GovernancePolicyListResponse = {
  items: GovernancePolicy[];
  total: number;
  page: number;
  page_size: number;
};

export type GovernancePolicyVersionsResponse = GovernancePolicyListResponse;

export type GovernanceRetentionState =
  | "ACTIVE"
  | "REVIEW_DUE"
  | "LEGAL_HOLD"
  | "DISPOSITION_REVIEW_REQUIRED"
  | "DISPOSITION_APPROVED"
  | "DISPOSITION_BLOCKED"
  | "NOT_EVALUATED";

export type GovernanceDataStatus = "OK" | "INCOMPLETE" | "UNAVAILABLE";

export type GovernanceRetentionEvaluation = {
  evaluation_id: string;
  case_id: string;
  evaluation_kind: "EVALUATION" | "REVIEW";
  evaluation_version: number;
  policy_id: string | null;
  policy_version: number | null;
  policy_snapshot: Record<string, unknown>;
  as_of: string | null;
  evaluated_at: string | null;
  retention_start: string | null;
  retention_deadline: string | null;
  next_review_at: string | null;
  governance_state: GovernanceRetentionState;
  data_status: GovernanceDataStatus;
  disposition_eligible: boolean;
  integrity_status: string;
  verification_id: string | null;
  legal_hold_ids: string[];
  reasons: string[];
  reviewed_by: string | null;
  review_reason: string | null;
  created_by: string | null;
  request_id: string | null;
  idempotency_key: string | null;
  created_at: string | null;
  deletion_authorized: false;
  deletion_note: string;
};

export type GovernanceRetentionQueueResponse = {
  items: GovernanceRetentionEvaluation[];
  total: number;
  page: number;
  page_size: number;
  as_of: string;
  non_claims: string[];
};

export type GovernanceRetentionCaseResponse = {
  case: Record<string, unknown>;
  evaluation: GovernanceRetentionEvaluation | null;
  state: GovernanceRetentionState;
  non_claims: string[];
};

export type GovernanceLegalHoldStatus =
  | "PENDING_APPROVAL"
  | "ACTIVE"
  | "REJECTED"
  | "RELEASED"
  | "WITHDRAWN";

export type GovernanceLegalHold = {
  hold_id: string;
  hold_number: string;
  case_id: string;
  evidence_reference_id: string | null;
  status: GovernanceLegalHoldStatus;
  scope: string;
  reason: string;
  requested_by: string;
  requested_role: string;
  requested_at: string | null;
  approved_by: string | null;
  approved_at: string | null;
  approval_reason: string | null;
  rejected_by: string | null;
  rejected_at: string | null;
  rejection_reason: string | null;
  released_by: string | null;
  released_at: string | null;
  release_reason: string | null;
  withdrawn_by: string | null;
  withdrawn_at: string | null;
  withdrawal_reason: string | null;
  version: number;
  idempotency_key: string | null;
  created_at: string | null;
  updated_at: string | null;
  metadata: Record<string, unknown>;
};

export type GovernanceLegalHoldEvent = {
  event_id: string;
  hold_id: string;
  event_type: string;
  actor_id: string;
  actor_role: string;
  reason: string;
  from_status: string | null;
  to_status: string | null;
  occurred_at: string | null;
  metadata: Record<string, unknown>;
  created_at: string | null;
};

export type GovernanceLegalHoldListResponse = {
  items: GovernanceLegalHold[];
  total: number;
  page: number;
  page_size: number;
};

export type GovernanceLegalHoldDetail = {
  hold: GovernanceLegalHold;
  events: GovernanceLegalHoldEvent[];
  non_claims: string[];
};

export type GovernanceDispositionStatus =
  | "REVIEW_REQUIRED"
  | "APPROVAL_PENDING"
  | "APPROVED"
  | "BLOCKED"
  | "WITHDRAWN";

export type GovernanceDisposition = {
  disposition_id: string;
  request_number: string;
  case_id: string;
  evaluation_id: string | null;
  status: GovernanceDispositionStatus;
  justification: string;
  requested_by: string;
  requested_role: string;
  requested_at: string | null;
  policy_id: string | null;
  policy_version: number | null;
  required_approval_level: "SINGLE_REVIEWER" | "DUAL_REVIEWER";
  approval_count: number;
  reviewer_id: string | null;
  reviewed_at: string | null;
  decision_reason: string | null;
  blocked_reason_codes: string[];
  version: number;
  idempotency_key: string | null;
  created_at: string | null;
  updated_at: string | null;
  metadata: Record<string, unknown>;
  physical_deletion_performed: false;
  authorizes_future_process: boolean;
  disposition_approval_note: string;
};

export type GovernanceDispositionDecisionRecord = {
  decision_id: string;
  disposition_id: string;
  decision: string;
  actor_id: string;
  actor_role: string;
  reason: string;
  from_status: string;
  to_status: string;
  occurred_at: string | null;
  metadata: Record<string, unknown>;
  created_at: string | null;
};

export type GovernanceDispositionListResponse = {
  items: GovernanceDisposition[];
  total: number;
  page: number;
  page_size: number;
};

export type GovernanceDispositionDetail = {
  disposition: GovernanceDisposition;
  decisions: GovernanceDispositionDecisionRecord[];
  non_claims: string[];
};

export type GovernanceExportApprovalStatus =
  | "PENDING_APPROVAL"
  | "POLICY_AUTO_APPROVED"
  | "APPROVED"
  | "REJECTED"
  | "WITHDRAWN"
  | "GENERATED"
  | "VERIFIED"
  | "FAILED";

export type GovernanceExportApproval = {
  approval_id: string;
  request_number: string;
  case_id: string;
  status: GovernanceExportApprovalStatus;
  reason: string;
  requested_by: string;
  requested_role: string;
  requested_at: string | null;
  policy_id: string | null;
  policy_version: number | null;
  include_evidence_bytes: boolean;
  required_approval_level: "SINGLE_REVIEWER" | "DUAL_REVIEWER";
  approved_by: string | null;
  approved_at: string | null;
  approval_reason: string | null;
  rejected_by: string | null;
  rejected_at: string | null;
  rejection_reason: string | null;
  withdrawn_by: string | null;
  withdrawn_at: string | null;
  withdrawal_reason: string | null;
  export_id: string | null;
  export_sha256: string | null;
  manifest_digest: string | null;
  root_digest: string | null;
  filename: string | null;
  size_bytes: number | null;
  file_count: number | null;
  generated_by: string | null;
  generated_at: string | null;
  generation_error: string | null;
  verified_by: string | null;
  verified_at: string | null;
  verification_outcome: string;
  verification_detail: string;
  expires_at: string | null;
  review_at: string | null;
  version: number;
  idempotency_key: string | null;
  created_at: string | null;
  updated_at: string | null;
  metadata: Record<string, unknown>;
  delivery_claimed: false;
  external_recipient_validated: false;
};

export type GovernanceExportApprovalListResponse = {
  items: GovernanceExportApproval[];
  total: number;
  page: number;
  page_size: number;
};

export type GovernanceAuditEvent = {
  event_id: string;
  event_type: string;
  actor_id: string;
  actor_role: string;
  target_type: string;
  target_id: string;
  case_id: string | null;
  outcome: string;
  reason: string;
  request_id: string | null;
  occurred_at: string;
  event_key: string;
  event_hash: string;
  metadata: Record<string, unknown>;
  created_at: string | null;
};

export type GovernanceAuditListResponse = {
  items: GovernanceAuditEvent[];
  total: number;
  page: number;
  page_size: number;
  assurance: string;
  non_claims: string[];
};

export type GovernanceReportSection = {
  status: string;
  [key: string]: unknown;
};

export type GovernanceReportDetailRow = {
  case_id: string;
  case_number: string | null;
  case_status: string | null;
  case_type: string | null;
  governance_state: GovernanceRetentionState;
  data_status: GovernanceDataStatus;
  policy_id: string | null;
  policy_version: number | null;
  retention_deadline: string | null;
  next_review_at: string | null;
  integrity_status: string;
  disposition_eligible: boolean;
  reasons: string[];
  legal_hold_ids: string[];
  deletion_authorized: false;
};

export type GovernanceComplianceReport = {
  generated_at: string;
  generated_by: string | null;
  as_of: string;
  scope: "SUMMARY" | "DETAIL";
  case_id: string | null;
  format: string;
  assurance: string;
  audit_assurance: string;
  overall_status: string;
  sections: Record<string, GovernanceReportSection>;
  detail: GovernanceReportDetailRow[] | null;
  regulatory_certification_claimed: false;
  external_immutable_storage_claimed: false;
  external_anchor_claimed: false;
  automatic_deletion: false;
  automatic_hold_release: false;
  automatic_disposition_approval: false;
  non_claims: string[];
  limitations: string[];
};

export type GovernanceStatus = {
  enabled: boolean;
  assurance: string;
  policy_count: number;
  evaluation_states: Record<string, number>;
  hold_states: Record<string, number>;
  disposition_states: Record<string, number>;
  export_states: Record<string, number>;
  audit_event_count: number;
  audit_integrity: {
    checked: number;
    verified: number;
    outcome: string;
    assurance: string;
  };
  retention_scheduler: "DISABLED";
  automatic_deletion: false;
  automatic_hold_release: false;
  automatic_disposition_approval: false;
  regulatory_certification_claimed: false;
  external_immutable_storage_claimed: false;
  external_anchor_claimed: false;
  non_claims: string[];
  limitations: string[];
};

// ---------------------------------------------------------------------------
// V36 governance automation
// ---------------------------------------------------------------------------
export type GovernanceAutomationJobType =
  | "RETENTION_EVALUATION"
  | "RETENTION_REVIEW_REMINDERS"
  | "LEGAL_HOLD_REMINDERS"
  | "DISPOSITION_REVIEW_REMINDERS"
  | "EXPORT_APPROVAL_REMINDERS"
  | "COMPLIANCE_SNAPSHOT"
  | "GOVERNANCE_HEALTH_CHECK";

export type GovernanceAutomationJobStatus =
  | "PENDING"
  | "RUNNING"
  | "SUCCEEDED"
  | "FAILED"
  | "CANCELLED"
  | "UNAVAILABLE";

export type GovernanceAutomationTrigger = "SCHEDULE" | "MANUAL" | "RETRY" | "RECOVERY";

export type GovernanceAutomationSchedule = {
  schedule_id: string;
  job_type: GovernanceAutomationJobType;
  enabled: boolean;
  interval_minutes: number;
  config: Record<string, unknown>;
  config_version: number;
  last_slot: string | null;
  last_idempotency_key: string | null;
  updated_by: string | null;
  created_at: string | null;
  updated_at: string | null;
};

export type GovernanceAutomationJob = {
  job_id: string;
  job_type: GovernanceAutomationJobType;
  status: GovernanceAutomationJobStatus;
  trigger: GovernanceAutomationTrigger;
  schedule_slot: string | null;
  dedup_key: string;
  retry_of_job_id: string | null;
  attempt: number;
  max_attempts: number;
  config_version: number | null;
  config_snapshot: Record<string, unknown>;
  requested_by: string | null;
  requested_role: string | null;
  request_id: string | null;
  created_at: string | null;
  available_at: string | null;
  started_at: string | null;
  finished_at: string | null;
  lease_owner: string | null;
  lease_expires_at: string | null;
  heartbeat_at: string | null;
  cancel_requested_at: string | null;
  cancel_requested_by: string | null;
  cancel_requested: boolean;
  result: Record<string, unknown>;
  error_code: string | null;
  error_message: string | null;
};

export type GovernanceAutomationJobEvent = {
  event_id: string;
  job_id: string;
  event_type: string;
  from_status: string | null;
  to_status: string | null;
  actor_id: string | null;
  actor_role: string | null;
  detail: Record<string, unknown>;
  created_at: string | null;
};

export type GovernanceAutomationStatus = {
  enabled: boolean;
  assurance: string;
  scheduler: {
    enabled: boolean;
    state: string;
    running: boolean;
    name?: string;
    queue?: Record<string, number>;
    stale_jobs?: number;
    cycles?: number;
    enqueued?: number;
    executed?: number;
    failed?: number;
    recovered?: number;
    last_cycle_at?: string | null;
    last_success_at?: string | null;
  };
  schedule_count: number;
  enabled_schedule_count: number;
  schedules: GovernanceAutomationSchedule[];
  queue: Record<string, number>;
  job_count: number;
  snapshot_count: number;
  last_jobs: Record<string, GovernanceAutomationJob>;
  stale_jobs: number;
  supported_job_types: string[];
  non_claims: string[];
  limitations: string[];
};

export type GovernanceAutomationHealth = {
  enabled: boolean;
  overall_status: "OK" | "DEGRADED" | "FAILED";
  scheduler: {
    enabled: boolean;
    state: string;
    running: boolean;
    queue?: Record<string, number>;
    stale_jobs?: number;
  };
  governance_audit: {
    outcome: string;
    checked?: number;
    verified?: number;
    assurance?: string;
    error?: string;
  };
  integrity: {
    status: string;
    latest_audit_status?: string;
    store_status?: string;
    open_findings?: number;
    error?: string;
  };
  queue: Record<string, number>;
  stale_jobs: number;
  generated_at: string | null;
  assurance: string;
  non_claims: string[];
};

export type GovernanceAutomationScheduleListResponse = {
  items: GovernanceAutomationSchedule[];
  automation_enabled: boolean;
  non_claims: string[];
};

export type GovernanceAutomationJobListResponse = {
  items: GovernanceAutomationJob[];
  total: number;
  page: number;
  page_size: number;
};

export type GovernanceAutomationJobDetail = {
  job: GovernanceAutomationJob;
  events: GovernanceAutomationJobEvent[];
  non_claims: string[];
};

export type GovernanceReminderItem = {
  notification_id: string;
  event_type: string;
  target_type: string | null;
  target_id: string | null;
  case_id: string | null;
  reminder_window: string | null;
  severity: string;
  created_at: string | null;
  muted: boolean;
  muted_until: string | null;
  delivery_state: "PENDING" | "DELIVERED" | "FAILED" | "PARTIAL";
  delivery_claimed: false;
  channels: string[];
};

export type GovernanceReminderActivity = {
  items: GovernanceReminderItem[];
  total: number;
  page: number;
  page_size: number;
  summary_limit: number;
  by_event_type: Record<string, number>;
  delivery_states: Record<string, number>;
  muted: number;
  notifier_enabled: boolean;
  delivery_claimed: false;
  non_claims: string[];
};

export type GovernanceSnapshot = {
  snapshot_id: string;
  snapshot_type: string;
  as_of: string | null;
  generated_at: string | null;
  generated_by: string | null;
  job_id: string | null;
  trigger: string;
  dedup_key: string;
  payload_digest: string;
  digest_valid: boolean;
  row_count: number;
  schema_version: number;
  payload: Record<string, unknown>;
};

export type GovernanceSnapshotListResponse = {
  items: GovernanceSnapshot[];
  total: number;
  page: number;
  page_size: number;
  non_claims: string[];
};

export type GovernanceSnapshotDetail = {
  snapshot: GovernanceSnapshot;
  non_claims: string[];
};
