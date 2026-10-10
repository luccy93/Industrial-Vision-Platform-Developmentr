import { apiFetch } from "../operations/client";
import type {
  AlertRule,
  AlertRuleListResponse,
  AlertingStatus,
  DeliveryListResponse,
  NotificationDetail,
  NotificationListResponse,
} from "../../types";

export type RuleForm = {
  name: string;
  description: string;
  enabled: boolean;
  domains: string[];
  event_types: string[];
  min_severity: string;
  min_priority: string;
  camera_ids: string;
  incident_statuses: string[];
  channels: string[];
  cooldown_seconds: number;
};

export function emptyRuleForm(): RuleForm {
  return {
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
  };
}

/** Client-side validation mirrors the API contract (server re-validates). */
export function validateRuleForm(form: RuleForm): string | null {
  if (!form.name.trim()) return "Rule name is required.";
  if (form.channels.length === 0) return "Select at least one channel.";
  if (!Number.isInteger(form.cooldown_seconds) || form.cooldown_seconds < 0) {
    return "Cooldown must be a non-negative whole number of seconds.";
  }
  if (form.cooldown_seconds > 86400) return "Cooldown must not exceed 86400 seconds.";
  return null;
}

function rulePayload(form: RuleForm): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    name: form.name.trim(),
    description: form.description,
    enabled: form.enabled,
    domains: form.domains,
    event_types: form.event_types,
    channels: form.channels,
    cooldown_seconds: form.cooldown_seconds,
  };
  if (form.min_severity) payload.min_severity = form.min_severity;
  if (form.min_priority) payload.min_priority = form.min_priority;
  if (form.camera_ids.trim()) {
    payload.camera_ids = form.camera_ids
      .split(",")
      .map((part) => part.trim())
      .filter(Boolean);
  }
  if (form.incident_statuses.length > 0) payload.incident_statuses = form.incident_statuses;
  return payload;
}

export function fetchAlertingStatus(signal?: AbortSignal): Promise<AlertingStatus> {
  return apiFetch<AlertingStatus>("/api/v1/alerting/status", { signal });
}

export function fetchRules(page = 1, signal?: AbortSignal): Promise<AlertRuleListResponse> {
  return apiFetch<AlertRuleListResponse>(`/api/v1/alerting/rules?page=${page}&page_size=20`, {
    signal,
  });
}

export function createRule(form: RuleForm, signal?: AbortSignal): Promise<AlertRule> {
  return apiFetch<AlertRule>("/api/v1/alerting/rules", {
    method: "POST",
    body: JSON.stringify(rulePayload(form)),
    signal,
  });
}

export function patchRule(
  ruleId: string,
  patch: Partial<ReturnType<typeof rulePayload>>,
  signal?: AbortSignal
): Promise<AlertRule> {
  return apiFetch<AlertRule>(`/api/v1/alerting/rules/${encodeURIComponent(ruleId)}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
    signal,
  });
}

export function fetchNotifications(
  params: {
    severity?: string;
    domain?: string;
    camera_id?: string;
    rule_id?: string;
    page?: number;
    page_size?: number;
  } = {},
  signal?: AbortSignal
): Promise<NotificationListResponse> {
  const query = new URLSearchParams();
  if (params.severity) query.set("severity", params.severity);
  if (params.domain) query.set("domain", params.domain);
  if (params.camera_id) query.set("camera_id", params.camera_id);
  if (params.rule_id) query.set("rule_id", params.rule_id);
  query.set("page", String(params.page ?? 1));
  query.set("page_size", String(params.page_size ?? 20));
  return apiFetch<NotificationListResponse>(`/api/v1/alerting/notifications?${query}`, { signal });
}

export function fetchNotificationDetail(
  notificationId: string,
  signal?: AbortSignal
): Promise<NotificationDetail> {
  return apiFetch<NotificationDetail>(
    `/api/v1/alerting/notifications/${encodeURIComponent(notificationId)}`,
    { signal }
  );
}

export function fetchDeliveries(
  params: { notification_id?: string; status?: string; channel?: string; page?: number } = {},
  signal?: AbortSignal
): Promise<DeliveryListResponse> {
  const query = new URLSearchParams();
  if (params.notification_id) query.set("notification_id", params.notification_id);
  if (params.status) query.set("status", params.status);
  if (params.channel) query.set("channel", params.channel);
  query.set("page", String(params.page ?? 1));
  query.set("page_size", "20");
  return apiFetch<DeliveryListResponse>(`/api/v1/alerting/deliveries?${query}`, { signal });
}

export function retryDelivery(
  deliveryId: string,
  signal?: AbortSignal
): Promise<{ retried: boolean }> {
  return apiFetch(`/api/v1/alerting/deliveries/${encodeURIComponent(deliveryId)}/retry`, {
    method: "POST",
    signal,
  });
}
