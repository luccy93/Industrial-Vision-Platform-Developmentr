"""Role and permission policy — single source of truth (V16).

Least privilege, enforced in the backend via shared dependencies.
Frontend role checks are usability only and never a security boundary.

Capability assignments (locked V16 decisions):

- ``read``: authenticated dashboard, operations, analytics, incidents,
  notifications — all roles.
- ``incident_write``: incident lifecycle actions + evidence — ADMIN, OPERATOR.
- ``camera_control``: camera start/stop — ADMIN, OPERATOR (stop requires
  confirmation + reason; audited; never treated as proof an area is safe).
- ``notification_mute``: time-limited per-notification mute — ADMIN, OPERATOR.
  Detection continues; history stays visible.
- ``integrity_audit_run``: start/cancel continuous integrity audits — ADMIN,
  OPERATOR. Reads (status/history/findings) remain available to every role.
- ``forensic_case_write``: create/update forensic cases, evidence references,
  notes, actions, assignments, incident links, and finding correlation —
  ADMIN, OPERATOR. Reads remain available to every role.
- ``forensic_verify``: run read-only case/evidence verification — ADMIN,
  OPERATOR.
- ``forensic_case_close``: resolve, close, and reopen forensic cases — ADMIN
  only. Separated from case writing so closure is an explicit second step.
- ``forensic_export``: generate, download, and verify forensic export packages
  — ADMIN only (dedicated capability; evidence-reference exports are sensitive).
- ``governance_read``: governance status, policies, retention queue, holds,
  dispositions, export approvals, and SUMMARY readiness reports — all roles.
- ``governance_policy_write``: create/version/enable/disable/archive policies —
  ADMIN only.
- ``retention_evaluate``: run bounded, non-destructive retention evaluations and
  complete reviews — ADMIN, OPERATOR.
- ``legal_hold_write``: request/withdraw legal holds — ADMIN, OPERATOR.
- ``legal_hold_approve``: approve, reject, or release legal holds — ADMIN only.
- ``disposition_request``: request/withdraw disposition review — ADMIN, OPERATOR.
- ``disposition_review``: approve or reject disposition review — ADMIN only.
- ``forensic_export_request``: request/withdraw governance export approval —
  ADMIN, OPERATOR.
- ``forensic_export_approve``: approve or reject governance export requests —
  ADMIN only. Generation and download still require ``forensic_export``.
- ``governance_audit_read``: read append-only governance access audit — ADMIN.
- ``governance_report_generate``: generate DETAIL readiness reports — ADMIN.
- ``governance_automation_read``: read automation status, health, schedules,
  jobs, and reminder activity — all roles.
- ``governance_automation_configure``: enable/disable schedules and edit bounded
  interval/config values — ADMIN only.
- ``governance_automation_retry``: manually run a job or retry a terminal job —
  ADMIN, OPERATOR.
- ``governance_automation_cancel``: cancel a pending job or request cooperative
  cancellation of a running job — ADMIN, OPERATOR.
- ``governance_snapshot_read``: read compliance snapshot history and CSV — all
  roles.
- ``governance_snapshot_generate``: generate a compliance snapshot on demand —
  ADMIN, OPERATOR.
- ``governance_executive_read``: executive status, health, KPI summary, and
  source coverage — all roles.
- ``governance_executive_detail_read``: executive detail reads, report history,
  report payloads, CSV, and configuration reads — ADMIN, OPERATOR.
- ``governance_executive_report_generate``: generate bounded local executive
  reports — ADMIN only.
- ``governance_executive_action_read``: read strategic actions and their audit
  history — ADMIN, OPERATOR.
- ``governance_executive_action_write``: create and transition strategic
  actions — ADMIN, OPERATOR.
- ``governance_executive_action_assign``: assign or reassign an action owner —
  ADMIN only.
- ``governance_executive_configure``: append executive operational
  configuration — ADMIN only.
- ``governance_workflow_read``: workflow status, ownership reports, workflow and
  task overview lists, and SLA reads — all roles.
- ``governance_workflow_detail_read``: workflow detail, templates, references,
  and escalation lists — ADMIN, OPERATOR.
- ``governance_workflow_create``: instantiate workflows from a pinned template
  version — ADMIN, OPERATOR.
- ``governance_workflow_transition``: apply strict workflow lifecycle
  transitions — ADMIN, OPERATOR.
- ``governance_workflow_assign``: assign or reassign workflow and task owners
  with a mandatory reason — ADMIN, OPERATOR.
- ``governance_workflow_task_write``: task lifecycle transitions and cross-domain
  reference attachment — ADMIN, OPERATOR.
- ``governance_workflow_escalate``: create, acknowledge, and resolve workflow
  escalations — ADMIN, OPERATOR.
- ``governance_workflow_template_manage``: create template versions and disable
  templates — ADMIN only.
- ``governance_workflow_audit_read``: read append-only workflow event history —
  ADMIN, OPERATOR.
- ``admin_config``: camera CRUD, zones, profiles, defect categories,
  safety/quality suppression, alert rules, delivery retry — ADMIN only.
- ``user_admin``: user CRUD, role changes, activation, session revocation
  of other users — ADMIN only, with recent-auth step-up.
"""

from __future__ import annotations

from enum import Enum


class Role(str, Enum):
    ADMIN = "ADMIN"
    OPERATOR = "OPERATOR"
    VIEWER = "VIEWER"


# Capability -> roles granted. Central map; route handlers must not
# scatter ad-hoc role-string checks.
ROLE_CAPABILITIES: dict[str, frozenset[Role]] = {
    "read": frozenset({Role.ADMIN, Role.OPERATOR, Role.VIEWER}),
    "incident_write": frozenset({Role.ADMIN, Role.OPERATOR}),
    "camera_control": frozenset({Role.ADMIN, Role.OPERATOR}),
    "notification_mute": frozenset({Role.ADMIN, Role.OPERATOR}),
    "integrity_audit_run": frozenset({Role.ADMIN, Role.OPERATOR}),
    "forensic_case_write": frozenset({Role.ADMIN, Role.OPERATOR}),
    "forensic_verify": frozenset({Role.ADMIN, Role.OPERATOR}),
    "forensic_case_close": frozenset({Role.ADMIN}),
    "forensic_export": frozenset({Role.ADMIN}),
    "governance_read": frozenset({Role.ADMIN, Role.OPERATOR, Role.VIEWER}),
    "governance_policy_write": frozenset({Role.ADMIN}),
    "retention_evaluate": frozenset({Role.ADMIN, Role.OPERATOR}),
    "legal_hold_write": frozenset({Role.ADMIN, Role.OPERATOR}),
    "legal_hold_approve": frozenset({Role.ADMIN}),
    "disposition_request": frozenset({Role.ADMIN, Role.OPERATOR}),
    "disposition_review": frozenset({Role.ADMIN}),
    "forensic_export_request": frozenset({Role.ADMIN, Role.OPERATOR}),
    "forensic_export_approve": frozenset({Role.ADMIN}),
    "governance_audit_read": frozenset({Role.ADMIN}),
    "governance_report_generate": frozenset({Role.ADMIN}),
    "governance_automation_read": frozenset({Role.ADMIN, Role.OPERATOR, Role.VIEWER}),
    "governance_automation_configure": frozenset({Role.ADMIN}),
    "governance_automation_retry": frozenset({Role.ADMIN, Role.OPERATOR}),
    "governance_automation_cancel": frozenset({Role.ADMIN, Role.OPERATOR}),
    "governance_snapshot_read": frozenset({Role.ADMIN, Role.OPERATOR, Role.VIEWER}),
    "governance_snapshot_generate": frozenset({Role.ADMIN, Role.OPERATOR}),
    "governance_intelligence_read": frozenset({Role.ADMIN, Role.OPERATOR, Role.VIEWER}),
    "governance_risk_read": frozenset({Role.ADMIN, Role.OPERATOR, Role.VIEWER}),
    "governance_sla_read": frozenset({Role.ADMIN, Role.OPERATOR, Role.VIEWER}),
    "governance_trends_read": frozenset({Role.ADMIN, Role.OPERATOR, Role.VIEWER}),
    "governance_recommendations_read": frozenset({Role.ADMIN, Role.OPERATOR, Role.VIEWER}),
    "governance_recommendation_acknowledge": frozenset({Role.ADMIN, Role.OPERATOR}),
    "governance_recommendation_dismiss": frozenset({Role.ADMIN}),
    "governance_intelligence_refresh": frozenset({Role.ADMIN, Role.OPERATOR}),
    "governance_intelligence_configure": frozenset({Role.ADMIN}),
    "governance_executive_read": frozenset({Role.ADMIN, Role.OPERATOR, Role.VIEWER}),
    "governance_executive_detail_read": frozenset({Role.ADMIN, Role.OPERATOR}),
    "governance_executive_report_generate": frozenset({Role.ADMIN}),
    "governance_executive_action_read": frozenset({Role.ADMIN, Role.OPERATOR}),
    "governance_executive_action_write": frozenset({Role.ADMIN, Role.OPERATOR}),
    "governance_executive_action_assign": frozenset({Role.ADMIN}),
    "governance_executive_configure": frozenset({Role.ADMIN}),
    "governance_workflow_read": frozenset({Role.ADMIN, Role.OPERATOR, Role.VIEWER}),
    "governance_workflow_detail_read": frozenset({Role.ADMIN, Role.OPERATOR}),
    "governance_workflow_create": frozenset({Role.ADMIN, Role.OPERATOR}),
    "governance_workflow_transition": frozenset({Role.ADMIN, Role.OPERATOR}),
    "governance_workflow_assign": frozenset({Role.ADMIN, Role.OPERATOR}),
    "governance_workflow_task_write": frozenset({Role.ADMIN, Role.OPERATOR}),
    "governance_workflow_escalate": frozenset({Role.ADMIN, Role.OPERATOR}),
    "governance_workflow_template_manage": frozenset({Role.ADMIN}),
    "governance_workflow_audit_read": frozenset({Role.ADMIN, Role.OPERATOR}),
    "admin_config": frozenset({Role.ADMIN}),
    "user_admin": frozenset({Role.ADMIN}),
}

#: Admin operations that additionally require recent authentication
#: (session ``authenticated_at`` within the step-up window).
SENSITIVE_USER_OPS = frozenset({"user.create", "user.role", "user.deactivate", "session.revoke_others"})


def normalize_role(value: object) -> Role:
    """Parse and validate a role value; raises ``ValueError`` when unknown."""
    if isinstance(value, Role):
        return value
    normalized = str(value or "").strip().upper()
    try:
        return Role(normalized)
    except ValueError:
        raise ValueError(f"unknown role: {normalized}") from None


def can(role: Role | str, capability: str) -> bool:
    """Return True when ``role`` is granted ``capability``."""
    parsed = normalize_role(role)
    granted = ROLE_CAPABILITIES.get(capability, frozenset())
    return parsed in granted


def capabilities_for(role: Role | str) -> frozenset[str]:
    """Return every capability granted to ``role``."""
    parsed = normalize_role(role)
    return frozenset(capability for capability, roles in ROLE_CAPABILITIES.items() if parsed in roles)
