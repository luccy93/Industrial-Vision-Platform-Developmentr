"""V39 enterprise governance workflow orchestration service.

Coordinates versioned workflow templates, persistent workflow instances, task
dependency evaluation, ownership, cross-domain read-only references, SLA
indicators, escalations, and append-only event history on top of the existing
V33-V38 domains.

The service never approves or releases a legal hold, approves or rejects a
disposition, deletes or modifies evidence, approves or generates an export,
alters custody, resolves a recommendation, or completes an executive action.
Escalations are review prompts delivered through the existing V15 pipeline; V39
starts no scheduler and claims no delivery.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from backend.app.auth.roles import can, normalize_role
from backend.app.core.logging import get_logger
from backend.app.core.metrics import (
    record_governance_workflow_creation,
    record_governance_workflow_dependency,
    record_governance_workflow_escalation,
    record_governance_workflow_operation,
    record_governance_workflow_transition,
    set_governance_workflow_counts,
    set_governance_workflow_overdue,
    set_governance_workflow_sla,
)
from backend.app.core.redaction import redact_text
from backend.app.domain.common import utcnow
from backend.app.governance.constants import GovernanceAuditEventType
from backend.app.governance.workflows.constants import (
    DEFAULT_PAGE_SIZE,
    DEFAULT_SLA_WARNING_HOURS,
    ESCALATION_STATUS_VALUES,
    MAX_ESCALATIONS_PER_WORKFLOW,
    MAX_PAGE_SIZE,
    MAX_REFERENCES_PER_WORKFLOW,
    MAX_WORKFLOW_OUTCOME_LENGTH,
    MAX_WORKFLOW_REASON_LENGTH,
    MIN_OUTCOME_LENGTH,
    MIN_REASON_LENGTH,
    REFERENCE_DOMAIN_CAPABILITY,
    REFERENCE_DOMAIN_VALUES,
    TASK_STATUS_VALUES,
    TEMPLATE_STATUS_VALUES,
    WORKFLOW_ASSURANCE,
    WORKFLOW_LIMITATIONS,
    WORKFLOW_NON_CLAIMS,
    WORKFLOW_PRIORITY_VALUES,
    WORKFLOW_SLA_STATE_VALUES,
    WORKFLOW_STATUS_VALUES,
    WORKFLOW_TERMINAL_STATUSES,
    WORKFLOW_TRANSITIONS,
    EscalationType,
    ReferenceAvailability,
    TaskStatus,
    TemplateStatus,
    WorkflowEventType,
    WorkflowSlaState,
    WorkflowStatus,
)
from backend.app.governance.workflows.dependencies import (
    DEPENDENCY_BLOCKED,
    DEPENDENCY_PENDING,
    DEPENDENCY_READY,
    dependency_verdict,
    validate_template_definition,
)
from backend.app.governance.workflows.errors import (
    EscalationNotEligibleError,
    OwnerValidationError,
    ReferenceDeletedError,
    ReferenceNotFoundError,
    ReferenceUnauthorizedError,
    ReferenceUnavailableError,
    SourceCaseMismatchError,
    TaskNotFoundError,
    TemplateNotFoundError,
    TemplateValidationError,
    WorkflowConfigError,
    WorkflowDisabledError,
    WorkflowError,
    WorkflowNotFoundError,
    WorkflowValidationError,
)
from backend.app.governance.workflows.references import ReferenceResolver
from backend.app.governance.workflows.sla import evaluate_sla, sla_state_counts

logger = get_logger(__name__)

_WORKFLOW_START_STATUSES = frozenset({WorkflowStatus.READY.value, WorkflowStatus.IN_PROGRESS.value})


def _as_utc(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    text = str(value).strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _text(value: Any, limit: int) -> str:
    return redact_text(str(value or "").strip())[:limit]


def _safe_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    return {}


class GovernanceWorkflowService:
    """Enterprise workflow templates, instances, tasks, references, and escalations."""

    def __init__(
        self,
        *,
        settings: Any,
        repository: Any,
        governance_service: Any = None,
        forensic_repository: Any = None,
        integrity_store: Any = None,
        governance_repository: Any = None,
        automation_repository: Any = None,
        intelligence_repository: Any = None,
        executive_repository: Any = None,
        auth_repository: Any = None,
        notifier: Any = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._settings = settings
        self._repository = repository
        self._governance = governance_service
        self._forensics = forensic_repository
        self._integrity = integrity_store
        self._governance_repository = governance_repository
        self._automation = automation_repository
        self._intelligence = intelligence_repository
        self._executive = executive_repository
        self._auth = auth_repository
        self._notifier = notifier
        self._clock = clock or utcnow

    # ------------------------------------------------------------------
    # Configuration and small helpers
    # ------------------------------------------------------------------
    def _require_enabled(self) -> None:
        if not bool(getattr(self._settings, "governance_enabled", True)):
            raise WorkflowDisabledError("governance is disabled")
        if not bool(getattr(self._settings, "governance_workflow_enabled", True)):
            raise WorkflowDisabledError("governance workflow orchestration is disabled")

    def _page_size(self, page_size: int | None) -> int:
        default = int(getattr(self._settings, "governance_workflow_page_size", DEFAULT_PAGE_SIZE))
        size = int(page_size if page_size is not None else default)
        return min(MAX_PAGE_SIZE, max(1, size))

    def _warning_hours(self) -> int:
        return int(
            getattr(
                self._settings,
                "governance_workflow_default_warning_hours",
                DEFAULT_SLA_WARNING_HOURS,
            )
        )

    def _sample_limit(self) -> int:
        return int(getattr(self._settings, "governance_workflow_max_active_sample", 500))

    @staticmethod
    def _role(actor_role: str | None) -> Any:
        try:
            return normalize_role(actor_role or "")
        except ValueError:
            return None

    @contextmanager
    def _operation(self, name: str):  # type: ignore[no-untyped-def]
        started = time.perf_counter()
        outcome = "SUCCESS"
        try:
            yield
        except (WorkflowValidationError, TemplateValidationError, WorkflowError):
            outcome = "REJECTED"
            raise
        except Exception:
            outcome = "FAILED"
            raise
        finally:
            try:
                record_governance_workflow_operation(name, outcome, time.perf_counter() - started)
            except Exception:  # noqa: BLE001 - metrics must never break a request
                logger.warning("workflow metric recording failed", exc_info=True)

    def _validate_owner(self, owner_type: str, owner_id: str) -> tuple[str, str]:
        normalized_type = str(owner_type or "").strip().upper()
        identifier = _text(owner_id, 256)
        if normalized_type not in {"USER", "ROLE"}:
            raise OwnerValidationError("owner_type must be USER or ROLE")
        if not identifier:
            raise OwnerValidationError("owner_id is required")
        if normalized_type == "ROLE":
            try:
                return normalized_type, normalize_role(identifier).value
            except ValueError:
                raise OwnerValidationError(f"unknown owner role: {identifier}") from None
        if self._auth is None:
            raise OwnerValidationError("the identity store is unavailable; a user owner cannot be validated")
        user = None
        try:
            user = self._auth.get_user_by_email(identifier)
            if user is None:
                user = self._auth.get_user_by_id(identifier)
        except Exception:  # noqa: BLE001 - identity lookup must not fabricate an owner
            raise OwnerValidationError("the identity store could not validate the owner") from None
        if user is None or not bool(getattr(user, "is_active", False)):
            raise OwnerValidationError("owner is not an active user")
        email = str(getattr(user, "email", "") or "").strip()
        return normalized_type, email or identifier

    def _validate_case(self, case_id: str | None) -> str | None:
        if not case_id:
            return None
        if self._forensics is None:
            raise WorkflowConfigError(
                "the forensic source is unavailable; the case reference cannot be validated"
            )
        try:
            case = self._forensics.get_case(case_id)
        except Exception:  # noqa: BLE001 - unavailable source must not be invented
            raise ReferenceUnavailableError("the forensic case source could not be read") from None
        if case is None:
            raise ReferenceNotFoundError("FORENSIC_CASE", case_id)
        return str(case_id)

    def _resolver(self, actor_role: str | None) -> ReferenceResolver:
        role = self._role(actor_role)
        lookup = (lambda capability: can(role, capability)) if role is not None else None
        return ReferenceResolver(
            forensic_repository=self._forensics,
            integrity_store=self._integrity,
            governance_repository=self._governance_repository,
            automation_repository=self._automation,
            intelligence_repository=self._intelligence,
            executive_repository=self._executive,
            capability_lookup=lookup,
            clock=self._clock,
        )

    def _workflow_sla(self, workflow: Mapping[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
        status = str(workflow.get("status") or "").upper()
        moment = now or self._clock()
        if status == WorkflowStatus.DRAFT.value:
            return evaluate_sla(
                entity_type="WORKFLOW",
                entity_id=str(workflow.get("workflow_id") or ""),
                status=status,
                due_at=workflow.get("due_at"),
                start_at=None,
                resolved_at=None,
                now=moment,
                applicable=False,
                warning_hours=self._warning_hours(),
            )
        resolution = workflow.get("completed_at") or workflow.get("cancelled_at")
        start = workflow.get("ready_at") or workflow.get("created_at")
        return evaluate_sla(
            entity_type="WORKFLOW",
            entity_id=str(workflow.get("workflow_id") or ""),
            status=status,
            due_at=workflow.get("due_at"),
            start_at=start,
            resolved_at=resolution,
            now=moment,
            blocked=status == WorkflowStatus.BLOCKED.value,
            cancelled=status == WorkflowStatus.CANCELLED.value,
            warning_hours=self._warning_hours(),
        )

    def _task_sla(self, task: Mapping[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
        status = str(task.get("status") or "").upper()
        moment = now or self._clock()
        if status in {TaskStatus.PENDING.value, TaskStatus.CANCELLED.value}:
            return evaluate_sla(
                entity_type="TASK",
                entity_id=str(task.get("task_id") or ""),
                status=status,
                due_at=task.get("due_at"),
                start_at=None,
                resolved_at=task.get("cancelled_at"),
                now=moment,
                applicable=False,
                warning_hours=self._warning_hours(),
            )
        start = task.get("started_at") or task.get("created_at")
        return evaluate_sla(
            entity_type="TASK",
            entity_id=str(task.get("task_id") or ""),
            status=status,
            due_at=task.get("due_at"),
            start_at=start,
            resolved_at=task.get("completed_at"),
            now=moment,
            blocked=status == TaskStatus.BLOCKED.value,
            cancelled=status == TaskStatus.CANCELLED.value,
            warning_hours=self._warning_hours(),
        )

    @staticmethod
    def _dependency_map(
        dependencies: Sequence[Mapping[str, Any]],
    ) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {}
        for dependency in dependencies:
            task_id = str(dependency.get("task_id") or "")
            depends_on = str(dependency.get("depends_on_task_id") or "")
            if task_id and depends_on:
                result.setdefault(task_id, []).append(depends_on)
        for value in result.values():
            value.sort()
        return result

    def _record_dependency_counts(self, counts: Mapping[str, int]) -> None:
        for outcome in (DEPENDENCY_READY, DEPENDENCY_BLOCKED, DEPENDENCY_PENDING):
            amount = int(counts.get(outcome, 0) or 0)
            for _ in range(min(amount, 500)):
                try:
                    record_governance_workflow_dependency(outcome)
                except Exception:  # noqa: BLE001 - metrics must never break a request
                    logger.warning("workflow dependency metric failed", exc_info=True)
                    return

    def _refresh_counts(self) -> None:
        try:
            set_governance_workflow_counts(
                self._repository.workflow_status_counts(),
                self._repository.task_status_counts(),
            )
            set_governance_workflow_overdue(self._repository.overdue_counts(now=self._clock()))
        except Exception:  # noqa: BLE001 - metrics must never break a request
            logger.warning("workflow count metric refresh failed", exc_info=True)

    def _audit(
        self,
        *,
        event_type: str,
        actor_id: str | None,
        actor_role: str,
        target_type: str,
        target_id: str,
        case_id: str | None = None,
        reason: str = "",
        request_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        if self._governance is None:
            return
        try:
            self._governance.record_access(
                event_type=event_type,
                actor_id=actor_id,
                actor_role=actor_role,
                target_type=target_type,
                target_id=target_id,
                case_id=case_id,
                reason=reason,
                request_id=request_id,
                metadata=metadata,
            )
        except Exception:  # noqa: BLE001 - audit failure must not fabricate success
            logger.warning("workflow governance audit write failed", exc_info=True)

    def _require_reason(self, value: Any, *, field: str) -> str:
        text = _text(value, MAX_WORKFLOW_REASON_LENGTH)
        if len(text) < MIN_REASON_LENGTH:
            raise WorkflowValidationError(
                f"{field} is required and must be at least {MIN_REASON_LENGTH} characters"
            )
        return text

    def _require_outcome(self, value: Any) -> str:
        text = _text(value, MAX_WORKFLOW_OUTCOME_LENGTH)
        if len(text) < MIN_OUTCOME_LENGTH:
            raise WorkflowValidationError(
                f"outcome_summary is required and must be at least {MIN_OUTCOME_LENGTH} characters"
            )
        return text

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------
    def status(self) -> dict[str, Any]:
        self._require_enabled()
        moment = _as_utc(self._clock()) or datetime.now(UTC)
        workflow_counts = self._repository.workflow_status_counts()
        task_counts = self._repository.task_status_counts()
        escalation_counts = self._repository.escalation_status_counts()
        unassigned = self._repository.unassigned_counts()
        overdue = self._repository.overdue_counts(now=moment)
        try:
            set_governance_workflow_counts(workflow_counts, task_counts)
            set_governance_workflow_overdue(overdue)
        except Exception:  # noqa: BLE001 - metrics must never break a request
            logger.warning("workflow status metric refresh failed", exc_info=True)

        sla_counts = {state: 0 for state in WORKFLOW_SLA_STATE_VALUES}
        sla_counts["UNKNOWN"] = 0
        sample = self._repository.active_workflows(limit=self._sample_limit())
        for workflow in sample:
            state = str(self._workflow_sla(workflow, now=moment).get("state") or "UNKNOWN")
            if state in sla_counts:
                sla_counts[state] += 1
            else:
                sla_counts["UNKNOWN"] += 1
        try:
            set_governance_workflow_sla(sla_counts)
        except Exception:  # noqa: BLE001 - metrics must never break a request
            logger.warning("workflow SLA metric refresh failed", exc_info=True)

        return {
            "enabled": True,
            "assurance": WORKFLOW_ASSURANCE,
            "workflow_counts": workflow_counts,
            "workflow_total": sum(int(value) for value in workflow_counts.values()),
            "task_counts": task_counts,
            "task_total": sum(int(value) for value in task_counts.values()),
            "escalation_counts": escalation_counts,
            "escalation_total": sum(int(value) for value in escalation_counts.values()),
            "unassigned": unassigned,
            "overdue": overdue,
            "sla_counts": sla_counts,
            "sla_sample_size": len(sample),
            "sla_sample_limit": self._sample_limit(),
            "sources": {
                "forensic": "AVAILABLE" if self._forensics is not None else "UNAVAILABLE",
                "integrity": "AVAILABLE" if self._integrity is not None else "UNAVAILABLE",
                "governance": ("AVAILABLE" if self._governance_repository is not None else "UNAVAILABLE"),
                "automation": "AVAILABLE" if self._automation is not None else "UNAVAILABLE",
                "intelligence": ("AVAILABLE" if self._intelligence is not None else "UNAVAILABLE"),
                "executive": "AVAILABLE" if self._executive is not None else "UNAVAILABLE",
                "identity": "AVAILABLE" if self._auth is not None else "UNAVAILABLE",
                "notifications": (
                    "AVAILABLE"
                    if self._notifier is not None and bool(getattr(self._notifier, "enabled", False))
                    else "UNAVAILABLE"
                ),
            },
            "lifecycle": {
                "workflow_statuses": list(WORKFLOW_STATUS_VALUES),
                "task_statuses": list(TASK_STATUS_VALUES),
                "template_statuses": list(TEMPLATE_STATUS_VALUES),
                "escalation_statuses": list(ESCALATION_STATUS_VALUES),
                "workflow_transitions": {key: sorted(value) for key, value in WORKFLOW_TRANSITIONS.items()},
            },
            "scheduled_workflows": False,
            "scheduled_workflows_note": (
                "V39 computes SLA and escalation state on demand or on explicit user action; "
                "it starts no scheduler and no second worker."
            ),
            "generated_at": _iso(moment),
            "non_claims": list(WORKFLOW_NON_CLAIMS),
            "limitations": list(WORKFLOW_LIMITATIONS),
        }

    # ------------------------------------------------------------------
    # Templates
    # ------------------------------------------------------------------
    def _validated_definition(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        raw_tasks = payload.get("tasks")
        if isinstance(raw_tasks, Sequence) and not isinstance(raw_tasks, (str, bytes)):
            normalized_tasks = []
            for index, task in enumerate(raw_tasks):
                if not isinstance(task, Mapping):
                    raise TemplateValidationError(f"tasks[{index}] must be an object")
                item = dict(task)
                if item.get("order_index") is None:
                    item["order_index"] = index
                normalized_tasks.append(item)
            return validate_template_definition({"tasks": normalized_tasks})
        raise TemplateValidationError("template definition must contain a task list")

    def create_template(
        self,
        payload: Mapping[str, Any],
        *,
        actor_id: str | None,
        actor_role: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        with self._operation("create_template"):
            template_key = _text(payload.get("template_key"), 64).upper()
            if not template_key:
                raise TemplateValidationError("template_key is required")
            name = _text(payload.get("name"), 200)
            if len(name) < 3:
                raise TemplateValidationError("name must be at least 3 characters")
            reason = self._require_reason(payload.get("reason"), field="reason")
            idempotency_key = _text(payload.get("idempotency_key"), 128)
            if not idempotency_key:
                raise TemplateValidationError("idempotency_key is required")
            validated = self._validated_definition(payload)
            existing = self._repository.find_template_by_idempotency_key(idempotency_key)
            if existing is not None:
                return self._template_response(existing, replayed=True)
            version = self._repository.next_template_version(template_key)
            template, created = self._repository.create_template(
                template_key=template_key,
                version=version,
                name=name,
                description=_text(payload.get("description"), 4000),
                definition=validated["definition"],
                definition_digest=validated["definition_digest"],
                task_count=validated["task_count"],
                dependency_count=validated["dependency_count"],
                created_by=str(actor_id or "SYSTEM"),
                idempotency_key=idempotency_key,
                actor_role=actor_role,
                reason=reason,
                event_type=WorkflowEventType.TEMPLATE_CREATED.value,
                now=self._clock(),
            )
            if created:
                self._audit(
                    event_type=GovernanceAuditEventType.WORKFLOW_TEMPLATE_CREATED.value,
                    actor_id=actor_id,
                    actor_role=actor_role,
                    target_type="GOVERNANCE_WORKFLOW_TEMPLATE",
                    target_id=str(template["template_id"]),
                    reason=reason,
                    request_id=request_id,
                    metadata={
                        "template_key": template_key,
                        "version": version,
                        "task_count": validated["task_count"],
                        "dependency_count": validated["dependency_count"],
                    },
                )
                try:
                    record_governance_workflow_creation("CREATED")
                except Exception:  # noqa: BLE001
                    logger.warning("workflow creation metric failed", exc_info=True)
            else:
                try:
                    record_governance_workflow_creation("REPLAYED")
                except Exception:  # noqa: BLE001
                    logger.warning("workflow creation metric failed", exc_info=True)
            return self._template_response(template, replayed=not created)

    def create_template_version(
        self,
        template_key: str,
        payload: Mapping[str, Any],
        *,
        actor_id: str | None,
        actor_role: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        with self._operation("create_template"):
            normalized_key = _text(template_key, 64).upper()
            latest = self._repository.latest_template(normalized_key, statuses=TEMPLATE_STATUS_VALUES)
            if latest is None:
                raise TemplateNotFoundError(normalized_key)
            if str(latest.get("status") or "").upper() == TemplateStatus.DISABLED.value:
                raise WorkflowValidationError(
                    "a disabled template cannot receive a new version; create a new template key"
                )
            name = _text(payload.get("name"), 200) or str(latest.get("name") or "")
            description = (
                _text(payload.get("description"), 4000)
                if payload.get("description") is not None
                else str(latest.get("description") or "")
            )
            reason = self._require_reason(payload.get("reason"), field="reason")
            idempotency_key = _text(payload.get("idempotency_key"), 128)
            if not idempotency_key:
                raise TemplateValidationError("idempotency_key is required")
            validated = self._validated_definition(payload)
            existing = self._repository.find_template_by_idempotency_key(idempotency_key)
            if existing is not None:
                return self._template_response(existing, replayed=True)
            version = self._repository.next_template_version(normalized_key)
            template, created = self._repository.create_template(
                template_key=normalized_key,
                version=version,
                name=name,
                description=description,
                definition=validated["definition"],
                definition_digest=validated["definition_digest"],
                task_count=validated["task_count"],
                dependency_count=validated["dependency_count"],
                created_by=str(actor_id or "SYSTEM"),
                idempotency_key=idempotency_key,
                actor_role=actor_role,
                reason=reason,
                event_type=WorkflowEventType.TEMPLATE_UPDATED.value,
                now=self._clock(),
            )
            if created:
                self._audit(
                    event_type=GovernanceAuditEventType.WORKFLOW_TEMPLATE_VERSION_CREATED.value,
                    actor_id=actor_id,
                    actor_role=actor_role,
                    target_type="GOVERNANCE_WORKFLOW_TEMPLATE",
                    target_id=str(template["template_id"]),
                    reason=reason,
                    request_id=request_id,
                    metadata={
                        "template_key": normalized_key,
                        "version": version,
                        "previous_version": latest.get("version"),
                        "definition_digest": validated["definition_digest"],
                    },
                )
                try:
                    record_governance_workflow_creation("CREATED")
                except Exception:  # noqa: BLE001
                    logger.warning("workflow creation metric failed", exc_info=True)
            else:
                try:
                    record_governance_workflow_creation("REPLAYED")
                except Exception:  # noqa: BLE001
                    logger.warning("workflow creation metric failed", exc_info=True)
            return self._template_response(template, replayed=not created)

    def disable_template(
        self,
        template_id: str,
        payload: Mapping[str, Any],
        *,
        actor_id: str | None,
        actor_role: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        with self._operation("disable_template"):
            reason = self._require_reason(payload.get("reason"), field="reason")
            template, changed = self._repository.disable_template(
                template_id,
                actor_id=actor_id,
                actor_role=actor_role,
                reason=reason,
                now=self._clock(),
            )
            if changed:
                self._audit(
                    event_type=GovernanceAuditEventType.WORKFLOW_TEMPLATE_DISABLED.value,
                    actor_id=actor_id,
                    actor_role=actor_role,
                    target_type="GOVERNANCE_WORKFLOW_TEMPLATE",
                    target_id=str(template["template_id"]),
                    reason=reason,
                    request_id=request_id,
                    metadata={
                        "template_key": template.get("template_key"),
                        "version": template.get("version"),
                    },
                )
            return {
                "template": template,
                "events": self._repository.template_events(str(template["template_id"])),
                "changed": changed,
                "non_claims": list(WORKFLOW_NON_CLAIMS),
            }

    def _template_response(self, template: Mapping[str, Any], *, replayed: bool) -> dict[str, Any]:
        return {
            "template": template,
            "events": self._repository.template_events(str(template["template_id"])),
            "replayed": replayed,
            "non_claims": list(WORKFLOW_NON_CLAIMS),
        }

    def list_templates(
        self,
        *,
        template_key: str | None = None,
        status: str | None = None,
        page: int = 1,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        normalized_status = str(status).upper() if status else None
        if normalized_status and normalized_status not in TEMPLATE_STATUS_VALUES:
            raise WorkflowValidationError(f"unsupported template status: {status}")
        bounded = self._page_size(page_size)
        items, total = self._repository.list_templates(
            template_key=template_key,
            status=normalized_status,
            page=max(1, int(page)),
            page_size=bounded,
        )
        return {
            "items": items,
            "total": total,
            "page": max(1, int(page)),
            "page_size": bounded,
            "lifecycle": {
                "statuses": list(TEMPLATE_STATUS_VALUES),
                "disabled_is_terminal": True,
            },
            "non_claims": list(WORKFLOW_NON_CLAIMS),
        }

    def template_detail(self, template_id: str) -> dict[str, Any]:
        self._require_enabled()
        template = self._repository.get_template(template_id)
        if template is None:
            raise TemplateNotFoundError(template_id)
        return {
            "template": template,
            "events": self._repository.template_events(template_id),
            "non_claims": list(WORKFLOW_NON_CLAIMS),
        }

    def _resolve_template(
        self,
        *,
        template_id: str | None,
        template_key: str | None,
        template_version: int | None,
    ) -> dict[str, Any]:
        if template_id:
            template = self._repository.get_template(template_id)
            if template is None:
                raise TemplateNotFoundError(template_id)
        elif template_key:
            key = _text(template_key, 64).upper()
            if template_version is not None:
                template = self._repository.template_by_key_version(key, template_version)
            else:
                template = self._repository.latest_template(key)
            if template is None:
                raise TemplateNotFoundError(f"{key}@{template_version}" if template_version else key)
        else:
            raise WorkflowValidationError("template_id or template_key is required")
        if str(template.get("status") or "").upper() == TemplateStatus.DISABLED.value:
            raise WorkflowValidationError("the selected template is disabled")
        return template

    # ------------------------------------------------------------------
    # Workflows
    # ------------------------------------------------------------------
    def create_workflow(
        self,
        payload: Mapping[str, Any],
        *,
        actor_id: str | None,
        actor_role: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        with self._operation("create_workflow"):
            title = _text(payload.get("title"), 200)
            if len(title) < 3:
                raise WorkflowValidationError("title must be at least 3 characters")
            reason = self._require_reason(payload.get("reason"), field="reason")
            idempotency_key = _text(payload.get("idempotency_key"), 128)
            if not idempotency_key:
                raise WorkflowValidationError("idempotency_key is required")
            existing = self._repository.find_workflow_by_idempotency_key(idempotency_key)
            if existing is not None:
                return self._workflow_response(existing, replayed=True)
            template = self._resolve_template(
                template_id=payload.get("template_id"),
                template_key=payload.get("template_key"),
                template_version=payload.get("template_version"),
            )
            case_id = self._validate_case(payload.get("case_id"))
            priority = _text(payload.get("priority"), 16).upper() or "MEDIUM"
            if priority not in WORKFLOW_PRIORITY_VALUES:
                raise WorkflowValidationError(f"unsupported workflow priority: {priority}")
            due_at = _as_utc(payload.get("due_at"))
            if payload.get("due_at") is not None and due_at is None:
                raise WorkflowValidationError("due_at must be a valid timestamp")
            owner_type = payload.get("owner_type")
            owner_id = payload.get("owner_id")
            if owner_type is not None:
                owner_type, owner_id = self._validate_owner(str(owner_type), str(owner_id or ""))
            else:
                owner_type, owner_id = None, None
            workflow, created = self._repository.create_workflow(
                template=template,
                case_id=case_id,
                title=title,
                description=_text(payload.get("description"), 4000),
                priority=priority,
                due_at=due_at,
                owner_type=owner_type,
                owner_id=owner_id,
                created_by=str(actor_id or "SYSTEM"),
                actor_role=actor_role,
                idempotency_key=idempotency_key,
                reason=reason,
                now=self._clock(),
            )
            if created:
                self._audit(
                    event_type=GovernanceAuditEventType.WORKFLOW_CREATED.value,
                    actor_id=actor_id,
                    actor_role=actor_role,
                    target_type="GOVERNANCE_WORKFLOW",
                    target_id=str(workflow["workflow_id"]),
                    case_id=workflow.get("case_id"),
                    reason=reason,
                    request_id=request_id,
                    metadata={
                        "template_id": workflow.get("template_id"),
                        "template_key": workflow.get("template_key"),
                        "template_version": workflow.get("template_version"),
                    },
                )
                try:
                    record_governance_workflow_creation("CREATED")
                except Exception:  # noqa: BLE001
                    logger.warning("workflow creation metric failed", exc_info=True)
            else:
                try:
                    record_governance_workflow_creation("REPLAYED")
                except Exception:  # noqa: BLE001
                    logger.warning("workflow creation metric failed", exc_info=True)
            self._refresh_counts()
            return self._workflow_response(workflow, replayed=not created)

    def _workflow_response(self, workflow: Mapping[str, Any], *, replayed: bool) -> dict[str, Any]:
        workflow_id = str(workflow["workflow_id"])
        tasks = self._repository.workflow_tasks(workflow_id)
        dependencies = self._repository.workflow_dependencies(workflow_id)
        moment = _as_utc(self._clock()) or datetime.now(UTC)
        return {
            "workflow": workflow,
            "tasks": tasks,
            "dependencies": dependencies,
            "sla": self._workflow_sla(workflow, now=moment),
            "events": self._repository.workflow_events(workflow_id),
            "replayed": replayed,
            "non_claims": list(WORKFLOW_NON_CLAIMS),
        }

    def list_workflows(
        self,
        *,
        status: str | None = None,
        owner_id: str | None = None,
        case_id: str | None = None,
        unassigned: bool = False,
        overdue: bool = False,
        page: int = 1,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        normalized_status = str(status).upper() if status else None
        if normalized_status and normalized_status not in WORKFLOW_STATUS_VALUES:
            raise WorkflowValidationError(f"unsupported workflow status: {status}")
        bounded = self._page_size(page_size)
        moment = _as_utc(self._clock()) or datetime.now(UTC)
        items, total = self._repository.list_workflows(
            status=normalized_status,
            owner_id=owner_id,
            case_id=case_id,
            unassigned=bool(unassigned),
            overdue=bool(overdue),
            page=max(1, int(page)),
            page_size=bounded,
            now=moment,
        )
        enriched = [{**item, "sla": self._workflow_sla(item, now=moment)} for item in items]
        return {
            "items": enriched,
            "total": total,
            "page": max(1, int(page)),
            "page_size": bounded,
            "filters": {
                "status": normalized_status,
                "owner_id": owner_id,
                "case_id": case_id,
                "unassigned": bool(unassigned),
                "overdue": bool(overdue),
            },
            "status_counts": self._repository.workflow_status_counts(),
            "unassigned": self._repository.unassigned_counts(),
            "overdue": self._repository.overdue_counts(now=moment),
            "non_claims": list(WORKFLOW_NON_CLAIMS),
        }

    def workflow_detail(self, workflow_id: str) -> dict[str, Any]:
        self._require_enabled()
        workflow = self._repository.get_workflow(workflow_id)
        if workflow is None:
            raise WorkflowNotFoundError(workflow_id)
        moment = _as_utc(self._clock()) or datetime.now(UTC)
        tasks = self._repository.workflow_tasks(workflow_id)
        dependencies = self._repository.workflow_dependencies(workflow_id)
        dependency_map = self._dependency_map(dependencies)
        status_by_id = {str(task["task_id"]): str(task["status"]) for task in tasks}
        key_by_id = {str(task["task_id"]): str(task["task_key"]) for task in tasks}
        enriched_tasks = []
        for task in tasks:
            task_id = str(task["task_id"])
            dependency_ids = dependency_map.get(task_id, [])
            enriched_tasks.append(
                {
                    **task,
                    "dependencies": [
                        key_by_id.get(dependency_id, dependency_id) for dependency_id in dependency_ids
                    ],
                    "dependency_state": dependency_verdict(
                        dependency_ids=dependency_ids, status_by_id=status_by_id
                    ),
                    "sla": self._task_sla(task, now=moment),
                }
            )
        events = self._repository.workflow_events(workflow_id)
        escalations, escalation_total = self._repository.list_escalations(
            workflow_id=workflow_id, page=1, page_size=100
        )
        references = self._repository.list_references(workflow_id)
        ownership_history = [
            {
                "event_id": event.get("event_id"),
                "event_type": event.get("event_type"),
                "task_id": event.get("task_id"),
                "actor_id": event.get("actor_id"),
                "created_at": event.get("created_at"),
                "detail": event.get("detail"),
            }
            for event in events
            if str(event.get("event_type") or "")
            in {
                WorkflowEventType.WORKFLOW_ASSIGNED.value,
                WorkflowEventType.WORKFLOW_REASSIGNED.value,
                WorkflowEventType.TASK_ASSIGNED.value,
            }
        ]
        return {
            "workflow": workflow,
            "sla": self._workflow_sla(workflow, now=moment),
            "tasks": enriched_tasks,
            "dependencies": dependencies,
            "references": references,
            "escalations": escalations,
            "escalation_total": escalation_total,
            "events": events,
            "ownership_history": ownership_history,
            "lifecycle": {
                "statuses": list(WORKFLOW_STATUS_VALUES),
                "transitions": {key: sorted(value) for key, value in WORKFLOW_TRANSITIONS.items()},
                "terminal": sorted(WORKFLOW_TERMINAL_STATUSES),
            },
            "non_claims": list(WORKFLOW_NON_CLAIMS),
        }

    def transition_workflow(
        self,
        workflow_id: str,
        payload: Mapping[str, Any],
        *,
        actor_id: str | None,
        actor_role: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        with self._operation("transition_workflow"):
            workflow = self._repository.get_workflow(workflow_id)
            if workflow is None:
                raise WorkflowNotFoundError(workflow_id)
            from_status = str(workflow.get("status") or "").upper()
            target_status = str(payload.get("target_status") or "").upper()
            if target_status not in WORKFLOW_STATUS_VALUES:
                raise WorkflowValidationError(f"unsupported workflow status: {payload.get('target_status')}")
            expected_version = int(payload.get("expected_version") or 0)
            if expected_version < 1:
                raise WorkflowValidationError("expected_version must be at least 1")
            reason = _text(payload.get("reason"), MAX_WORKFLOW_REASON_LENGTH)
            block_reason = _text(payload.get("block_reason"), MAX_WORKFLOW_REASON_LENGTH)
            cancel_reason = _text(payload.get("cancel_reason"), MAX_WORKFLOW_REASON_LENGTH)
            outcome_summary = _text(payload.get("outcome_summary"), MAX_WORKFLOW_OUTCOME_LENGTH)
            if target_status == WorkflowStatus.BLOCKED.value:
                if len(block_reason or reason) < MIN_REASON_LENGTH:
                    raise WorkflowValidationError("blocking a workflow requires a reason")
            if target_status == WorkflowStatus.CANCELLED.value:
                if len(cancel_reason or reason) < MIN_REASON_LENGTH:
                    raise WorkflowValidationError("cancelling a workflow requires a reason")
            if target_status == WorkflowStatus.COMPLETED.value:
                if len(outcome_summary) < MIN_OUTCOME_LENGTH:
                    raise WorkflowValidationError("completing a workflow requires an outcome summary")
            try:
                updated = self._repository.transition_workflow(
                    workflow_id,
                    target_status=target_status,
                    expected_version=expected_version,
                    actor_id=actor_id,
                    actor_role=actor_role,
                    reason=reason or f"Workflow transitioned to {target_status}.",
                    outcome_summary=outcome_summary or None,
                    block_reason=block_reason or None,
                    cancel_reason=cancel_reason or None,
                    dependency_observer=self._record_dependency_counts,
                    now=self._clock(),
                )
            except Exception as exc:
                outcome = "CONFLICT" if getattr(exc, "code", "").endswith("VERSION_CONFLICT") else "REJECTED"
                try:
                    record_governance_workflow_transition("WORKFLOW", from_status, target_status, outcome)
                except Exception:  # noqa: BLE001
                    logger.warning("workflow transition metric failed", exc_info=True)
                raise
            try:
                record_governance_workflow_transition("WORKFLOW", from_status, target_status, "APPLIED")
            except Exception:  # noqa: BLE001
                logger.warning("workflow transition metric failed", exc_info=True)
            self._audit(
                event_type=GovernanceAuditEventType.WORKFLOW_TRANSITIONED.value,
                actor_id=actor_id,
                actor_role=actor_role,
                target_type="GOVERNANCE_WORKFLOW",
                target_id=workflow_id,
                case_id=updated.get("case_id"),
                reason=reason or f"Workflow transitioned to {target_status}.",
                request_id=request_id,
                metadata={
                    "from_status": from_status,
                    "to_status": target_status,
                    "expected_version": expected_version,
                    "outcome_summary": outcome_summary or None,
                },
            )
            self._refresh_counts()
            return {
                "workflow": updated,
                "tasks": self._repository.workflow_tasks(workflow_id),
                "sla": self._workflow_sla(updated),
                "events": self._repository.workflow_events(workflow_id),
                "non_claims": list(WORKFLOW_NON_CLAIMS),
            }

    def assign_workflow(
        self,
        workflow_id: str,
        payload: Mapping[str, Any],
        *,
        actor_id: str | None,
        actor_role: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        with self._operation("assign_workflow"):
            reason = self._require_reason(payload.get("reason"), field="reason")
            owner_type, owner_id = self._validate_owner(
                str(payload.get("owner_type") or ""), str(payload.get("owner_id") or "")
            )
            expected_version = int(payload.get("expected_version") or 0)
            if expected_version < 1:
                raise WorkflowValidationError("expected_version must be at least 1")
            try:
                workflow = self._repository.assign_workflow(
                    workflow_id,
                    owner_type=owner_type,
                    owner_id=owner_id,
                    expected_version=expected_version,
                    actor_id=actor_id,
                    actor_role=actor_role,
                    reason=reason,
                    now=self._clock(),
                )
            except Exception as exc:
                outcome = "CONFLICT" if getattr(exc, "code", "").endswith("VERSION_CONFLICT") else "REJECTED"
                try:
                    record_governance_workflow_transition("WORKFLOW", "UNKNOWN", "UNKNOWN", outcome)
                except Exception:  # noqa: BLE001
                    logger.warning("workflow assignment metric failed", exc_info=True)
                raise
            self._audit(
                event_type=GovernanceAuditEventType.WORKFLOW_ASSIGNED.value,
                actor_id=actor_id,
                actor_role=actor_role,
                target_type="GOVERNANCE_WORKFLOW",
                target_id=workflow_id,
                case_id=workflow.get("case_id"),
                reason=reason,
                request_id=request_id,
                metadata={"owner_type": owner_type, "owner_id": owner_id},
            )
            return {
                "workflow": workflow,
                "events": self._repository.workflow_events(workflow_id),
                "non_claims": list(WORKFLOW_NON_CLAIMS),
            }

    # ------------------------------------------------------------------
    # Tasks
    # ------------------------------------------------------------------
    def list_tasks(
        self,
        *,
        workflow_id: str | None = None,
        status: str | None = None,
        owner_id: str | None = None,
        unassigned: bool = False,
        overdue: bool = False,
        page: int = 1,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        normalized_status = str(status).upper() if status else None
        if normalized_status and normalized_status not in TASK_STATUS_VALUES:
            raise WorkflowValidationError(f"unsupported task status: {status}")
        bounded = self._page_size(page_size)
        moment = _as_utc(self._clock()) or datetime.now(UTC)
        items, total = self._repository.list_tasks(
            workflow_id=workflow_id,
            status=normalized_status,
            owner_id=owner_id,
            unassigned=bool(unassigned),
            overdue=bool(overdue),
            page=max(1, int(page)),
            page_size=bounded,
            now=moment,
        )
        return {
            "items": [{**item, "sla": self._task_sla(item, now=moment)} for item in items],
            "total": total,
            "page": max(1, int(page)),
            "page_size": bounded,
            "status_counts": self._repository.task_status_counts(),
            "overdue": self._repository.overdue_counts(now=moment),
            "non_claims": list(WORKFLOW_NON_CLAIMS),
        }

    def transition_task(
        self,
        workflow_id: str,
        task_id: str,
        payload: Mapping[str, Any],
        *,
        actor_id: str | None,
        actor_role: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        with self._operation("transition_task"):
            workflow = self._repository.get_workflow(workflow_id)
            if workflow is None:
                raise WorkflowNotFoundError(workflow_id)
            task = self._repository.get_task(workflow_id, task_id)
            if task is None:
                raise TaskNotFoundError(task_id)
            from_status = str(task.get("status") or "").upper()
            target_status = str(payload.get("target_status") or "").upper()
            if target_status not in TASK_STATUS_VALUES:
                raise WorkflowValidationError(f"unsupported task status: {payload.get('target_status')}")
            expected_version = int(payload.get("expected_version") or 0)
            if expected_version < 1:
                raise WorkflowValidationError("expected_version must be at least 1")
            reason = _text(payload.get("reason"), MAX_WORKFLOW_REASON_LENGTH)
            block_reason = _text(payload.get("block_reason"), MAX_WORKFLOW_REASON_LENGTH)
            cancel_reason = _text(payload.get("cancel_reason"), MAX_WORKFLOW_REASON_LENGTH)
            outcome_summary = _text(payload.get("outcome_summary"), MAX_WORKFLOW_OUTCOME_LENGTH)
            if target_status == TaskStatus.BLOCKED.value:
                if len(block_reason or reason) < MIN_REASON_LENGTH:
                    raise WorkflowValidationError("blocking a task requires a reason")
            if target_status == TaskStatus.CANCELLED.value:
                if len(cancel_reason or reason) < MIN_REASON_LENGTH:
                    raise WorkflowValidationError("cancelling a task requires a reason")
            if target_status == TaskStatus.COMPLETED.value:
                if len(outcome_summary) < MIN_OUTCOME_LENGTH:
                    raise WorkflowValidationError("completing a task requires an outcome summary")
            try:
                updated = self._repository.transition_task(
                    workflow_id,
                    task_id,
                    target_status=target_status,
                    expected_version=expected_version,
                    actor_id=actor_id,
                    actor_role=actor_role,
                    reason=reason or f"Task transitioned to {target_status}.",
                    outcome_summary=outcome_summary or None,
                    block_reason=block_reason or None,
                    cancel_reason=cancel_reason or None,
                    dependency_observer=self._record_dependency_counts,
                    now=self._clock(),
                )
            except Exception as exc:
                outcome = "CONFLICT" if getattr(exc, "code", "").endswith("VERSION_CONFLICT") else "REJECTED"
                try:
                    record_governance_workflow_transition("TASK", from_status, target_status, outcome)
                except Exception:  # noqa: BLE001
                    logger.warning("task transition metric failed", exc_info=True)
                raise
            try:
                record_governance_workflow_transition("TASK", from_status, target_status, "APPLIED")
            except Exception:  # noqa: BLE001
                logger.warning("task transition metric failed", exc_info=True)
            self._audit(
                event_type=GovernanceAuditEventType.WORKFLOW_TASK_TRANSITIONED.value,
                actor_id=actor_id,
                actor_role=actor_role,
                target_type="GOVERNANCE_WORKFLOW_TASK",
                target_id=task_id,
                case_id=workflow.get("case_id"),
                reason=reason or f"Task transitioned to {target_status}.",
                request_id=request_id,
                metadata={
                    "workflow_id": workflow_id,
                    "from_status": from_status,
                    "to_status": target_status,
                    "outcome_summary": outcome_summary or None,
                },
            )
            self._refresh_counts()
            return {
                "task": updated,
                "tasks": self._repository.workflow_tasks(workflow_id),
                "sla": self._task_sla(updated),
                "events": self._repository.task_events(task_id),
                "workflow_status": workflow.get("status"),
                "non_claims": list(WORKFLOW_NON_CLAIMS),
            }

    def assign_task(
        self,
        workflow_id: str,
        task_id: str,
        payload: Mapping[str, Any],
        *,
        actor_id: str | None,
        actor_role: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        with self._operation("assign_task"):
            reason = self._require_reason(payload.get("reason"), field="reason")
            owner_type, owner_id = self._validate_owner(
                str(payload.get("owner_type") or ""), str(payload.get("owner_id") or "")
            )
            expected_version = int(payload.get("expected_version") or 0)
            if expected_version < 1:
                raise WorkflowValidationError("expected_version must be at least 1")
            workflow = self._repository.get_workflow(workflow_id)
            if workflow is None:
                raise WorkflowNotFoundError(workflow_id)
            try:
                task = self._repository.assign_task(
                    workflow_id,
                    task_id,
                    owner_type=owner_type,
                    owner_id=owner_id,
                    expected_version=expected_version,
                    actor_id=actor_id,
                    actor_role=actor_role,
                    reason=reason,
                    now=self._clock(),
                )
            except Exception as exc:
                outcome = "CONFLICT" if getattr(exc, "code", "").endswith("VERSION_CONFLICT") else "REJECTED"
                try:
                    record_governance_workflow_transition("TASK", "UNKNOWN", "UNKNOWN", outcome)
                except Exception:  # noqa: BLE001
                    logger.warning("task assignment metric failed", exc_info=True)
                raise
            self._audit(
                event_type=GovernanceAuditEventType.WORKFLOW_TASK_ASSIGNED.value,
                actor_id=actor_id,
                actor_role=actor_role,
                target_type="GOVERNANCE_WORKFLOW_TASK",
                target_id=task_id,
                case_id=workflow.get("case_id"),
                reason=reason,
                request_id=request_id,
                metadata={
                    "workflow_id": workflow_id,
                    "owner_type": owner_type,
                    "owner_id": owner_id,
                },
            )
            return {
                "task": task,
                "events": self._repository.task_events(task_id),
                "non_claims": list(WORKFLOW_NON_CLAIMS),
            }

    # ------------------------------------------------------------------
    # References
    # ------------------------------------------------------------------
    def add_reference(
        self,
        workflow_id: str,
        payload: Mapping[str, Any],
        *,
        actor_id: str | None,
        actor_role: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        with self._operation("add_reference"):
            workflow = self._repository.get_workflow(workflow_id)
            if workflow is None:
                raise WorkflowNotFoundError(workflow_id)
            if str(workflow.get("status") or "") in WORKFLOW_TERMINAL_STATUSES:
                raise WorkflowValidationError("a terminal workflow cannot receive new references")
            domain = str(payload.get("domain") or "").strip().upper()
            if domain not in REFERENCE_DOMAIN_VALUES:
                raise WorkflowValidationError(f"unsupported reference domain: {domain}")
            source_id = _text(payload.get("source_id"), 128)
            if not source_id:
                raise WorkflowValidationError("source_id is required")
            reason = self._require_reason(payload.get("reason"), field="reason")
            task_id = str(payload.get("task_id") or "").strip() or None
            if task_id is not None:
                task = self._repository.get_task(workflow_id, task_id)
                if task is None:
                    raise TaskNotFoundError(task_id)
            if self._repository.count_references(workflow_id) >= MAX_REFERENCES_PER_WORKFLOW:
                raise WorkflowValidationError(
                    f"a workflow may contain at most {MAX_REFERENCES_PER_WORKFLOW} references"
                )
            resolver = self._resolver(actor_role)
            resolved = resolver.resolve(domain, source_id)
            availability = str(resolved.get("availability") or "").upper()
            if availability == ReferenceAvailability.UNAUTHORIZED.value:
                raise ReferenceUnauthorizedError(
                    f"the caller lacks {REFERENCE_DOMAIN_CAPABILITY.get(domain, 'the source')} "
                    "for this reference"
                )
            if availability == ReferenceAvailability.MISSING.value:
                raise ReferenceNotFoundError(domain, source_id)
            if availability == ReferenceAvailability.DELETED.value:
                raise ReferenceDeletedError(
                    f"the referenced {domain} record reports a deleted or disposed status"
                )
            if availability != ReferenceAvailability.AVAILABLE.value:
                raise ReferenceUnavailableError(f"the referenced {domain} record is not currently available")
            source_case_id = resolved.get("source_case_id")
            workflow_case_id = workflow.get("case_id")
            if source_case_id and str(source_case_id) != str(workflow_case_id or ""):
                raise SourceCaseMismatchError("the referenced record belongs to a different case boundary")
            reference_key = _text(payload.get("reference_key"), 160) or resolver.reference_key(
                domain, source_id
            )
            reference, created = self._repository.add_reference(
                workflow_id=workflow_id,
                task_id=task_id,
                domain=domain,
                source_id=source_id,
                reference_key=reference_key,
                source_label=str(resolved.get("source_label") or ""),
                source_case_id=source_case_id,
                availability=availability,
                source_status=str(resolved.get("source_status") or ""),
                source_version=resolved.get("source_version"),
                added_by=str(actor_id or "SYSTEM"),
                reason=reason,
                actor_role=actor_role,
                now=self._clock(),
            )
            if created:
                self._audit(
                    event_type=GovernanceAuditEventType.WORKFLOW_REFERENCE_ADDED.value,
                    actor_id=actor_id,
                    actor_role=actor_role,
                    target_type="GOVERNANCE_WORKFLOW",
                    target_id=workflow_id,
                    case_id=workflow.get("case_id"),
                    reason=reason,
                    request_id=request_id,
                    metadata={
                        "reference_id": reference.get("reference_id"),
                        "domain": domain,
                        "source_id": source_id,
                        "task_id": task_id,
                    },
                )
            return {
                "reference": reference,
                "references": self._repository.list_references(workflow_id),
                "replayed": not created,
                "source_mutated": False,
                "non_claims": list(WORKFLOW_NON_CLAIMS),
            }

    def list_references(self, workflow_id: str) -> dict[str, Any]:
        self._require_enabled()
        workflow = self._repository.get_workflow(workflow_id)
        if workflow is None:
            raise WorkflowNotFoundError(workflow_id)
        return {
            "workflow_id": workflow_id,
            "items": self._repository.list_references(workflow_id),
            "source_mutated": False,
            "non_claims": list(WORKFLOW_NON_CLAIMS),
        }

    # ------------------------------------------------------------------
    # Escalations
    # ------------------------------------------------------------------
    def _escalation_eligible(
        self,
        escalation_type: str,
        *,
        workflow: Mapping[str, Any],
        task: Mapping[str, Any] | None,
        moment: datetime,
    ) -> bool:
        normalized = str(escalation_type).upper()
        if normalized == EscalationType.MANUAL.value:
            return True
        if normalized == EscalationType.UNASSIGNED.value:
            owner = task.get("owner_id") if task is not None else workflow.get("owner_id")
            return not owner
        if normalized == EscalationType.BLOCKED.value:
            status = task.get("status") if task is not None else workflow.get("status")
            return str(status or "").upper() == "BLOCKED"
        if normalized in {
            EscalationType.SLA_OVERDUE.value,
            EscalationType.SLA_AT_RISK.value,
        }:
            sla = (
                self._task_sla(task, now=moment)
                if task is not None
                else self._workflow_sla(workflow, now=moment)
            )
            expected = (
                WorkflowSlaState.OVERDUE.value
                if normalized == EscalationType.SLA_OVERDUE.value
                else WorkflowSlaState.AT_RISK.value
            )
            return str(sla.get("state") or "").upper() == expected
        return False

    def create_escalation(
        self,
        workflow_id: str,
        payload: Mapping[str, Any],
        *,
        actor_id: str | None,
        actor_role: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        with self._operation("create_escalation"):
            workflow = self._repository.get_workflow(workflow_id)
            if workflow is None:
                raise WorkflowNotFoundError(workflow_id)
            if str(workflow.get("status") or "") in WORKFLOW_TERMINAL_STATUSES:
                raise WorkflowValidationError("a terminal workflow cannot be escalated")
            escalation_type = str(payload.get("escalation_type") or "").strip().upper()
            if escalation_type not in {
                EscalationType.SLA_OVERDUE.value,
                EscalationType.SLA_AT_RISK.value,
                EscalationType.BLOCKED.value,
                EscalationType.UNASSIGNED.value,
                EscalationType.MANUAL.value,
            }:
                raise WorkflowValidationError(
                    f"unsupported escalation type: {payload.get('escalation_type')}"
                )
            severity = str(payload.get("severity") or "MEDIUM").strip().upper()
            if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                raise WorkflowValidationError(f"unsupported escalation severity: {severity}")
            reason = self._require_reason(payload.get("reason"), field="reason")
            idempotency_key = _text(payload.get("idempotency_key"), 128)
            if not idempotency_key:
                raise WorkflowValidationError("idempotency_key is required")
            task_id = str(payload.get("task_id") or "").strip() or None
            task = None
            if task_id is not None:
                task = self._repository.get_task(workflow_id, task_id)
                if task is None:
                    raise TaskNotFoundError(task_id)
            if self._repository.count_escalations(workflow_id) >= MAX_ESCALATIONS_PER_WORKFLOW:
                raise WorkflowValidationError(
                    f"a workflow may contain at most {MAX_ESCALATIONS_PER_WORKFLOW} escalations"
                )
            moment = _as_utc(self._clock()) or datetime.now(UTC)
            if not self._escalation_eligible(escalation_type, workflow=workflow, task=task, moment=moment):
                raise EscalationNotEligibleError(
                    f"escalation type {escalation_type} does not match the current deterministic state"
                )
            escalation, created = self._repository.create_escalation(
                workflow_id=workflow_id,
                task_id=task_id,
                escalation_type=escalation_type,
                severity=severity,
                reason=reason,
                requested_by=str(actor_id or "SYSTEM"),
                actor_role=actor_role,
                idempotency_key=idempotency_key,
                now=moment,
            )
            notifications = {
                "enabled": False,
                "considered": 0,
                "queued": 0,
                "duplicate": 0,
                "suppressed": 0,
                "no_rule": 0,
                "failed": 0,
            }
            if created:
                self._audit(
                    event_type=GovernanceAuditEventType.WORKFLOW_ESCALATION_CREATED.value,
                    actor_id=actor_id,
                    actor_role=actor_role,
                    target_type="GOVERNANCE_WORKFLOW_ESCALATION",
                    target_id=str(escalation["escalation_id"]),
                    case_id=workflow.get("case_id"),
                    reason=reason,
                    request_id=request_id,
                    metadata={
                        "workflow_id": workflow_id,
                        "task_id": task_id,
                        "escalation_type": escalation_type,
                        "severity": severity,
                    },
                )
                notifications = self._notify_escalation(
                    workflow=workflow,
                    escalation=escalation,
                    severity=severity,
                    reason=reason,
                )
            try:
                record_governance_workflow_escalation(
                    escalation_type,
                    str(escalation.get("status") or "OPEN"),
                    "CREATED" if created else "REPLAYED",
                )
            except Exception:  # noqa: BLE001
                logger.warning("workflow escalation metric failed", exc_info=True)
            self._refresh_counts()
            return {
                "escalation": escalation,
                "escalations": self._repository.list_escalations(
                    workflow_id=workflow_id, page=1, page_size=100
                )[0],
                "replayed": not created,
                "notifications": notifications,
                "non_claims": list(WORKFLOW_NON_CLAIMS),
            }

    def _notify_escalation(
        self,
        *,
        workflow: Mapping[str, Any],
        escalation: Mapping[str, Any],
        severity: str,
        reason: str,
    ) -> dict[str, int]:
        stats = {
            "enabled": False,
            "considered": 0,
            "queued": 0,
            "duplicate": 0,
            "suppressed": 0,
            "no_rule": 0,
            "failed": 0,
        }
        if not bool(
            getattr(
                self._settings,
                "governance_workflow_escalation_notifications_enabled",
                False,
            )
        ):
            return stats
        if self._notifier is None or not bool(getattr(self._notifier, "enabled", False)):
            return stats
        stats["enabled"] = True
        try:
            result = self._notifier.notify_event(
                event_type="GOVERNANCE_WORKFLOW_ESCALATION",
                case={
                    "case_id": workflow.get("case_id"),
                    "case_number": None,
                    "status": workflow.get("status"),
                    "version": workflow.get("version"),
                },
                target_type="GOVERNANCE_WORKFLOW",
                target_id=str(workflow.get("workflow_id")),
                severity=severity,
                detail=(
                    f"Workflow escalation {escalation.get('escalation_type')}: "
                    f"{_text(reason, 500)}. Review only; no source-domain action is performed."
                ),
                reason_codes=[str(escalation.get("escalation_type") or "")],
                dedup_version=escalation.get("version"),
            )
        except Exception:  # noqa: BLE001 - delivery is queued, never claimed
            logger.warning("workflow escalation notification failed", exc_info=True)
            stats["failed"] += 1
            return stats
        for key in ("considered", "queued", "duplicate", "suppressed", "no_rule", "failed"):
            stats[key] += int(result.get(key, 0) or 0)
        return stats

    def acknowledge_escalation(
        self,
        escalation_id: str,
        payload: Mapping[str, Any],
        *,
        actor_id: str | None,
        actor_role: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        with self._operation("acknowledge_escalation"):
            reason = self._require_reason(payload.get("reason"), field="reason")
            expected_version = int(payload.get("expected_version") or 0)
            if expected_version < 1:
                raise WorkflowValidationError("expected_version must be at least 1")
            escalation = self._repository.acknowledge_escalation(
                escalation_id,
                expected_version=expected_version,
                actor_id=actor_id,
                actor_role=actor_role,
                reason=reason,
                now=self._clock(),
            )
            self._audit(
                event_type=GovernanceAuditEventType.WORKFLOW_ESCALATION_ACKNOWLEDGED.value,
                actor_id=actor_id,
                actor_role=actor_role,
                target_type="GOVERNANCE_WORKFLOW_ESCALATION",
                target_id=escalation_id,
                reason=reason,
                request_id=request_id,
                metadata={"workflow_id": escalation.get("workflow_id")},
            )
            try:
                record_governance_workflow_escalation(
                    str(escalation.get("escalation_type") or ""),
                    str(escalation.get("status") or ""),
                    "ACKNOWLEDGED",
                )
            except Exception:  # noqa: BLE001
                logger.warning("workflow escalation metric failed", exc_info=True)
            return {
                "escalation": escalation,
                "non_claims": list(WORKFLOW_NON_CLAIMS),
            }

    def resolve_escalation(
        self,
        escalation_id: str,
        payload: Mapping[str, Any],
        *,
        actor_id: str | None,
        actor_role: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        with self._operation("resolve_escalation"):
            reason = self._require_reason(payload.get("reason"), field="reason")
            resolution = self._require_outcome(payload.get("resolution"))
            expected_version = int(payload.get("expected_version") or 0)
            if expected_version < 1:
                raise WorkflowValidationError("expected_version must be at least 1")
            escalation = self._repository.resolve_escalation(
                escalation_id,
                expected_version=expected_version,
                actor_id=actor_id,
                actor_role=actor_role,
                reason=reason,
                resolution=resolution,
                now=self._clock(),
            )
            self._audit(
                event_type=GovernanceAuditEventType.WORKFLOW_ESCALATION_RESOLVED.value,
                actor_id=actor_id,
                actor_role=actor_role,
                target_type="GOVERNANCE_WORKFLOW_ESCALATION",
                target_id=escalation_id,
                reason=reason,
                request_id=request_id,
                metadata={
                    "workflow_id": escalation.get("workflow_id"),
                    "resolution": resolution,
                },
            )
            try:
                record_governance_workflow_escalation(
                    str(escalation.get("escalation_type") or ""),
                    str(escalation.get("status") or ""),
                    "RESOLVED",
                )
            except Exception:  # noqa: BLE001
                logger.warning("workflow escalation metric failed", exc_info=True)
            return {
                "escalation": escalation,
                "non_claims": list(WORKFLOW_NON_CLAIMS),
            }

    def list_escalations(
        self,
        *,
        workflow_id: str | None = None,
        status: str | None = None,
        page: int = 1,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        normalized_status = str(status).upper() if status else None
        if normalized_status and normalized_status not in ESCALATION_STATUS_VALUES:
            raise WorkflowValidationError(f"unsupported escalation status: {status}")
        bounded = self._page_size(page_size)
        items, total = self._repository.list_escalations(
            workflow_id=workflow_id,
            status=normalized_status,
            page=max(1, int(page)),
            page_size=bounded,
        )
        return {
            "items": items,
            "total": total,
            "page": max(1, int(page)),
            "page_size": bounded,
            "status_counts": self._repository.escalation_status_counts(),
            "non_claims": list(WORKFLOW_NON_CLAIMS),
        }

    # ------------------------------------------------------------------
    # SLA and ownership reporting
    # ------------------------------------------------------------------
    def workflow_sla(self, workflow_id: str) -> dict[str, Any]:
        self._require_enabled()
        workflow = self._repository.get_workflow(workflow_id)
        if workflow is None:
            raise WorkflowNotFoundError(workflow_id)
        moment = _as_utc(self._clock()) or datetime.now(UTC)
        tasks = self._repository.workflow_tasks(workflow_id)
        task_sla = [self._task_sla(task, now=moment) for task in tasks]
        workflow_sla = self._workflow_sla(workflow, now=moment)
        return {
            "workflow_id": workflow_id,
            "workflow": workflow_sla,
            "tasks": task_sla,
            "counts": sla_state_counts(
                [str(workflow_sla.get("state") or "")] + [str(item.get("state") or "") for item in task_sla]
            ),
            "non_claims": list(WORKFLOW_NON_CLAIMS),
        }

    def ownership_report(self) -> dict[str, Any]:
        self._require_enabled()
        moment = _as_utc(self._clock()) or datetime.now(UTC)
        return {
            "unassigned": self._repository.unassigned_counts(),
            "overdue": self._repository.overdue_counts(now=moment),
            "workflow_counts": self._repository.workflow_status_counts(),
            "task_counts": self._repository.task_status_counts(),
            "generated_at": _iso(moment),
            "non_claims": list(WORKFLOW_NON_CLAIMS),
        }


__all__ = ["GovernanceWorkflowService"]
