"""Deterministic V39 template DAG validation and dependency evaluation.

Templates are immutable, versioned task graphs. Validation is bounded and
deterministic: unknown keys, duplicate keys, self-dependencies, and cycles are
rejected before any row is written. Runtime evaluation only reads stored task
statuses; it never infers a completion or fabricates a dependency result.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any

from backend.app.forensics.custody import canonical_json_bytes, sha256_hex
from backend.app.governance.workflows.constants import (
    MAX_TEMPLATE_DEFINITION_BYTES,
    MAX_TEMPLATE_DEPENDENCIES,
    MAX_TEMPLATE_TASKS,
    MAX_WORKFLOW_DESCRIPTION_LENGTH,
    MAX_WORKFLOW_TITLE_LENGTH,
    MIN_TITLE_LENGTH,
    TASK_KEY_PATTERN,
    TASK_STATUS_VALUES,
    TaskStatus,
)
from backend.app.governance.workflows.errors import DependencyError, TemplateValidationError

_TASK_KEY_RE = re.compile(TASK_KEY_PATTERN)

DEPENDENCY_READY = "READY"
DEPENDENCY_PENDING = "PENDING"
DEPENDENCY_BLOCKED = "BLOCKED"


def _bounded_text(value: Any, *, field: str, maximum: int, minimum: int = 0) -> str:
    text = str(value or "").strip()
    if len(text) < minimum:
        raise TemplateValidationError(f"{field} must be at least {minimum} characters")
    if len(text) > maximum:
        raise TemplateValidationError(f"{field} must be at most {maximum} characters")
    return text


def _normalize_task(raw: Any, *, index: int, seen: set[str]) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise TemplateValidationError(f"task[{index}] must be an object")
    task_key = str(raw.get("task_key") or "").strip()
    if not task_key or not _TASK_KEY_RE.fullmatch(task_key):
        raise TemplateValidationError(f"task[{index}].task_key must match {TASK_KEY_PATTERN}")
    if task_key in seen:
        raise TemplateValidationError(f"duplicate task_key: {task_key}")
    seen.add(task_key)
    title = _bounded_text(
        raw.get("title"),
        field=f"task[{index}].title",
        maximum=MAX_WORKFLOW_TITLE_LENGTH,
        minimum=MIN_TITLE_LENGTH,
    )
    description = str(raw.get("description") or "").strip()
    if len(description) > MAX_WORKFLOW_DESCRIPTION_LENGTH:
        raise TemplateValidationError(
            f"task[{index}].description must be at most {MAX_WORKFLOW_DESCRIPTION_LENGTH} characters"
        )
    depends_on_raw = raw.get("depends_on") or []
    if not isinstance(depends_on_raw, (list, tuple)):
        raise TemplateValidationError(f"task[{index}].depends_on must be a list")
    depends_on: list[str] = []
    for value in depends_on_raw:
        dependency_key = str(value or "").strip()
        if not dependency_key or not _TASK_KEY_RE.fullmatch(dependency_key):
            raise TemplateValidationError(f"task[{index}].depends_on contains an invalid task key")
        if dependency_key == task_key:
            raise TemplateValidationError(f"task {task_key} cannot depend on itself")
        if dependency_key not in depends_on:
            depends_on.append(dependency_key)
    try:
        order_raw = raw.get("order_index")
        order_index = index if order_raw is None else int(order_raw)
    except (TypeError, ValueError):
        raise TemplateValidationError(f"task[{index}].order_index must be an integer") from None
    if order_index < 0 or order_index > 10_000:
        raise TemplateValidationError(f"task[{index}].order_index is out of bounds")
    due_in_hours = raw.get("due_in_hours")
    if due_in_hours is not None:
        try:
            due_in_hours = int(due_in_hours)
        except (TypeError, ValueError):
            raise TemplateValidationError(f"task[{index}].due_in_hours must be an integer") from None
        if due_in_hours < 1 or due_in_hours > 24 * 3650:
            raise TemplateValidationError(f"task[{index}].due_in_hours is out of bounds")
    return {
        "task_key": task_key,
        "title": title,
        "description": description,
        "required": bool(raw.get("required", True)),
        "depends_on": sorted(depends_on),
        "order_index": order_index,
        "due_in_hours": due_in_hours,
    }


def _topological_order(tasks: Sequence[Mapping[str, Any]]) -> list[str]:
    """Kahn's algorithm with deterministic tie-breaking by order/key."""
    order_index = {str(task["task_key"]): int(task["order_index"]) for task in tasks}
    dependencies = {str(task["task_key"]): set(str(item) for item in task["depends_on"]) for task in tasks}
    dependents: dict[str, list[str]] = {key: [] for key in dependencies}
    indegree: dict[str, int] = {}
    for key, required in dependencies.items():
        unknown = sorted(item for item in required if item not in dependencies)
        if unknown:
            raise DependencyError(f"task {key} depends on unknown task key(s): {', '.join(unknown)}")
        indegree[key] = len(required)
        for dependency in required:
            dependents[dependency].append(key)
    ready = sorted(
        (key for key, degree in indegree.items() if degree == 0),
        key=lambda key: (order_index[key], key),
    )
    ordered: list[str] = []
    while ready:
        key = ready.pop(0)
        ordered.append(key)
        for dependent in sorted(dependents[key], key=lambda item: (order_index[item], item)):
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                ready.append(dependent)
        ready.sort(key=lambda item: (order_index[item], item))
    if len(ordered) != len(tasks):
        cyclic = sorted(key for key, degree in indegree.items() if degree > 0)
        raise TemplateValidationError("template task dependencies contain a cycle: " + ", ".join(cyclic))
    return ordered


def validate_template_definition(definition: Any) -> dict[str, Any]:
    """Validate and normalize a bounded template definition.

    The returned mapping is canonical: tasks are ordered by ``order_index`` and
    ``task_key`` and dependency lists are sorted. Its digest is stable for the
    same logical template.
    """
    if not isinstance(definition, Mapping):
        raise TemplateValidationError("template definition must be an object")
    raw_tasks = definition.get("tasks")
    if not isinstance(raw_tasks, (list, tuple)) or not raw_tasks:
        raise TemplateValidationError("template definition must contain at least one task")
    if len(raw_tasks) > MAX_TEMPLATE_TASKS:
        raise TemplateValidationError(f"template definition may contain at most {MAX_TEMPLATE_TASKS} tasks")
    seen: set[str] = set()
    tasks = [_normalize_task(raw, index=index, seen=seen) for index, raw in enumerate(raw_tasks)]
    tasks.sort(key=lambda task: (int(task["order_index"]), str(task["task_key"])))
    dependency_count = sum(len(task["depends_on"]) for task in tasks)
    if dependency_count > MAX_TEMPLATE_DEPENDENCIES:
        raise TemplateValidationError(
            f"template definition may contain at most {MAX_TEMPLATE_DEPENDENCIES} dependencies"
        )
    order = _topological_order(tasks)
    normalized = {
        "schema_version": 1,
        "tasks": tasks,
        "topological_order": order,
    }
    encoded = canonical_json_bytes(normalized)
    if len(encoded) > MAX_TEMPLATE_DEFINITION_BYTES:
        raise TemplateValidationError(
            f"template definition must be at most {MAX_TEMPLATE_DEFINITION_BYTES} bytes"
        )
    return {
        "definition": normalized,
        "definition_digest": sha256_hex(encoded),
        "task_count": len(tasks),
        "dependency_count": dependency_count,
        "topological_order": order,
    }


def template_digest(definition: Any) -> str:
    """Deterministic digest over a canonical template definition."""
    return sha256_hex(canonical_json_bytes(definition))


def dependency_verdict(
    *,
    dependency_ids: Sequence[str],
    status_by_id: Mapping[str, str],
) -> str:
    """Return the deterministic dependency verdict for one task.

    ``READY`` means every dependency is completed. ``BLOCKED`` means at least
    one dependency was cancelled. Otherwise the task stays ``PENDING``.
    """
    if not dependency_ids:
        return DEPENDENCY_READY
    verdict = DEPENDENCY_READY
    for dependency_id in dependency_ids:
        status = str(status_by_id.get(str(dependency_id)) or "").upper()
        if status not in TASK_STATUS_VALUES:
            return DEPENDENCY_PENDING
        if status == TaskStatus.CANCELLED.value:
            return DEPENDENCY_BLOCKED
        if status != TaskStatus.COMPLETED.value:
            verdict = DEPENDENCY_PENDING
    return verdict


def dependency_state_counts(verdicts: Sequence[str]) -> dict[str, int]:
    """Bounded deterministic counts used by metrics and status responses."""
    counts = {
        DEPENDENCY_READY: 0,
        DEPENDENCY_PENDING: 0,
        DEPENDENCY_BLOCKED: 0,
    }
    for verdict in verdicts:
        normalized = str(verdict).upper()
        if normalized in counts:
            counts[normalized] += 1
    return counts


def duplicate_task_keys(tasks: Sequence[Mapping[str, Any]]) -> list[str]:
    """Return duplicate task keys, used only by defensive tests."""
    counts = Counter(str(task.get("task_key") or "") for task in tasks)
    return sorted(key for key, count in counts.items() if count > 1)


__all__ = [
    "DEPENDENCY_BLOCKED",
    "DEPENDENCY_PENDING",
    "DEPENDENCY_READY",
    "dependency_state_counts",
    "dependency_verdict",
    "duplicate_task_keys",
    "template_digest",
    "validate_template_definition",
]
