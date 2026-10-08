"""Managed worker abstractions (V11, §21–§24)."""

from __future__ import annotations

from backend.app.workers.base import ManagedWorker, WorkerSnapshot, WorkerState, WorkerSupervisor

__all__ = ["ManagedWorker", "WorkerSnapshot", "WorkerState", "WorkerSupervisor"]
