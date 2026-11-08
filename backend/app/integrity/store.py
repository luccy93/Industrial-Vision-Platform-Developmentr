"""Isolated, durable V33 monitoring store.

Design decision: V33 writes only its own SQLite monitoring database, never
the primary application schema and never any V30-V32 artifact. This keeps the
read-only guarantee structural and avoids an Alembic migration. All workers
that need cross-process duplicate prevention must share the same store file;
SQLite write locking plus a durable execution lease provide serialization.

The store contains audit-run summaries, per-scope results, sanitized findings,
lease rows, and alert dedup/cooldown state. It never contains evidence bytes,
private keys, credentials, or raw authorization material.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import (
    Column,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    create_engine,
    delete,
    event,
    func,
    select,
    text,
    update,
)
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.pool import StaticPool

from backend.app.integrity.constants import (
    AnchorStatus,
    AssuranceLevel,
    AuditStatus,
    AuditTrigger,
    IntegrityScope,
    ScopeStatus,
    Severity,
)
from backend.app.integrity.errors import MonitoringStoreError, MonitoringStoreUnavailable
from backend.app.integrity.models import (
    AuditRun,
    Finding,
    ScopeResult,
    empty_finding_counts,
    utc_now_iso,
)

STORE_SCHEMA_VERSION = "1"

metadata = MetaData()

audit_runs = Table(
    "integrity_audit_runs",
    metadata,
    Column("audit_run_id", String(64), primary_key=True),
    Column("trigger", String(16), nullable=False, index=True),
    Column("requested_scopes", Text, nullable=False),
    Column("completed_scopes", Text, nullable=False, default="[]"),
    Column("status", String(16), nullable=False, index=True),
    Column("started_at", String(32), nullable=False, index=True),
    Column("completed_at", String(32), nullable=True),
    Column("duration_ms", Integer, nullable=False, default=0),
    Column("cancelled", Integer, nullable=False, default=0),
    Column("timed_out", Integer, nullable=False, default=0),
    Column("retry_count", Integer, nullable=False, default=0),
    Column("artifacts_checked", Integer, nullable=False, default=0),
    Column("finding_counts", Text, nullable=False, default="{}"),
    Column("reason_code_counts", Text, nullable=False, default="{}"),
    Column("error_summary", Text, nullable=True),
    Column("external_anchor_configured", Integer, nullable=False, default=0),
    Column("assurance", String(24), nullable=False, default="NONE"),
    Column("requested_by", String(128), nullable=True),
    Column("schedule_slot", String(64), nullable=True, unique=True),
    Column("heartbeat_at", String(32), nullable=True),
    Column("created_at", String(32), nullable=False, index=True),
)

findings = Table(
    "integrity_findings",
    metadata,
    Column("finding_id", String(64), primary_key=True),
    Column("audit_run_id", String(64), nullable=False, index=True),
    Column("scope", String(32), nullable=False, index=True),
    Column("severity", String(16), nullable=False, index=True),
    Column("reason_code", String(64), nullable=False, index=True),
    Column("artifact_id", String(512), nullable=False, default=""),
    Column("detected_at", String(32), nullable=False, index=True),
    Column("explanation", Text, nullable=False, default=""),
    Column("verification_source", String(256), nullable=False, default=""),
    Column("recommended_action", Text, nullable=False, default=""),
    UniqueConstraint(
        "audit_run_id",
        "scope",
        "reason_code",
        "artifact_id",
        "verification_source",
        name="uq_integrity_finding_identity",
    ),
)

scope_results = Table(
    "integrity_scope_results",
    metadata,
    Column("id", String(160), primary_key=True),
    Column("audit_run_id", String(64), nullable=False, index=True),
    Column("scope", String(32), nullable=False, index=True),
    Column("status", String(16), nullable=False, index=True),
    Column("started_at", String(32), nullable=False),
    Column("completed_at", String(32), nullable=False),
    Column("duration_ms", Integer, nullable=False, default=0),
    Column("artifacts_checked", Integer, nullable=False, default=0),
    Column("checks_total", Integer, nullable=False, default=0),
    Column("checks_failed", Integer, nullable=False, default=0),
    Column("findings_count", Integer, nullable=False, default=0),
    Column("reason_codes", Text, nullable=False, default="[]"),
    Column("error_summary", Text, nullable=True),
    Column("truncated", Integer, nullable=False, default=0),
    Column("details", Text, nullable=False, default="{}"),
    UniqueConstraint("audit_run_id", "scope", name="uq_integrity_scope_run"),
)

leases = Table(
    "integrity_store_leases",
    metadata,
    Column("lease_name", String(64), primary_key=True),
    Column("owner", String(64), nullable=False),
    Column("acquired_at", String(32), nullable=False),
    Column("expires_at", String(32), nullable=False),
    Column("heartbeat_at", String(32), nullable=False),
)

alert_state = Table(
    "integrity_alert_state",
    metadata,
    Column("id", String(160), primary_key=True),
    Column("rule_id", String(64), nullable=False, index=True),
    Column("dedup_key", String(256), nullable=False),
    Column("reason_code", String(64), nullable=False),
    Column("scope", String(32), nullable=False),
    Column("cooldown_key", String(128), nullable=False, index=True),
    Column("last_sent_at", String(32), nullable=False),
    Column("notification_id", String(64), nullable=True),
    UniqueConstraint("rule_id", "dedup_key", name="uq_integrity_alert_dedup"),
)

store_meta = Table(
    "integrity_store_meta",
    metadata,
    Column("key", String(64), primary_key=True),
    Column("value", Text, nullable=False),
)


def _json_dump(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _json_load(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def _bool(value: Any) -> bool:
    return bool(int(value or 0))


def _run_from_row(row: Any) -> AuditRun:
    mapping = row._mapping
    return AuditRun(
        audit_run_id=str(mapping["audit_run_id"]),
        trigger=AuditTrigger(str(mapping["trigger"])),
        requested_scopes=[
            IntegrityScope(str(scope)) for scope in _json_load(mapping["requested_scopes"], [])
        ],
        completed_scopes=[
            IntegrityScope(str(scope)) for scope in _json_load(mapping["completed_scopes"], [])
        ],
        status=AuditStatus(str(mapping["status"])),
        started_at=str(mapping["started_at"]),
        completed_at=str(mapping["completed_at"]) if mapping["completed_at"] else None,
        duration_ms=int(mapping["duration_ms"] or 0),
        cancelled=_bool(mapping["cancelled"]),
        timed_out=_bool(mapping["timed_out"]),
        retry_count=int(mapping["retry_count"] or 0),
        artifacts_checked=int(mapping["artifacts_checked"] or 0),
        finding_counts=dict(_json_load(mapping["finding_counts"], {})),
        reason_code_counts=dict(_json_load(mapping["reason_code_counts"], {})),
        error_summary=str(mapping["error_summary"]) if mapping["error_summary"] else None,
        external_anchor_configured=_bool(mapping["external_anchor_configured"]),
        assurance=AssuranceLevel(str(mapping["assurance"] or "NONE")),
        requested_by=str(mapping["requested_by"]) if mapping["requested_by"] else None,
        schedule_slot=str(mapping["schedule_slot"]) if mapping["schedule_slot"] else None,
        created_at=str(mapping["created_at"]),
    )


def _finding_from_row(row: Any) -> Finding:
    mapping = row._mapping
    return Finding(
        finding_id=str(mapping["finding_id"]),
        audit_run_id=str(mapping["audit_run_id"]),
        scope=IntegrityScope(str(mapping["scope"])),
        severity=Severity(str(mapping["severity"])),
        reason_code=str(mapping["reason_code"]),
        artifact_id=str(mapping["artifact_id"]) if mapping["artifact_id"] else None,
        detected_at=str(mapping["detected_at"]),
        explanation=str(mapping["explanation"] or ""),
        verification_source=str(mapping["verification_source"] or ""),
        recommended_action=str(mapping["recommended_action"] or ""),
    )


def _scope_from_row(row: Any) -> ScopeResult:
    mapping = row._mapping
    return ScopeResult(
        audit_run_id=str(mapping["audit_run_id"]),
        scope=IntegrityScope(str(mapping["scope"])),
        status=ScopeStatus(str(mapping["status"])),
        started_at=str(mapping["started_at"]),
        completed_at=str(mapping["completed_at"]),
        duration_ms=int(mapping["duration_ms"] or 0),
        artifacts_checked=int(mapping["artifacts_checked"] or 0),
        checks_total=int(mapping["checks_total"] or 0),
        checks_failed=int(mapping["checks_failed"] or 0),
        findings_count=int(mapping["findings_count"] or 0),
        reason_codes=list(_json_load(mapping["reason_codes"], [])),
        error_summary=str(mapping["error_summary"]) if mapping["error_summary"] else None,
        truncated=_bool(mapping["truncated"]),
        details=dict(_json_load(mapping["details"], {})),
    )


class MonitoringStore:
    """SQLite-backed audit history, findings, and coordination state."""

    def __init__(self, url: str, *, retention_days: int = 30) -> None:
        parsed = urlparse(str(url or ""))
        if parsed.scheme.split("+", 1)[0] != "sqlite":
            raise MonitoringStoreUnavailable("the V33 monitoring store requires an isolated sqlite:// URL")
        self.url = str(url)
        self.retention_days = max(1, int(retention_days))
        self._write_lock = threading.RLock()
        self._initialized = False
        connect_args: dict[str, Any] = {"check_same_thread": False, "timeout": 5.0}
        poolclass = None
        if ":memory:" in self.url:
            poolclass = StaticPool
        try:
            self._engine: Engine = create_engine(
                self.url,
                connect_args=connect_args,
                pool_pre_ping=True,
                poolclass=poolclass,
            )
        except (SQLAlchemyError, ValueError) as exc:
            raise MonitoringStoreUnavailable(
                f"monitoring store engine could not be created: {type(exc).__name__}"
            ) from None
        self._install_pragmas()

    # ------------------------------------------------------------------
    # Lifecycle and low-level helpers
    # ------------------------------------------------------------------
    def _ensure_parent_directory(self) -> None:
        try:
            parsed = make_url(self.url)
        except Exception:
            return
        if parsed.get_backend_name() != "sqlite":
            return
        raw_path = str(parsed.database or "")
        if not raw_path or raw_path == ":memory:":
            return
        path = Path(raw_path)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise MonitoringStoreUnavailable(
                f"monitoring store directory is not writable: {type(exc).__name__}"
            ) from None

    def _install_pragmas(self) -> None:
        @event.listens_for(self._engine, "connect")
        def _set_sqlite_pragmas(dbapi_connection: Any, _connection_record: Any) -> None:
            cursor = dbapi_connection.cursor()
            try:
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.execute("PRAGMA busy_timeout=5000")
                cursor.execute("PRAGMA foreign_keys=ON")
            finally:
                cursor.close()

    @contextmanager
    def _connection(self) -> Iterator[Any]:
        try:
            with self._engine.connect() as connection:
                yield connection
        except MonitoringStoreUnavailable:
            raise
        except SQLAlchemyError as exc:
            raise MonitoringStoreUnavailable(f"monitoring store unavailable: {type(exc).__name__}") from None

    def initialize(self) -> None:
        if self._initialized:
            return
        with self._write_lock:
            if self._initialized:
                return
            self._ensure_parent_directory()
            try:
                metadata.create_all(self._engine)
                with self._engine.begin() as connection:
                    statement = sqlite_insert(store_meta).values(
                        key="schema_version", value=STORE_SCHEMA_VERSION
                    )
                    connection.execute(statement.on_conflict_do_nothing())
                self._initialized = True
            except SQLAlchemyError as exc:
                raise MonitoringStoreUnavailable(
                    f"monitoring store schema initialization failed: {type(exc).__name__}"
                ) from None

    def is_available(self) -> bool:
        try:
            self.initialize()
            with self._connection() as connection:
                connection.execute(text("SELECT 1"))
            return True
        except MonitoringStoreUnavailable:
            return False

    def close(self) -> None:
        try:
            self._engine.dispose()
        except Exception:
            pass
        self._initialized = False

    # ------------------------------------------------------------------
    # Audit runs
    # ------------------------------------------------------------------
    def create_run(self, run: AuditRun) -> bool:
        self.initialize()
        values = {
            "audit_run_id": run.audit_run_id,
            "trigger": run.trigger.value,
            "requested_scopes": _json_dump([scope.value for scope in run.requested_scopes]),
            "completed_scopes": _json_dump([scope.value for scope in run.completed_scopes]),
            "status": run.status.value,
            "started_at": run.started_at,
            "completed_at": run.completed_at,
            "duration_ms": int(run.duration_ms),
            "cancelled": int(run.cancelled),
            "timed_out": int(run.timed_out),
            "retry_count": int(run.retry_count),
            "artifacts_checked": int(run.artifacts_checked),
            "finding_counts": _json_dump(run.finding_counts or empty_finding_counts()),
            "reason_code_counts": _json_dump(run.reason_code_counts),
            "error_summary": run.error_summary,
            "external_anchor_configured": int(run.external_anchor_configured),
            "assurance": run.assurance.value,
            "requested_by": run.requested_by,
            "schedule_slot": run.schedule_slot,
            "heartbeat_at": run.started_at,
            "created_at": run.created_at,
        }
        with self._write_lock:
            try:
                with self._engine.begin() as connection:
                    connection.execute(audit_runs.insert().values(**values))
                return True
            except IntegrityError:
                return False
            except SQLAlchemyError as exc:
                raise MonitoringStoreError(f"audit-run insert failed: {type(exc).__name__}") from None

    def update_run(self, audit_run_id: str, **fields: Any) -> bool:
        allowed = {
            "completed_scopes",
            "status",
            "completed_at",
            "duration_ms",
            "cancelled",
            "timed_out",
            "retry_count",
            "artifacts_checked",
            "finding_counts",
            "reason_code_counts",
            "error_summary",
            "external_anchor_configured",
            "assurance",
            "heartbeat_at",
        }
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError(f"unknown audit-run fields: {sorted(unknown)}")
        values = dict(fields)
        for key in ("completed_scopes", "finding_counts", "reason_code_counts"):
            if key in values and not isinstance(values[key], str):
                values[key] = _json_dump(values[key])
        for key in ("cancelled", "timed_out", "external_anchor_configured"):
            if key in values:
                values[key] = int(bool(values[key]))
        if "status" in values and isinstance(values["status"], AuditStatus):
            values["status"] = values["status"].value
        if "assurance" in values and isinstance(values["assurance"], AssuranceLevel):
            values["assurance"] = values["assurance"].value
        with self._write_lock:
            try:
                with self._engine.begin() as connection:
                    result = connection.execute(
                        update(audit_runs)
                        .where(audit_runs.c.audit_run_id == str(audit_run_id))
                        .values(**values)
                    )
                    return bool(result.rowcount)
            except SQLAlchemyError as exc:
                raise MonitoringStoreError(f"audit-run update failed: {type(exc).__name__}") from None

    def complete_run(self, run: AuditRun) -> bool:
        return self.update_run(
            run.audit_run_id,
            completed_scopes=[scope.value for scope in run.completed_scopes],
            status=run.status,
            completed_at=run.completed_at,
            duration_ms=run.duration_ms,
            cancelled=run.cancelled,
            timed_out=run.timed_out,
            retry_count=run.retry_count,
            artifacts_checked=run.artifacts_checked,
            finding_counts=run.finding_counts,
            reason_code_counts=run.reason_code_counts,
            error_summary=run.error_summary,
            external_anchor_configured=run.external_anchor_configured,
            assurance=run.assurance,
            heartbeat_at=run.completed_at or run.started_at,
        )

    def get_run(self, audit_run_id: str) -> AuditRun | None:
        self.initialize()
        with self._connection() as connection:
            row = connection.execute(
                select(audit_runs).where(audit_runs.c.audit_run_id == str(audit_run_id))
            ).first()
            return _run_from_row(row) if row is not None else None

    def get_run_by_schedule_slot(self, schedule_slot: str) -> AuditRun | None:
        self.initialize()
        with self._connection() as connection:
            row = connection.execute(
                select(audit_runs).where(audit_runs.c.schedule_slot == str(schedule_slot))
            ).first()
            return _run_from_row(row) if row is not None else None

    def find_active_run(self) -> AuditRun | None:
        self.initialize()
        with self._connection() as connection:
            row = connection.execute(
                select(audit_runs)
                .where(audit_runs.c.status == AuditStatus.RUNNING.value)
                .order_by(audit_runs.c.started_at.desc())
                .limit(1)
            ).first()
            return _run_from_row(row) if row is not None else None

    def _run_filters(
        self,
        *,
        status: str | None,
        scope: str | None,
        trigger: str | None,
        started_from: str | None,
        started_to: str | None,
    ) -> list[Any]:
        clauses: list[Any] = []
        if status:
            clauses.append(audit_runs.c.status == str(status).upper())
        if trigger:
            clauses.append(audit_runs.c.trigger == str(trigger).upper())
        if scope:
            token = f'%"{str(scope).upper()}"%'
            clauses.append(
                (audit_runs.c.requested_scopes.like(token)) | (audit_runs.c.completed_scopes.like(token))
            )
        if started_from:
            clauses.append(audit_runs.c.started_at >= str(started_from))
        if started_to:
            clauses.append(audit_runs.c.started_at <= str(started_to))
        return clauses

    def list_runs(
        self,
        *,
        status: str | None = None,
        scope: str | None = None,
        trigger: str | None = None,
        started_from: str | None = None,
        started_to: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[AuditRun], int]:
        self.initialize()
        page = max(1, int(page))
        page_size = max(1, int(page_size))
        clauses = self._run_filters(
            status=status,
            scope=scope,
            trigger=trigger,
            started_from=started_from,
            started_to=started_to,
        )
        with self._connection() as connection:
            count_query = select(func.count()).select_from(audit_runs)
            list_query = select(audit_runs)
            for clause in clauses:
                count_query = count_query.where(clause)
                list_query = list_query.where(clause)
            total = int(connection.execute(count_query).scalar_one())
            rows = connection.execute(
                list_query.order_by(audit_runs.c.started_at.desc(), audit_runs.c.audit_run_id.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            ).all()
            return [_run_from_row(row) for row in rows], total

    def history(self, *, page: int = 1, page_size: int = 20) -> tuple[list[AuditRun], int]:
        return self.list_runs(page=page, page_size=page_size)

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------
    def add_findings(
        self,
        items: Sequence[Finding],
        *,
        max_findings: int = 1000,
    ) -> tuple[int, bool]:
        """Insert findings idempotently, bounded per run.

        Returns ``(inserted_count, truncated)``. Existing identities are not
        duplicated; a retry therefore cannot inflate findings.
        """
        self.initialize()
        if not items:
            return 0, False
        by_run: dict[str, list[Finding]] = {}
        for item in items:
            by_run.setdefault(item.audit_run_id, []).append(item)
        inserted = 0
        truncated = False
        with self._write_lock:
            try:
                with self._engine.begin() as connection:
                    for audit_run_id, run_items in by_run.items():
                        existing = int(
                            connection.execute(
                                select(func.count())
                                .select_from(findings)
                                .where(findings.c.audit_run_id == audit_run_id)
                            ).scalar_one()
                        )
                        remaining = max(0, int(max_findings) - existing)
                        if remaining <= 0:
                            truncated = True
                            continue
                        batch = run_items[:remaining]
                        if len(batch) < len(run_items):
                            truncated = True
                        values = [
                            {
                                "finding_id": item.finding_id,
                                "audit_run_id": item.audit_run_id,
                                "scope": item.scope.value,
                                "severity": item.severity.value,
                                "reason_code": item.reason_code,
                                "artifact_id": item.artifact_id or "",
                                "detected_at": item.detected_at,
                                "explanation": item.explanation,
                                "verification_source": item.verification_source,
                                "recommended_action": item.recommended_action,
                            }
                            for item in batch
                        ]
                        statement = sqlite_insert(findings).values(values)
                        connection.execute(statement.on_conflict_do_nothing())
                        inserted += len(batch)
            except SQLAlchemyError as exc:
                raise MonitoringStoreError(f"finding insert failed: {type(exc).__name__}") from None
        return inserted, truncated

    def list_findings(
        self,
        *,
        severity: str | None = None,
        reason_code: str | None = None,
        scope: str | None = None,
        audit_run_id: str | None = None,
        artifact_id: str | None = None,
        detected_from: str | None = None,
        detected_to: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[Finding], int]:
        self.initialize()
        page = max(1, int(page))
        page_size = max(1, int(page_size))
        clauses: list[Any] = []
        if severity:
            clauses.append(findings.c.severity == str(severity).upper())
        if reason_code:
            clauses.append(findings.c.reason_code == str(reason_code).upper())
        if scope:
            clauses.append(findings.c.scope == str(scope).upper())
        if audit_run_id:
            clauses.append(findings.c.audit_run_id == str(audit_run_id))
        if artifact_id:
            clauses.append(findings.c.artifact_id == str(artifact_id))
        if detected_from:
            clauses.append(findings.c.detected_at >= str(detected_from))
        if detected_to:
            clauses.append(findings.c.detected_at <= str(detected_to))
        with self._connection() as connection:
            count_query = select(func.count()).select_from(findings)
            list_query = select(findings)
            for clause in clauses:
                count_query = count_query.where(clause)
                list_query = list_query.where(clause)
            total = int(connection.execute(count_query).scalar_one())
            rows = connection.execute(
                list_query.order_by(findings.c.detected_at.desc(), findings.c.finding_id.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            ).all()
            return [_finding_from_row(row) for row in rows], total

    # ------------------------------------------------------------------
    # Scope results
    # ------------------------------------------------------------------
    def upsert_scope_result(self, result: ScopeResult) -> None:
        self.initialize()
        values = {
            "id": f"{result.audit_run_id}:{result.scope.value}",
            "audit_run_id": result.audit_run_id,
            "scope": result.scope.value,
            "status": result.status.value,
            "started_at": result.started_at,
            "completed_at": result.completed_at,
            "duration_ms": int(result.duration_ms),
            "artifacts_checked": int(result.artifacts_checked),
            "checks_total": int(result.checks_total),
            "checks_failed": int(result.checks_failed),
            "findings_count": int(result.findings_count),
            "reason_codes": _json_dump(sorted(set(result.reason_codes))),
            "error_summary": result.error_summary,
            "truncated": int(result.truncated),
            "details": _json_dump(result.details),
        }
        with self._write_lock:
            try:
                with self._engine.begin() as connection:
                    statement = sqlite_insert(scope_results).values(**values)
                    update_values = {
                        key: value
                        for key, value in values.items()
                        if key not in ("id", "audit_run_id", "scope")
                    }
                    connection.execute(
                        statement.on_conflict_do_update(index_elements=["id"], set_=update_values)
                    )
            except SQLAlchemyError as exc:
                raise MonitoringStoreError(f"scope-result upsert failed: {type(exc).__name__}") from None

    def list_scope_results(self, audit_run_id: str) -> list[ScopeResult]:
        self.initialize()
        with self._connection() as connection:
            rows = connection.execute(
                select(scope_results)
                .where(scope_results.c.audit_run_id == str(audit_run_id))
                .order_by(scope_results.c.scope.asc())
            ).all()
            return [_scope_from_row(row) for row in rows]

    def get_run_detail(self, audit_run_id: str) -> dict[str, Any] | None:
        run = self.get_run(audit_run_id)
        if run is None:
            return None
        scopes = self.list_scope_results(audit_run_id)
        items, total = self.list_findings(audit_run_id=audit_run_id, page=1, page_size=500)
        return {
            "audit": run.to_dict(include_details=True),
            "scope_results": [scope.to_dict() for scope in scopes],
            "findings": [item.to_dict() for item in items],
            "findings_total": total,
        }

    # ------------------------------------------------------------------
    # Summary and status inputs
    # ------------------------------------------------------------------
    def summary(self) -> dict[str, Any]:
        self.initialize()
        with self._connection() as connection:
            total_runs = int(connection.execute(select(func.count()).select_from(audit_runs)).scalar_one())
            by_status = {
                str(status): int(count)
                for status, count in connection.execute(
                    select(audit_runs.c.status, func.count(audit_runs.c.audit_run_id)).group_by(
                        audit_runs.c.status
                    )
                ).all()
            }
            by_trigger = {
                str(trigger): int(count)
                for trigger, count in connection.execute(
                    select(audit_runs.c.trigger, func.count(audit_runs.c.audit_run_id)).group_by(
                        audit_runs.c.trigger
                    )
                ).all()
            }
            by_severity = {
                str(severity): int(count)
                for severity, count in connection.execute(
                    select(findings.c.severity, func.count(findings.c.finding_id)).group_by(
                        findings.c.severity
                    )
                ).all()
            }
            by_reason = {
                str(reason): int(count)
                for reason, count in connection.execute(
                    select(findings.c.reason_code, func.count(findings.c.finding_id))
                    .group_by(findings.c.reason_code)
                    .order_by(func.count(findings.c.finding_id).desc())
                    .limit(100)
                ).all()
            }
            by_scope = {
                str(scope): int(count)
                for scope, count in connection.execute(
                    select(findings.c.scope, func.count(findings.c.finding_id)).group_by(findings.c.scope)
                ).all()
            }
            total_findings = int(connection.execute(select(func.count()).select_from(findings)).scalar_one())
            total_artifacts = int(
                connection.execute(
                    select(func.coalesce(func.sum(audit_runs.c.artifacts_checked), 0))
                ).scalar_one()
            )
            verified_rows = connection.execute(
                select(
                    scope_results.c.scope,
                    func.coalesce(func.sum(scope_results.c.artifacts_checked), 0),
                )
                .where(scope_results.c.status == ScopeStatus.PASS.value)
                .group_by(scope_results.c.scope)
            ).all()
            verified = {str(scope): int(count) for scope, count in verified_rows}
            last_success_row = connection.execute(
                select(audit_runs)
                .where(audit_runs.c.status == AuditStatus.PASS.value)
                .order_by(audit_runs.c.started_at.desc())
                .limit(1)
            ).first()
            last_failure_row = connection.execute(
                select(audit_runs)
                .where(audit_runs.c.status == AuditStatus.FAIL.value)
                .order_by(audit_runs.c.started_at.desc())
                .limit(1)
            ).first()
            latest_row = connection.execute(
                select(audit_runs)
                .order_by(audit_runs.c.started_at.desc(), audit_runs.c.audit_run_id.desc())
                .limit(1)
            ).first()
            running = int(
                connection.execute(
                    select(func.count())
                    .select_from(audit_runs)
                    .where(audit_runs.c.status == AuditStatus.RUNNING.value)
                ).scalar_one()
            )
            latest_findings = 0
            if latest_row is not None:
                latest_id = str(latest_row._mapping["audit_run_id"])
                latest_findings = int(
                    connection.execute(
                        select(func.count()).select_from(findings).where(findings.c.audit_run_id == latest_id)
                    ).scalar_one()
                )
        return {
            "total_runs": total_runs,
            "by_status": by_status,
            "by_trigger": by_trigger,
            "by_severity": by_severity,
            "by_reason_code": by_reason,
            "by_scope": by_scope,
            "total_findings": total_findings,
            "total_audited_artifacts": total_artifacts,
            "verified": verified,
            "last_success": _run_from_row(last_success_row).to_dict() if last_success_row else None,
            "last_failure": _run_from_row(last_failure_row).to_dict() if last_failure_row else None,
            "latest_audit": _run_from_row(latest_row).to_dict() if latest_row else None,
            "running_audits": running,
            "open_findings": latest_findings,
        }

    def status_counts(self) -> dict[str, int]:
        self.initialize()
        with self._connection() as connection:
            return {
                str(status): int(count)
                for status, count in connection.execute(
                    select(audit_runs.c.status, func.count(audit_runs.c.audit_run_id)).group_by(
                        audit_runs.c.status
                    )
                ).all()
            }

    # ------------------------------------------------------------------
    # Execution leases (durable duplicate prevention)
    # ------------------------------------------------------------------
    def acquire_execution_lease(
        self,
        owner: str,
        *,
        slots: int = 1,
        ttl_seconds: float = 900.0,
        now: str | None = None,
    ) -> str | None:
        self.initialize()
        moment = now or utc_now_iso()
        expires = _expiry(moment, ttl_seconds)
        with self._write_lock:
            try:
                with self._engine.begin() as connection:
                    for index in range(max(1, int(slots))):
                        lease_name = f"audit-slot-{index}"
                        inserted = connection.execute(
                            sqlite_insert(leases)
                            .values(
                                lease_name=lease_name,
                                owner=str(owner),
                                acquired_at=moment,
                                expires_at=expires,
                                heartbeat_at=moment,
                            )
                            .on_conflict_do_nothing()
                        ).rowcount
                        if inserted:
                            return lease_name
                        claimed = connection.execute(
                            update(leases)
                            .where(
                                leases.c.lease_name == lease_name,
                                (leases.c.owner == str(owner)) | (leases.c.expires_at < moment),
                            )
                            .values(
                                owner=str(owner),
                                acquired_at=moment,
                                expires_at=expires,
                                heartbeat_at=moment,
                            )
                        ).rowcount
                        if claimed:
                            return lease_name
                return None
            except SQLAlchemyError as exc:
                raise MonitoringStoreError(f"lease acquisition failed: {type(exc).__name__}") from None

    def heartbeat_lease(
        self,
        lease_name: str,
        owner: str,
        *,
        ttl_seconds: float = 900.0,
        now: str | None = None,
    ) -> bool:
        moment = now or utc_now_iso()
        with self._write_lock:
            with self._engine.begin() as connection:
                result = connection.execute(
                    update(leases)
                    .where(leases.c.lease_name == lease_name, leases.c.owner == str(owner))
                    .values(heartbeat_at=moment, expires_at=_expiry(moment, ttl_seconds))
                )
                return bool(result.rowcount)

    def release_execution_lease(self, lease_name: str, owner: str) -> None:
        with self._write_lock:
            with self._engine.begin() as connection:
                connection.execute(
                    delete(leases).where(leases.c.lease_name == lease_name, leases.c.owner == str(owner))
                )

    def recover_stale_runs(
        self,
        *,
        stale_before: str,
        now: str | None = None,
    ) -> list[str]:
        """Mark interrupted RUNNING records so crashes never leave them stuck."""
        self.initialize()
        moment = now or utc_now_iso()
        recovered: list[str] = []
        with self._write_lock:
            with self._engine.begin() as connection:
                rows = connection.execute(
                    select(audit_runs).where(
                        audit_runs.c.status == AuditStatus.RUNNING.value,
                        func.coalesce(audit_runs.c.heartbeat_at, audit_runs.c.started_at) < str(stale_before),
                    )
                ).all()
                for row in rows:
                    run = _run_from_row(row)
                    connection.execute(
                        update(audit_runs)
                        .where(audit_runs.c.audit_run_id == run.audit_run_id)
                        .values(
                            status=AuditStatus.UNAVAILABLE.value,
                            completed_at=moment,
                            timed_out=1,
                            error_summary="audit run was interrupted before completion",
                            heartbeat_at=moment,
                        )
                    )
                    recovered.append(run.audit_run_id)
        if recovered:
            self.add_findings(
                [
                    Finding.create(
                        audit_run_id=run_id,
                        scope=(run.requested_scopes or [IntegrityScope.EVIDENCE])[0],
                        reason_code="AUDIT_INTERRUPTED",
                        explanation="the audit run stopped heartbeating and was recovered as unavailable",
                    )
                    for run_id in recovered
                ]
            )
        return recovered

    # ------------------------------------------------------------------
    # Alert dedup and cooldown state
    # ------------------------------------------------------------------
    def alert_is_allowed(
        self,
        *,
        rule_id: str,
        dedup_key: str,
        cooldown_key: str,
        cooldown_seconds: int,
        now: str | None = None,
    ) -> tuple[bool, str | None, str | None]:
        """Return ``(allowed, notification_id, suppression_reason)``.

        ``DUPLICATE`` means the exact finding was already notified for this
        rule. ``COOLDOWN`` means a correlated finding is inside the cooldown
        window. Both suppress delivery; neither claims delivery success.
        """
        self.initialize()
        moment = now or utc_now_iso()
        with self._connection() as connection:
            existing = connection.execute(
                select(alert_state).where(
                    alert_state.c.rule_id == str(rule_id),
                    alert_state.c.dedup_key == str(dedup_key),
                )
            ).first()
            if existing is not None:
                return (
                    False,
                    str(existing._mapping["notification_id"] or "") or None,
                    "DUPLICATE",
                )
            if cooldown_seconds > 0:
                cutoff = _expiry(moment, -float(cooldown_seconds))
                recent = connection.execute(
                    select(alert_state)
                    .where(
                        alert_state.c.rule_id == str(rule_id),
                        alert_state.c.cooldown_key == str(cooldown_key),
                        alert_state.c.last_sent_at >= cutoff,
                    )
                    .limit(1)
                ).first()
                if recent is not None:
                    return (
                        False,
                        str(recent._mapping["notification_id"] or "") or None,
                        "COOLDOWN",
                    )
        return True, None, None

    def record_alert_sent(
        self,
        *,
        rule_id: str,
        dedup_key: str,
        reason_code: str,
        scope: str,
        cooldown_key: str,
        notification_id: str | None,
        now: str | None = None,
    ) -> None:
        self.initialize()
        moment = now or utc_now_iso()
        identity = f"{rule_id}:{dedup_key}"
        values = {
            "id": identity,
            "rule_id": str(rule_id),
            "dedup_key": str(dedup_key),
            "reason_code": str(reason_code),
            "scope": str(scope),
            "cooldown_key": str(cooldown_key),
            "last_sent_at": moment,
            "notification_id": str(notification_id) if notification_id else None,
        }
        with self._write_lock:
            with self._engine.begin() as connection:
                statement = sqlite_insert(alert_state).values(**values)
                connection.execute(
                    statement.on_conflict_do_update(
                        index_elements=["id"],
                        set_={
                            "last_sent_at": moment,
                            "notification_id": values["notification_id"],
                            "cooldown_key": str(cooldown_key),
                        },
                    )
                )

    # ------------------------------------------------------------------
    # Retention
    # ------------------------------------------------------------------
    def prune(self, *, retention_days: int | None = None, limit: int = 1000) -> int:
        self.initialize()
        days = max(1, int(retention_days if retention_days is not None else self.retention_days))
        cutoff = _expiry(utc_now_iso(), -float(days) * 86400.0)
        with self._write_lock:
            try:
                with self._engine.begin() as connection:
                    rows = connection.execute(
                        select(audit_runs.c.audit_run_id)
                        .where(
                            audit_runs.c.status != AuditStatus.RUNNING.value,
                            func.coalesce(audit_runs.c.completed_at, audit_runs.c.started_at) < cutoff,
                        )
                        .order_by(audit_runs.c.started_at.asc())
                        .limit(max(1, int(limit)))
                    ).all()
                    run_ids = [str(row._mapping["audit_run_id"]) for row in rows]
                    if not run_ids:
                        return 0
                    connection.execute(delete(findings).where(findings.c.audit_run_id.in_(run_ids)))
                    connection.execute(delete(scope_results).where(scope_results.c.audit_run_id.in_(run_ids)))
                    connection.execute(delete(audit_runs).where(audit_runs.c.audit_run_id.in_(run_ids)))
                    return len(run_ids)
            except SQLAlchemyError as exc:
                raise MonitoringStoreError(f"retention prune failed: {type(exc).__name__}") from None


def _expiry(moment: str, delta_seconds: float) -> str:
    from backend.app.integrity.models import parse_iso, utc_now_iso

    parsed = parse_iso(moment)
    if parsed is None:
        return utc_now_iso()
    from datetime import timedelta

    return (
        (parsed + timedelta(seconds=delta_seconds)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    )


def status_from_counts(counts: dict[str, int]) -> dict[str, int]:
    """Normalize status counts to every terminal status (dashboard helper)."""
    return {
        status.value: int(counts.get(status.value, 0))
        for status in (
            AuditStatus.PASS,
            AuditStatus.FAIL,
            AuditStatus.PARTIAL,
            AuditStatus.UNAVAILABLE,
            AuditStatus.NOT_RUN,
            AuditStatus.RUNNING,
        )
    }


def anchor_status_from_text(value: object) -> AnchorStatus:
    text = str(value or "").strip().upper()
    try:
        return AnchorStatus(text)
    except ValueError:
        return AnchorStatus.UNAVAILABLE
