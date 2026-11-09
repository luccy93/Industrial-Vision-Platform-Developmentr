"""Deterministic forensic ZIP exports with a detached manifest digest (V34).

An export contains references, hashes, metadata, notes, actions, and custody
records - not copies of protected evidence. Original evidence bytes are
included only when policy explicitly enables it, the reference digest still
matches, and the bounded package limits allow it.

The archive is byte-deterministic for the same case state and export request:
fixed member order, canonical JSON, fixed ZIP timestamps/attributes, and no
wall-clock value inside the documents. A detached ``manifest.sha256`` member
records the manifest digest; the database records the archive digest too.
"""

from __future__ import annotations

import io
import json
import os
import re
import uuid
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from backend.app.core.redaction import redact_structure
from backend.app.forensics.constants import (
    EXPORT_DEFAULT_MAX_BYTES,
    EXPORT_DEFAULT_MAX_FILES,
    EXPORT_FILENAME_PREFIX,
    EXPORT_MANIFEST,
    EXPORT_MANIFEST_DIGEST,
    EXPORT_MAX_JSON_BYTES,
    EXPORT_POLICY_VERSION,
    EXPORT_REQUIRED_MEMBERS,
    EXPORT_SCHEMA_VERSION,
    EXTERNAL_ANCHORING_NOTE,
)
from backend.app.forensics.custody import canonical_json_bytes, sha256_hex
from backend.app.forensics.errors import (
    ExportPolicyError,
    ExportTooLargeError,
    UnsafeArchivePathError,
)

_FIXED_DATE = (1980, 1, 1, 0, 0, 0)
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")
_MAX_MEMBER_NAME = 200


@dataclass
class ExportPackage:
    export_id: str
    filename: str
    storage_relative_path: str
    sha256: str
    size_bytes: int
    file_count: int
    manifest_digest: str
    root_digest: str
    schema_version: str
    policy_version: str
    evidence_bytes_included: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "export_id": self.export_id,
            "filename": self.filename,
            "storage_relative_path": self.storage_relative_path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "file_count": self.file_count,
            "manifest_digest": self.manifest_digest,
            "root_digest": self.root_digest,
            "schema_version": self.schema_version,
            "policy_version": self.policy_version,
            "evidence_bytes_included": self.evidence_bytes_included,
        }


@dataclass
class ExportVerification:
    outcome: str
    detail: str
    reason_codes: list[str]
    file_count: int = 0
    manifest_digest: str = ""
    root_digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "detail": self.detail,
            "reason_codes": sorted(set(self.reason_codes)),
            "file_count": self.file_count,
            "manifest_digest": self.manifest_digest,
            "root_digest": self.root_digest,
            "external_anchor_claimed": False,
            "external_anchor_note": EXTERNAL_ANCHORING_NOTE,
        }


def json_bytes(value: Any) -> bytes:
    """Canonical, human-readable JSON bytes used for every export document."""
    return (
        json.dumps(
            redact_structure(value),
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _safe_name(value: str) -> str:
    text = _SAFE_NAME.sub("-", str(value or "")).strip("-.")
    return (text or "artifact")[:_MAX_MEMBER_NAME]


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(filename=name, date_time=_FIXED_DATE)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    return info


def _document_members(case_detail: Mapping[str, Any]) -> dict[str, bytes]:
    case = dict(case_detail.get("case") or {})
    correlations = list(case_detail.get("correlations") or [])
    incident_links = list(case_detail.get("incident_links") or [])
    references = list(case_detail.get("evidence_references") or [])
    custody = dict(case_detail.get("custody") or {})
    notes = list(case_detail.get("notes") or [])
    actions = list(case_detail.get("actions") or [])
    assignments = list(case_detail.get("assignments") or [])
    latest_verification = case_detail.get("latest_verification")

    audit_run_ids = sorted(
        {str(item.get("audit_run_id")) for item in correlations if item.get("audit_run_id")}
        | {str(item.get("source_audit_run_id")) for item in references if item.get("source_audit_run_id")}
    )
    documents: dict[str, Any] = {
        "case.json": case,
        "incident-reference.json": {
            "originating_incident_id": case.get("originating_incident_id"),
            "incident_links": incident_links,
            "note": "V10 incident rows are referenced by id; they are not copied or modified.",
        },
        "findings.json": {
            "correlations": correlations,
            "note": (
                "V33 findings are referenced by stable finding_id and audit_run_id; "
                "original findings are never copied, replaced, or re-hashed."
            ),
        },
        "audit-runs.json": {
            "originating_audit_run_id": case.get("originating_audit_run_id"),
            "referenced_audit_run_ids": audit_run_ids,
            "note": "Audit runs remain in the isolated V33 monitoring store.",
        },
        "evidence-references.json": {
            "references": references,
            "note": (
                "References record identifiers, relative paths, and expected digests only. "
                "Original evidence bytes are excluded unless explicitly included."
            ),
        },
        "custody-ledger.json": custody,
        "investigation-notes.json": {
            "notes": notes,
            "note": "Edits are preserved as immutable revisions in the case database.",
        },
        "operator-actions.json": {"actions": actions},
        "verification-report.json": latest_verification
        or {
            "outcome": "NOT_RUN",
            "detail": "no case verification has been recorded",
        },
        "assignments.json": {"assignments": assignments},
    }
    missing = [name for name in EXPORT_REQUIRED_MEMBERS if name not in documents]
    if missing:
        raise ExportPolicyError(f"export document set is incomplete: {sorted(missing)}")
    return {name: json_bytes(documents[name]) for name in EXPORT_REQUIRED_MEMBERS}


def _evidence_members(
    references: Sequence[Mapping[str, Any]],
    *,
    evidence_base: Path | None,
) -> dict[str, bytes]:
    """Include original bytes only for references whose digest still matches."""
    if evidence_base is None:
        raise ExportPolicyError("evidence-byte export requires a configured protected evidence root")
    members: dict[str, bytes] = {}
    root = evidence_base.expanduser().resolve(strict=False)
    for reference in references:
        if str(reference.get("artifact_type") or "") not in {
            "EVIDENCE_FILE",
            "EVIDENCE_SIDECAR",
            "EVIDENCE_AUDIT_CHAIN",
            "SIGNED_CHECKPOINT",
            "TRUST_STATE",
            "TRUST_STORE",
            "TRANSPARENCY_LOG",
            "TREE_HEAD",
            "INCLUSION_PROOF",
            "CONSISTENCY_PROOF",
            "RECEIPT",
        }:
            continue
        expected = str(reference.get("expected_sha256") or "").strip().lower()
        relative_path = str(reference.get("original_relative_path") or "").strip()
        if not expected or not relative_path:
            raise ExportPolicyError(
                "evidence-byte export requires an expected digest and relative path for every file reference"
            )
        candidate = (root / relative_path).resolve(strict=False)
        if candidate != root and root not in candidate.parents:
            raise ExportPolicyError("evidence reference escapes the protected evidence root")
        if not candidate.is_file():
            raise ExportPolicyError("referenced evidence is unavailable; export was not created")
        data = candidate.read_bytes()
        if sha256_hex(data) != expected:
            raise ExportPolicyError("referenced evidence digest no longer matches; export was not created")
        artifact_type = _safe_name(str(reference.get("artifact_type") or "EVIDENCE"))
        artifact_id = _safe_name(str(reference.get("artifact_id") or "artifact"))
        members[f"evidence/{artifact_type}/{artifact_id}"] = data
    return members


def build_export_package(
    *,
    case_detail: Mapping[str, Any],
    export_id: str | None = None,
    export_root: Path,
    include_evidence_bytes: bool = False,
    evidence_base: Path | None = None,
    max_files: int = EXPORT_DEFAULT_MAX_FILES,
    max_bytes: int = EXPORT_DEFAULT_MAX_BYTES,
) -> ExportPackage:
    """Build and atomically store one deterministic export ZIP."""
    case = dict(case_detail.get("case") or {})
    if not case.get("case_id") or not case.get("case_number"):
        raise ExportPolicyError("case identity is required for an export")
    identifier = str(export_id or uuid.uuid4())
    documents = _document_members(case_detail)
    if include_evidence_bytes:
        documents.update(
            _evidence_members(
                list(case_detail.get("evidence_references") or []),
                evidence_base=evidence_base,
            )
        )
    if len(documents) + 2 > max_files:
        raise ExportTooLargeError(
            f"export would contain {len(documents) + 2} members; the limit is {max_files}"
        )
    total_json = sum(len(payload) for payload in documents.values())
    if total_json > EXPORT_MAX_JSON_BYTES:
        raise ExportTooLargeError("export documents exceed the configured JSON size bound")

    member_entries = [
        {
            "name": name,
            "sha256": sha256_hex(documents[name]),
            "size_bytes": len(documents[name]),
        }
        for name in sorted(documents)
    ]
    root_digest = sha256_hex(canonical_json_bytes(member_entries))
    manifest = {
        "schema_version": EXPORT_SCHEMA_VERSION,
        "policy_version": EXPORT_POLICY_VERSION,
        "case_id": case.get("case_id"),
        "case_number": case.get("case_number"),
        "case_version": int(case.get("version") or 1),
        "case_updated_at": case.get("updated_at"),
        "evidence_bytes_included": bool(include_evidence_bytes),
        "members": member_entries,
        "root_digest": root_digest,
        "limitations": [
            EXTERNAL_ANCHORING_NOTE,
            "A digest manifest proves package integrity relative to its own content; it does "
            "not independently prove the authenticity of the original artifacts.",
        ],
        "external_anchor_claimed": False,
    }
    manifest_bytes = json_bytes(manifest)
    manifest_digest = sha256_hex(manifest_bytes)
    digest_bytes = (manifest_digest + "\n").encode("ascii")

    archive_entries = dict(documents)
    archive_entries[EXPORT_MANIFEST] = manifest_bytes
    archive_entries[EXPORT_MANIFEST_DIGEST] = digest_bytes
    names = sorted(archive_entries)
    total_size = sum(len(payload) for payload in archive_entries.values())
    if total_size > max_bytes:
        raise ExportTooLargeError(f"export would contain {total_size} bytes; the limit is {max_bytes}")

    filename = f"{EXPORT_FILENAME_PREFIX}{_safe_name(str(case.get('case_number')))}-{identifier}.zip"
    case_directory = export_root.expanduser().resolve(strict=False) / _safe_name(str(case.get("case_number")))
    case_directory.mkdir(parents=True, exist_ok=True)
    target = case_directory / filename
    temporary = case_directory / f".{filename}.{uuid.uuid4().hex}.tmp"
    try:
        with zipfile.ZipFile(
            temporary, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as archive:
            for name in names:
                archive.writestr(_zip_info(name), archive_entries[name])
        os.replace(temporary, target)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    data = target.read_bytes()
    archive_digest = sha256_hex(data)
    relative_path = f"{_safe_name(str(case.get('case_number')))}/{filename}"
    return ExportPackage(
        export_id=identifier,
        filename=filename,
        storage_relative_path=relative_path,
        sha256=archive_digest,
        size_bytes=len(data),
        file_count=len(names),
        manifest_digest=manifest_digest,
        root_digest=root_digest,
        schema_version=EXPORT_SCHEMA_VERSION,
        policy_version=EXPORT_POLICY_VERSION,
        evidence_bytes_included=bool(include_evidence_bytes),
    )


def _reject_unsafe_name(name: str) -> None:
    if (
        not name
        or "\x00" in name
        or "\\" in name
        or name.startswith("/")
        or re.match(r"^[A-Za-z]:", name)
        or any(part in {"", ".", ".."} for part in name.split("/"))
    ):
        raise UnsafeArchivePathError(f"unsafe archive member name: {name!r}")


def verify_export_package(
    path: Path,
    *,
    expected_sha256: str | None = None,
    expected_manifest_digest: str | None = None,
    max_files: int = EXPORT_DEFAULT_MAX_FILES,
    max_bytes: int = EXPORT_DEFAULT_MAX_BYTES,
) -> ExportVerification:
    """Verify an export archive without extracting it to disk."""
    reasons: list[str] = []
    if not path.is_file():
        return ExportVerification(
            outcome="UNAVAILABLE",
            detail="export archive is not present",
            reason_codes=["FORENSIC_EXPORT_UNAVAILABLE"],
        )
    data = path.read_bytes()
    if len(data) > max_bytes:
        return ExportVerification(
            outcome="FAIL",
            detail="export archive exceeds the configured size bound",
            reason_codes=["FORENSIC_EXPORT_TOO_LARGE"],
        )
    archive_digest = sha256_hex(data)
    if expected_sha256 and archive_digest != str(expected_sha256).strip().lower():
        reasons.append("FORENSIC_EXPORT_ARCHIVE_DIGEST_MISMATCH")
    try:
        with zipfile.ZipFile(io.BytesIO(data), mode="r") as archive:
            infos = archive.infolist()
            if len(infos) > max_files:
                reasons.append("FORENSIC_EXPORT_TOO_LARGE")
            names: list[str] = []
            for info in infos:
                _reject_unsafe_name(info.filename)
                mode = (info.external_attr >> 16) & 0o170000
                if mode == 0o120000:
                    raise UnsafeArchivePathError(f"symlink archive member is not allowed: {info.filename!r}")
                names.append(info.filename)
            if len(names) != len(set(names)):
                reasons.append("FORENSIC_EXPORT_DUPLICATE_MEMBER")
            name_set = set(names)
            for required in EXPORT_REQUIRED_MEMBERS:
                if required not in name_set:
                    reasons.append("FORENSIC_EXPORT_MEMBER_MISSING")
                    break
            if EXPORT_MANIFEST not in name_set or EXPORT_MANIFEST_DIGEST not in name_set:
                reasons.append("FORENSIC_EXPORT_MANIFEST_MISSING")
                return ExportVerification(
                    outcome="FAIL",
                    detail="export manifest or detached digest is missing",
                    reason_codes=sorted(set(reasons)),
                    file_count=len(names),
                )
            manifest_bytes = archive.read(EXPORT_MANIFEST)
            manifest_digest = sha256_hex(manifest_bytes)
            detached = archive.read(EXPORT_MANIFEST_DIGEST).decode("ascii", errors="replace").strip()
            if detached != manifest_digest:
                reasons.append("FORENSIC_EXPORT_MANIFEST_DIGEST_MISMATCH")
            if expected_manifest_digest and manifest_digest != str(expected_manifest_digest).strip().lower():
                reasons.append("FORENSIC_EXPORT_MANIFEST_DIGEST_MISMATCH")
            try:
                manifest = json.loads(manifest_bytes.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                reasons.append("FORENSIC_EXPORT_MANIFEST_INVALID")
                manifest = {}
            if manifest.get("schema_version") != EXPORT_SCHEMA_VERSION:
                reasons.append("FORENSIC_EXPORT_SCHEMA_UNSUPPORTED")
            if manifest.get("policy_version") != EXPORT_POLICY_VERSION:
                reasons.append("FORENSIC_EXPORT_POLICY_UNSUPPORTED")
            members = manifest.get("members")
            if not isinstance(members, list) or not members:
                reasons.append("FORENSIC_EXPORT_MANIFEST_INVALID")
                members = []
            for member in members:
                if not isinstance(member, dict):
                    reasons.append("FORENSIC_EXPORT_MANIFEST_INVALID")
                    continue
                name = str(member.get("name") or "")
                if name not in name_set:
                    reasons.append("FORENSIC_EXPORT_MEMBER_MISSING")
                    continue
                payload = archive.read(name)
                if sha256_hex(payload) != str(member.get("sha256") or ""):
                    reasons.append("FORENSIC_EXPORT_MEMBER_DIGEST_MISMATCH")
                if len(payload) != int(member.get("size_bytes") or -1):
                    reasons.append("FORENSIC_EXPORT_MEMBER_SIZE_MISMATCH")
            root_digest = sha256_hex(canonical_json_bytes(members))
            if root_digest != str(manifest.get("root_digest") or ""):
                reasons.append("FORENSIC_EXPORT_ROOT_DIGEST_MISMATCH")
            if manifest.get("external_anchor_claimed") is not False:
                reasons.append("FORENSIC_EXPORT_ANCHOR_CLAIM_INVALID")
            expected_members = set(EXPORT_REQUIRED_MEMBERS) | {
                EXPORT_MANIFEST,
                EXPORT_MANIFEST_DIGEST,
            }
            if manifest.get("evidence_bytes_included") is True:
                allowed_evidence = {
                    name for name in names if name.startswith("evidence/") and name not in expected_members
                }
                expected_members |= allowed_evidence
            unexpected = name_set - expected_members
            if unexpected:
                reasons.append("FORENSIC_EXPORT_UNEXPECTED_MEMBER")
    except (UnsafeArchivePathError, zipfile.BadZipFile, KeyError, OSError):
        return ExportVerification(
            outcome="FAIL",
            detail="export archive is malformed or contains an unsafe member",
            reason_codes=sorted(set(reasons) | {"FORENSIC_EXPORT_ARCHIVE_INVALID"}),
        )
    outcome = "FAIL" if reasons else "PASS"
    return ExportVerification(
        outcome=outcome,
        detail=(
            "export manifest, member digests, root digest, and archive digest are valid"
            if not reasons
            else "export verification found integrity problems"
        ),
        reason_codes=sorted(set(reasons)),
        file_count=len(names),
        manifest_digest=manifest_digest,
        root_digest=root_digest,
    )


__all__ = [
    "ExportPackage",
    "ExportVerification",
    "build_export_package",
    "json_bytes",
    "verify_export_package",
]
