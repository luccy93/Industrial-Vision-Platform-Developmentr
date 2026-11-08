"""Resolved, read-only V30-V32 input locations for the V33 auditor."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


def _optional_path(value: object) -> Path | None:
    text = str(value or "").strip()
    if not text:
        return None
    return Path(text).expanduser()


@dataclass(frozen=True)
class IntegrityTargets:
    """Configured protected inputs. ``None`` means "not configured"."""

    evidence_root: Path | None = None
    evidence_manifest: Path | None = None
    evidence_report: Path | None = None
    evidence_integrity: Path | None = None
    evidence_audit: Path | None = None
    evidence_checkpoint: Path | None = None
    evidence_trust_store: Path | None = None
    evidence_trust_state: Path | None = None
    evidence_trusted_fingerprint: str | None = None
    transparency_log: Path | None = None
    tree_heads_dir: Path | None = None
    inclusion_proofs_dir: Path | None = None
    consistency_proofs_dir: Path | None = None
    transparency_trust_store: Path | None = None
    transparency_trust_state: Path | None = None
    tree_head_trusted_fingerprint: str | None = None
    receipt: Path | None = None

    @classmethod
    def from_settings(cls, settings: Any) -> IntegrityTargets:
        return cls(
            evidence_root=_optional_path(getattr(settings, "integrity_evidence_root", "")),
            evidence_manifest=_optional_path(getattr(settings, "integrity_evidence_manifest", "")),
            evidence_report=_optional_path(getattr(settings, "integrity_evidence_report", "")),
            evidence_integrity=_optional_path(getattr(settings, "integrity_evidence_integrity", "")),
            evidence_audit=_optional_path(getattr(settings, "integrity_evidence_audit", "")),
            evidence_checkpoint=_optional_path(getattr(settings, "integrity_evidence_checkpoint", "")),
            evidence_trust_store=_optional_path(getattr(settings, "integrity_evidence_trust_store", "")),
            evidence_trust_state=_optional_path(getattr(settings, "integrity_evidence_trust_state", "")),
            evidence_trusted_fingerprint=(
                str(getattr(settings, "integrity_evidence_trusted_fingerprint", "") or "").strip() or None
            ),
            transparency_log=_optional_path(getattr(settings, "integrity_transparency_log", "")),
            tree_heads_dir=_optional_path(getattr(settings, "integrity_tree_heads_dir", "")),
            inclusion_proofs_dir=_optional_path(getattr(settings, "integrity_inclusion_proofs_dir", "")),
            consistency_proofs_dir=_optional_path(getattr(settings, "integrity_consistency_proofs_dir", "")),
            transparency_trust_store=_optional_path(
                getattr(settings, "integrity_transparency_trust_store", "")
            ),
            transparency_trust_state=_optional_path(
                getattr(settings, "integrity_transparency_trust_state", "")
            ),
            tree_head_trusted_fingerprint=(
                str(getattr(settings, "integrity_tree_head_trusted_fingerprint", "") or "").strip() or None
            ),
            receipt=_optional_path(getattr(settings, "integrity_receipt", "")),
        )

    @property
    def safe_roots(self) -> tuple[Path, ...]:
        roots: list[Path] = []
        for candidate in (
            self.evidence_root,
            self.evidence_report.parent if self.evidence_report else None,
            self.transparency_log.parent if self.transparency_log else None,
            self.tree_heads_dir,
            self.inclusion_proofs_dir,
            self.consistency_proofs_dir,
        ):
            if candidate is not None and candidate not in roots:
                roots.append(candidate)
        return tuple(roots)

    def configured_inputs(self) -> list[Path]:
        """Every explicitly configured protected input path (not directories)."""
        values = [
            self.evidence_manifest,
            self.evidence_report,
            self.evidence_integrity,
            self.evidence_audit,
            self.evidence_checkpoint,
            self.evidence_trust_store,
            self.evidence_trust_state,
            self.transparency_log,
            self.transparency_trust_store,
            self.transparency_trust_state,
            self.receipt,
        ]
        return [value for value in values if value is not None]

    def configured_directories(self) -> list[Path]:
        values = [self.tree_heads_dir, self.inclusion_proofs_dir, self.consistency_proofs_dir]
        return [value for value in values if value is not None]
