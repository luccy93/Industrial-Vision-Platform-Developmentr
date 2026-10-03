"""Quality repository — PostgreSQL-backed inspection configuration.

Only slow-changing configuration is stored: profiles, regions, defect
categories, and profile<->category associations. The runtime never queries
this layer (the engine holds a snapshot), and frame-level results are never
written here.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from backend.app.domain.common import utcnow
from backend.app.models.quality_orm import (
    DefectCategoryORM,
    InspectionProfileORM,
    InspectionRegionORM,
    ProfileDefectCategoryORM,
)
from backend.app.quality.schemas import (
    DecisionPolicy,
    DefectCategory,
    DefectSeverity,
    InspectionProfile,
    InspectionRegion,
    InspectionType,
    MissingEvidenceBehavior,
    ProductCorrelation,
    ProfileDefectCategory,
    RegionType,
)


class ProfileConflictError(ValueError):
    """Raised when a profile_id is already used by the same camera."""


class DefectCategoryConflictError(ValueError):
    """Raised when a defect category code already exists."""


class DefectCategoryNotFoundError(ValueError):
    """Raised when a profile references an unknown defect category code."""


def _policy_to_dict(policy: DecisionPolicy) -> dict[str, Any]:
    return {
        "fail_threshold": policy.fail_threshold,
        "review_threshold": policy.review_threshold,
        "fail_severities": [s.value for s in policy.fail_severities],
        "required_region_ids": list(policy.required_region_ids),
        "missing_evidence_behavior": policy.missing_evidence_behavior.value,
        "error_behavior": policy.error_behavior.value,
    }


def _policy_from_dict(data: dict[str, Any] | None) -> DecisionPolicy:
    raw = data or {}
    return DecisionPolicy(
        fail_threshold=float(raw.get("fail_threshold", 0.6)),
        review_threshold=float(raw.get("review_threshold", 0.35)),
        fail_severities=[DefectSeverity(s) for s in raw.get("fail_severities", ["HIGH", "CRITICAL"])],
        required_region_ids=list(raw.get("required_region_ids", [])),
        missing_evidence_behavior=MissingEvidenceBehavior(raw.get("missing_evidence_behavior", "REVIEW")),
        error_behavior=raw.get("error_behavior", "RECORD_ERROR"),
    )


def profile_to_domain(row: InspectionProfileORM) -> InspectionProfile:
    correlation = row.product_correlation
    return InspectionProfile(
        profile_id=row.profile_id,
        camera_id=row.camera_id,
        name=row.name,
        enabled=bool(row.enabled),
        inspection_type=InspectionType(row.inspection_type),
        confidence_threshold=row.confidence_threshold,
        review_threshold=row.review_threshold,
        decision_policy=_policy_from_dict(row.decision_policy),
        product_correlation=ProductCorrelation(**correlation) if correlation else None,
        metadata=dict(row.meta or {}),
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def region_to_domain(row: InspectionRegionORM) -> InspectionRegion:
    return InspectionRegion(
        region_id=row.region_id,
        camera_id=row.camera_id,
        profile_id=row.profile_id,
        name=row.name,
        region_type=RegionType(row.region_type),
        geometry=dict(row.geometry or {}),
        enabled=bool(row.enabled),
        required=bool(row.required),
        metadata=dict(row.meta or {}),
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def category_to_domain(row: DefectCategoryORM) -> DefectCategory:
    return DefectCategory(
        defect_id=row.id,
        code=row.code,
        name=row.name,
        description=row.description,
        severity=DefectSeverity(row.severity),
        enabled=bool(row.enabled),
        confidence_threshold=row.confidence_threshold,
        review_threshold=row.review_threshold,
        metadata=dict(row.meta or {}),
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def association_to_domain(row: ProfileDefectCategoryORM) -> ProfileDefectCategory:
    return ProfileDefectCategory(
        profile_id=row.profile_id,
        defect_category_id=row.defect_category_id,
        defect_code=row.defect_code,
        enabled=bool(row.enabled),
        override_confidence_threshold=row.override_confidence_threshold,
        override_review_threshold=row.override_review_threshold,
        metadata=dict(row.meta or {}),
    )


class InspectionProfileRepository:
    """CRUD over profiles + their regions and category associations."""

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    def create(
        self,
        *,
        camera_id: str,
        profile: InspectionProfile,
        regions: list[InspectionRegion] | None = None,
        associations: list[ProfileDefectCategory] | None = None,
    ) -> InspectionProfile:
        now: datetime = utcnow()
        with self._session_factory() as session:
            exists = (
                session.query(InspectionProfileORM)
                .filter_by(camera_id=camera_id, profile_id=profile.profile_id)
                .one_or_none()
            )
            if exists is not None:
                raise ProfileConflictError(f"profile {profile.profile_id} already exists for {camera_id}")
            row = InspectionProfileORM(
                id=str(uuid.uuid4()),
                profile_id=profile.profile_id,
                camera_id=camera_id,
                name=profile.name,
                inspection_type=profile.inspection_type.value,
                enabled=profile.enabled,
                confidence_threshold=profile.confidence_threshold,
                review_threshold=profile.review_threshold,
                decision_policy=_policy_to_dict(profile.decision_policy),
                product_correlation=(
                    profile.product_correlation.model_dump() if profile.product_correlation else None
                ),
                meta=profile.metadata,
                created_at=now,
                updated_at=now,
            )
            session.add(row)
            for region in regions or []:
                session.add(
                    InspectionRegionORM(
                        id=str(uuid.uuid4()),
                        region_id=region.region_id,
                        camera_id=camera_id,
                        profile_id=profile.profile_id,
                        name=region.name,
                        region_type=region.region_type.value,
                        geometry=region.geometry,
                        enabled=region.enabled,
                        required=region.required,
                        meta=region.metadata,
                        created_at=now,
                        updated_at=now,
                    )
                )
            for association in associations or []:
                session.add(
                    ProfileDefectCategoryORM(
                        id=str(uuid.uuid4()),
                        camera_id=camera_id,
                        profile_id=profile.profile_id,
                        defect_category_id=association.defect_category_id,
                        defect_code=association.defect_code,
                        enabled=association.enabled,
                        override_confidence_threshold=association.override_confidence_threshold,
                        override_review_threshold=association.override_review_threshold,
                        meta=association.metadata,
                        created_at=now,
                        updated_at=now,
                    )
                )
            session.commit()
            session.refresh(row)
            return profile_to_domain(row)

    def get(self, camera_id: str, profile_id: str) -> InspectionProfile | None:
        with self._session_factory() as session:
            row = (
                session.query(InspectionProfileORM)
                .filter_by(camera_id=camera_id, profile_id=profile_id)
                .one_or_none()
            )
            return profile_to_domain(row) if row else None

    def list_all(self, camera_id: str) -> list[InspectionProfile]:
        with self._session_factory() as session:
            rows = (
                session.query(InspectionProfileORM)
                .filter_by(camera_id=camera_id)
                .order_by(InspectionProfileORM.created_at, InspectionProfileORM.profile_id)
                .all()
            )
            return [profile_to_domain(row) for row in rows]

    def list_regions(self, camera_id: str, profile_id: str | None = None) -> list[InspectionRegion]:
        with self._session_factory() as session:
            query = session.query(InspectionRegionORM).filter_by(camera_id=camera_id)
            if profile_id is not None:
                query = query.filter_by(profile_id=profile_id)
            rows = query.order_by(InspectionRegionORM.region_id).all()
            return [region_to_domain(row) for row in rows]

    def list_associations(self, camera_id: str, profile_id: str | None = None) -> list[ProfileDefectCategory]:
        with self._session_factory() as session:
            query = session.query(ProfileDefectCategoryORM).filter_by(camera_id=camera_id)
            if profile_id is not None:
                query = query.filter_by(profile_id=profile_id)
            rows = query.order_by(ProfileDefectCategoryORM.defect_code).all()
            return [association_to_domain(row) for row in rows]

    def count(self, camera_id: str) -> int:
        with self._session_factory() as session:
            return int(session.query(InspectionProfileORM).filter_by(camera_id=camera_id).count())

    def update(self, camera_id: str, profile_id: str, **fields: object) -> InspectionProfile | None:
        allowed = {
            "name",
            "inspection_type",
            "enabled",
            "confidence_threshold",
            "review_threshold",
            "decision_policy",
            "product_correlation",
            "metadata",
        }
        with self._session_factory() as session:
            row = (
                session.query(InspectionProfileORM)
                .filter_by(camera_id=camera_id, profile_id=profile_id)
                .one_or_none()
            )
            if row is None:
                return None
            for key, value in fields.items():
                if key not in allowed or value is None:
                    continue
                if key == "inspection_type" and isinstance(value, InspectionType):
                    row.inspection_type = value.value
                elif key == "decision_policy" and isinstance(value, DecisionPolicy):
                    row.decision_policy = _policy_to_dict(value)
                elif key == "product_correlation" and isinstance(value, ProductCorrelation):
                    row.product_correlation = value.model_dump()
                elif key == "metadata" and isinstance(value, dict):
                    row.meta = dict(value)
                elif hasattr(row, key):
                    setattr(row, key, value)
            row.updated_at = utcnow()
            session.commit()
            session.refresh(row)
            return profile_to_domain(row)

    def replace_regions(
        self, camera_id: str, profile_id: str, regions: list[InspectionRegion]
    ) -> list[InspectionRegion]:
        """Replace a profile's regions wholesale (validated by the caller)."""
        now: datetime = utcnow()
        with self._session_factory() as session:
            session.query(InspectionRegionORM).filter_by(camera_id=camera_id, profile_id=profile_id).delete()
            for region in regions:
                session.add(
                    InspectionRegionORM(
                        id=str(uuid.uuid4()),
                        region_id=region.region_id,
                        camera_id=camera_id,
                        profile_id=profile_id,
                        name=region.name,
                        region_type=region.region_type.value,
                        geometry=region.geometry,
                        enabled=region.enabled,
                        required=region.required,
                        meta=region.metadata,
                        created_at=now,
                        updated_at=now,
                    )
                )
            session.commit()
            rows = (
                session.query(InspectionRegionORM)
                .filter_by(camera_id=camera_id, profile_id=profile_id)
                .order_by(InspectionRegionORM.region_id)
                .all()
            )
            return [region_to_domain(row) for row in rows]

    def replace_associations(
        self,
        camera_id: str,
        profile_id: str,
        associations: list[ProfileDefectCategory],
    ) -> list[ProfileDefectCategory]:
        """Replace a profile's category associations wholesale."""
        now: datetime = utcnow()
        with self._session_factory() as session:
            session.query(ProfileDefectCategoryORM).filter_by(
                camera_id=camera_id, profile_id=profile_id
            ).delete()
            for association in associations:
                session.add(
                    ProfileDefectCategoryORM(
                        id=str(uuid.uuid4()),
                        camera_id=camera_id,
                        profile_id=profile_id,
                        defect_category_id=association.defect_category_id,
                        defect_code=association.defect_code,
                        enabled=association.enabled,
                        override_confidence_threshold=association.override_confidence_threshold,
                        override_review_threshold=association.override_review_threshold,
                        meta=association.metadata,
                        created_at=now,
                        updated_at=now,
                    )
                )
            session.commit()
            rows = (
                session.query(ProfileDefectCategoryORM)
                .filter_by(camera_id=camera_id, profile_id=profile_id)
                .order_by(ProfileDefectCategoryORM.defect_code)
                .all()
            )
            return [association_to_domain(row) for row in rows]

    def delete(self, camera_id: str, profile_id: str) -> bool:
        with self._session_factory() as session:
            row = (
                session.query(InspectionProfileORM)
                .filter_by(camera_id=camera_id, profile_id=profile_id)
                .one_or_none()
            )
            if row is None:
                return False
            session.query(InspectionRegionORM).filter_by(camera_id=camera_id, profile_id=profile_id).delete()
            session.query(ProfileDefectCategoryORM).filter_by(
                camera_id=camera_id, profile_id=profile_id
            ).delete()
            session.delete(row)
            session.commit()
            return True

    def delete_for_camera(self, camera_id: str) -> int:
        with self._session_factory() as session:
            profiles = session.query(InspectionProfileORM).filter_by(camera_id=camera_id).all()
            for row in profiles:
                session.query(InspectionRegionORM).filter_by(
                    camera_id=camera_id, profile_id=row.profile_id
                ).delete()
                session.query(ProfileDefectCategoryORM).filter_by(
                    camera_id=camera_id, profile_id=row.profile_id
                ).delete()
                session.delete(row)
            session.commit()
            return len(profiles)


class DefectCategoryRepository:
    """CRUD over the reusable defect category catalog."""

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    def create(self, category: DefectCategory) -> DefectCategory:
        now: datetime = utcnow()
        with self._session_factory() as session:
            exists = session.query(DefectCategoryORM).filter_by(code=category.code).one_or_none()
            if exists is not None:
                raise DefectCategoryConflictError(f"defect category {category.code} already exists")
            row = DefectCategoryORM(
                id=category.defect_id or str(uuid.uuid4()),
                code=category.code,
                name=category.name,
                description=category.description,
                severity=category.severity.value,
                enabled=category.enabled,
                confidence_threshold=category.confidence_threshold,
                review_threshold=category.review_threshold,
                meta=category.metadata,
                created_at=now,
                updated_at=now,
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return category_to_domain(row)

    def get(self, code: str) -> DefectCategory | None:
        with self._session_factory() as session:
            row = session.query(DefectCategoryORM).filter_by(code=code).one_or_none()
            return category_to_domain(row) if row else None

    def list_all(self) -> list[DefectCategory]:
        with self._session_factory() as session:
            rows = session.query(DefectCategoryORM).order_by(DefectCategoryORM.code).all()
            return [category_to_domain(row) for row in rows]

    def update(self, code: str, **fields: object) -> DefectCategory | None:
        allowed = {
            "name",
            "description",
            "severity",
            "enabled",
            "confidence_threshold",
            "review_threshold",
            "metadata",
        }
        with self._session_factory() as session:
            row = session.query(DefectCategoryORM).filter_by(code=code).one_or_none()
            if row is None:
                return None
            for key, value in fields.items():
                if key not in allowed or value is None:
                    continue
                if key == "severity" and isinstance(value, DefectSeverity):
                    row.severity = value.value
                elif key == "metadata" and isinstance(value, dict):
                    row.meta = dict(value)
                elif hasattr(row, key):
                    setattr(row, key, value)
            row.updated_at = utcnow()
            session.commit()
            session.refresh(row)
            return category_to_domain(row)

    def delete(self, code: str) -> bool:
        with self._session_factory() as session:
            row = session.query(DefectCategoryORM).filter_by(code=code).one_or_none()
            if row is None:
                return False
            session.delete(row)
            session.commit()
            return True

    def get_by_codes(self, codes: list[str]) -> dict[str, DefectCategory]:
        """Resolve codes (case-insensitive) to categories; unknown codes are absent."""
        normalized = [code.strip().upper() for code in codes if code.strip()]
        if not normalized:
            return {}
        with self._session_factory() as session:
            rows = session.query(DefectCategoryORM).filter(DefectCategoryORM.code.in_(normalized)).all()
            return {row.code: category_to_domain(row) for row in rows}
