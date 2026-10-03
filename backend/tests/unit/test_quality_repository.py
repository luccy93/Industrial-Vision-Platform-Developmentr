"""Quality repository tests — persistence, camera isolation, cascade delete."""

from __future__ import annotations

import pytest

from backend.app.infrastructure.db import get_session_factory, init_db
from backend.app.models.quality_orm import (
    DefectCategoryORM,
    InspectionProfileORM,
    InspectionRegionORM,
    ProfileDefectCategoryORM,
)
from backend.app.quality.repository import (
    DefectCategoryConflictError,
    DefectCategoryRepository,
    InspectionProfileRepository,
    ProfileConflictError,
)
from backend.app.quality.schemas import DefectSeverity, InspectionType, ProfileDefectCategory
from backend.tests.quality_helpers import make_category, make_profile, make_region


@pytest.fixture()
def factories(tmp_path):
    url = f"sqlite:///{tmp_path}/quality_repo.db"
    init_db(url)
    factory = get_session_factory(url)
    return InspectionProfileRepository(factory), DefectCategoryRepository(factory)


def _association(profile_id: str = "profile-01", code: str = "CRACK") -> ProfileDefectCategory:
    return ProfileDefectCategory(
        profile_id=profile_id,
        defect_category_id="cat-crack",
        defect_code=code,
        enabled=True,
    )


def test_create_and_get_profile_round_trip(factories) -> None:
    profiles, _ = factories
    created = profiles.create(camera_id="cam-01", profile=make_profile())
    assert created.profile_id == "profile-01"
    fetched = profiles.get("cam-01", "profile-01")
    assert fetched is not None
    assert fetched.name == "Surface inspection"
    assert fetched.inspection_type is InspectionType.SURFACE
    assert fetched.confidence_threshold == 0.6
    assert fetched.decision_policy.fail_threshold == 0.6


def test_duplicate_profile_id_conflicts(factories) -> None:
    profiles, _ = factories
    profiles.create(camera_id="cam-01", profile=make_profile())
    with pytest.raises(ProfileConflictError):
        profiles.create(camera_id="cam-01", profile=make_profile())


def test_same_profile_id_allowed_on_other_camera(factories) -> None:
    profiles, _ = factories
    profiles.create(camera_id="cam-01", profile=make_profile())
    other = profiles.create(camera_id="cam-02", profile=make_profile())
    assert other.camera_id == "cam-02"
    assert profiles.get("cam-02", "profile-01") is not None


def test_regions_persisted_and_listed(factories) -> None:
    profiles, _ = factories
    regions = [make_region(), make_region(region_id="region-02", name="Second")]
    profiles.create(camera_id="cam-01", profile=make_profile(), regions=regions)
    listed = profiles.list_regions("cam-01", "profile-01")
    assert [r.region_id for r in listed] == ["region-01", "region-02"]
    assert profiles.list_regions("cam-99", "profile-01") == []


def test_associations_persisted_and_listed(factories) -> None:
    profiles, _ = factories
    profiles.create(camera_id="cam-01", profile=make_profile(), associations=[_association()])
    listed = profiles.list_associations("cam-01", "profile-01")
    assert len(listed) == 1
    assert listed[0].defect_code == "CRACK"
    assert listed[0].enabled is True


def test_update_profile_fields(factories) -> None:
    profiles, _ = factories
    profiles.create(camera_id="cam-01", profile=make_profile())
    updated = profiles.update("cam-01", "profile-01", name="Renamed", enabled=False)
    assert updated is not None
    assert updated.name == "Renamed"
    assert updated.enabled is False
    assert profiles.update("cam-01", "missing", name="x") is None


def test_replace_regions(factories) -> None:
    profiles, _ = factories
    profiles.create(camera_id="cam-01", profile=make_profile(), regions=[make_region()])
    replaced = profiles.replace_regions(
        "cam-01", "profile-01", [make_region(region_id="region-09", name="Ninth")]
    )
    assert [r.region_id for r in replaced] == ["region-09"]
    assert [r.region_id for r in profiles.list_regions("cam-01", "profile-01")] == ["region-09"]


def test_replace_associations(factories) -> None:
    profiles, _ = factories
    profiles.create(camera_id="cam-01", profile=make_profile(), associations=[_association()])
    replaced = profiles.replace_associations("cam-01", "profile-01", [_association(code="DENT")])
    assert [a.defect_code for a in replaced] == ["DENT"]


def test_delete_profile_cascades(factories) -> None:
    profiles, _ = factories
    profiles.create(
        camera_id="cam-01",
        profile=make_profile(),
        regions=[make_region()],
        associations=[_association()],
    )
    assert profiles.delete("cam-01", "profile-01") is True
    assert profiles.get("cam-01", "profile-01") is None
    assert profiles.list_regions("cam-01", "profile-01") == []
    assert profiles.list_associations("cam-01", "profile-01") == []
    assert profiles.delete("cam-01", "profile-01") is False


def test_delete_for_camera(factories) -> None:
    profiles, _ = factories
    profiles.create(camera_id="cam-01", profile=make_profile())
    profiles.create(camera_id="cam-01", profile=make_profile(profile_id="p-02", name="Second"))
    profiles.create(camera_id="cam-02", profile=make_profile())
    assert profiles.delete_for_camera("cam-01") == 2
    assert profiles.list_all("cam-01") == []
    assert len(profiles.list_all("cam-02")) == 1


def test_category_crud(factories) -> None:
    _, categories = factories
    created = categories.create(make_category())
    assert created.code == "CRACK"
    assert categories.get("CRACK") is not None
    assert categories.get("crack") is None  # exact-code lookup; API normalizes
    updated = categories.update("CRACK", name="Hairline crack", severity=DefectSeverity.CRITICAL)
    assert updated is not None
    assert updated.name == "Hairline crack"
    assert updated.severity is DefectSeverity.CRITICAL
    assert categories.update("NOPE", name="x") is None
    assert categories.delete("CRACK") is True
    assert categories.get("CRACK") is None
    assert categories.delete("CRACK") is False


def test_category_duplicate_code_conflicts(factories) -> None:
    _, categories = factories
    categories.create(make_category())
    with pytest.raises(DefectCategoryConflictError):
        categories.create(make_category())


def test_get_by_codes_case_insensitive(factories) -> None:
    _, categories = factories
    categories.create(make_category())
    categories.create(make_category(defect_id="cat-dent", code="DENT", name="Dent"))
    resolved = categories.get_by_codes(["crack", " DENT ", "nope"])
    assert set(resolved) == {"CRACK", "DENT"}
    assert categories.get_by_codes([]) == {}


def test_camera_categories_survive_profile_delete(factories) -> None:
    profiles, categories = factories
    categories.create(make_category())
    profiles.create(camera_id="cam-01", profile=make_profile(), associations=[_association()])
    profiles.delete("cam-01", "profile-01")
    # The global catalog is independent of any profile.
    assert categories.get("CRACK") is not None


def test_orm_tables_match_migration(factories) -> None:
    """Column layouts must stay aligned with 003_create_quality_inspection."""
    assert {c.name for c in InspectionProfileORM.__table__.columns} == {
        "id",
        "profile_id",
        "camera_id",
        "name",
        "inspection_type",
        "enabled",
        "confidence_threshold",
        "review_threshold",
        "decision_policy",
        "product_correlation",
        "metadata",
        "created_at",
        "updated_at",
    }
    assert {c.name for c in InspectionRegionORM.__table__.columns} == {
        "id",
        "region_id",
        "camera_id",
        "profile_id",
        "name",
        "region_type",
        "geometry",
        "enabled",
        "required",
        "metadata",
        "created_at",
        "updated_at",
    }
    assert {c.name for c in DefectCategoryORM.__table__.columns} == {
        "id",
        "code",
        "name",
        "description",
        "severity",
        "enabled",
        "confidence_threshold",
        "review_threshold",
        "metadata",
        "created_at",
        "updated_at",
    }
    assert {c.name for c in ProfileDefectCategoryORM.__table__.columns} == {
        "id",
        "camera_id",
        "profile_id",
        "defect_category_id",
        "defect_code",
        "enabled",
        "override_confidence_threshold",
        "override_review_threshold",
        "metadata",
        "created_at",
        "updated_at",
    }
