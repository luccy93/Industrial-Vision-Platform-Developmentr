# Quality Inspection — V07 Industrial Quality Inspection Framework

> V07 provides an industrial quality-inspection **framework** and decision
> pipeline. It does **not** claim that generic detection models can identify
> arbitrary manufacturing defects. Production defect recognition requires
> appropriately trained and validated inspection models.
>
> Confidence values are model/rule strength scores in [0, 1]. They are **not**
> automatically calibrated probabilities.

```text
Camera / Frame
      ↓
Inspection Configuration (profiles, regions, defect categories)
      ↓
Quality Inspection Pipeline (ROI extraction → model → observations)
      ↓
Decision Policy → PASS / FAIL / REVIEW / ERROR
      ↓
Quality Events (inspection-level + defect-level) → REST + WebSocket + UI
```

## Framework vs. trained defect model

| Layer | V07 status |
|---|---|
| Inspection framework (profiles, regions, categories, policy, events, metrics) | **implemented** |
| Deterministic fixture adapter (scripted test double) | **implemented** — returns explicitly supplied observations; never invents defects, never random, never a real model |
| Specialized defect model (trained YOLO defect detector, segmentation, anomaly) | **not implemented** — clean boundary at `backend.app.quality.inspection.InspectionModel` |

The fixture adapter exists so the decision pipeline can be tested end-to-end
without specialized weights. It is a test double: *given these observations,
does the decision engine produce the right decision?* The production registry
refuses to resolve it outside dev/testing — a missing real model is never
silently replaced by synthetic observations.

## Domain model

`backend/app/quality/`: `schemas.py` (enums + models), `policy.py` (pure
decision functions), `regions.py` (geometry, reuses V06 primitives),
`inspection.py` (model boundary), `fixture.py` (scripted adapter),
`registry.py` (honest model resolution), `engine.py` (runtime),
`repository.py` (configuration persistence), `ws.py` (message builders).

V07 owns quality configuration, regions, defect categories, observations,
decisions, sessions, events, metrics, and evidence metadata. V05/V06 keep
safety events, severity, suppression, zones, proximity, and dwell. The two
domains never share an event model.

## Inspection profiles

`InspectionProfile` (persisted in `inspection_profiles`): `profile_id`,
`camera_id`, `name`, `enabled`, `inspection_type` (GENERAL/SURFACE/ASSEMBLY/
COMPONENT/DIMENSION/CUSTOM), `confidence_threshold`, `review_threshold`,
`decision_policy`, optional `product_correlation` (`product_id`, `batch_id`,
`work_order_id`, `unit_id` — operator-supplied, never fabricated), `metadata`.

## Inspection regions

`InspectionRegion` (persisted in `inspection_regions`): normalized image
coordinates (x, y in [0, 1]), `RECTANGLE` (`{x, y, width, height}`) or
`POLYGON` (point list), `enabled`, `required`, `metadata`. Geometry validation
reuses the V06 spatial primitives (`ZonePoint`, `point_in_polygon`) so polygon
rules are defined exactly once. V06 owns zones; V07 owns regions — separate
domain models, shared geometry.

## Defect categories

`DefectCategory` (persisted in `defect_categories`): reusable catalog entries
(`code`, `name`, `description`, `severity`, `enabled`, `confidence_threshold`,
`review_threshold`, `metadata`). These are **definitions**, not evidence that
any model can detect them. Profiles associate categories through
`inspection_profile_defect_categories` with per-profile `enabled` and
threshold overrides.

## Decision policy

`DecisionPolicy` (pure functions in `policy.py`):

```text
confidence >= fail_threshold and severity in fail_severities        → FAIL
review_threshold <= confidence < fail_threshold
    and severity in review_severities                               → REVIEW
no qualifying defect                                               → PASS
required region produced no evidence                               → REVIEW (default) | FAIL | IGNORE
model missing / not ready / raised / invalid config                → ERROR
```

Thresholds are always read from configuration — no production values are
hard-coded. `decision_reason` explains every decision, e.g.
`FAIL: HIGH severity CRACK observation (confidence 0.97) exceeded fail
threshold 0.60`.

## No-model behavior

```text
quality disabled                 → no inspection attempt, no result
no profiles configured            → no inspection attempts, no errors
profile enabled, model missing   → ERROR (INSPECTION_MODEL_NOT_CONFIGURED)
model configured, no defects     → PASS
defect exceeds fail criteria     → FAIL
ambiguous evidence               → REVIEW
model load/inspection failure    → ERROR
invalid inspection config       → ERROR
```

A missing model never becomes PASS: PASS means the configured inspection
completed and found no qualifying defects.

## Quality events

`QualityEvent` (in memory, bounded): inspection-level `QUALITY_FAIL` /
`QUALITY_REVIEW` / `QUALITY_ERROR`, and defect-level `DEFECT_DETECTED`.
Defect events originate from actual `DefectObservation`s — never from a
decision alone — with dedupe identity `(camera_id, profile_id, defect_code,
region_id)` plus stable observation/track identity where available. Hierarchy:
`DefectObservation → QualityDecision → QualityEvent`. Lifecycle
`ACTIVE → RESOLVED` after `QUALITY_EVENT_RESOLUTION_GRACE_SECONDS`, or
`SUPPRESSED` via API. Consecutive failures touch one event instead of
creating per-frame spam.

## Persistence policy

Persisted (PostgreSQL, Alembic `003_create_quality_inspection`):
`inspection_profiles`, `inspection_regions`, `defect_categories`,
`inspection_profile_defect_categories`. Never persisted: frames, detections,
bounding boxes, per-frame inspection results. Historical quality analytics
arrive in a later volume.

## Configuration

See `.env.example` (`QUALITY_*` block). Key defaults: `QUALITY_ENABLED=true`,
`QUALITY_INSPECTION_MODEL=` (empty → honest ERROR on inspection attempt),
`QUALITY_INSPECTION_INTERVAL_FRAMES=5`, `QUALITY_EVENT_RESOLUTION_GRACE_SECONDS=3.0`.

## API & WebSocket

REST: profile CRUD under `/api/v1/cameras/{id}/inspection-profiles`, minimal
defect-category CRUD under `/api/v1/quality/defect-categories`,
`GET /api/v1/quality/status`, `GET /api/v1/cameras/{id}/quality/latest`,
bounded `.../quality/results` and `.../quality/events`, and
`POST .../quality/suppress/{event_id}`.

WebSocket `/ws/cameras/{id}` keeps every V02–V06 message and adds
`quality_event` and `quality_result` (never image/base64 payloads).

## Frontend

`/quality`: engine status, profile management (list/create/edit/enable/delete),
defect-category selection with threshold overrides, a lightweight normalized
region editor (rectangle drag, polygon vertices), latest decision with
observations, and the quality event list. When no frame surface is available
the canvas is explicitly labelled as a coordinate surface — never a fake
image.

## Testing

Deterministic and hermetic: synthetic frames, the scripted fixture adapter,
fixed-epoch test clock. No GPU, CUDA, camera, RTSP, internet, or weight
downloads. See `docs/DEVELOPMENT.md` for the test layout.

## Non-claims

- No claim that generic detectors identify manufacturing defects.
- Confidence is not a calibrated probability.
- No barcode/OCR/PLC product correlation (identifiers are operator-supplied).
- No persistent image storage or external uploads.
- No certified regulatory compliance.
