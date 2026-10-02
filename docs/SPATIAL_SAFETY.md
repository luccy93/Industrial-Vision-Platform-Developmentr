# Spatial Safety — V06 Image-Space Reasoning

> V06 performs image-space spatial reasoning. Zone membership and proximity
> are camera-image approximations and do not represent physical-world
> distance unless camera calibration, depth, or another metric reconstruction
> capability is introduced in a future volume.

```text
V04 Tracks → Spatial Scene Analysis → Zones → Entry/Exit/Dwell
           → Proximity Relationships → V05 SafetyEvent lifecycle → REST + WS
```

## Zone architecture

`backend/app/spatial/`: `schemas.py` (zone model), `geometry.py` (pure
functions), `engine.py` (per-camera registry + runtime). Zones persist in
PostgreSQL (`zones` table, Alembic `002_create_zones`); all runtime state
(membership, timers, pair state) stays in memory.

## Polygon representation

Normalized `x, y ∈ [0, 1]` — resolution-independent. Minimum 3 finite points
spanning area in both axes. Membership uses the bbox **bottom-center** as a
ground-contact approximation (documented heuristic, not physical position).

(Full runtime, API, WebSocket, and frontend documentation lands with Commit 02/03.)
