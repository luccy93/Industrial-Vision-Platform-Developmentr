"""Autonomous perception domain (V08) — relative scene understanding, not driving safety.

V08 provides an autonomous-perception *foundation*: scene representation,
perceived objects from V04 tracks, lane perception, ego-relative motion
abstractions, trajectory estimation, collision-risk analysis, and a relative
bird's-eye view. It is NOT a certified autonomous-driving or ADAS safety
system. Without calibrated cameras, depth sensors, or validated metric
models, the system reports image-space quantities, relative estimates, and
explicitly unavailable values — never exact meters, depth, or certified
collision times.
"""
