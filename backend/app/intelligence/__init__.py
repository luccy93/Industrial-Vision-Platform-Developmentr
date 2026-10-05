"""Event & risk intelligence (V09) — orchestration layer, not a domain engine.

V09 consumes the outputs of the V05 safety, V06 spatial, V07 quality, and V08
autonomous engines and produces normalized events, correlated risk clusters,
and explainable risk assessments. It never re-runs inference, tracking,
geometry, inspection, or perception, and it never invents source events.

Risk scores are normalized operational heuristics in [0, 1]. They are not
calibrated probabilities, statistical forecasts, or certified safety
measurements.
"""
