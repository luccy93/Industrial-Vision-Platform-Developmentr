"""Quality inspection domain (V07) — framework, not a trained defect model.

V07 provides the inspection framework: profiles, regions, defect categories,
decision policy, sessions, events, and metrics. It does NOT claim that generic
detection models can identify manufacturing defects. Production defect
recognition requires appropriately trained and validated inspection models
(see ``backend.app.quality.inspection`` for the model boundary).
"""
