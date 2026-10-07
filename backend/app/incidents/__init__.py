"""Incident management domain (V10) — operational records, not perception.

V10 consumes V09 risk intelligence and maintains the operational lifecycle
of incidents: creation, acknowledgement, assignment, escalation,
investigation, mitigation, resolution, closure, evidence, and timeline. It
never performs detection, tracking, safety analysis, quality inspection,
autonomous perception, or risk scoring — those remain in V03–V09.

Authentication and RBAC are intentionally deferred to V16: operators are
opaque identifier strings, never validated identities.
"""
