"""Role and permission policy — single source of truth (V16).

Least privilege, enforced in the backend via shared dependencies.
Frontend role checks are usability only and never a security boundary.

Capability assignments (locked V16 decisions):

- ``read``: authenticated dashboard, operations, analytics, incidents,
  notifications — all roles.
- ``incident_write``: incident lifecycle actions + evidence — ADMIN, OPERATOR.
- ``camera_control``: camera start/stop — ADMIN, OPERATOR (stop requires
  confirmation + reason; audited; never treated as proof an area is safe).
- ``notification_mute``: time-limited per-notification mute — ADMIN, OPERATOR.
  Detection continues; history stays visible.
- ``admin_config``: camera CRUD, zones, profiles, defect categories,
  safety/quality suppression, alert rules, delivery retry — ADMIN only.
- ``user_admin``: user CRUD, role changes, activation, session revocation
  of other users — ADMIN only, with recent-auth step-up.
"""

from __future__ import annotations

from enum import Enum


class Role(str, Enum):
    ADMIN = "ADMIN"
    OPERATOR = "OPERATOR"
    VIEWER = "VIEWER"


# Capability -> roles granted. Central map; route handlers must not
# scatter ad-hoc role-string checks.
ROLE_CAPABILITIES: dict[str, frozenset[Role]] = {
    "read": frozenset({Role.ADMIN, Role.OPERATOR, Role.VIEWER}),
    "incident_write": frozenset({Role.ADMIN, Role.OPERATOR}),
    "camera_control": frozenset({Role.ADMIN, Role.OPERATOR}),
    "notification_mute": frozenset({Role.ADMIN, Role.OPERATOR}),
    "admin_config": frozenset({Role.ADMIN}),
    "user_admin": frozenset({Role.ADMIN}),
}

#: Admin operations that additionally require recent authentication
#: (session ``authenticated_at`` within the step-up window).
SENSITIVE_USER_OPS = frozenset(
    {"user.create", "user.role", "user.deactivate", "session.revoke_others"}
)


def normalize_role(value: object) -> Role:
    """Parse and validate a role value; raises ``ValueError`` when unknown."""
    if isinstance(value, Role):
        return value
    normalized = str(value or "").strip().upper()
    try:
        return Role(normalized)
    except ValueError:
        raise ValueError(f"unknown role: {normalized}") from None


def can(role: Role | str, capability: str) -> bool:
    """Return True when ``role`` is granted ``capability``."""
    parsed = normalize_role(role)
    granted = ROLE_CAPABILITIES.get(capability, frozenset())
    return parsed in granted


def capabilities_for(role: Role | str) -> frozenset[str]:
    """Return every capability granted to ``role``."""
    parsed = normalize_role(role)
    return frozenset(
        capability for capability, roles in ROLE_CAPABILITIES.items() if parsed in roles
    )
