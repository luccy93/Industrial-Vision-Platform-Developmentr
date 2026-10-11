"""Authentication and RBAC package (V16).

Database-backed opaque sessions, server-enforced role permissions,
single-use WebSocket tickets. No JWT, no bearer tokens for browsers,
no credentials in logs. Backend enforcement is authoritative; the
frontend is usability only.
"""

from __future__ import annotations
