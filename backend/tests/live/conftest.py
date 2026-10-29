"""Live staging qualification tests (V25).

These tests talk to real GitHub, registry, staging, and GPU infrastructure. They
are opt-in via ``-m live`` and are excluded from the default suite. Nothing in
this directory runs during ordinary CI.
"""

from __future__ import annotations
