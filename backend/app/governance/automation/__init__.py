"""V36 governance automation (opt-in, bounded, non-destructive).

The automation layer schedules and runs governance review jobs on top of the
V35 governance service. It never deletes evidence, approves holds or
dispositions, or generates forensic exports.
"""

from __future__ import annotations

__all__: list[str] = []
