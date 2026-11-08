"""V33 continuous integrity auditing and transparency monitoring.

The package is deliberately isolated from the V30-V32 evidence, checkpoint,
transparency, and trust-state stores. Audit execution is read-only for every
protected input; only the dedicated monitoring store is written.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "33.0.0"
