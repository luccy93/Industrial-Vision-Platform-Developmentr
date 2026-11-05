"""Read-only V30 evidence verification entry point.

This module is a thin alias for the canonical release CLI:

    python -m tools.verify_evidence --report release-report.json

It supports the same options as
``python -m tools.release.cli verify-evidence``. Verification never repairs,
rewrites, quarantines, or deletes evidence.
"""

from __future__ import annotations

import sys

from tools.release.cli import main


def run(argv: list[str] | None = None) -> int:
    """Run ``verify-evidence`` with the supplied arguments."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    return main(["verify-evidence", *arguments])


if __name__ == "__main__":
    raise SystemExit(run())
