"""Performance tests (V19). Opt-in via -m perf; default suite excludes them."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.perf
