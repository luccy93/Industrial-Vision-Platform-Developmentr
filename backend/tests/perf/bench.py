"""Performance benchmark helpers for V19.

Deterministic, offline-capable. Provides a small timing harness that reports
median/p95/p99 and throughput without fabricating results.
"""

from __future__ import annotations

import statistics
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass
class BenchmarkResult:
    name: str
    samples: int
    median_ms: float
    p95_ms: float
    p99_ms: float
    min_ms: float
    max_ms: float
    throughput_ops_per_sec: float
    failures: int


def run_benchmark(
    fn: Callable[[], Any],
    *,
    name: str = "benchmark",
    iterations: int = 20,
    warmup: int = 3,
) -> BenchmarkResult:
    # Warmup
    for _ in range(max(0, warmup)):
        try:
            fn()
        except Exception:
            pass
    samples: list[float] = []
    failures = 0
    for _ in range(max(1, iterations)):
        start = time.perf_counter()
        try:
            fn()
        except Exception:
            failures += 1
        elapsed = (time.perf_counter() - start) * 1000.0
        samples.append(elapsed)
    samples_sorted = sorted(samples)
    n = len(samples_sorted)

    def percentile(p: float) -> float:
        if n == 1:
            return samples_sorted[0]
        idx = int((n - 1) * p)
        idx = max(0, min(n - 1, idx))
        return samples_sorted[idx]

    median = statistics.median(samples_sorted)
    total_seconds = sum(samples) / 1000.0
    throughput = (n - failures) / total_seconds if total_seconds > 0 else 0.0
    return BenchmarkResult(
        name=name,
        samples=n,
        median_ms=round(median, 3),
        p95_ms=round(percentile(0.95), 3),
        p99_ms=round(percentile(0.99), 3),
        min_ms=round(samples_sorted[0], 3),
        max_ms=round(samples_sorted[-1], 3),
        throughput_ops_per_sec=round(throughput, 2),
        failures=failures,
    )
