# Performance & Reliability Testing — V19

> V18 established observability (JSON logs, Prometheus metrics, optional
> tracing). V19 adds a performance-testing foundation and reliability
> validation on top of it. No application contracts, wire formats, or
> migrations change in this volume.

## Scope

Two distinct concerns, kept deliberately separate:

- **Reliability** — deterministic correctness tests (outbox retry/duplicate
  handling, worker lifecycle, DB session cleanup, WebSocket lifecycle,
  concurrent API requests). These run in the normal suite and are the
  CI gate.
- **Performance** — timing/throughput benchmarks. These are **opt-in,
  environment-dependent measurements**, never mandatory CI pass/fail gates.

## Harness

`backend/tests/perf/bench.py` provides `run_benchmark(fn, ...)`, a small
offline timing harness that returns a `BenchmarkResult`
(`median_ms`, `p95_ms`, `p99_ms`, `min/max`, `throughput_ops_per_sec`,
`failures`) using `time.perf_counter`. It fabricates nothing: it times the
callable it is given and records real samples.

All benchmark tests carry `pytestmark = pytest.mark.perf`. The `perf`
marker is registered in `pytest.ini`, and the default run deselects it:

```ini
addopts = -m "not perf"
```

Run the deterministic suite (perf excluded):

```bash
python -m pytest
```

Run the benchmarks explicitly:

```bash
python -m pytest -m perf backend/tests/perf
```

## Reliability coverage

| Area | File | What it proves |
|---|---|---|
| Outbox throughput/correctness | `unit/test_outbox_performance.py` | Full drain delivers every valid envelope; idempotent enqueue rejects duplicates; first failure is requeued (not dead). |
| Outbox integration | `integration/test_outbox_throughput.py` | 500-event backlog drains across batches with exact claimed/delivered counts. |
| Worker lifecycle | `unit/test_worker_reliability.py` | Publisher start/stop semantics, idempotent start, bounded failure isolation. |
| API concurrency | `integration/test_api_concurrency.py` | Concurrent `/health` and `/ready` requests all succeed. |
| DB pool/session cleanup | `integration/test_db_pool_reliability.py` | Sessions close after exceptions; concurrent sessions stay isolated. |
| WebSocket lifecycle | `integration/test_websocket_reliability.py` | Unauthenticated sockets close `4401` and are never tracked; N authorized clients register and fully release (no leaks); tickets are single-use. |
| WS backpressure/priority | `integration/test_ws_manager.py` (pre-existing) | Bounded queue sheds LOW first; HIGH lifecycle never silently dropped. |

Shared event fixtures live in `backend/tests/outbox_fixtures.py`
(`make_event_envelope`, `drain_all`). Envelopes are built via the real
`EventEnvelope` model so tests exercise the actual
serialize/validate/deserialize path — malformed payloads are never used to
fake a green result.

## Baseline sample (illustrative, not a contract)

A single local run on the development machine (Python 3.11, **SQLite**,
**CPU** — no GPU, no PostgreSQL):

| Benchmark | median | p95 | p99 | throughput |
|---|---|---|---|---|
| `/health` | 9.54 ms | 10.92 ms | 11.74 ms | ~106 ops/s |
| `/ready` | 8.90 ms | 12.66 ms | 15.24 ms | ~100 ops/s |
| Outbox drain (1000 events, batch 200) | — | — | — | ~120 events/s |

These numbers are **environment-dependent and informational only**. They
exist to make regressions visible when re-run on the same host; they are
not pass/fail thresholds and are not asserted in CI.

## CI policy

- The deterministic reliability suite always runs and must pass.
- Benchmarks are excluded by default and run only with `-m perf`.
- No absolute latency/throughput threshold is enforced in CI. A machine
  without a GPU and without PostgreSQL cannot produce meaningful
  GPU/PostgreSQL performance gates, so none are claimed.

## Limitations (honest)

- **No GPU**: GPU inference throughput is not measured here. Any GPU
  performance claim must be validated on GPU hardware (`compose.gpu.yaml`)
  and is currently **SKIPPED**, not passed.
- **SQLite, not PostgreSQL**: outbox/DB timings above are SQLite. They do
  not transfer to PostgreSQL and are not presented as PostgreSQL results.
- **Single host, single process**: concurrency tests exercise in-process
  threads, not multi-worker or distributed behavior.
- Timing is subject to machine load; re-run on a quiet host for stable
  comparisons.

## Running the full validation

```bash
python -m ruff check .
python -m ruff format --check .
python -m mypy backend          # pre-existing baseline errors noted below
python -m pytest                # deterministic suite (perf deselected)
python -m pytest -m perf backend/tests/perf
```

Known mypy baseline (pre-existing, not introduced by V19, not CI-enforced):
errors remain in `backend/app/core/logging.py` and
`backend/tests/unit/test_auth_foundation.py`. V19 test files are mypy-clean.
