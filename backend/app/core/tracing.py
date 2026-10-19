"""Optional OpenTelemetry tracing foundations (V18).

Disabled by default. Enabled only via Settings.tracing_enabled. No exporter,
network connection or background worker is started when disabled. Missing
optional OpenTelemetry packages degrade gracefully (tracing stays off).

No sensitive headers, cookies, tokens or request bodies are captured.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("industrial-vision.tracing")

_INITIALIZED = False


def init_tracing(settings: Any) -> bool:
    """Initialize tracing if enabled and packages are available.

    Returns True when tracing was (or already is) initialized.
    Idempotent: calling twice does not double-instrument.
    """
    global _INITIALIZED
    if _INITIALIZED:
        return True
    if not getattr(settings, "tracing_enabled", False):
        return False
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except Exception as exc:  # pragma: no cover - depends on installed packages
        logger.warning("tracing unavailable: %s", type(exc).__name__)
        return False

    service = getattr(settings, "service_name", "industrial-vision-platform")
    environment = getattr(settings, "app_env", None)
    env_value = getattr(environment, "value", str(environment)) if environment is not None else "development"
    resource = Resource.create({"service.name": service, "deployment.environment": env_value})

    provider = TracerProvider(resource=resource)
    endpoint = getattr(settings, "trace_exporter_endpoint", None)
    if endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

            exporter = OTLPSpanExporter(endpoint=endpoint)
            provider.add_span_processor(BatchSpanProcessor(exporter))
        except Exception as exc:  # pragma: no cover
            logger.warning("tracing exporter unavailable: %s", type(exc).__name__)
    trace.set_tracer_provider(provider)

    # FastAPI instrumentation (best-effort, no sensitive data).
    try:
        pass

        # Instrumentation is applied per-app in create_app via instrument_app.
    except Exception:  # pragma: no cover
        pass

    _INITIALIZED = True
    logger.info("tracing initialized service=%s", service)
    return True


def instrument_app(app: Any) -> None:
    """Apply FastAPI instrumentation when tracing is enabled. Safe no-op otherwise."""
    if not _INITIALIZED:
        return
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        FastAPIInstrumentor.instrument_app(app)
    except Exception as exc:  # pragma: no cover
        logger.warning("fastapi instrumentation failed: %s", type(exc).__name__)


def shutdown_tracing() -> None:
    """Flush/shutdown tracing providers. Safe no-op when disabled."""
    global _INITIALIZED
    if not _INITIALIZED:
        return
    try:
        from opentelemetry import trace

        provider = trace.get_tracer_provider()
        shutdown = getattr(provider, "shutdown", None)
        if callable(shutdown):
            shutdown()
    except Exception:  # pragma: no cover
        pass
    _INITIALIZED = False
