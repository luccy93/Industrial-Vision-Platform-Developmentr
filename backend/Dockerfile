# syntax=docker/dockerfile:1

# Industrial Vision Platform — backend (CPU default).
#
# Multi-stage: build tools + wheel cache stay in the builder; the runtime
# is a slim non-root image with only the libraries torch/OpenCV need.
# Single uvicorn worker by design: lifespan threads (outbox publisher,
# alerting evaluator/delivery, redis subscriber) must not be duplicated
# across processes. Do not add --workers without proving worker safety.
#
# GPU acceleration is a separate opt-in image (backend/Dockerfile.gpu).

ARG PYTHON_BASE=python:3.11-slim-bookworm

FROM ${PYTHON_BASE} AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /code
COPY backend/requirements.txt ./backend-requirements.txt
RUN pip install --no-cache-dir --prefix=/install -r backend-requirements.txt

FROM ${PYTHON_BASE} AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Runtime libraries for CPU torch + headless OpenCV (no X/Qt stack).
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /usr/sbin/nologin appuser

WORKDIR /code
COPY --from=builder /install /usr/local
COPY backend ./backend
RUN mkdir -p /code/models /code/data && chown -R appuser:appuser /code

USER appuser
EXPOSE 8000

# Trivial liveness only (V11 division): dependency-aware readiness is
# served by /ready and gated in Compose, not here.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/live')"]

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
