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
# CPU-only torch pair from the official cpu index (verified
# 2.14.0+cpu / 0.29.0+cpu): the default PyPI torch wheel bundles CUDA
# libraries (~6 GB) which must not enter the CPU image. Two-pass install
# with a constraints pin — a single mixed-index resolve trips pip hash
# checks, and an unconstrained second pass upgrades torch to CUDA.
ARG TORCH_VERSION=2.14.0
ARG TORCHVISION_VERSION=0.29.0

FROM ${PYTHON_BASE} AS builder

ARG TORCH_VERSION
ARG TORCHVISION_VERSION
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /code
COPY backend/requirements.txt ./backend-requirements.txt
# An isolated venv (not --prefix): pass 2's pip sees pass 1's torch and
# keeps it. The bare == constraints satisfy PEP 440 against the +cpu
# local builds; --prefix targets are invisible to pip's detection.
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --timeout 100 --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir --timeout 100 \
        --index-url https://download.pytorch.org/whl/cpu \
        torch==${TORCH_VERSION} torchvision==${TORCHVISION_VERSION} \
    && printf "torch==${TORCH_VERSION}\ntorchvision==${TORCHVISION_VERSION}\n" > /tmp/cpu-constraints.txt \
    && /opt/venv/bin/pip install --no-cache-dir --timeout 100 \
        --constraint /tmp/cpu-constraints.txt -r backend-requirements.txt \
    && /opt/venv/bin/python -c "import torch; assert '+cpu' in torch.__version__, torch.__version__"

FROM ${PYTHON_BASE} AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Runtime libraries for CPU torch + OpenCV wheels (no X/Qt stack).
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 libglib2.0-0 libgl1 libxcb1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /usr/sbin/nologin appuser

WORKDIR /code
COPY --from=builder /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
COPY backend ./backend
RUN mkdir -p /code/models /code/data && chown -R appuser:appuser /code

USER appuser
EXPOSE 8000

# Trivial liveness only (V11 division): dependency-aware readiness is
# served by /ready and gated in Compose, not here.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/live')"]

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
