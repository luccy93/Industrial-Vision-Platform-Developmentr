"""Container deployment static validation (V17).

Offline checks over Dockerfiles and Compose files — no Docker daemon,
no GPU, no network required. Live image/stack validation happens in
the documented manual smoke workflow (see docs/DOCKER_GPU_DEPLOYMENT.md).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]


def _read(name: str) -> str:
    return (REPO_ROOT / name).read_text(encoding="utf-8")


def _compose(name: str) -> dict:
    with open(REPO_ROOT / name, encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def test_backend_dockerfile_production_grade() -> None:
    body = _read("backend/Dockerfile")
    assert "python:3.11-slim-bookworm" in body
    assert "latest" not in body.replace("PYTHONUNBUFFERED", "").replace("PIP_NO_CACHE_DIR", "")
    assert "AS builder" in body and "AS runtime" in body
    assert "USER appuser" in body
    assert "HEALTHCHECK" in body and "/live" in body
    # Single worker by design (lifespan threads must not duplicate): the
    # entrypoint carries no --workers flag on any directive line.
    assert not any(
        line.strip().startswith(("CMD", "ENTRYPOINT", "RUN")) and "--workers" in line
        for line in body.splitlines()
    )
    assert ".env" not in body  # no environment files baked into the image
    assert "backend/tests" not in body
    assert 'CMD ["uvicorn", "backend.app.main:app"' in body


def test_gpu_dockerfile_pins_cu126_and_stays_non_root() -> None:
    body = _read("backend/Dockerfile.gpu")
    assert "torch==2.13.0" in body
    assert "torchvision==0.28.0" in body
    assert "https://download.pytorch.org/whl/cu126" in body
    assert "USER appuser" in body
    assert "MODEL_DEVICE=cuda" in body


def test_frontend_dockerfile_standalone_runner() -> None:
    body = _read("frontend/Dockerfile")
    assert "npm ci" in body
    assert ".next/standalone" in body
    assert 'CMD ["node", "server.js"]' in body
    assert "USER appuser" in body
    assert "HEALTHCHECK" in body
    runner = body.split("AS runner", 1)[1]
    assert "npm start" not in runner  # exec node directly, no npm wrapper
    assert "NEXT_PUBLIC_API_URL" not in runner  # build-time only, not runtime env


def test_compose_cpu_topology() -> None:
    config = _compose("compose.yaml")
    services = config["services"]
    assert {"postgres", "redis", "migrate", "api", "web"} <= set(services)
    # Datastores are internal-only: no published ports.
    assert "ports" not in services["postgres"]
    assert "ports" not in services["redis"]
    # Service DNS, never localhost, for container-to-container traffic.
    api_env = services["api"]["environment"]
    assert "@postgres:5432/" in api_env["DATABASE_URL"]
    assert "localhost" not in api_env["DATABASE_URL"]
    assert api_env["REDIS_URL"] == "redis://redis:6379/0"
    # Migration gates the backend.
    migrate_on = services["migrate"]["depends_on"]["postgres"]["condition"]
    assert migrate_on == "service_healthy"
    assert "alembic" in " ".join(services["migrate"]["command"])
    assert "upgrade" in " ".join(services["migrate"]["command"])
    assert services["migrate"].get("restart") == "no"
    api_on = services["api"]["depends_on"]
    assert api_on["migrate"]["condition"] == "service_completed_successfully"
    assert api_on["postgres"]["condition"] == "service_healthy"
    assert services["web"]["depends_on"]["api"]["condition"] == "service_healthy"
    # Web shell published on loopback; API internal; DAL reaches api by DNS.
    web_ports = " ".join(str(p) for p in services["web"].get("ports", []))
    assert "3000" in web_ports
    assert "0.0.0.0" not in web_ports
    assert "ports" not in services["api"]
    assert services["web"]["environment"]["API_INTERNAL_URL"] == "http://api:8000"
    # Restart + logging + networks + volumes.
    for name in ("postgres", "redis", "api", "web"):
        assert services[name].get("restart") == "unless-stopped", name
        assert services[name]["logging"]["options"]["max-size"] == "10m", name
    assert "frontend" in config["networks"] and "backend" in config["networks"]
    assert "postgres-data" in config["volumes"]
    # No GPU requirements leak into the CPU stack.
    assert "nvidia" not in yaml.safe_dump(config)


def test_compose_gpu_overlay_is_opt_in_only() -> None:
    config = _compose("compose.gpu.yaml")
    services = config["services"]
    assert set(services) == {"api"}
    devices = services["api"]["deploy"]["resources"]["reservations"]["devices"]
    assert devices[0]["driver"] == "nvidia"
    assert "gpu" in devices[0]["capabilities"]
    assert services["api"]["environment"]["MODEL_DEVICE"] == "cuda"
    assert "Dockerfile.gpu" in services["api"]["build"]["dockerfile"]
    assert "ports" not in services["api"]


def test_compose_dev_overlay_loopback_only() -> None:
    config = _compose("compose.dev.yaml")
    for name in ("api", "postgres", "redis"):
        for published in config["services"][name].get("ports", []):
            assert str(published).startswith("127.0.0.1:"), (name, published)
            assert ":5432" in str(published) or ":6379" in str(published) or ":8000" in str(published)


def test_compose_merged_gpu_config_resolves() -> None:
    """Merged GPU stack keeps CPU services intact (offline merge check)."""
    base = _compose("compose.yaml")["services"]
    overlay = _compose("compose.gpu.yaml")["services"]
    assert set(overlay) == {"api"}
    assert base["api"]["environment"]["MODEL_DEVICE"] == "${MODEL_DEVICE:-cpu}"
    assert overlay["api"]["environment"]["MODEL_DEVICE"] == "cuda"


def test_dockerignore_excludes_secrets_and_tests() -> None:
    body = _read(".dockerignore")
    for entry in (".env", "backend/tests/", "models/*.pt", "node_modules/", ".git/"):
        assert entry in body, entry
    assert "!.env.example" in body  # template explicitly kept out of the secrets rule


def test_env_example_has_no_real_secrets() -> None:
    body = _read(".env.example")
    assert "ALERTING_SMTP_PASSWORD=\n" in body
    assert "ALERTING_WEBHOOK_SECRET=\n" in body
    assert "V16 authentication & RBAC" in body
