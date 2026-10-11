# Infrastructure (V17)

- `compose.yaml` (repo root): migrate, api, web, postgres, redis (CPU default).
- `compose.dev.yaml`: loopback-only debug ports for local development.
- `compose.gpu.yaml`: opt-in NVIDIA reservations + CUDA backend image.
- `backend/Dockerfile`: CPU-default Python image (non-root, single worker).
- `backend/Dockerfile.gpu`: CUDA 12.6 PyTorch image (opt-in only).
- `frontend/Dockerfile`: standalone Next.js production image (non-root).
- Full guide: `docs/DOCKER_GPU_DEPLOYMENT.md`.
