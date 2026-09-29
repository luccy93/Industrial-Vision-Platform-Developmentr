# CPU-default backend image. GPU workloads attach in later volumes
# via --gpus / compose deploy.reservations (see docker-compose.yml).
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /code

COPY backend/requirements.txt backend/requirements-dev.txt ./backend/
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend ./backend
COPY .env.example ./.env.example

EXPOSE 8000
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
