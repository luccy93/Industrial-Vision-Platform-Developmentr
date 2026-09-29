"""Centralized application configuration.

Single source of truth for environment-driven settings. Supports
development / testing / production via ``APP_ENV``. No secrets are
hardcoded; everything sensitive comes from the environment.
"""

from __future__ import annotations

from enum import Enum
from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppEnv(str, Enum):
    development = "development"
    testing = "testing"
    production = "production"


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Application ---
    app_name: str = Field(default="industrial-vision-platform")
    app_env: AppEnv = Field(default=AppEnv.development)
    log_level: str = Field(default="INFO")

    # --- API ---
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)

    # --- Data layer (ready, not mandatory in V01) ---
    database_url: str = Field(
        default="postgresql+psycopg2://postgres:postgres@localhost:5432/industrial_vision"
    )
    redis_url: str = Field(default="redis://localhost:6379/0")

    # --- AI / model (configuration only in V01) ---
    gpu_enabled: bool = Field(default=False)
    model_device: str = Field(default="cpu")
    model_confidence_threshold: float = Field(default=0.5, ge=0.0, le=1.0)

    # --- Realtime ---
    websocket_enabled: bool = Field(default=True)

    # --- V02 video ingestion ---
    target_processing_fps: float = Field(default=10.0, ge=0.0)
    frame_skip: int = Field(default=0, ge=0)
    buffer_size: int = Field(default=30, ge=1, le=1000)

    @field_validator("log_level")
    @classmethod
    def _normalize_log_level(cls, value: str) -> str:
        normalized = value.upper()
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if normalized not in allowed:
            raise ValueError(f"LOG_LEVEL must be one of {sorted(allowed)}")
        return normalized

    @property
    def is_testing(self) -> bool:
        return self.app_env == AppEnv.testing

    @property
    def is_production(self) -> bool:
        return self.app_env == AppEnv.production


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached settings instance (override in tests via dependency)."""
    return Settings()
