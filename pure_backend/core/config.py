import os
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    environment: str = "production"
    database_url: str = "postgresql+psycopg://postgres:postgres@db:5432/app_db"
    app_secret: str = "change-me-in-compose"
    access_token_hours: int = 12
    enforce_https: bool = True
    enable_runtime_schema_patch: bool = False

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings(
        environment=os.getenv("ENVIRONMENT", "production"),
        database_url=os.getenv("DATABASE_URL", "postgresql+psycopg://postgres:postgres@db:5432/app_db"),
        app_secret=os.getenv("APP_SECRET", "change-me-in-compose"),
        enforce_https=os.getenv("ENFORCE_HTTPS", "true").lower() == "true",
        enable_runtime_schema_patch=os.getenv("ENABLE_RUNTIME_SCHEMA_PATCH", "false").lower() == "true",
    )
