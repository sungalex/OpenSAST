from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RULES_DIR = PROJECT_ROOT / "rules"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="AISAST_", extra="ignore"
    )

    # Core
    app_name: str = "aiSAST"
    debug: bool = False
    project_root: Path = PROJECT_ROOT
    rules_dir: Path = DEFAULT_RULES_DIR
    work_dir: Path = PROJECT_ROOT / ".aisast-work"

    # Database
    database_url: str = "postgresql+psycopg2://aisast:aisast@localhost:5432/aisast"

    # Redis / Celery
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

    # MinIO
    minio_endpoint: str = "localhost:9000"
    minio_access_key: str = "minioadmin"
    minio_secret_key: str = "minioadmin"
    minio_bucket: str = "aisast-sources"
    minio_secure: bool = False

    # Auth
    secret_key: str = "change-me-in-production-please-32-chars-min"
    access_token_expire_minutes: int = 60 * 24

    # 최초 부트스트랩 관리자 (API 서버가 기동될 때 DB에 자동 생성)
    bootstrap_admin_email: str = "admin@aisast.local"
    bootstrap_admin_password: str = "aisast-admin"
    bootstrap_admin_display_name: str = "aiSAST Admin"

    # LLM
    llm_provider: str = Field(default="ollama")  # ollama | anthropic | noop
    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-opus-4-6"
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "gemma2:9b"
    llm_timeout_seconds: int = 60
    llm_context_window_lines: int = 20

    # Engine binaries (override if not in PATH)
    opengrep_bin: str = "semgrep"
    bandit_bin: str = "bandit"
    eslint_bin: str = "eslint"
    gosec_bin: str = "gosec"
    spotbugs_bin: str = "spotbugs"
    codeql_bin: str = "codeql"


@lru_cache
def get_settings() -> Settings:
    return Settings()
