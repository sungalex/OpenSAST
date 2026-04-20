"""aiSAST 설정.

3개 배포 프로파일(`local` / `docker` / `cloud`)을 기본값 번들로 제공하며, 모든
항목은 `AISAST_*` 환경변수로 재정의된다. 프로파일은 단지 **기본값만** 바꾼다.

선택 방법:
  AISAST_PROFILE=cloud docker compose -f docker-compose.yml -f docker-compose.prod.yml up

프로파일이 달라도 코드베이스는 동일하며, 미들웨어·로그 레벨·기본 CORS·문서 노출·
rate limit 임계값 같은 보안·운영 관련 기본값만 조정된다.
"""

from __future__ import annotations

import tempfile
from enum import Enum
from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RULES_DIR = PROJECT_ROOT / "rules"
DEFAULT_RESOURCES_DIR = PROJECT_ROOT / "aisast" / "resources"

# 작업 디렉터리 기본값 — OS 독립적으로 tempfile.gettempdir() 을 사용한다.
# Linux: /tmp/aisast-work, macOS: /var/folders/.../aisast-work,
# Windows: %LOCALAPPDATA%/Temp/aisast-work (WSL2 는 Linux 처리)
# Docker 환경에서는 compose 가 AISAST_WORK_DIR=/var/aisast-work 를 명시 주입한다.
DEFAULT_WORK_DIR = Path(tempfile.gettempdir()) / "aisast-work"


class Profile(str, Enum):
    LOCAL = "local"
    DOCKER = "docker"
    CLOUD = "cloud"


_PROFILE_DEFAULTS: dict[Profile, dict[str, object]] = {
    Profile.LOCAL: {
        "cors_origins": ["*"],
        "enable_docs": True,
        "log_level": "DEBUG",
        "log_format": "console",
        "rate_limit_per_minute": 0,  # 0 = off
        "db_pool_size": 5,
        "enforce_strong_secret": False,
        "enforce_https": False,
    },
    Profile.DOCKER: {
        "cors_origins": [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
        ],
        "enable_docs": True,
        "log_level": "INFO",
        "log_format": "console",
        "rate_limit_per_minute": 100,
        "db_pool_size": 10,
        "enforce_strong_secret": False,
        "enforce_https": False,
    },
    Profile.CLOUD: {
        "cors_origins": [],  # 운영은 env 로 명시 주입 필수
        "enable_docs": False,
        "log_level": "INFO",
        "log_format": "json",
        "rate_limit_per_minute": 60,
        "db_pool_size": 20,
        "enforce_strong_secret": True,
        "enforce_https": True,
    },
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="AISAST_", extra="ignore"
    )

    # ---- Core -----------------------------------------------------------
    app_name: str = "aiSAST"
    debug: bool = False
    profile: Profile = Profile.LOCAL
    project_root: Path = PROJECT_ROOT
    rules_dir: Path = DEFAULT_RULES_DIR
    resources_dir: Path = DEFAULT_RESOURCES_DIR
    work_dir: Path = DEFAULT_WORK_DIR

    # ---- 커스터마이징 오버레이 -----------------------------------------
    # 사용자가 패키지 업그레이드 후에도 보존할 리소스·룰 경로
    custom_rules_dir: Path | None = None
    custom_resources_dir: Path | None = None
    mois_catalog_path: Path | None = None  # YAML 파일로 49개 카탈로그 완전 교체
    reference_standards_path: Path | None = None

    # ---- Database / Queue ----------------------------------------------
    database_url: str = "postgresql+psycopg2://aisast:aisast@localhost:5432/aisast"
    db_pool_size: int = 5
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

    # ---- MinIO ----------------------------------------------------------
    minio_endpoint: str = "localhost:9000"
    minio_access_key: str = "minioadmin"
    minio_secret_key: str = "minioadmin"
    minio_bucket: str = "aisast-sources"
    minio_secure: bool = False

    # ---- Auth ----------------------------------------------------------
    secret_key: str = "change-me-in-production-please-32-chars-min"
    access_token_expire_minutes: int = 60 * 24
    enforce_strong_secret: bool = False
    password_min_length: int = 12
    password_required_classes: int = 3  # upper/lower/digit/special 중 N종 이상
    failed_login_threshold: int = 5
    failed_login_lockout_minutes: int = 15
    refresh_cookie_name: str = "aisast_refresh"
    refresh_cookie_secure: bool = False
    refresh_cookie_samesite: str = "Lax"
    refresh_token_expire_days: int = 7
    jwt_issuer: str = "aisast"
    jwt_audience: str = "aisast-api"

    # 최초 부트스트랩 관리자
    bootstrap_admin_email: str = "admin@opensast.local"
    bootstrap_admin_password: str = "aisast-admin"
    bootstrap_admin_display_name: str = "aiSAST Admin"

    # ---- HTTP / 보안 ----------------------------------------------------
    cors_origins: list[str] = Field(default_factory=lambda: ["*"])
    enable_docs: bool = True
    enforce_https: bool = False
    rate_limit_per_minute: int = 0  # 0 = 비활성
    max_body_bytes: int = 2 * 1024 * 1024  # 일반 요청 2 MiB
    max_upload_bytes: int = 500 * 1024 * 1024  # zip 업로드 500 MiB
    security_headers_enabled: bool = True
    log_level: str = "INFO"
    log_format: str = "console"  # console | json

    # ---- LLM -----------------------------------------------------------
    llm_provider: str = Field(default="ollama")
    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-opus-4-6"
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "gemma2:9b"
    llm_timeout_seconds: int = 60
    llm_context_window_lines: int = 20
    llm_default_fp_probability: int = 50

    # ---- Celery task timeouts -----------------------------------------
    scan_task_soft_time_limit: int = 3600
    scan_task_time_limit: int = 7200
    triage_task_soft_time_limit: int = 1800
    triage_task_time_limit: int = 2400

    # ---- Engine binaries -----------------------------------------------
    opengrep_bin: str = "semgrep"
    bandit_bin: str = "bandit"
    eslint_bin: str = "eslint"
    gosec_bin: str = "gosec"
    spotbugs_bin: str = "spotbugs"
    codeql_bin: str = "codeql"

    # ---- validators ----------------------------------------------------
    @field_validator("cors_origins", mode="before")
    @classmethod
    def _parse_cors(cls, v):
        """콤마 구분 문자열도 허용."""

        if isinstance(v, str):
            items = [s.strip() for s in v.split(",") if s.strip()]
            return items or ["*"]
        return v

    def apply_profile_defaults(self) -> "Settings":
        """프로파일별 기본값을 아직 명시되지 않은 필드에만 적용."""

        defaults = _PROFILE_DEFAULTS.get(self.profile, {})
        for key, value in defaults.items():
            # 사용자가 명시한 env 값은 건드리지 않음: model_fields_set 확인
            if key in self.model_fields_set:
                continue
            setattr(self, key, value)
        return self

    def validate_profile(self) -> list[str]:
        """프로파일별 무결성 검사 — 경고 메시지 목록 반환."""

        warnings: list[str] = []
        if self.enforce_strong_secret:
            if (
                len(self.secret_key) < 32
                or "change-me" in self.secret_key.lower()
            ):
                warnings.append(
                    f"[{self.profile.value}] AISAST_SECRET_KEY 가 약함: 32자 이상, "
                    "'change-me' 미포함 필수"
                )
        if self.profile is Profile.CLOUD and not self.cors_origins:
            warnings.append(
                "[cloud] AISAST_CORS_ORIGINS 가 비어있음 — 운영에서는 명시 필요"
            )
        if (
            self.profile is Profile.CLOUD
            and self.bootstrap_admin_password == "aisast-admin"
        ):
            warnings.append(
                "[cloud] 기본 부트스트랩 비밀번호 사용 중 — 즉시 변경하세요"
            )
        return warnings


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.apply_profile_defaults()
    return settings


def reset_settings_cache() -> None:
    """테스트 환경에서 설정 재로드를 위한 캐시 초기화."""

    get_settings.cache_clear()
