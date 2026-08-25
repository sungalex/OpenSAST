"""OpenSAST 설정.

3개 배포 프로파일(`local` / `docker` / `cloud`)을 기본값 번들로 제공하며, 모든
항목은 `OPENSAST_*` 환경변수로 재정의된다. 프로파일은 단지 **기본값만** 바꾼다.

선택 방법:
  OPENSAST_PROFILE=cloud docker compose -f docker-compose.yml -f docker-compose.prod.yml up

프로파일이 달라도 코드베이스는 동일하며, 미들웨어·로그 레벨·기본 CORS·문서 노출·
rate limit 임계값 같은 보안·운영 관련 기본값만 조정된다.

**설정 진실의 원천은 이 파일 하나다 (ADR-0006).** 서비스·미들웨어는 상수를
하드코딩하지 않고 반드시 `Settings` 에서 읽는다. 문서(ARCHITECTURE §2.4)의 표는
이 파일을 서술할 뿐이며, 불일치가 생기면 이 파일이 정본이다.

우선순위(낮음 → 높음):
  프로파일 기본값 → 오버레이 YAML(`OPENSAST_OVERLAY_CONFIG`) → 환경변수 / .env
"""

from __future__ import annotations

import secrets as _secrets
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RULES_DIR = PROJECT_ROOT / "rules"
DEFAULT_RESOURCES_DIR = PROJECT_ROOT / "opensast" / "resources"

# 작업·스토리지 디렉터리 기본값 — 프로세스 CWD 기준 프로젝트 폴더 하위로 고정한다.
# OS 임시 디렉터리(/tmp 등)는 재부팅·OS 클린업 시 소실될 수 있어 프로젝트 생명주기
# 와 동기화하기 위해 `<cwd>/.opensast-work` 를 기본으로 사용. Docker 환경에서는
# compose 가 OPENSAST_WORK_DIR=/var/opensast-work 를 명시 주입하고, 호스트의
# `./.opensast-work` 를 bind-mount 해 프로젝트 폴더와 생명주기를 일치시킨다.
#
# API 와 워커가 서로 다른 CWD 로 기동하면 같은 상대 경로가 다른 절대 경로로
# 해석되므로, 다중 프로세스 배포에서는 OPENSAST_WORK_DIR 을 반드시 명시한다.
DEFAULT_WORK_DIR = Path.cwd() / ".opensast-work"

#: 시크릿 키 미설정 시 개발 프로파일에서 쓰는 임시 키.
#: **프로세스 수명 동안 고정**이라 같은 프로세스가 발급·검증한 토큰은 유효하다.
#: 여러 워커/레플리카로 띄우면 프로세스마다 달라지므로 로그인 세션이 깨진다 —
#: 그래서 사용될 때마다 경고를 남긴다.
_EPHEMERAL_SECRET_KEY = _secrets.token_hex(32)


def _default_work_dir() -> Path:
    """인스턴스 생성 시점의 CWD 를 기준으로 평가한다 (import 시점 고정 회피)."""

    return Path.cwd() / ".opensast-work"


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
        "fail_fast_on_config_warning": False,
        "auto_migrate_on_startup": True,
    },
    Profile.DOCKER: {
        "cors_origins": [
            "http://localhost:8080",
            "http://127.0.0.1:8080",
        ],
        "enable_docs": True,
        "log_level": "INFO",
        "log_format": "console",
        "rate_limit_per_minute": 100,
        "db_pool_size": 10,
        "enforce_strong_secret": False,
        "enforce_https": False,
        "fail_fast_on_config_warning": False,
        "auto_migrate_on_startup": True,
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
        # 운영에서는 약한 시크릿·빈 CORS 로 기동하지 못하게 막는다 (ADR-0006)
        "fail_fast_on_config_warning": True,
        # 프로덕션 스키마는 alembic upgrade head 로만 변경한다 (ADR-0006)
        "auto_migrate_on_startup": False,
    },
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="OPENSAST_", extra="ignore"
    )

    # ---- Core -----------------------------------------------------------
    app_name: str = "OpenSAST"
    debug: bool = False
    profile: Profile = Profile.LOCAL
    project_root: Path = PROJECT_ROOT
    rules_dir: Path = DEFAULT_RULES_DIR
    resources_dir: Path = DEFAULT_RESOURCES_DIR
    work_dir: Path = Field(default_factory=_default_work_dir)

    # ---- 커스터마이징 오버레이 -----------------------------------------
    # 사용자가 패키지 업그레이드 후에도 보존할 리소스·룰 경로
    custom_rules_dir: Path | None = None
    #: 리소스 오버라이드 디렉터리. 여기에 `mois_catalog.yaml` /
    #: `reference_standards.yaml` 을 두면 개별 경로를 지정하지 않아도 적용된다.
    custom_resources_dir: Path | None = None
    mois_catalog_path: Path | None = None  # YAML 파일로 49개 카탈로그 완전 교체
    reference_standards_path: Path | None = None
    #: 설정 오버레이 YAML (ARCHITECTURE §5.5). 환경변수보다 낮은 우선순위.
    overlay_config: Path | None = None

    # ---- Database / Queue ----------------------------------------------
    database_url: str = "postgresql+psycopg2://opensast:opensast@localhost:5432/opensast"
    db_pool_size: int = 5
    db_max_overflow: int = 10
    db_pool_recycle_seconds: int = 1800
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"
    #: 기동 시 `auto_migrate` 실행 여부. 프로덕션은 alembic 을 쓰므로 False.
    auto_migrate_on_startup: bool = True

    # ---- Auth ----------------------------------------------------------
    #: JWT 서명 키. **기본값은 비어 있다** — 소스에 예시 시크릿을 두지 않는다.
    #: 미설정 시 개발 프로파일에서는 프로세스 수명 동안 유효한 임시 키가
    #: 생성되고(재시작 시 기존 토큰 무효), cloud 프로파일에서는 기동을 거부한다.
    secret_key: str = ""
    access_token_expire_minutes: int = 60 * 24
    enforce_strong_secret: bool = False
    #: 설정 경고를 기동 실패로 승격할지 여부 (cloud 프로파일 기본값 True)
    fail_fast_on_config_warning: bool = False
    password_min_length: int = 12
    password_required_classes: int = 3  # upper/lower/digit/special 중 N종 이상
    failed_login_threshold: int = 5
    failed_login_lockout_minutes: int = 15
    refresh_cookie_name: str = "opensast_refresh"
    refresh_cookie_secure: bool = False
    refresh_cookie_samesite: str = "Lax"
    refresh_token_expire_days: int = 7
    jwt_issuer: str = "opensast"
    jwt_audience: str = "opensast-api"

    # 최초 부트스트랩 관리자
    bootstrap_admin_email: str = "admin@opensast.local"
    bootstrap_admin_password: str = "opensast-admin"
    bootstrap_admin_display_name: str = "OpenSAST Admin"

    # ---- HTTP / 보안 ----------------------------------------------------
    cors_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["*"]
    )
    enable_docs: bool = True
    enforce_https: bool = False
    rate_limit_per_minute: int = 0  # 0 = 비활성
    max_body_bytes: int = 2 * 1024 * 1024  # 일반 요청 2 MiB
    max_upload_bytes: int = 500 * 1024 * 1024  # zip 업로드 500 MiB
    security_headers_enabled: bool = True
    log_level: str = "INFO"
    log_format: str = "console"  # console | json

    # ---- 스캔 대상 경로 허용 목록 ---------------------------------------
    #: `POST /api/scans` 의 `source_path` 로 허용할 루트 디렉터리 목록.
    #: 비워두면 `work_dir` 하나만 허용한다. 워커 호스트의 임의 경로를 스캔한 뒤
    #: 소스 뷰어로 읽어내는 경로를 차단하기 위한 방어선이다.
    scan_allowed_source_roots: Annotated[list[Path], NoDecode] = Field(
        default_factory=list
    )

    # ---- LLM -----------------------------------------------------------
    llm_provider: str = Field(default="ollama")
    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-opus-4-6"
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "gemma2:9b"
    llm_timeout_seconds: int = 60
    llm_context_window_lines: int = 20
    llm_default_fp_probability: int = 50
    #: triage 동시 LLM 호출 수. Ollama 단일 인스턴스는 낮게(2~4) 잡는다.
    llm_max_concurrency: int = 4
    #: 한 번의 triage 에서 처리할 Finding 최대 개수 (0 = 무제한).
    #: 초과분은 severity 순으로 잘리며, 잘렸다는 사실이 결과에 기록된다.
    triage_max_findings: int = 2000
    #: triage 결과 Redis 캐시 TTL (초). 0 이면 캐시 비활성.
    triage_cache_ttl_seconds: int = 86400

    # ---- Celery task timeouts -----------------------------------------
    scan_task_soft_time_limit: int = 3600
    scan_task_time_limit: int = 7200
    triage_task_soft_time_limit: int = 1800
    triage_task_time_limit: int = 2400

    # ---- 파이프라인 ------------------------------------------------------
    #: 1차/2차 Pass 안에서 엔진을 동시에 실행할 개수 (1 = 순차).
    engine_max_concurrency: int = 4

    # ---- 조회 상한 -------------------------------------------------------
    #: 스캔별 Finding 조회 기본 상한. 초과 시 응답에 절단 사실을 표시한다.
    findings_page_limit: int = 1000

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

    @field_validator("scan_allowed_source_roots", mode="before")
    @classmethod
    def _parse_roots(cls, v):
        """콜론 또는 콤마 구분 문자열도 허용."""

        if isinstance(v, str):
            sep = ":" if ":" in v and "," not in v else ","
            return [s.strip() for s in v.split(sep) if s.strip()]
        return v

    # ---- 파생 값 --------------------------------------------------------
    def allowed_source_roots(self) -> list[Path]:
        """스캔 대상으로 허용된 루트 디렉터리의 정규화된 목록."""

        roots = list(self.scan_allowed_source_roots) or [Path(self.work_dir)]
        out: list[Path] = []
        for r in roots:
            try:
                out.append(Path(r).expanduser().resolve())
            except (OSError, RuntimeError):  # pragma: no cover - 방어
                continue
        return out

    def resolved_mois_catalog_path(self) -> Path | None:
        """MOIS 카탈로그 오버라이드 경로 (명시 경로 → 리소스 디렉터리 순)."""

        if self.mois_catalog_path:
            return Path(self.mois_catalog_path)
        if self.custom_resources_dir:
            candidate = Path(self.custom_resources_dir) / "mois_catalog.yaml"
            if candidate.exists():
                return candidate
        return None

    def resolved_reference_standards_path(self) -> Path | None:
        """레퍼런스 표준 오버라이드 경로 (명시 경로 → 리소스 디렉터리 순)."""

        if self.reference_standards_path:
            return Path(self.reference_standards_path)
        if self.custom_resources_dir:
            candidate = Path(self.custom_resources_dir) / "reference_standards.yaml"
            if candidate.exists():
                return candidate
        return None

    # ---- 프로파일 / 검증 -------------------------------------------------
    #: 이번 프로세스에서 임시 키를 사용 중인지 (경고·진단용)
    uses_ephemeral_secret: bool = False

    def apply_profile_defaults(self) -> "Settings":
        """프로파일별 기본값을 아직 명시되지 않은 필드에만 적용."""

        defaults = _PROFILE_DEFAULTS.get(self.profile, {})
        for key, value in defaults.items():
            # 사용자가 명시한 env 값은 건드리지 않음: model_fields_set 확인
            if key in self.model_fields_set:
                continue
            setattr(self, key, value)
        self._apply_ephemeral_secret()
        return self

    def _apply_ephemeral_secret(self) -> None:
        """시크릿 키가 비어 있으면 개발 프로파일에 한해 임시 키를 채운다.

        예전에는 소스에 `change-me-...` 예시 키가 박혀 있었다. 시크릿 스캐너가
        잡을 뿐 아니라, 그 값이 그대로 운영으로 흘러가기도 쉽다. 반대로 빈 값을
        허용하면 개발 프로파일에서 **빈 문자열로 JWT 를 서명**하게 된다.

        임시 키는 두 문제를 모두 피한다 — 리터럴이 없고, 빈 키도 없다.
        cloud 프로파일은 그대로 비워 두어 `validate_profile()` 이 잡게 한다.
        """

        if self.secret_key:
            return
        if self.profile is Profile.CLOUD:
            return  # 검증에서 기동 거부시킨다
        self.secret_key = _EPHEMERAL_SECRET_KEY
        self.uses_ephemeral_secret = True

    def validate_profile(self) -> list[str]:
        """프로파일별 무결성 검사 — 경고 메시지 목록 반환."""

        warnings: list[str] = []
        if not self.secret_key:
            warnings.append(
                f"[{self.profile.value}] OPENSAST_SECRET_KEY 가 설정되지 않음 — "
                "`openssl rand -hex 32` 로 생성해 주입하세요"
            )
        elif self.uses_ephemeral_secret:
            warnings.append(
                f"[{self.profile.value}] OPENSAST_SECRET_KEY 미설정 — 임시 키를 "
                "생성했습니다. 재시작 시 기존 토큰이 무효화되며, 프로세스를 여러 개 "
                "띄우면 로그인 세션이 깨집니다. 개발 용도로만 사용하세요."
            )
        if self.enforce_strong_secret:
            if (
                len(self.secret_key) < 32
                or "change-me" in self.secret_key.lower()
            ):
                warnings.append(
                    f"[{self.profile.value}] OPENSAST_SECRET_KEY 가 약함: 32자 이상, "
                    "'change-me' 미포함 필수"
                )
        if self.profile is Profile.CLOUD and not self.cors_origins:
            warnings.append(
                "[cloud] OPENSAST_CORS_ORIGINS 가 비어있음 — 운영에서는 명시 필요"
            )
        if self.profile is Profile.CLOUD and "*" in self.cors_origins:
            warnings.append(
                "[cloud] OPENSAST_CORS_ORIGINS 에 와일드카드('*') 사용 불가"
            )
        if (
            self.profile is Profile.CLOUD
            and self.bootstrap_admin_password == "opensast-admin"
        ):
            warnings.append(
                "[cloud] 기본 부트스트랩 비밀번호 사용 중 — 즉시 변경하세요"
            )
        return warnings

    def enforce_startup_policy(self) -> list[str]:
        """기동 시 설정 검증. `fail_fast_on_config_warning` 이면 예외를 던진다.

        Returns: 경고 목록 (fail-fast 가 아닐 때).
        Raises: RuntimeError — 운영 프로파일에서 안전하지 않은 기본값 감지 시.
        """

        warnings = self.validate_profile()
        if warnings and self.fail_fast_on_config_warning:
            joined = "\n  - ".join(warnings)
            raise RuntimeError(
                "안전하지 않은 설정으로 기동할 수 없습니다 "
                f"(profile={self.profile.value}):\n  - {joined}\n"
                "값을 수정하거나 OPENSAST_FAIL_FAST_ON_CONFIG_WARNING=false 로 "
                "명시적으로 완화하세요."
            )
        return warnings


# ---------------------------------------------------------------------------
# 오버레이 YAML (ARCHITECTURE §5.5)
# ---------------------------------------------------------------------------


def _flatten_overlay(data: dict[str, Any]) -> dict[str, Any]:
    """1단계 중첩 섹션을 `섹션_키` 형태로 평탄화한다.

    `{"llm": {"provider": "anthropic"}}` → `{"llm_provider": "anthropic"}`
    """

    flat: dict[str, Any] = {}
    for key, value in (data or {}).items():
        if isinstance(value, dict):
            for sub, sub_value in value.items():
                flat[f"{key}_{sub}"] = sub_value
        else:
            flat[key] = value
    return flat


def load_overlay(path: Path) -> dict[str, Any]:
    """오버레이 YAML 을 읽어 `Settings` 필드명 기준 dict 로 반환한다.

    `Settings` 에 없는 키는 경고 후 무시한다 — 오타가 조용히 삼켜지지 않도록.
    """

    import yaml

    from opensast.utils.logging import get_logger

    log = get_logger(__name__)
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except Exception as exc:  # noqa: BLE001
        log.warning("설정 오버레이 로드 실패 %s: %s", path, exc)
        return {}
    if not isinstance(raw, dict):
        log.warning("설정 오버레이 최상위가 매핑이 아님: %s", path)
        return {}

    flat = _flatten_overlay(raw)
    known = set(Settings.model_fields)
    out: dict[str, Any] = {}
    for key, value in flat.items():
        if key in known:
            out[key] = value
        else:
            log.warning("설정 오버레이의 알 수 없는 키 무시: %r (%s)", key, path)
    return out


@lru_cache
def get_settings() -> Settings:
    # 1) 환경변수 / .env 만으로 1차 로드 — 오버레이 경로를 알아내기 위함
    settings = Settings()
    overlay_path = settings.overlay_config
    if overlay_path and Path(overlay_path).exists():
        overlay = load_overlay(Path(overlay_path))
        if overlay:
            # 2) 오버레이를 기본값 자리에 넣고 재구성.
            #    환경변수는 pydantic-settings 우선순위에 따라 여전히 최상위다.
            explicit = settings.model_fields_set - {"overlay_config"}
            merged = {k: v for k, v in overlay.items() if k not in explicit}
            settings = Settings(**merged)
    settings.apply_profile_defaults()
    return settings


def reset_settings_cache() -> None:
    """테스트 환경에서 설정 재로드를 위한 캐시 초기화."""

    get_settings.cache_clear()
