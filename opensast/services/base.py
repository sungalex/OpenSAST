"""서비스 계층 공통 추상 기반.

**인가 경계 정책 (ADR-001)**

서비스는 반드시 `ActorContext` 를 받아야 한다. 예전에는 `actor` 가 선택 인자였고
누락 시 조직 필터가 "전체 통과" 로 평가되어, 라우트가 actor 를 빠뜨리는 것만으로
조직 격리가 무력화됐다. 이제는 다음 두 가지로 그 실패 모드를 제거한다.

1. `BaseService.__init__` 이 `actor` 를 **필수** 인자로 받는다. 라우트가 빠뜨리면
   `TypeError` 로 즉시 드러난다.
2. `_org_filter()` 의 기본값이 **차단**이다. actor 의 조직과 일치하는 레코드만
   통과하며(조직 미지정 사용자는 조직 미지정 레코드만), 전체 조회는
   `ActorContext.system()` 컨텍스트에서만 가능하다.

미인증·시스템 컨텍스트는 명시적 팩토리로만 만든다:

- `ActorContext.anonymous(...)` — 로그인 시도 등 미인증 경로. 아무것도 통과 못 함.
- `ActorContext.system(...)` — CLI · Celery 워커 · 부트스트랩. 조직 스코핑 우회.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import true
from sqlalchemy.orm import Session

from opensast.db import models, repo


class ServiceError(Exception):
    """도메인 규칙 위반."""

    def __init__(
        self, message: str, *, status_code: int = status.HTTP_400_BAD_REQUEST
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code

    def as_http(self) -> HTTPException:
        return HTTPException(status_code=self.status_code, detail=self.message)


@dataclass
class ActorContext:
    """호출자 식별 + 감사 메타데이터 묶음.

    라우트는 `opensast.api.deps.get_actor` 의존성으로 이 객체를 만들어 서비스에
    주입한다. 직접 생성이 필요한 경우는 아래 두 팩토리 중 하나를 쓴다.
    """

    user: models.User | None
    ip: str | None = None
    user_agent: str | None = None
    organization_id: int | None = None
    is_system: bool = False

    # ---- 명시적 팩토리 --------------------------------------------------
    @classmethod
    def anonymous(
        cls, *, ip: str | None = None, user_agent: str | None = None
    ) -> "ActorContext":
        """미인증 컨텍스트 — 로그인 시도, 실패 감사 기록 등에만 사용."""

        return cls(user=None, ip=ip, user_agent=user_agent)

    @classmethod
    def system(cls, *, reason: str = "") -> "ActorContext":
        """신뢰 컨텍스트 — CLI · Celery 워커 · 부트스트랩.

        조직 스코핑과 역할 검사를 우회하므로, HTTP 요청 처리 경로에서는
        **절대** 사용하지 않는다.
        """

        return cls(
            user=None,
            is_system=True,
            user_agent=f"system:{reason}" if reason else "system",
        )

    # ---- 조회 -----------------------------------------------------------
    @property
    def user_id(self) -> int | None:
        return self.user.id if self.user else None

    @property
    def role(self) -> str:
        if self.user is not None:
            return self.user.role
        return "system" if self.is_system else "anonymous"

    def require_role(self, *roles: str) -> None:
        if self.is_system:
            return
        if self.role not in roles:
            raise ServiceError(
                f"requires role in {roles}, got {self.role}",
                status_code=status.HTTP_403_FORBIDDEN,
            )


class BaseService:
    """모든 서비스의 기반.

    - `session` 을 생성자 주입 (트랜잭션 경계)
    - `actor` 는 **필수** — 인가 판단에 필요한 정보를 옵션으로 두지 않는다
    - 감사 로그 발행 헬퍼 제공
    - 커밋/롤백은 라우트 종료 시점의 get_db 가 처리하지 않으므로 서비스가 직접
      `session.commit()` 한다. 오류 시 FastAPI 예외 핸들러가 자동 롤백.
    """

    def __init__(self, session: Session, actor: ActorContext) -> None:
        if not isinstance(actor, ActorContext):
            raise TypeError(
                f"{type(self).__name__} requires an ActorContext; got "
                f"{type(actor).__name__!r}. 미인증 경로는 ActorContext.anonymous(), "
                "배치·CLI 경로는 ActorContext.system() 을 명시적으로 전달하세요."
            )
        self.session = session
        self.actor = actor

    # ---- 조직 스코핑 -----------------------------------------------------
    def _org_filter(self, model_class):
        """조직 스코핑 필터 — 기본값은 **차단**이다.

        - `system` 컨텍스트: 전체 통과
        - 그 외: actor 의 `organization_id` 와 일치하는 레코드만 통과.
          actor 가 조직 미지정(None)이면 조직 미지정 레코드만 통과한다
          (SQLAlchemy 가 `IS NULL` 로 컴파일하므로 단일 테넌시 배포에서도 정상 동작).
        """

        if self.actor.is_system:
            return true()
        return model_class.organization_id == self.actor.organization_id

    def _assert_org(self, obj: Any, *, label: str = "resource") -> None:
        """조직 소유가 아닌 객체 접근을 404 로 차단한다 (존재 여부 노출 방지)."""

        if self.actor.is_system:
            return
        if getattr(obj, "organization_id", None) != self.actor.organization_id:
            raise ServiceError(
                f"{label} not found", status_code=status.HTTP_404_NOT_FOUND
            )

    # ---- 감사 -----------------------------------------------------------
    def _audit(
        self,
        action: str,
        *,
        target_type: str | None = None,
        target_id: int | str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        repo.record_audit(
            self.session,
            user_id=self.actor.user_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            detail=detail or {},
            ip=self.actor.ip,
        )
