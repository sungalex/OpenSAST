"""서비스 계층 공통 추상 기반."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException, status
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

    라우트가 `get_current_user` + `Request` 로부터 만들어 서비스에 주입한다.
    미인증 컨텍스트(ex. 로그인 시도)는 `user` 를 None 으로 둔다.
    """

    user: models.User | None
    ip: str | None = None
    user_agent: str | None = None
    organization_id: int | None = None

    @property
    def user_id(self) -> int | None:
        return self.user.id if self.user else None

    @property
    def role(self) -> str:
        return self.user.role if self.user else "anonymous"

    def require_role(self, *roles: str) -> None:
        if self.role not in roles:
            raise ServiceError(
                f"requires role in {roles}, got {self.role}",
                status_code=status.HTTP_403_FORBIDDEN,
            )


class BaseService:
    """모든 서비스의 기반.

    - `session` 을 생성자 주입 (트랜잭션 경계)
    - 감사 로그 발행 헬퍼 제공
    - 커밋/롤백은 라우트 종료 시점의 get_db 가 처리하지 않으므로 서비스가 직접
      `session.commit()` 한다. 오류 시 FastAPI 예외 핸들러가 자동 롤백.
    """

    def __init__(self, session: Session, actor: ActorContext | None = None) -> None:
        self.session = session
        self.actor = actor or ActorContext(user=None)

    def _org_filter(self, model_class):
        """조직 스코핑 필터.

        actor 에 organization_id 가 설정되어 있으면 해당 조직의 레코드만 반환,
        None 이면 전체 반환 (super-admin / 미인증 컨텍스트).
        """
        org_id = self.actor.organization_id if self.actor else None
        if org_id is None:
            return True
        return model_class.organization_id == org_id

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
