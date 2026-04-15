"""서비스 계층 — 라우트와 DB 사이의 비즈니스 로직 · 트랜잭션 · 감사.

각 서비스는 다음을 책임진다:

1. **비즈니스 규칙 검증** — 도메인 불변식(상태 전이 규칙, 중복 금지 등)
2. **트랜잭션 경계** — 서비스 메서드 하나가 하나의 논리적 작업
3. **감사 로그 발행** — 모든 변경 작업은 `audit_logs` 에 기록
4. **RBAC 강제** — 필요 권한 체크 (라우트가 1차, 서비스가 2차 방어선)

라우트는 `ActorContext` 로 호출자 정보(user_id, role, ip) 를 전달한다.
"""

from aisast.services.base import ActorContext, ServiceError
from aisast.services.finding_service import FindingService
from aisast.services.gate_service import GateService
from aisast.services.project_service import ProjectService
from aisast.services.rule_set_service import RuleSetService
from aisast.services.scan_service import ScanService
from aisast.services.suppression_service import SuppressionService

__all__ = [
    "ActorContext",
    "ServiceError",
    "FindingService",
    "GateService",
    "ProjectService",
    "RuleSetService",
    "ScanService",
    "SuppressionService",
]
