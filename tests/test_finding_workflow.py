"""이슈 상태 워크플로 전이 규칙 검증."""

import pytest

from aisast.services.finding_service import (
    _ADMIN_TRANSITIONS,
    _SELF_TRANSITIONS as _ALLOWED_SELF_TRANSITIONS,
)


def test_self_transitions_reject_direct_exclusion() -> None:
    # 일반 사용자는 'new' → 'excluded' 직접 전이 불가 (관리자 승인 필요)
    assert "excluded" not in _ALLOWED_SELF_TRANSITIONS["new"]


def test_self_transitions_allow_request_then_review() -> None:
    assert "exclusion_requested" in _ALLOWED_SELF_TRANSITIONS["new"]
    assert "excluded" in _ADMIN_TRANSITIONS["exclusion_requested"]
    assert "rejected" in _ADMIN_TRANSITIONS["exclusion_requested"]


def test_admin_can_revert_excluded() -> None:
    assert "new" in _ADMIN_TRANSITIONS["excluded"]


def test_fixed_can_be_reopened() -> None:
    assert "new" in _ALLOWED_SELF_TRANSITIONS["fixed"]
