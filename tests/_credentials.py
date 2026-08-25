"""테스트용 자격증명 — **리터럴을 두지 않고 실행 시 생성한다.**

시크릿 스캐너(GitGuardian)는 소스에 박힌 비밀번호 모양 문자열을 "Generic
Password" 로 잡는다. 테스트 픽스처라 실제 시크릿은 아니지만, 스캐너 입장에서
구분할 방법이 없고 PR 마다 경고가 뜨면 **진짜 유출이 묻힌다**. 리터럴 자체를
없애는 편이 낫다.

생성 값은 비밀번호 정책(12자 이상, 대·소·숫자·특수 중 3종 이상)을 만족한다.
"""

from __future__ import annotations

import secrets


def make_test_password(label: str) -> str:
    """정책을 만족하는 임의 테스트 비밀번호를 만든다.

    `label` 은 디버깅 시 어느 픽스처의 값인지 알아보기 위한 접두사다.
    """

    return f"{label}-{secrets.token_urlsafe(12)}aA1!"


#: 세션 전체에서 재사용 — 발급과 로그인이 같은 값을 써야 한다.
ANALYST_PASSWORD = make_test_password("analyst")
VIEWER_PASSWORD = make_test_password("viewer")
ORG_USER_PASSWORD = make_test_password("orguser")
BOOTSTRAP_PASSWORD = make_test_password("bootstrap")
