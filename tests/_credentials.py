"""테스트용 자격증명 — **리터럴을 두지 않고 실행 시 생성한다.**

시크릿 스캐너(GitGuardian `generic_password` 등)는 소스에 박힌 비밀번호 모양
문자열을 잡는다. 테스트 픽스처라 실제 시크릿은 아니지만 스캐너 입장에서 구분할
방법이 없고, PR 마다 경고가 뜨면 **진짜 유출이 그 소음에 묻힌다.** 리터럴 자체를
없애는 편이 낫다.

GitGuardian 의 generic_password 탐지기는 비밀번호처럼 보이는 식별자와 따옴표
문자열이 가까이 있을 때 매칭한다. 따라서 이 파일에는 규칙이 하나 있다:

> **`*_PASSWORD` 식별자가 있는 줄에 따옴표 문자열을 두지 않는다.**

예전 버전은 디버깅 편의로 역할 이름을 접두사로 넘겼고, 그 인자 리터럴이
인시던트로 잡혔다(GitGuardian incident 36586696). 접두사가 주는 정보는 실패
메시지의 변수명으로 이미 드러나므로 가치가 없었다 — 그래서 인자를 없앴다.

생성 값은 비밀번호 정책(12자 이상, 대·소문자·숫자·특수문자 조합)을 만족한다.
"""

from __future__ import annotations

import secrets

#: 정책 충족을 보장하기 위한 고정 접미사. 무작위 토큰만으로는 특수문자가
#: 포함된다는 보장이 없다.
_POLICY_SUFFIX = "aA1!"


def make_test_password() -> str:
    """비밀번호 정책을 만족하는 임의의 테스트 비밀번호를 만든다.

    호출할 때마다 서로 다른 값을 돌려준다. 소스에 남는 리터럴은 정책 충족용
    접미사뿐이며, 그 자체는 비밀이 아니다.
    """

    return f"{secrets.token_urlsafe(12)}{_POLICY_SUFFIX}"


#: 세션 전체에서 재사용한다 — 사용자 생성과 로그인이 같은 값을 써야 한다.
ANALYST_PASSWORD = make_test_password()
VIEWER_PASSWORD = make_test_password()
ORG_USER_PASSWORD = make_test_password()
BOOTSTRAP_PASSWORD = make_test_password()
