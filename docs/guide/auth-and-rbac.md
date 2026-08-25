# 인증과 권한

> 이 문서는 `docs/USER_GUIDE.md`(1,926줄 단일 파일)를 독자별로 분할한 것이다
> ([ADR-0007](../adr/0007-documentation-architecture.md)).

> **정본 주의**
>
> RBAC 표의 정본은 [ARCHITECTURE §4.3](../ARCHITECTURE.md#43-권한-rbac) 이며,
> 강제 지점은 `api/deps.py` 의 `require_actor()` 와 서비스의 `require_role()` 이다
> ([ADR-0005](../adr/0005-authorization-boundary.md)).

---

## 인증 및 RBAC

- `opensast/api/security.py`: JWT(HS256, jose) 및 **bcrypt 직접** 해싱 (72바이트 상한 안전 처리, passlib 비사용).
  - **v0.5.0**: JWT에 `iat`(발급 시각)·`jti`(UUID 고유 ID) 클레임 추가.
  - **Refresh token**: `POST /api/auth/refresh`로 새 access+refresh 쌍 발급. 로그인 응답에 `refresh_token` 포함.
- `opensast/api/schemas.py`: 이메일 검증은 `EmailStr` 대신 느슨한 정규식(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)을 사용해 `.local`·`.internal` 등 내부망 도메인을 허용한다. 입력은 자동으로 소문자 정규화된다.
- `opensast/api/deps.py::get_current_user` 가 모든 보호 라우트에 주입된다.
- `require_role("admin", …)` 으로 역할 기반 접근 제어 가능. 기본 역할:
  - `admin` — 전체 권한, 사용자 생성 가능
  - `analyst` — 프로젝트·스캔·Finding 조회/생성
  - `viewer` — (모델 정의됨, 쓰기 엔드포인트는 막혀 있음)
- 토큰 만료: `OPENSAST_ACCESS_TOKEN_EXPIRE_MINUTES` (기본 24시간).
- **Rate limit**: Redis 기반 분산 rate limit. IP 당 분당 요청 수 제한(프로파일별 기본값 상이).
- **CSRF 미들웨어**: cloud 프로파일에서 자동 활성화. 쿠키(`opensast_csrf`) + 헤더(`X-CSRF-Token`) 이중 검증. `/api/auth/login`, `/api/auth/refresh`, `/health`, `/ready`, `/metrics` 는 면제.
- **CSP**: `unsafe-inline` 제거, nonce 기반 CSP로 전환.

### 부트스트랩 관리자

`opensast/db/repo.py::ensure_bootstrap_admin` 이 FastAPI `startup` 이벤트에서
호출된다. 동일 이메일의 사용자가 이미 있으면 아무것도 하지 않는다(기존
비밀번호 보존). `opensast init-db` CLI 에서도 동일 로직을 재사용한다.

---
