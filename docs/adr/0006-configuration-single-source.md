# ADR-0006: 설정 진실의 원천을 하나로 만들고 배포 프로파일을 산출물에서 명시한다

**Status:** Accepted
**Date:** 2026-08-25
**Deciders:** 백엔드 오너, 운영

## Context

3-프로파일 설계(`local` / `docker` / `cloud`)는 이 프로젝트에서 가장 강조되는
아키텍처 특징이었지만, 실제로는 다음 상태였다.

**프로파일이 켜지지 않는 경로가 있었다.** `docker-compose.prod.yml` 은
`OPENSAST_PROFILE: cloud` 를 설정하지만, README 가 안내하는 기본 경로
(`docker compose up --build`)가 쓰는 `docker-compose.yml` 에는 프로파일 지정이
없었다. 즉 팀/온프레미스 표준 배포가 `local` 기본값으로 떴다 —
`cors_origins=["*"]`, `enable_docs=True`, `rate_limit_per_minute=0`,
`enforce_strong_secret=False`. `.env.example` 에도 `OPENSAST_PROFILE` 이 없었다.

**경고가 아무도 보지 않는 곳으로 갔다.** `validate_profile()` 은 약한 시크릿과 빈
CORS 를 감지하지만 결과가 `log.warning` 이었다. 컨테이너 로그의 경고 한 줄은
운영에서 실질적으로 없는 것과 같다.

**설정 값이 세 곳에서 진실을 주장했다.**

| 항목 | ARCHITECTURE 표 | `config.py` | 실제 사용 |
|---|---|---|---|
| 일반 요청 본문 상한 | 1 MiB | 2 MiB | 2 MiB — 문서가 틀림 |
| 업로드 상한 | 500 MiB | 500 MiB | `scan_service._MAX_UPLOAD_BYTES` 하드코딩 |
| `db_pool_size` | 프로파일별 5/10/20 | 동일하게 정의 | **`create_engine` 에 전달 안 됨** |
| `OPENSAST_OVERLAY_CONFIG` | §5.5 에 사용법 명시 | 필드 없음 | **미구현** |
| `custom_resources_dir` | §5.2 확장 지점 | 필드만 존재 | **참조 0건** |
| Celery time limit | — | `scan_task_*` 설정 존재 | `celery_app.py` 에 3600/7200 하드코딩 |

문서에 있는데 코드에 없는 설정은 최악이다. 사용자는 지정했다고 믿고, 아무 일도
일어나지 않는다.

## Decision

**`opensast/config.py` 가 설정의 유일한 진실의 원천이다.** 서비스·미들웨어·워커는
상수를 하드코딩하지 않고 반드시 `Settings` 에서 읽는다. 문서의 표는 이 파일을
*서술*할 뿐이며, 불일치가 생기면 코드가 정본이다.

우선순위(낮음 → 높음): **프로파일 기본값 → 오버레이 YAML → 환경변수 / `.env`**

### 1. 산출물이 자기 환경을 선언한다

- `docker-compose.yml` → `OPENSAST_PROFILE: docker` (api·worker 양쪽)
- `docker-compose.prod.yml` → `cloud` 유지 + 필수 시크릿을
  `${VAR:?메시지}` 형태로 강제해, 값이 없으면 compose 가 기동 전에 거부
- `.env.example` → `OPENSAST_PROFILE` 을 첫 항목으로, 프로파일이 무엇을 바꾸는지
  주석으로 명시

### 2. 운영에서는 경고가 곧 기동 실패

```python
def enforce_startup_policy(self) -> list[str]:
    warnings = self.validate_profile()
    if warnings and self.fail_fast_on_config_warning:
        raise RuntimeError(...)
    return warnings
```

`fail_fast_on_config_warning` 은 cloud 프로파일 기본값 `True` 다. 약한 시크릿,
빈 CORS, 와일드카드 CORS, 기본 부트스트랩 비밀번호로는 **기동하지 못한다.**
`OPENSAST_FAIL_FAST_ON_CONFIG_WARNING=false` 로 명시적으로만 완화할 수 있다.

### 3. 죽어 있던 설정을 배선하거나 없앤다

- `db_pool_size` / `db_max_overflow` / `db_pool_recycle_seconds` →
  `create_engine()` 에 전달. SQLite 는 QueuePool 을 쓰지 않으므로 드라이버를 보고
  분기한다.
- `custom_resources_dir` → `resolved_mois_catalog_path()` /
  `resolved_reference_standards_path()` 가 이 디렉터리의 `mois_catalog.yaml` /
  `reference_standards.yaml` 을 자동으로 집어 든다.
- `OPENSAST_OVERLAY_CONFIG` → 실제로 구현. 1단계 중첩 섹션을 `섹션_키` 로
  평탄화하며(`llm: {provider: x}` → `llm_provider`), `Settings` 에 없는 키는
  **경고 후 무시**한다 — 오타가 조용히 삼켜지지 않도록.
- `scan_service._MAX_UPLOAD_BYTES` 삭제 → `settings.max_upload_bytes`
- `celery_app` 의 3600/7200 → `settings.scan_task_*`
- ARCHITECTURE 의 1 MiB 표기를 코드값 2 MiB 로 정정 (코드가 정본)

### 4. 스키마 변경 경로도 프로파일이 정한다

`auto_migrate_on_startup` 을 추가하고 cloud 기본값을 `False` 로 둔다. 프로덕션
스키마는 `alembic upgrade head` 로만 바뀐다. `auto_migrate` 는 컬럼 추가만
가능하므로, 프로덕션 경로에 남아 있으면 스키마 드리프트가 누적된다.

## Options Considered

| 안 | 안전성 | 온보딩 마찰 | 평가 |
|---|---|---|---|
| A. 기본 프로파일을 `docker` 로 변경 | 중간 | 낮음 | 로컬 개발이 불편해지고, "산출물이 환경을 선언하지 않는다" 는 근본 원인은 남는다 |
| **B. compose 에 명시 + cloud 검증 실패화 (채택)** | 높음 | 낮음 | 각 산출물이 자기 환경을 선언하고, 운영은 침묵 대신 실패로 알린다 |
| C. 프로파일 폐기, 순수 환경변수 | 중간 | 높음 | "안전한 기본값 번들" 이라는 장점을 버리고 모든 값을 매번 지정하게 만든다 |

## Consequences

**쉬워지는 것**

- 운영 배포가 약한 시크릿·빈 CORS 로는 아예 뜨지 않는다.
- 문서의 프로파일 표가 처음으로 사실이 된다.
- 설정 한 곳만 보면 실제 동작을 알 수 있다.

**어려워지는 것**

- 기존 cloud 배포가 있다면 `OPENSAST_SECRET_KEY`, `OPENSAST_CORS_ORIGINS`,
  `OPENSAST_BOOTSTRAP_ADMIN_PASSWORD` 를 갖추기 전까지 기동하지 못한다.
  **동작 변경이므로 릴리스 노트 필수.**
- cloud 프로파일에서 `auto_migrate` 가 꺼지므로 배포 파이프라인에
  `alembic upgrade head` 단계를 명시해야 한다.
- 기동 실패가 **import 시점**에 터지지 않도록 ASGI `app` 을 지연 생성으로 바꿔야
  했다. 예전 구조에서는 `opensast.api` 하위 모듈을 import 하는 것만으로
  `create_app()` 이 돌아, cloud 프로파일 `.env` 를 둔 개발자는 테스트 수집조차
  할 수 없었다. fail-fast 를 도입하면서 드러난 기존 결함이다.

**다시 볼 것**

- 시크릿을 환경변수 평문으로 두는 문제는 이 ADR 의 범위 밖이다. Docker secrets
  파일 마운트 또는 Vault/AWS SM 연동을 후속 ADR 로.
- `DEFAULT_WORK_DIR` 은 여전히 프로세스 CWD 기준이다. API 와 워커가 다른 CWD 로
  뜨면 같은 상대 경로가 다르게 해석된다. 지금은 `.env.example` 주석과 compose 의
  명시적 절대 경로로 막았지만, 다중 노드 확장 시 재검토가 필요하다.

## Action Items

1. [x] compose 3종에 프로파일·필수 시크릿 명시
2. [x] `enforce_startup_policy()` 및 cloud fail-fast
3. [x] `db_pool_size` 배선, `_MAX_UPLOAD_BYTES` 제거, Celery time limit 설정화
4. [x] `OPENSAST_OVERLAY_CONFIG` 구현, `custom_resources_dir` 배선
5. [x] `auto_migrate_on_startup` 도입 (cloud 기본 False)
6. [x] ASGI `app` 지연 생성 (PEP 562) — import 부작용 제거
7. [x] 테스트를 리포지토리 `.env` 로부터 격리 (conftest autouse)
8. [x] 회귀 테스트 (`tests/test_security_regressions.py`)
9. [ ] 시크릿 관리 후속 ADR (Docker secrets / Vault)
