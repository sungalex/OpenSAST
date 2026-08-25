# 확장 / 커스터마이징

> 이 문서는 `docs/USER_GUIDE.md`(1,926줄 단일 파일)를 독자별로 분할한 것이다
> ([ADR-0007](../adr/0007-documentation-architecture.md)).

> **정본 주의**
>
> 확장 지점의 정본은 [ARCHITECTURE §5](../ARCHITECTURE.md#5-커스터마이징-격리) 다.

---

## 확장 / 커스터마이징 가이드

OpenSAST 는 **5가지 확장 지점**을 제공한다. 커스터마이징은 코어 패키지 수정 없이
이루어지며, 패키지 업그레이드 시에도 유지된다. 전체 아키텍처 원칙은
[docs/ARCHITECTURE.md](../ARCHITECTURE.md) 참조.

### 20.1 플러그인 패키지 (엔진 / LLM / 리포트 / 레퍼런스)

Python entry_points 로 플러그인을 등록하면 `pip install` 만으로 OpenSAST 가 자동
발견한다.

```toml
# my-plugin/pyproject.toml
[project]
name = "opensast-plugin-mycheck"
dependencies = ["opensast>=0.5.0"]

[project.entry-points."opensast.engines"]
mycheck = "aisast_plugin_mycheck:MyCheckEngine"

[project.entry-points."opensast.llm"]
vllm = "aisast_plugin_mycheck:VLLMClient"

[project.entry-points."opensast.hooks"]
jira-sync = "aisast_plugin_mycheck:JiraHook"
```

카테고리 목록:

| entry_point 그룹 | 인터페이스 | 설명 |
|-----------------|-----------|------|
| `opensast.engines` | `Engine` | SAST 분석 엔진 어댑터 |
| `opensast.llm` | `LLMClient` | 오탐 필터링용 LLM 프로바이더 |
| `opensast.reports` | 함수 또는 클래스 | 신규 리포트 포맷 |
| `opensast.references` | dict 반환 함수 | CWE→표준 매핑 공급자 |
| `opensast.hooks` | `ScanHook` | 수명주기 훅 |

런타임 등록도 가능:

```python
from opensast.plugins import engine_registry
engine_registry.register("mysast", MySAST, source="runtime")
```

비활성화:

```bash
OPENSAST_PLUGINS_DISABLED=jira-sync,mycheck docker compose up
```

### 20.2 YAML 리소스 오버레이

**커스텀 MOIS 항목 추가** — 행안부 개정판, 사내 전용 룰 코드:

```yaml
# /etc/opensast/mois_override.yaml
items:
  - id: "SR1-1"
    name_kr: "SQL 삽입 (개정판)"
    name_en: "SQL Injection"
    category: "입력데이터 검증 및 표현"
    cwe_ids: ["CWE-89", "CWE-564"]
    severity: "HIGH"
    primary_engines: ["opengrep"]
  - id: "ORG-SR-101"
    name_kr: "사내 API 키 하드코드"
    category: "보안기능"
    cwe_ids: ["CWE-798"]
    severity: "HIGH"
    primary_engines: ["opengrep"]
```

```bash
OPENSAST_MOIS_CATALOG_PATH=/etc/opensast/mois_override.yaml
```

기존 49개 위에 **병합** 되므로 내장 항목을 보존하면서 추가/교체할 수 있다.
샘플: `opensast/resources/mois_catalog.sample.yaml`.

**커스텀 레퍼런스 표준 추가** — KISA-KSG, ISO 27001, 사내 표준:

```yaml
# /etc/opensast/refs_override.yaml
mappings:
  "CWE-89":
    - standard: "KISA-KSG-2024"
      id: "DB-001"
      title: "데이터베이스 입력 검증 필수"
  "CWE-79":
    - standard: "ISO-27001"
      id: "A.14.2.5"
      title: "Secure system engineering principles"
```

```bash
OPENSAST_REFERENCE_STANDARDS_PATH=/etc/opensast/refs_override.yaml
```

샘플: `opensast/resources/reference_standards.sample.yaml`.

### 20.3 커스텀 룰 디렉터리

Opengrep 룰은 내장 `rules/opengrep/` 과 **같은 레벨로** 사용자 디렉터리를
추가할 수 있다:

```bash
mkdir -p /etc/opensast/my-rules/python
cp my-custom-rule.yml /etc/opensast/my-rules/python/

OPENSAST_CUSTOM_RULES_DIR=/etc/opensast/my-rules \
  docker compose up -d
```

업그레이드 시 내장 룰만 덮어쓰고 `/etc/opensast/my-rules` 는 건드리지 않는다.

### 20.4 확장 훅

Python 코드로 수명주기 이벤트를 구독:

```python
# my_aisast_plugin/hooks.py
from opensast.hooks import hook_registry
from opensast.db import models

class JiraIssueSync:
    def on_status_change(self, finding: models.Finding, old: str, new: str):
        if new == "confirmed":
            create_jira_ticket(finding)

    def post_scan(self, scan_id: str, result):
        if any(f.severity == "HIGH" for f in result.findings):
            send_slack_alert(scan_id, result.findings)

hook_registry.register("jira-sync", JiraIssueSync())
```

지원 이벤트:

| 이벤트 | 시점 | 인자 |
|--------|------|------|
| `pre_scan` | 스캔 시작 직전 | `(scan_id, target)` |
| `post_scan` | 스캔 완료 후 (Triage 포함) | `(scan_id, result)` |
| `pre_persist` | DB 저장 직전 | `(scan_id, result)` |
| `post_persist` | DB 저장 후 | `(scan_id, scan_row)` |
| `on_status_change` | Finding 상태 전이 시 | `(finding, old, new)` |

모든 훅 호출은 격리되어 있어 한 훅의 예외가 다른 훅이나 코어 파이프라인을
멈추게 하지 않는다.

### 20.5 설정 프로파일

배포 환경마다 동일 코드베이스로 기본값을 바꿀 수 있다:

| 프로파일 | 대상 | 주요 차이 |
|----------|------|-----------|
| `local` | 개발자 워크스테이션 | CORS=`*`, docs 활성, rate limit off, 약한 secret 허용 |
| `docker` | 팀/온프렘 Compose | CORS=localhost, rate 100/min, INFO 로그 |
| `cloud` | 프로덕션 클라우드 | **docs 비활성**, **HSTS 강제**, secret 강도 검증, rate 60/min, JSON 로그(`OPENSAST_LOG_FORMAT=json`), CORS allowlist 강제, **CSRF 활성**, **CSP nonce** |

```bash
OPENSAST_PROFILE=cloud \
  OPENSAST_SECRET_KEY=$(openssl rand -hex 32) \
  OPENSAST_CORS_ORIGINS=https://sast.corp.com \
  docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

모든 개별 값은 여전히 `OPENSAST_*` 환경변수로 재정의된다. 프로파일은 **기본값**
만 바꾼다.

### 20.6 서비스 계층 재사용

라우트와 독립된 비즈니스 로직은 `opensast.services` 에 있으므로 Celery 태스크·
CLI·외부 스크립트에서 동일한 API 로 재사용할 수 있다:

```python
from opensast.db.session import session_scope
from opensast.services import ActorContext, ProjectService, ScanService

with session_scope() as session:
    actor = ActorContext(user=None, ip="127.0.0.1")
    project = ProjectService(session, actor).create(name="nightly-scan")
    scan = ScanService(session, actor).queue_from_path(
        project_id=project.id,
        source_path="/build/workspace",
        language_hint="java",
        enable_second_pass=True,
        enable_triage=True,
    )
```

### 20.7 Alembic 마이그레이션

스키마 변경은 Alembic 정식 마이그레이션으로 관리:

```bash
# 새 모델 추가 후
alembic revision --autogenerate -m "add some_table"

# 적용
alembic upgrade head

# 또는 CLI
opensast db-upgrade
```

`auto_migrate` 는 개발용 fallback 으로만 동작하며, 프로덕션에서는 반드시
Alembic 을 사용한다.

### 20.8 프로덕션 배포 (3-tier)

```
 브라우저                  nginx                 FastAPI            Postgres
 ────────   HTTPS   ───▶  (tls종료)  ───▶       (api/worker)  ───▶ (managed)
                           · 정적 서빙            · 서비스계층
                           · /api 프록시         · 플러그인 로드
                           · 보안 헤더           · 감사 로그
```

`docker-compose.prod.yml` override 로 nginx + 정적 빌드 프론트엔드 + cloud
프로파일 API 가 한 번에 올라온다. 자세한 실행 방법은 `ARCHITECTURE.md §6.3`
참조.

### 20.9 업그레이드 체크리스트

패키지 버전을 올릴 때 다음 6가지가 보존되는지만 확인하면 된다 — 모두 환경변수/
볼륨 기반이므로 코드 수정 불필요.

1. `OPENSAST_MOIS_CATALOG_PATH` — 카탈로그 오버레이 YAML 경로
2. `OPENSAST_REFERENCE_STANDARDS_PATH` — 레퍼런스 오버레이 YAML 경로
3. `OPENSAST_CUSTOM_RULES_DIR` — 커스텀 Opengrep 룰 디렉터리
4. 설치된 플러그인 패키지 (`pip list | grep opensast-plugin-`)
5. `docker-compose.override.yml` — 환경변수·볼륨 커스텀
6. DB 데이터 — Alembic 이 호환 마이그레이션 제공

---
