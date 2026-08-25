# 엔터프라이즈 기능·멀티테넌시·관측성

> 이 문서는 `docs/USER_GUIDE.md`(1,926줄 단일 파일)를 독자별로 분할한 것이다
> ([ADR-0003](../adr/0003-documentation-architecture.md)).

---

## 엔터프라이즈 기능

### 19.1 이슈 상태 워크플로

```
new ─┬─▶ confirmed ─┬─▶ fixed ─┐
     │              │           │
     │              ▼           │
     ├─▶ exclusion_requested ───┼─▶ (admin) excluded ─┐
     │                          │                     │
     │                          └─▶ (admin) rejected ─┤
     │                                                │
     └─◀────────────────────────────────────────────  ┘
                  (취소·재오픈은 일반 사용자 가능)
```

상태 전이 규칙:

- 일반 사용자: `new ↔ confirmed`, `new → exclusion_requested`, `* → fixed`,
  `exclusion_requested → new` (취소), `fixed → new/confirmed` (재오픈)
- 관리자만: `exclusion_requested → excluded/rejected`, `excluded → new`,
  `* → excluded` (즉시 승인)

```bash
# 상태 변경 (개발자가 확인 처리)
curl -X POST http://localhost:8000/api/findings/123/status \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status":"confirmed","reason":"실제 SQL 삽입 확인"}'

# 제외 신청
curl -X POST .../api/findings/123/status -d '{"status":"exclusion_requested","reason":"테스트 코드"}'

# 관리자 승인
curl -X POST .../api/findings/123/status -d '{"status":"excluded","reason":"테스트 케이스 허용"}'
```

### 19.2 Advanced Issue Filter

```bash
curl "http://localhost:8000/api/findings/search?\
project_id=1&\
severity=HIGH&severity=MEDIUM&\
engine=opengrep&engine=bandit&\
mois_id=SR1-1&mois_id=SR1-3&\
status=new&status=confirmed&\
path_glob=src/**/api/*.py&\
text=injection&\
limit=100" \
  -H "Authorization: Bearer $TOKEN"
```

지원 파라미터: `scan_id`, `project_id`, `severity[]`, `engine[]`, `status[]`,
`mois_id[]`, `cwe[]`, `path_glob` (fnmatch), `text` (rule_id/message/file_path
ILIKE), `include_excluded` (기본 false), `limit`/`offset`.

### 19.3 자연어 이슈 검색 (LLM)

```bash
curl -X POST http://localhost:8000/api/findings/ask \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"관리자 인증 없이 호출되는 SQL 삽입 중 HIGH 만 보여줘", "project_id": 1}'
```

내부 동작:
1. LLM(`build_client()`) 이 시스템 프롬프트에 따라 질의를 JSON 필터로 변환
2. 변환된 필터(severity, mois_ids, cwe_ids, statuses, text 등)로 DB 조회
3. LLM 부재/호출 실패 시 `_keyword_fallback()` 키워드 파서로 기본 추출

### 19.4 대시보드

```bash
curl http://localhost:8000/api/dashboard/overview               # 카드 4개
curl http://localhost:8000/api/dashboard/trends?days=30         # 시계열
curl http://localhost:8000/api/dashboard/top-rules?limit=10     # TOP 룰
curl http://localhost:8000/api/dashboard/mois-coverage          # 49개 커버리지
curl http://localhost:8000/api/dashboard/category-distribution  # 카테고리 분포
```

### 19.5 체커 그룹(RuleSet)

```bash
curl -X POST http://localhost:8000/api/rule-sets \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "MOIS-Strict-Java",
    "description": "Java 프로젝트 행안부 49개 + SpotBugs",
    "enabled_engines": ["opengrep","spotbugs","codeql"],
    "include_rules": [],
    "exclude_rules": ["mois-sr6-2-debug-print"],
    "min_severity": "MEDIUM",
    "is_default": false
  }'
```

### 19.6 경로·함수 제외 규칙

```bash
# tests/ 경로의 모든 탐지 자동 제외
curl -X POST http://localhost:8000/api/projects/1/suppressions \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"kind":"path","pattern":"**/tests/**","reason":"테스트 코드 허용"}'

# 특정 룰만 비활성
curl -X POST .../suppressions -d '{"kind":"rule","pattern":"mois-sr6-2-debug-print","reason":"개발 단계 허용"}'

# 함수명 기반 제외
curl -X POST .../suppressions -d '{"kind":"function","pattern":"sanitize_html_safe","reason":"내부 검증 함수"}'
```

스캔 영구 저장 시 `repo.persist_scan_result()` 가 자동으로 매칭되는 Finding 의
`status='excluded'`, `status_reason='auto-suppressed by project suppression rule'`
로 처리한다.

### 19.7 이전 분석 비교(diff)

```bash
# 가장 최근 vs 직전 분석 자동 비교
curl http://localhost:8000/api/scans/abc123def456/diff -H "Authorization: Bearer $TOKEN"

# 임의의 base 지정
curl http://localhost:8000/api/scans/abc123def456/diff?base=xyz789 -H "Authorization: Bearer $TOKEN"
```

응답: `new[]`, `resolved[]`, `persistent: int`, `summary: {new, resolved, persistent, new_high}`.
diff 키는 `finding_hash` (rule + engine + file + line + mois 의 SHA1).

### 19.8 CI/CD 빌드 게이트

```bash
# 1) 정책 등록 (최초 1회 또는 변경 시)
curl -X PUT http://localhost:8000/api/gate/policy \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{
    "project_id": 1,
    "max_high": 0,
    "max_medium": 50,
    "max_low": 500,
    "max_new_high": 0,
    "block_on_triage_fp_below": 30,
    "enabled": true
  }'

# 2) CI 파이프라인에서 게이트 호출
RESULT=$(curl -sS -X POST http://localhost:8000/api/gate/check \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"project_id":1,"scan_id":"abc123","base_scan_id":"prev999"}')
PASSED=$(echo "$RESULT" | jq .passed)
[ "$PASSED" = "true" ] || { echo "BLOCKED:"; echo "$RESULT"; exit 1; }
```

응답: `{passed, reasons[], counts:{HIGH,MEDIUM,LOW}, new_high}`. `reasons` 가
임계값 위반 사유를 한국어로 반환하므로 CI 로그에 그대로 노출 가능.

### 19.9 소스 파일 뷰어

```bash
curl "http://localhost:8000/api/scans/abc123/source?path=src/api/db.py" \
  -H "Authorization: Bearer $TOKEN"
# {"path":"src/api/db.py","truncated":false,"size":1234,"content":"..."}
```

경로 탈출(`../`) 차단, 512KB 상한, 큰 파일은 `truncated:true` 로 잘라서 반환.
스캔 작업 디렉터리가 정리된 경우 410 Gone.

### 19.10 감사 로그

자동 기록되는 액션(샘플):
- `auth.login`, `auth.login_failed`
- `finding.status_change` (이전/이후 상태, 사유, scan_id, rule_id)
- `suppression.create`, `suppression.delete`

```bash
curl "http://localhost:8000/api/admin/audit?action=finding.status_change&limit=50" \
  -H "Authorization: Bearer $TOKEN"
```

권한: `admin` 만 조회 가능. 모든 엔트리에 user_id, IP, timestamp, 상세 JSON 포함.

### 19.11 다중 표준 레퍼런스

`/api/mois/items` 와 `/api/findings/*` 응답의 `references[]` 필드:

```json
[
  {"standard": "CWE", "id": "CWE-89", "title": "CWE-89", "url": "https://cwe.mitre.org/.../89.html"},
  {"standard": "OWASP-2021", "id": "A03", "title": "Injection", "url": "https://owasp.org/Top10/A03_2021-Injection/"},
  {"standard": "SANS-25", "id": "#3", "title": "SANS/CWE Top 25 #3", "url": "https://www.sans.org/top25-software-errors/"},
  {"standard": "PCI-DSS-4.0", "id": "6.2.4", "title": "PCI DSS v4.0 §6.2.4", "url": "https://www.pcisecuritystandards.org/"}
]
```

CWE → OWASP/SANS/PCI 매핑은 `opensast/mois/references.py` 단일 소스에서 관리되며
새 표준을 추가할 때 이 파일만 수정하면 모든 응답에 자동 반영된다. 또한 사용자
YAML 오버레이(§20.2) 로 **코드 수정 없이** KISA-KSG, ISO 27001 등을 추가할 수
있다.

---

## 관측성

v0.5.0에서 Prometheus 메트릭, OpenTelemetry 분산 트레이싱, 구조화 JSON 로깅이
추가되었다.

### 21.1 Prometheus 메트릭

`GET /metrics` 엔드포인트가 Prometheus text format으로 메트릭을 노출한다.

수집되는 주요 메트릭:
- `aisast_http_requests_total` — HTTP 요청 수 (method, path, status)
- `aisast_http_request_duration_seconds` — 요청 지연 시간 히스토그램
- `aisast_scans_total` — 스캔 실행 수 (status)
- `aisast_findings_total` — 탐지 건수 (severity)

Prometheus scrape 설정 예시:

```yaml
scrape_configs:
  - job_name: opensast
    static_configs:
      - targets: ['api:8000']
    metrics_path: /metrics
```

### 21.2 OpenTelemetry 트레이싱

환경변수로 활성화:

```bash
OPENSAST_OTEL_ENABLED=true
OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4317
```

활성화 시 HTTP 요청, Celery 태스크, LLM 호출, DB 쿼리에 span이 자동 부착된다.
Jaeger, Tempo 등 OTLP 호환 백엔드로 수집 가능.

### 21.3 구조화 로깅

```bash
OPENSAST_LOG_FORMAT=json
```

`json` 설정 시 모든 로그가 `{"timestamp":..., "level":..., "message":..., "extra":...}`
형태로 출력되어 ELK/Loki 등 로그 수집 파이프라인과 연동이 용이하다. 기본값은
`console`(사람이 읽기 좋은 형식).

### 21.4 Readiness Probe

`GET /ready` 는 DB 연결, Redis 연결, Celery broker ping을 모두 확인하고, 하나라도
실패하면 503을 반환한다. Kubernetes `readinessProbe`나 로드밸런서 헬스체크에 사용.

```yaml
# Kubernetes 예시
readinessProbe:
  httpGet:
    path: /ready
    port: 8000
  initialDelaySeconds: 5
  periodSeconds: 10
```

---

## 멀티테넌시

OpenSAST 는 **Organization(조직)** 단위로 데이터를 격리하는 멀티테넌시 모델을 지원한다.
하나의 OpenSAST 인스턴스에서 여러 팀이나 부서가 각자의 프로젝트/룰셋/감사로그를 독립적으로
관리할 수 있다.

### 22.1 Organization 모델

| 필드 | 타입 | 설명 |
|------|------|------|
| `id` | Integer (PK) | 자동 증가 ID |
| `slug` | String(120), unique | URL-safe 식별자 (예: `security-team`) |
| `name` | String(200) | 표시 이름 |
| `is_active` | Boolean | 비활성화 시 소속 사용자 접근 차단 |

### 22.2 조직 스코핑

다음 테이블에 `organization_id` FK가 추가된다:

- **users** -- 사용자가 소속된 조직
- **projects** -- 프로젝트별 조직 귀속. 조직 내에서 프로젝트 이름 유일
- **rule_sets** -- 조직별 체커 그룹
- **audit_logs** -- 조직별 감사 기록

서비스 계층(`BaseService._org_filter`)이 자동으로 현재 사용자의 `organization_id`에
맞는 레코드만 반환한다. `organization_id`가 None인 컨텍스트(슈퍼 관리자 등)는 전체
레코드를 조회할 수 있다.

### 22.3 JWT 토큰

로그인 시 발급되는 JWT에 `org_id` 클레임이 포함된다:

```json
{
  "sub": "user@example.com",
  "role": "analyst",
  "org_id": 1,
  "exp": 1745000000,
  "iat": 1744900000,
  "jti": "abc123...",
  "type": "access",
  "iss": "opensast",
  "aud": "opensast"
}
```

### 22.4 Organization CRUD API

| 메서드 | 경로 | 권한 | 설명 |
|--------|------|------|------|
| `POST` | `/api/organizations` | admin | 조직 생성 |
| `GET` | `/api/organizations` | 인증됨 | 조직 목록 |
| `GET` | `/api/organizations/{org_id}` | 인증됨 | 조직 상세 |

**조직 생성 예시:**

```bash
curl -X POST http://localhost:8000/api/organizations \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"slug": "security-team", "name": "Security Team"}'
```

### 22.5 Alembic 마이그레이션

`0003_multitenancy` 마이그레이션이 기존 데이터를 `default-org` 조직(id=1)에 자동
할당한다. 업그레이드 시 기존 데이터 유실 없이 멀티테넌시로 전환된다.
