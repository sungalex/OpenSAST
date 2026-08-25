# REST API

> 이 문서는 `docs/USER_GUIDE.md`(1,926줄 단일 파일)를 독자별로 분할한 것이다
> ([ADR-0003](../adr/0003-documentation-architecture.md)).

> **정본 주의**
>
> **정본은 OpenAPI 스키마다.** 서버를 띄우고 `/docs`(Swagger) 또는
> `/openapi.json` 을 보라 — 수기 명세는 필연적으로 코드와 어긋난다.
> cloud 프로파일에서는 docs 가 비활성이므로 개발/도커 프로파일에서 확인한다.
> 아래는 엔드포인트 지도와 인증 방법 등 스키마가 담지 못하는 맥락이다.

---

## REST API 레퍼런스

FastAPI 앱은 `opensast.api.app:app`에서 제공되며 OpenAPI는 `/docs`에서 확인할 수 있다.

### 5.1 공용

| 메서드 | 경로 | 설명 |
|--------|------|------|
| GET | `/health` | 헬스체크 |
| GET | `/ready` | 레디니스 프로브 (DB + Redis + Celery broker ping) |
| GET | `/metrics` | Prometheus 메트릭 (요청 수, 지연시간, 스캔 통계) |

### 5.2 인증 (`/api/auth`)

| 메서드 | 경로 | 설명 | 역할 |
|--------|------|------|------|
| POST | `/api/auth/login` | 이메일·비밀번호로 JWT 발급 | public |
| POST | `/api/auth/refresh` | Refresh token으로 새 토큰 쌍 발급 | 인증 필요 |
| POST | `/api/auth/users` | 사용자 생성 | `admin` |

**로그인 요청/응답**

```http
POST /api/auth/login
{ "email": "admin@opensast.local", "password": "opensast-admin" }

200 { "access_token": "eyJ...", "refresh_token": "eyJ...", "token_type": "bearer", "role": "admin" }
```

**토큰 갱신**

```http
POST /api/auth/refresh
Authorization: Bearer <refresh_token>

200 { "access_token": "eyJ...", "refresh_token": "eyJ...", "token_type": "bearer", "role": "admin" }
```

인증은 `Authorization: Bearer <token>` 헤더로 수행된다.

### 5.3 프로젝트 (`/api/projects`)

| 메서드 | 경로 | 설명 |
|--------|------|------|
| GET | `/api/projects` | 프로젝트 목록 |
| POST | `/api/projects` | 프로젝트 생성 |
| GET | `/api/projects/{project_id}` | 단일 조회 |

### 5.4 스캔 (`/api/scans`)

소스 코드 지정 3가지 모드를 모두 지원한다.

| 메서드 | 경로 | 설명 |
|--------|------|------|
| POST | `/api/scans` | **서버 경로 모드** — api/worker 가 이미 볼 수 있는 파일시스템 절대경로 |
| POST | `/api/scans/upload` | **ZIP 업로드 모드** — multipart `.zip` 업로드 후 자동 압축 해제 |
| POST | `/api/scans/git` | **Git URL 모드** — worker 가 `git clone --depth=1` 후 스캔 |
| GET | `/api/scans/{scan_id}` | 상태·결과 메타데이터 |
| GET | `/api/scans/{scan_id}/events` | SSE 실시간 스캔 진행 스트리밍 |
| GET | `/api/scans/project/{project_id}` | 프로젝트의 스캔 목록 |

**① 서버 경로 요청 (기존)**

```json
POST /api/scans
{
  "project_id": 1,
  "source_path": "/var/opensast-work/sources/my-service",
  "language_hint": "java",
  "enable_second_pass": true,
  "enable_triage": true
}
```

Docker 구성에서 api·worker 컨테이너는 named volume `opensast-work` 를
`/var/opensast-work` 에 공유 마운트하므로 업로드·clone 모드로 만들어진 경로를
동일하게 재사용할 수 있다.

**② ZIP 업로드 (multipart/form-data)**

```bash
curl -X POST http://localhost:8000/api/scans/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "project_id=1" \
  -F "language_hint=python" \
  -F "enable_second_pass=false" \
  -F "enable_triage=false" \
  -F "archive=@./my-service.zip"
```

- 최대 업로드 크기 500 MiB (`_MAX_UPLOAD_BYTES`)
- 확장자는 `.zip` 만 허용
- 압축 해제 시 **zip-slip** 방지 검증(엔트리 경로가 대상 디렉터리를 벗어나면 400)
- 풀린 경로는 `settings.work_dir/sources/<scan_id>/` 이며 스캔 완료 후 디스크에
  남는다 (수동 정리 필요)

**③ Git URL**

```json
POST /api/scans/git
{
  "project_id": 1,
  "git_url": "https://github.com/OWASP/NodeGoat.git",
  "branch": "master",
  "enable_second_pass": true,
  "enable_triage": true
}
```

- URL 스킴 허용: `http://`, `https://`, `ssh://`, `git@…`
- `branch` 미지정 시 원격 기본 브랜치
- `clone_and_scan_task` 가 `git clone --depth 1` 으로 체크아웃 후 스캔, **스캔
  종료 후 체크아웃 디렉터리를 자동 정리**한다 (결과는 DB 에 영구 저장).

**④ SSE 실시간 진행 스트리밍 (v0.5.0)**

```bash
curl -N http://localhost:8000/api/scans/abc123def456/events \
  -H "Authorization: Bearer $TOKEN"
```

`text/event-stream` 으로 스캔 진행 상태(엔진 시작/완료, triage 진행, 최종 결과)를
실시간 스트리밍한다. 프론트엔드에서 `EventSource` 로 구독하여 진행률 바를
업데이트할 수 있다.

### 5.5 Finding (`/api/findings`)

| 메서드 | 경로 | 설명 |
|--------|------|------|
| GET | `/api/findings/scan/{scan_id}` | 스캔의 모든 탐지 결과 |
| GET | `/api/findings/{finding_id}` | 단일 Finding |

### 5.6 리포트 (`/api/reports`)

| 메서드 | 경로 | Content-Type |
|--------|------|---------------|
| GET | `/api/reports/{scan_id}/sarif` | `application/sarif+json` |
| GET | `/api/reports/{scan_id}/html` | `text/html` |
| GET | `/api/reports/{scan_id}/excel` | `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` |

### 5.7 MOIS 카탈로그 (`/api/mois`)

| 메서드 | 경로 | 설명 |
|--------|------|------|
| GET | `/api/mois/items` | 49개 항목 목록(ID, 한글명, 분류, CWE, 심각도, 권장 엔진) |

---
