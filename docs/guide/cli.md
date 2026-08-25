# CLI 레퍼런스

> 이 문서는 `docs/USER_GUIDE.md`(1,926줄 단일 파일)를 독자별로 분할한 것이다
> ([ADR-0007](../adr/0007-documentation-architecture.md)).

---

## CLI 레퍼런스

설치 후 `opensast` 명령이 제공된다(`pyproject.toml` 의 `[project.scripts]`).

### 4.1 `opensast scan`

디렉터리를 스캔하고 SARIF 결과를 저장한다.

```bash
opensast scan <PATH> [OPTIONS]
```

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `-o, --output` | `opensast-result.sarif` | SARIF 출력 경로 |
| `--json` | *(없음)* | 도메인 JSON 추가 출력 |
| `--second-pass/--no-second-pass` | `true` | CodeQL/SpotBugs 2차 Pass |
| `--triage/--no-triage` | `true` | LLM 오탐 필터링 |
| `--language` | 자동 감지 | 언어 힌트(`java`, `python`, …) |

**예시**

```bash
# 1차 Pass만, LLM 비활성
opensast scan ./my-service --no-second-pass --no-triage

# 전체 Pass + JSON 덤프
opensast scan ./my-service --json result.json
```

스캔 완료 후 Rich 테이블로 **엔진별 / MOIS ID별 탐지 건수**를 출력한다.

### 4.2 `opensast list-mois`

행안부 49개 항목을 ID·한글명·분류·CWE·심각도 표로 출력한다. 카탈로그 자가진단용
로도 사용되며, 항목이 49개가 아니면 예외를 발생시킨다.

### 4.3 `opensast engines`

`rules/opengrep`, `semgrep`, `bandit`, `eslint`, `gosec`, `spotbugs`, `codeql` 바이너리가
PATH에 존재하는지 표시한다.

### 4.4 `opensast init-db`

DB 스키마를 생성하고 기본적으로 부트스트랩 관리자를 시드한다.

```bash
opensast init-db                   # 스키마 + admin 시드
opensast init-db --no-seed-admin   # 스키마만
```

### 4.5 `opensast serve`

내장 Uvicorn으로 API 서버를 실행한다.

```bash
opensast serve --host 0.0.0.0 --port 8000 --reload
```

### 4.6 `opensast report`

이미 생성된 SARIF 파일에서 HTML/Excel 리포트를 변환한다(DB 없이 동작).

```bash
opensast report result.sarif --html out.html --excel out.xlsx
```

---
