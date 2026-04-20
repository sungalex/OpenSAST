# openSAST 기여 가이드

openSAST 프로젝트에 관심을 가져주셔서 감사합니다. 이 문서는 프로젝트에 기여하는 방법을 안내합니다.

## 목차

- [개발 환경 설정](#개발-환경-설정)
- [코드 스타일](#코드-스타일)
- [커밋 메시지 규칙](#커밋-메시지-규칙)
- [PR 프로세스](#pr-프로세스)
- [Opengrep 룰 작성 가이드](#opengrep-룰-작성-가이드)
- [엔진 플러그인 작성 가이드](#엔진-플러그인-작성-가이드)
- [테스트 실행 방법](#테스트-실행-방법)

---

## 개발 환경 설정

### 사전 요구사항

- Python 3.12 이상
- Node.js 20 이상 (프론트엔드 개발 시)
- Docker & Docker Compose (통합 테스트 시)
- Git

### 백엔드 설정

```bash
# 저장소 클론
git clone https://github.com/sungalex/openSAST.git
cd openSAST

# 가상환경 생성 및 활성화
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 개발 의존성 포함 설치
pip install -e '.[dev]'

# 분석 엔진 설치 (선택)
pip install "semgrep>=1.70" "bandit[sarif]>=1.7"
```

### 프론트엔드 설정

```bash
cd frontend
npm install
npm run dev   # 개발 서버 시작 (http://localhost:5173)
```

### 시스템 의존성 (WeasyPrint PDF 리포트용)

**Ubuntu/Debian:**
```bash
sudo apt-get install -y libpango-1.0-0 libpangoft2-1.0-0 libcairo2 shared-mime-info
```

**macOS:**
```bash
brew install pango cairo libffi
```

---

## 코드 스타일

### Python (백엔드)

- **린터/포매터**: [ruff](https://docs.astral.sh/ruff/) 사용
  ```bash
  ruff check opensast        # 린트 검사
  ruff format opensast       # 코드 포매팅
  ```
- **타입 체크**: [mypy](https://mypy.readthedocs.io/) 사용 (점진 도입 중)
  ```bash
  mypy opensast --ignore-missing-imports
  ```
- **주요 규칙**:
  - 라인 길이: 120자
  - 타입 힌트 권장 (새 코드에는 필수)
  - docstring은 Google 스타일

### TypeScript (프론트엔드)

- **ESLint + Prettier** 설정이 `frontend/` 디렉토리에 포함되어 있습니다.
- `npx tsc -b --noEmit` 으로 타입 체크를 수행합니다.

---

## 커밋 메시지 규칙

[Conventional Commits](https://www.conventionalcommits.org/) 규칙을 따릅니다.

### 형식

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

### 타입

| 타입 | 설명 |
|------|------|
| `feat` | 새로운 기능 추가 |
| `fix` | 버그 수정 |
| `docs` | 문서 수정 |
| `style` | 코드 스타일 변경 (기능 변경 없음) |
| `refactor` | 리팩토링 |
| `test` | 테스트 추가/수정 |
| `chore` | 빌드, CI, 의존성 등 기타 변경 |
| `perf` | 성능 개선 |
| `ci` | CI 설정 변경 |

### 예시

```
feat(rules): MOIS SR2-3 하드코딩된 비밀번호 탐지 룰 추가
fix(api): 대용량 SARIF 파일 업로드 시 타임아웃 해결
docs: CONTRIBUTING.md 작성
ci: pip-audit 및 mypy 스텝 추가
```

---

## PR 프로세스

1. **이슈 확인**: 작업 전 관련 이슈가 있는지 확인하고, 없으면 새로 생성합니다.
2. **브랜치 생성**: `feat/`, `fix/`, `docs/` 등의 접두사를 사용합니다.
   ```bash
   git checkout -b feat/new-rule-sr1-5
   ```
3. **변경 사항 구현**: 코드 스타일을 준수하고 테스트를 추가합니다.
4. **로컬 테스트**: CI와 동일한 테스트를 로컬에서 실행합니다.
   ```bash
   pytest -q --tb=short
   cd frontend && npm test
   ```
5. **PR 생성**: 명확한 제목과 설명을 작성합니다.
   - 관련 이슈 번호를 `Closes #123` 형식으로 링크합니다.
   - 변경 사항의 목적과 영향을 설명합니다.
6. **코드 리뷰**: 최소 1명의 리뷰어 승인이 필요합니다.
7. **CI 통과**: 모든 CI 체크가 통과해야 머지 가능합니다.

---

## Opengrep 룰 작성 가이드

openSAST의 Opengrep(Semgrep) 커스텀 룰은 `rules/` 디렉토리에 YAML 형식으로 작성합니다.

### 필수 메타데이터

모든 룰에는 다음 MOIS 메타데이터가 **필수**입니다:

```yaml
rules:
  - id: mois-<cwe-short-name>-<variant>
    metadata:
      mois_id: "SR1-1"          # MOIS 보안약점 ID (필수)
      cwe: "CWE-89"             # CWE 번호 (필수)
      category: "입력데이터 검증 및 표현"  # MOIS 7대 분류
      severity: "HIGH"          # HIGH / MEDIUM / LOW
      confidence: "HIGH"        # HIGH / MEDIUM / LOW
      description: "MyBatis 환경에서의 SQL 인젝션"
    patterns:
      - pattern: |
          $MAPPER.select(..., $INPUT, ...)
    message: |
      사용자 입력값이 SQL 쿼리에 직접 삽입됩니다.
      파라미터 바인딩(#{})을 사용하세요.
    languages: [java]
    severity: ERROR
```

### 룰 작성 시 주의사항

- `id`는 `mois-` 접두사로 시작합니다.
- `mois_id`는 MOIS 49개 보안약점 항목 ID와 일치해야 합니다.
- 룰 테스트 파일을 `rules/tests/` 에 함께 추가합니다.
- 오탐율을 줄이기 위해 `pattern-not`, `pattern-inside` 등의 세부 패턴을 적극 활용합니다.

### 룰 테스트

```bash
# 특정 룰 테스트
semgrep --config rules/your-rule.yml tests/fixtures/

# 전체 룰 유효성 검사
semgrep --validate --config rules/
```

---

## 엔진 플러그인 작성 가이드

openSAST는 플러그인 아키텍처로 분석 엔진을 확장할 수 있습니다.

### 플러그인 구조

새 엔진 플러그인은 `opensast/plugins/` 디렉토리에 작성합니다:

```python
# opensast/plugins/my_engine.py
from opensast.plugins.base import EnginePlugin, ScanResult

class MyEnginePlugin(EnginePlugin):
    """커스텀 분석 엔진 플러그인."""

    name = "my-engine"
    supported_languages = ["python", "java"]

    def scan(self, target_path: str, **kwargs) -> list[ScanResult]:
        # 분석 로직 구현
        ...

    def is_available(self) -> bool:
        # 엔진 설치 여부 확인
        ...
```

### entry_points 등록

`pyproject.toml`에 플러그인을 등록합니다:

```toml
[project.entry-points."opensast.engines"]
my-engine = "opensast.plugins.my_engine:MyEnginePlugin"
```

### 플러그인 요구사항

- `EnginePlugin` 베이스 클래스를 상속해야 합니다.
- `scan()` 메서드는 표준 `ScanResult` 리스트를 반환해야 합니다.
- `is_available()` 메서드로 엔진 설치 여부를 확인할 수 있어야 합니다.
- SARIF 호환 결과 포맷을 지원해야 합니다.

---

## 테스트 실행 방법

### 백엔드 테스트

```bash
# 전체 테스트 실행
pytest -q --tb=short

# 커버리지 포함 실행
pytest -q --tb=short --cov=opensast --cov-report=term-missing

# 특정 테스트 파일 실행
pytest tests/test_api.py -v

# 특정 테스트 함수 실행
pytest tests/test_api.py::test_health_endpoint -v
```

### 프론트엔드 테스트

```bash
cd frontend

# 전체 테스트 실행
npm test

# 워치 모드
npm run test:watch
```

### MOIS 49개 항목 검증

```bash
python -c "from opensast.mois import MOIS_ITEMS; assert len(MOIS_ITEMS) == 49"
```

---

## 질문이 있으신가요?

- [GitHub Issues](https://github.com/sungalex/openSAST/issues)에 질문을 남겨주세요.
- 보안 취약점 관련은 [SECURITY.md](./SECURITY.md)를 참조해주세요.

감사합니다!
