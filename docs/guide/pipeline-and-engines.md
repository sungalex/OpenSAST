# 분석 파이프라인과 엔진

> 이 문서는 `docs/USER_GUIDE.md`(1,926줄 단일 파일)를 독자별로 분할한 것이다
> ([ADR-0007](../adr/0007-documentation-architecture.md)).

---

## 분석 파이프라인

`opensast.orchestrator.pipeline.ScanPipeline` 이 메인 오케스트레이터다.

```
[소스 루트]
     │
     ▼
┌────────────────────────────┐
│ 1차 Pass (고속 패턴 매칭)   │
│ opengrep / bandit /         │
│ eslint  / gosec             │
└──────────────┬─────────────┘
               ▼
┌────────────────────────────┐
│ 2차 Pass (심층 시맨틱)      │
│ codeql / spotbugs           │
└──────────────┬─────────────┘
               ▼
   merge_findings() 중복 제거
               │
               ▼
┌────────────────────────────┐
│ 3단계 LLM Triage            │
│ Triager.triage()            │
│  → TriageResult 부착(원본   │
│     Finding은 보존)         │
└──────────────┬─────────────┘
               ▼
           ScanResult
```

### 핵심 포인트

- **엔진 바이너리가 없으면 스킵**: `EngineUnavailable` 예외를 파이프라인이 잡아서 해당 엔진만 제외한다. 설치된 엔진 조합만으로도 동작한다.
- **원본 보존**: LLM이 오탐으로 판정해도 Finding은 삭제되지 않으며, `triage.verdict`만 설정된다. 이는 계획서의 리스크 대응 원칙("LLM은 필터링(제거)에만 사용하지 않는다")을 강제한다.
- **중복 제거**: `opensast.sarif.merge.merge_findings()`는 `finding_id`(해시) 및 `(파일, 라인, CWE)` 조합을 키로 사용하며, `_ENGINE_PRIORITY`에 따라 우선 엔진을 남긴다. 동일 위치에서 중복 시 severity가 더 높은 쪽을 유지한다(v0.5.0에서 LOW가 MEDIUM을 이기던 비교 버그 수정).
- **2nd Pass 조건**: `--engines` 로 엔진을 명시 지정해도 그 안에 `codeql`/`spotbugs`가 포함되면 2nd pass가 실행된다.
- **Celery 견고성**: 태스크별 `autoretry_for`/`retry_backoff` 설정, `soft_time_limit`/`time_limit` 분리, Redis pubsub 기반 진행률 추적이 v0.5.0에서 추가되었다.

---

## 분석 엔진 상세

`opensast/engines/` 하위에 각 어댑터가 구현되어 있다. 공통 인터페이스는
`Engine` 추상 클래스(`engines/base.py`)이며, 모두 SARIF 출력을 받아
`findings_from_sarif()`로 도메인 모델로 변환한다.

| 엔진 | 클래스 | 언어 | Pass | 실행 방식 |
|------|--------|------|------|-----------|
| **Opengrep/Semgrep** | `OpengrepEngine` | Java, Python, JS/TS, Go, PHP, Ruby, … | 1차 | `semgrep scan --config rules/opengrep --sarif-output …` |
| **Bandit** | `BanditEngine` | Python | 1차 | `bandit -r <root> -f sarif` |
| **ESLint** | `EslintEngine` | JS/TS | 1차 | `eslint --format @microsoft/eslint-formatter-sarif` |
| **gosec** | `GosecEngine` | Go | 1차 | `gosec -fmt=sarif ./...` (cwd=소스 루트) |
| **SpotBugs + FindSecBugs** | `SpotbugsEngine` | Java, Kotlin, Scala | 2차 | `.class` 디렉터리 존재 시 `spotbugs -sarif -output …` |
| **CodeQL** | `CodeqlEngine` | Java, Kotlin, Python, JS/TS, Go, C/C++ | 2차 | `codeql database create` → `codeql database analyze <pack>` |

### 7.1 엔진 설치

**엔진은 OpenSAST 에 번들되지 않는다.** 각 바이너리를 직접 설치해야 하며,
`shutil.which(<바이너리>)` 로 PATH 에서 찾는다. 설치돼 있지 않은 엔진은
`EngineUnavailable` 로 **건너뛰고**, 건너뛴 사실은 `ScanResult.notes` 에 남는다
— 스캔이 실패하지는 않지만 해당 언어의 결과가 비게 된다.

현재 상태 확인:

```bash
opensast engines
```

#### macOS (Homebrew)

```bash
brew install semgrep      # opengrep 엔진이 찾는 바이너리 이름이 'semgrep' 이다
pip install "bandit[sarif]"
npm install -g eslint @microsoft/eslint-formatter-sarif
brew install gosec
brew install spotbugs     # openjdk 의존
```

#### Linux (Debian/Ubuntu)

```bash
pip install semgrep "bandit[sarif]"
npm install -g eslint @microsoft/eslint-formatter-sarif
go install github.com/securego/gosec/v2/cmd/gosec@latest   # $GOPATH/bin 이 PATH 에 있어야 한다
# SpotBugs 는 배포판 패키지가 없으므로 릴리스 tarball 을 받아 bin/ 을 PATH 에 추가한다
```

#### 바이너리 이름 바꾸기

기본값은 `config.py` 의 `*_bin` 필드다 (`opengrep_bin` 기본값이 `semgrep` 인 것도
여기서 온다). Opengrep 포크를 따로 설치했다면:

```bash
export OPENSAST_OPENGREP_BIN=opengrep
```

같은 방식으로 `OPENSAST_BANDIT_BIN` · `OPENSAST_ESLINT_BIN` · `OPENSAST_GOSEC_BIN` ·
`OPENSAST_SPOTBUGS_BIN` · `OPENSAST_CODEQL_BIN` 을 지정할 수 있다.

#### CodeQL — 설치 전에 라이선스를 확인할 것

CodeQL 은 Homebrew 포뮬러가 없고, GitHub CLI 확장(`gh extension install
github/gh-codeql`) 또는 CodeQL CLI 번들을 직접 받아 설치한다.

> ⚠️ **CodeQL 은 "공개 비상업 오픈소스 프로젝트에 한해 무료"** 라는 GitHub
> 라이선스 제약이 있다. 공공기관·감리 업무 등 **상업적 진단에 사용하려면 GitHub
> Advanced Security 라이선스가 필요하다.** 이 제약 때문에
> [ADR-0001](../adr/0001-unified-analysis-pipeline.md) 은 CodeQL 을 제거하고
> Joern 으로 대체할 것을 제안했고(현재 Proposed), 버전 고정 전략은
> [ADR-0002](../adr/0002-joern-version-pinning.md) 에 있다. 아직 코드에는 CodeQL
> 어댑터가 남아 있으므로, 상업 사용 시에는 CodeQL 을 켜지 않는 편이 안전하다.

#### Docker 이미지에 들어 있는 것

`docker compose up` 으로 띄워도 엔진이 전부 생기지는 않는다. 현재 `Dockerfile` 이
설치하는 것은 **semgrep 과 bandit 둘뿐**이다.

```dockerfile
RUN pip install --no-cache-dir "semgrep>=1.70" "bandit[sarif]>=1.7"
```

gosec · SpotBugs · CodeQL 을 포함한 이미지(`opensast:X.Y-full`)는
[`ROADMAP.md`](../ROADMAP.md) 의 미구현 항목이다. 그전까지 Java·Go 진단은 로컬
설치 또는 이미지 커스터마이즈가 필요하다.

### 7.2 등록·선택

- `opensast/engines/registry.py` 의 `ENGINE_CLASSES`, `FIRST_PASS_ENGINES`, `SECOND_PASS_ENGINES` 가 단일 출처다.
- `available_engines()` 는 바이너리 존재 여부를 확인하여 CLI `opensast engines`에서 표시된다.

### 7.3 SpotBugs 특이사항

SpotBugs는 바이트코드 분석기이므로 `.class` 디렉터리가 필요하다.
`build/classes`, `target/classes`, `out/production` 중 존재하는 것을 자동 탐색하며,
하나도 없으면 로그만 남기고 결과는 빈 리스트로 돌려준다.

### 7.4 CodeQL 특이사항

- 소스 루트에 `pom.xml`/`build.gradle`·`pyproject.toml`·`package.json`·`go.mod`·`CMakeLists.txt` 가 있는지로 언어를 자동 감지한다.
- 사용 쿼리팩: `codeql/java-queries`, `codeql/python-queries`, `codeql/javascript-queries`, `codeql/go-queries`, `codeql/cpp-queries`.
- `rules/codeql/<language>/` 디렉터리에 사용자 쿼리가 있으면 `codeql database analyze` 호출에 함께 전달된다.

---
