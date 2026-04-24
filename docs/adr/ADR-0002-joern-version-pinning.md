# ADR-0002: Joern 엔진 버전 고정 전략

- 상태(Status): **Proposed** — Phase 3 킥오프 주(T+9)에 최종 버전 확정 시 **Accepted** 로 전환
- 작성일: 2026-04-24
- 작성자: OpenSAST 엔진 유지보수 팀
- 관련 문서:
  - [ADR-0001 — 2-Pass 분석 파이프라인 단일 오케스트레이션 통합 (rev.2)](./ADR-0001-unified-analysis-pipeline.md)
  - [ADR-0004 — SAST 엔진 버전 거버넌스 3-Tier 정책](./ADR-0004-engine-version-governance.md)
  - [UPGRADE-PLAN-unified-analysis.md §6](../plan/UPGRADE-PLAN-unified-analysis.md)
  - [ROADMAP.md §8](../ROADMAP.md)

### 변경 이력

- v1 (2026-04-24): 초안. Phase 3 킥오프 시점에 v2.0.x 최신 stable 패치를 선정·고정하는 정책 수립. 구체 버전·SHA256 은 T+9 결정 시 본 문서에 후속 커밋.

## 1. 맥락 (Context)

[ADR-0001 rev.2](./ADR-0001-unified-analysis-pipeline.md) 에서 CodeQL 을 GitHub Advanced Security 라이선스 리스크로 제거하고, 다국어 인터프로시저 테인트 분석을 **Joern (Apache-2.0)** 으로 대체하기로 결정했다. 본 ADR 은 Joern 바이너리의 버전 선정·고정·업그레이드 절차를 정의한다.

Joern 은 다른 어떤 엔진보다도 **버전 고정의 엄격성이 중요한 엔진**이다. 세 가지 이유가 있다.

첫째, **CLI 와 Scala DSL 의 빈번한 마이너 breaking change** — `joern-scan --overlay-dir` → `--overlays`, `joern-export --repr=findings` 출력 포맷 변경, `cpg.call.name` → `cpg.call.methodFullName` 같은 API 변경이 v2.0.x 라인 내에서도 여러 patch 사이에 발생한 이력이 있다. `rules/joern/**/*.sc` 스크립트는 이런 API 에 직접 의존하므로 버전 부동은 즉시 룰 오동작으로 이어진다.

둘째, **언어 프런트엔드(JavaSrc2CPG, PySrc2CPG, GoAstGenDumper 등)의 성숙도가 patch 별로 크게 다름** — 특히 Python/Go 프런트엔드는 v2.0 초반 patch 에서 CPG 빌드 실패가 빈번했고, 특정 patch 이후 안정화되었다. 임의 `latest` 사용은 지원 언어 커버리지의 비결정적 변동을 초래한다.

셋째, **공공부문 감리·감사 대응 요건** — OpenSAST 가 공공기관 납품될 때 "어느 스캔이 어느 엔진 버전으로 실행됐는가" 가 재현 가능한 증적이어야 한다. `>=2.0.0` 같은 느슨한 제약으로는 재현 불가능하며, 이는 행안부 「SW 보안약점 진단가이드」 준수상 수용 불가다.

현재 저장소에는 Joern 코드·룰이 전혀 없고 Phase 3 (T+9~T+13, 약 4주) 에 신규 도입된다. 이 ADR 은 도입과 동시에 적용될 거버넌스를 선언한다.

## 2. 결정 (Decision)

Joern 엔진은 [ADR-0004](./ADR-0004-engine-version-governance.md) 의 **Tier 1 (엄격 고정)** 정책을 적용한다. 구체 실행 규칙은 아래 §3~§7 에 명시한다.

### 2.1 버전 선정 기준 — 필수 5개 조건

다음 조건을 **모두** 만족하는 v2.0.x patch 중, 가장 최신 stable 을 선정한다.

1. **릴리스 후 최소 14일 경과** — 초기 릴리스 직후의 critical regression 관찰 기간 확보.
2. **JDK 21 경고 없이 기동** — OpenSAST 의 `Dockerfile.heavy` 는 `openjdk-21-jre-headless` 기반. `--enable-preview` 경고를 출력하는 patch 는 제외.
3. **5개 지원 언어(Java/Python/Go/JavaScript/TypeScript) CPG 빌드 성공률 100%** — `scripts/joern/select_version.py` 가 골든 픽스쳐 전수 돌려 검증.
4. **공개 CVE 없음** — GitHub Security Advisories + 의존성(sbt, ANTLR, Scala 라이브러리) CVE 이력 전수 조사 통과.
5. **직전 3개 patch 릴리스 노트에 CLI breaking change 없음** — 릴리스 노트를 수동 확인. 잦은 breaking 은 다음 patch 에도 리스크 높음 신호.

### 2.2 고정 메커니즘

- `.env.versions` 에 **정확한 버전 + SHA256 해시** 를 선언:
  ```env
  JOERN_VERSION=<확정-patch>
  JOERN_SHA256=<64자-hex>
  ```
- `Dockerfile.heavy` 의 `RUN curl ...` 명령이 SHA256 을 `sha256sum -c -` 로 검증. 불일치 시 빌드 실패.
- 이미지 빌드 시 `joern --version` 출력이 선언 버전과 일치하는지 확인 (릴리스 태그 오류 방지).
- 런타임에 `JOERN_VERSION` 환경변수를 컨테이너에 주입하고, `JoernEngine.run()` 이 `scan_engine_runs.metadata["joern_version"]` 으로 기록. 스캔별 실행 버전 추적이 감사 증빙에 사용된다.

### 2.3 업그레이드 흐름

- **Patch bump (2.0.X → 2.0.Y)** — Renovate 가 월요일 새벽 자동 PR 생성. CI 의 `joern-regression` 워크플로우(§5) 통과 + 사람 리뷰 1명 이상 승인 후 수동 머지. 자동 머지 금지.
- **Minor bump (2.0.x → 2.1.x)** — Renovate 비활성. 수동 PR + 별도 ADR(`ADR-NNNN-joern-minor-upgrade.md`) 필수. `rules/joern/` 호환성 일괄 점검과 스테이징 리허설 거친다.
- **Major bump (2.x → 3.x)** — Minor 와 동일 절차, 추가로 엔진 유지보수 팀 리드 + 보안팀 + 플랫폼 운영팀 3명 승인.

### 2.4 CVE 대응

- Renovate `vulnerabilityAlerts.enabled=true` 로 Advisory 수신 즉시 스케줄 무시 PR 생성.
- 보안 담당자가 24시간 내 `docs/security/cve-response/YYYY-MM-DD-CVE-XXX.md` 작성(심각도, 영향 범위, 임시 완화책).
- CI 회귀 게이트 통과 + 최소 2명 승인 시 48시간 내 긴급 릴리스(`v0.X.Y-security` 태그).
- 릴리스 후 플랫폼 운영자는 영향 범위 내 최근 30일 스캔을 자동 재스캔 대상으로 공지.

### 2.5 Joern 룰 스크립트 호환성 헤더

모든 `rules/joern/<lang>/<mois_id>.sc` 파일 상단에 호환 버전 주석을 의무화한다.

```scala
// rules/joern/java/sr1-1-sql-injection.sc
//
// Compatible-With: Joern >=2.0.XXX
// MOIS-ID: SR1-1
// CWE: CWE-89
// Last-Verified: 2026-06-XX (ADR-0002)
```

Minor/major 업그레이드 ADR 발행 시 이 헤더를 일괄 갱신하고, CI 의 `validate_rules.py` 가 선언 범위와 현재 `.env.versions` 가 호환되는지 검증한다.

## 3. 초기 버전 선정 절차 — Phase 3 킥오프 주(T+9)

선정은 해당 주에 반드시 완료되고, 그 결과로 본 ADR 의 상태가 **Accepted** 로 전환되며 구체 버전·SHA256 값이 §3.4 에 기록된다.

### 3.1 T+9 화요일

`scripts/joern/select_version.py` 실행 → `joernio/joern` GitHub Releases 에서 §2.1 조건 충족 candidate 최대 5개 추출. 결과를 `docs/plan/joern-version-selection.md` 에 커밋.

### 3.2 T+9 수요일

각 candidate 에 대해:
```bash
JOERN_VERSION=<ver> JOERN_SHA256=<hash> docker build -f Dockerfile.heavy -t opensast:heavy-test .
docker run --rm opensast:heavy-test joern --version
docker run --rm -v ./tests/fixtures/vulnerable-samples:/scan:ro opensast:heavy-test \
    python /app/scripts/bench/run_joern_regression.py --fixtures /scan --out /tmp/result.json
```

### 3.3 T+9 목요일

Candidate 별 비교표 작성(`docs/plan/joern-version-selection.md` 갱신):

| 버전 | 이미지 크기 | 1k LOC 스캔 시간 | CPG 빌드 성공률 (5개 언어) | 골든 finding 일치 | CVE |
|---|---|---|---|---|---|

### 3.4 T+9 금요일 — 선정 결정

표에서 다음 우선순위로 선정:

1. **골든 일치율 ≥ 95%**
2. **CPG 빌드 성공률 100%**
3. **CVE 없음**
4. 동률이면 **이미지 크기 작은 쪽** 우선

선정 결과를 본 ADR 아래 §3.5 에 추가 기재하고, `.env.versions` 에 커밋.

### 3.5 선정 결과 (Placeholder — T+9 금요일에 채움)

```
JOERN_VERSION=<TBD>
JOERN_SHA256=<TBD>
선정 사유:
  - 골든 일치: <X>%
  - CPG 빌드 성공: 5/5 언어
  - CVE: 없음 (<조사일 YYYY-MM-DD>)
  - 이미지 크기: <X> MB
  - 직전 3개 patch breaking change 없음 확인
Candidate 비교표 전체 링크:
  docs/plan/joern-version-selection.md#<anchor>
```

## 4. 결정 근거 (Rationale)

### 4.1 왜 v2.0.x 라인인가

Joern 2.x 는 2024년 초부터 본격 안정화된 라인으로, 1.x 대비 Scala 3 기반 리팩터링·CPG 스키마 정비·언어 프런트엔드 통합이 완료된 상태다. 2026년 2분기 기준 커뮤니티 지원이 가장 활발하다. 3.x 는 아직 릴리스 이력 자체가 없거나 극초기라 안정성 판단 불가.

### 4.2 왜 "Phase 3 킥오프 시점의 최신 stable" 인가

고정된 특정 버전을 ADR 에 하드코드하면 T+9 전까지 나올 수 있는 critical 패치를 반영하지 못한다. 반대로 릴리스 시점에 수동으로 판단하면 재현 가능한 규칙이 없다. "T+9 에 §2.1 조건 기계적으로 적용해 선정" 은 둘 사이 절충이다.

### 4.3 왜 Renovate 를 쓰는가 — patch 만 자동

Renovate 는 GitHub Releases 감지·CVE 알림·PR 생성을 통합한다. Dependabot 에 비해 custom manager(§4 .env.versions regex)가 유연해 비-패키지 버전 선언을 다룰 수 있다. 자동 머지를 막은 것은 `rules/joern/*.sc` 의 회귀가 CI 에서 100% 감지되지 않을 가능성에 대한 보수적 대응이다.

### 4.4 왜 SHA256 을 검증하는가

`curl` 응답이 MITM 공격받거나 릴리스 아티팩트가 사후 수정되는 경우(GitHub 측 실수 포함)를 방어한다. 감사 관점에서 "다운로드된 바이너리가 릴리스 태그와 무결성 일치" 의 증거가 된다. 공공부문 공급망 보안 요건에도 부합한다.

## 5. 운영 (Operational)

### 5.1 CI 회귀 게이트 — `.github/workflows/joern-regression.yml`

`.env.versions` 또는 `rules/joern/**` 변경 PR 에서 자동 실행:

1. `docker build -f Dockerfile.heavy --build-arg JOERN_VERSION --build-arg JOERN_SHA256`
2. Version smoke: `joern --version` 출력이 선언 버전과 일치 확인
3. Golden fixture regression: `tests/fixtures/vulnerable-samples/` 전수 스캔 + `scripts/bench/assert_golden.py`
4. License check: `scripts/check_licenses.py` — Apache-2.0 whitelist
5. 성능 회귀: duration +20% 초과 시 실패

**핵심 불변식**:
- `must_detect_rules` 손실 금지 (Finding 탐지 손실 = 실패)
- 안전 샘플(`negative.*`)에서 FP 발생 시 실패
- 성능 +20% 이상 회귀 시 실패

### 5.2 `/api/system/engines` 노출

사용자·감사관이 현재 실행 중인 Joern 버전을 실시간 조회할 수 있다:

```json
GET /api/system/engines
{
  "joern": {
    "version": "2.0.XXX",
    "sha256": "abc123...",
    "license": "Apache-2.0",
    "versioning_tier": "strict",
    "last_upgraded": "2026-06-15"
  }
}
```

### 5.3 릴리스 노트 의무 기재

OpenSAST 릴리스마다 `CHANGELOG.md` 에 Joern 버전 변경 여부 섹션 명시:

```markdown
## [앱 0.7.1] - 2026-07-15
### Engine Versions
- Joern: 2.0.XXX (no change)
- Opengrep: 1.YYY.Z → 1.YYY.Z+1 (patch bump)
```

## 6. 결과 (Consequences)

### 6.1 긍정적

- **재현성 확보**: 특정 OpenSAST 릴리스와 Joern 버전의 1:1 매핑. 감리·감사 대응 시 "어느 스캔이 어느 분석 엔진으로 실행됐나" 를 부인 불가 증적으로 제공.
- **공급망 보안**: SHA256 검증으로 바이너리 무결성 보증.
- **룰-엔진 결합 안정**: `rules/joern/*.sc` 가 매주 깨지는 시나리오 차단.
- **CVE 대응 자동화**: 48시간 이내 긴급 패치 프로세스 표준화.

### 6.2 부정적

- **이미지 빌드 시간 증가**: SHA256 검증과 `joern --version` 스모크 테스트로 빌드당 ~30초 추가.
- **Renovate PR 리뷰 부담**: 월 1회 patch PR 수동 리뷰 필요. 엔진 유지보수 팀에 고정 업무 추가.
- **Minor/major 업그레이드 lag**: 새 버전 릴리스 후 ADR 절차로 인해 실제 도입까지 1~2주 소요. 기능적 이득 있어도 지연됨.

### 6.3 중립 — 수용된 트레이드오프

- **Renovate 외부 의존**: GitHub 호스팅 서비스 의존. 사내 대안(renovate self-hosted)으로 전환 가능하지만 Phase 3 시점에는 외부 서비스 그대로 사용.
- **Scala `.sc` 스크립트의 JIT warmup**: 컨테이너 기동 후 첫 스캔 30~60초 추가 지연. warmup 스크립트로 완화하지만 완전 제거 불가.

## 7. 대안 (Alternatives Considered)

### 7.1 `latest` 태그 사용
- **기각** — 재현성·감사 증빙 요건 전면 위배. 공공부문 배포 시 수용 불가.

### 7.2 Major 버전만 pin (`2.0.x` 와일드카드)
- **기각** — Joern minor patch 간에도 breaking change 이력 존재. 와일드카드는 사실상 pin 효과 없음.

### 7.3 Fork 후 사내 레지스트리 배포
- **기각** — 유지 비용 과다. 공공 온프레미스 환경은 공식 릴리스 zip 을 그대로 사용하되 SHA256 검증으로 무결성 확보가 현실적.

### 7.4 Joern 대신 Semgrep Pro (상용)
- **기각** — OpenSAST 는 오픈소스 SAST 목표. 상용 엔진 의존은 CodeQL 제거 결정(ADR-0001 rev.2)과 모순.

## 8. 참조

- Joern 공식 릴리스: https://github.com/joernio/joern/releases
- Joern 라이선스: Apache-2.0 — https://github.com/joernio/joern/blob/master/LICENSE
- Renovate 설정: `.github/renovate.json`
- 선정 스크립트: `scripts/joern/select_version.py` (Phase 3 T+9 전까지 구현)
- 회귀 게이트: `.github/workflows/joern-regression.yml`
- 골든 픽스쳐: `tests/fixtures/golden/joern_expectations.yaml`
