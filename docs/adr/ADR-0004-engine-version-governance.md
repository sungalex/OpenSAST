# ADR-0004: SAST 엔진 버전 거버넌스 3-Tier 정책

- 상태(Status): **Proposed** — Joern pilot(ADR-0002) 검증 후 Phase 4 초에 Opengrep 적용 시 **Accepted**
- 작성일: 2026-04-24
- 작성자: OpenSAST 엔진 유지보수 팀 · 보안팀
- 관련 문서:
  - [ADR-0001 — 2-Pass 파이프라인 단일 오케스트레이션 통합 (rev.2)](./ADR-0001-unified-analysis-pipeline.md)
  - [ADR-0002 — Joern 엔진 버전 고정 전략](./ADR-0002-joern-version-pinning.md)
  - [ROADMAP.md §3.1 R8/R9, §8 #5b](../ROADMAP.md)
  - [UPGRADE-PLAN-unified-analysis.md §6](../plan/UPGRADE-PLAN-unified-analysis.md)

### 변경 이력

- v1 (2026-04-24): 초안. ADR-0002 (Joern 특수 고정) 이 열어 놓은 "다른 엔진은 왜 방치되는가" 라는 질문에 대한 체계적 답변으로 수립. 3-Tier 정책과 엔진별 매핑을 정의.

## 1. 맥락 (Context)

ADR-0002 에서 Joern 에 엄격한 버전 고정·회귀 게이트·CVE 대응 프로세스를 적용하기로 결정했다. 그러나 현 저장소의 다른 SAST 엔진 의존성은 정반대 상태다. `Dockerfile:58` 을 보면:

```dockerfile
RUN pip install --no-cache-dir "semgrep>=1.70" "bandit[sarif]>=1.7"
```

이 한 줄은 다음 6가지 문제를 동시에 가지고 있다.

1. **상한 미설정 (`>=` 만)** — 어제 빌드는 Semgrep 1.70, 오늘 빌드는 1.120 가능. 재현성 완전 소실.
2. **SHA256 미검증** — PyPI 패키지 무결성 검증 없음. 공급망 공격 노출.
3. **릴리스별 고정 기록 없음** — OpenSAST v0.6.0 이 어느 Semgrep 으로 돌았는지 추적 불가. 감사 증빙 불가.
4. **버그 재현 불가** — 사용자가 "Opengrep 이 X 를 못 잡는다" 신고 시 어느 버전인지 확인 수단 없음.
5. **CVE 대응 체계 없음** — Semgrep/Bandit CVE 발생해도 자동 감지 없이 계속 운영 가능.
6. **룰-엔진 결합 검증 없음** — `rules/opengrep/*.yml` 이 새 Semgrep 과 호환되는지 CI 게이트 없음.

**Joern 에만 엄격한 거버넌스를 적용하면서 Opengrep(1차 Pass 주력 엔진) 이 무방비 상태인 것은 리스크 프로파일로 보면 본말이 전도된 설계다.** Opengrep 이 매 스캔에서 가장 많이 실행되는 엔진이고, MOIS 룰 93%(113개 룰) 가 Opengrep YAML 이며, Semgrep 의 룰 구문은 minor 버전 간에도 바뀐 전례가 있다(taint DSL 개편, ellipsis 의미 변경 등).

본 ADR 은 이 불일치를 해소하기 위해 **엔진별 리스크 프로파일에 따라 차등 적용되는 3-Tier 정책**을 수립한다. 모든 엔진을 Tier 1 엄격 고정으로 끌어올리는 것은 비경제적이고, 반대로 모두 Tier 3 유연 정책으로 내리면 ADR-0002 결정을 부정한다. 엔진 고유 특성에 비례한 통제를 설계하는 것이 본 ADR 의 핵심 기여다.

## 2. 결정 (Decision)

**엔진별 버전 관리 엄격도는 다음 3-Tier 로 차등 적용한다.** 각 Tier 는 "버전 고정 수준 · 자동화 허용 범위 · CI 게이트 요구 · ADR 발행 의무" 네 축에서 명확히 구분된다.

### 2.1 Tier 1 — 엄격 고정 (Strict Pinning)

- **대상**: Opengrep, Joern
- **버전 고정**: `.env.versions` 에 exact 버전 + SHA256. Dockerfile 에서 검증.
- **Renovate 정책**: patch 만 PR 자동 생성, **자동 머지 금지**. Minor/major 는 Renovate 비활성 — 수동 ADR 경로 강제.
- **CI 게이트**: 골든 픽스쳐 회귀 스위트 필수 통과. `must_detect_rules` 손실 금지, `forbidden_rules`(안전 샘플의 FP) 발생 금지, 성능 +20% 이상 회귀 금지.
- **전용 ADR**: 필수. Joern → ADR-0002, Opengrep → ADR-0002 와 동등한 후속 ADR(Phase 4 초 발행).
- **CVE 대응**: 24시간 내 긴급 PR → 48시간 내 패치 릴리스.
- **업그레이드 주기**: 월 1회 patch, minor/major 는 분기 단위 검토.

### 2.2 Tier 2 — 중간 (Moderate Pinning)

- **대상**: SpotBugs
- **버전 고정**: exact 버전 + SHA256. Tier 1 과 동일.
- **Renovate 정책**: patch 자동 머지 허용 (CI 통과 시), minor 는 PR 만 자동 생성 후 수동 승인.
- **CI 게이트**: **스모크 테스트** 수준 — 기동 성공 + 기본 detector 몇 개 실행 후 crash 없음 + SARIF 출력 유효성. 골든 회귀는 선택.
- **전용 ADR**: 선택. SpotBugs 는 Java EE 특화로 상대적으로 변동성이 낮아 minor bump 때 ADR 이 과한 경우 다수.
- **CVE 대응**: Tier 1 과 동일 절차.
- **업그레이드 주기**: 분기 1회.

### 2.3 Tier 3 — 유연 (Flexible Bounding)

- **대상**: Bandit, gosec
- **버전 고정**: **major 상한** 만 설정 (`"bandit[sarif]>=1.7,<2.0"`, `"gosec v2.19.x"`). SHA256 검증 없음.
- **Renovate 정책**: patch/minor 모두 자동 머지 (CI 통과 시). Major 는 Renovate 비활성.
- **CI 게이트**: 전용 게이트 불필요. 기존 전체 pytest 수트 통과로 충분.
- **전용 ADR**: 불필요.
- **CVE 대응**: 자동 머지 경로로 충분. 긴급 프로세스는 동일하게 가동하되 리뷰 부담 없음.
- **업그레이드 주기**: 2주 (Renovate 기본).

### 2.4 Tier 분류 근거 — 3축 평가

각 엔진을 **룰 결합도 × API/CLI 변동성 × OpenSAST 침투도** 3축으로 평가한 결과:

| 엔진 | 룰 결합도 | 변동성 | 침투도 | CVE 빈도 | 결정 Tier |
|---|---|---|---|---|---|
| Opengrep | 🔴 높음 (113개 YAML 룰) | 🟠 중간 (taint DSL/ellipsis 변경 이력) | 🔴 최고 (1차 Pass 주력) | 중간 | **Tier 1** |
| Joern | 🔴 높음 (19개 `.sc`) | 🔴 높음 (CPG API 변경 잦음) | 🟠 중간 (deep 프리셋 전용) | 낮음~중간 | **Tier 1** |
| SpotBugs | 🟡 중간 (표준 detector) | 🟢 낮음 (Java EE 안정) | 🟡 중간 | 낮음 | **Tier 2** |
| Bandit | 🟢 낮음 (내장 plugin) | 🟢 낮음 | 🟡 중간 (Python 전용) | 드묾 | **Tier 3** |
| gosec | 🟢 낮음 (내장 rule) | 🟢 낮음 | 🟢 낮음 (Go 전용) | 드묾 | **Tier 3** |
| ESLint | — | — | — | — | **삭제** (ADR-0001 rev.2) |
| CodeQL | — | — | — | — | **삭제** (ADR-0001 rev.2) |

축 정의:
- **룰 결합도**: OpenSAST 룰셋이 해당 엔진의 API·문법에 얼마나 의존하는가. 높을수록 엔진 업그레이드가 룰 호환성을 깰 위험.
- **API/CLI 변동성**: upstream 의 minor/patch 간 breaking change 빈도.
- **침투도**: OpenSAST 스캔에서 해당 엔진이 실행되는 비율. 높을수록 엔진 장애 시 영향 범위 넓음.

## 3. 구현 (Implementation)

### 3.1 단일 버전 선언 지점 — `.env.versions`

모든 엔진 버전을 한 파일로 집중:

```env
# .env.versions — 엔진 바이너리 버전 SSOT
# 수정은 Renovate PR 또는 ADR 기반 수동 PR 으로만 허용.
# CODEOWNERS 로 엔진 유지보수 팀 승인 필수.

# Tier 1 — 엄격 고정 + 골든 회귀 필수
OPENGREP_VERSION=1.XXX.Y
OPENGREP_SHA256=<64-hex>

JOERN_VERSION=2.0.XXX            # ADR-0002 Phase 3 T+9 에 확정
JOERN_SHA256=<64-hex>

# Tier 2 — 고정 + 스모크
SPOTBUGS_VERSION=4.8.X
SPOTBUGS_SHA256=<64-hex>

# Tier 3 — 범위 상한 (pip/go 가 해석)
BANDIT_SPEC="bandit[sarif]>=1.7,<2.0"
GOSEC_VERSION_RANGE="v2.19.x"
```

`Dockerfile` 은 ARG 로 주입받아 Tier 1/2 는 SHA256 검증, Tier 3 는 상한만 전달.

### 3.2 엔진 메타데이터 레지스트리

`opensast/engines/base.py` 를 확장해 각 엔진이 자신의 Tier·라이선스·upstream 을 자기기술:

```python
from enum import Enum
from dataclasses import dataclass

class VersioningTier(str, Enum):
    STRICT = "strict"           # Tier 1
    MODERATE = "moderate"       # Tier 2
    FLEXIBLE = "flexible"       # Tier 3

@dataclass(frozen=True)
class EngineMeta:
    name: str
    languages: tuple[str, ...]
    license: str                # SPDX identifier
    versioning_tier: VersioningTier
    upstream_repo: str          # "semgrep/semgrep", "joernio/joern"

class OpengrepEngine(Engine):
    meta = EngineMeta(
        name="opengrep",
        languages=("java", "python", "javascript", "typescript", "go", "php", "ruby"),
        license="LGPL-2.1",
        versioning_tier=VersioningTier.STRICT,
        upstream_repo="semgrep/semgrep",
    )
```

### 3.3 감사 API — `GET /api/system/engines`

사용자·감사관이 현재 실행 중인 엔진의 버전·라이선스·Tier 를 조회 가능:

```json
{
  "opengrep": {
    "version": "1.XXX.Y",
    "sha256": "abc...",
    "license": "LGPL-2.1",
    "versioning_tier": "strict",
    "upstream_repo": "semgrep/semgrep",
    "last_upgraded": "2026-05-12"
  },
  "bandit": {
    "spec": ">=1.7,<2.0",
    "actual_version": "1.7.9",
    "license": "Apache-2.0",
    "versioning_tier": "flexible",
    "upstream_repo": "PyCQA/bandit"
  }
}
```

스캔별 실제 사용 버전은 `scan_engine_runs.metadata` 에 기록되어 "어느 스캔이 어느 버전으로 실행됐나" 가 사후 조회 가능.

### 3.4 Renovate 설정

`.github/renovate.json` 에 Tier 별 규칙 분기:

```json
{
  "packageRules": [
    {
      "description": "Tier 1 — Opengrep/Joern: patch 만 PR, 자동 머지 금지",
      "matchFileNames": [".env.versions"],
      "matchDepNames": ["semgrep/semgrep", "joernio/joern"],
      "matchUpdateTypes": ["patch"],
      "automerge": false,
      "labels": ["engine:tier1", "needs-regression"]
    },
    {
      "description": "Tier 1 minor/major 차단",
      "matchDepNames": ["semgrep/semgrep", "joernio/joern"],
      "matchUpdateTypes": ["minor", "major"],
      "enabled": false
    },
    {
      "description": "Tier 2 — SpotBugs: patch 자동 머지",
      "matchDepNames": ["spotbugs/spotbugs"],
      "matchUpdateTypes": ["patch"],
      "automerge": true
    },
    {
      "description": "Tier 3 — Bandit/gosec: patch/minor 자동 머지",
      "matchPackageNames": ["bandit", "securego/gosec"],
      "matchUpdateTypes": ["patch", "minor"],
      "automerge": true,
      "automergeType": "pr"
    }
  ],
  "vulnerabilityAlerts": {
    "enabled": true,
    "labels": ["security", "priority:high"]
  }
}
```

### 3.5 CI 게이트 매트릭스

- `.github/workflows/engine-regression.yml` — `.env.versions` 변경 감지 후 Tier 1 엔진별로 골든 회귀 분기 실행. 변경되지 않은 엔진은 스킵.
- 기존 `.github/workflows/ci.yml` — Tier 2/3 는 여기에 흡수. 별도 게이트 불필요.

### 3.6 CVE 대응 — 전 Tier 공통

- Renovate `vulnerabilityAlerts.enabled=true` 로 GitHub Advisory 즉시 수신.
- Advisory 수신 후 24시간 내 `docs/security/cve-response/YYYY-MM-DD-CVE-XXX.md` 작성 (보안팀 책임).
- Tier 1/2 는 긴급 릴리스 브랜치로 머지, Tier 3 는 Renovate 자동 경로로 충분.
- 48시간 내 영향 범위 공지 + 필요시 자동 재스캔 트리거.

## 4. 롤아웃 전략 (Rollout)

### 4.1 단계적 적용 — Joern Pilot 중심

모든 엔진을 동시에 Tier 1 로 올리면 회귀 원인 분리가 어렵다. 다음 순서로 단계적 전환:

| 단계 | 시기 | 대상 | 목적 |
|---|---|---|---|
| A | Phase 3 T+9 | Joern Tier 1 적용 (ADR-0002) | 거버넌스 인프라(EngineMeta, Renovate, 회귀 게이트) 검증 |
| B | Phase 3 말 T+13 | `opensast/engines/base.py` 에 `EngineMeta`/Tier enum 추가 | 엔진 메타 레지스트리 정립 |
| C | Phase 4 초 T+14 | **Opengrep Tier 1 승격** (후속 ADR 발행) | 가장 시급한 공백 해소. Tier 1 이식 경험 확보 |
| D | Phase 4 중 T+15 | SpotBugs Tier 2 적용 | 중간 수준 정책 검증 |
| E | v1.0 준비 | Bandit/gosec Tier 3 정식화 | 상한 설정 + Renovate 자동 머지 |

### 4.2 즉시 적용 가능한 Quick Win — Phase 3 이전

ADR-0002 Phase 3 착수를 기다리지 않고 **지금 당장** 리스크를 낮출 3가지 PR:

1. **Bandit/Semgrep 상한 추가** (30분) — `Dockerfile` 의 `>=` 를 `>=X,<Y` 로 교체. Tier 3 의 최소 수준을 선제 적용.
2. **`/api/system/engines` 엔드포인트** (2시간) — `EngineMeta` 없이도 환경변수 기반으로 버전 노출 가능. 사용자 문의 대응 시간 대폭 단축.
3. **`pip-audit` CI 스텝** (1시간) — ROADMAP T9 항목이므로 원래 해야 할 일. Semgrep/Bandit 의존성 CVE 자동 감지.

이 Quick Win 들은 Tier 정책 정식 적용 전의 "안전망" 역할을 한다.

## 5. 결정 근거 (Rationale)

### 5.1 왜 3개 Tier 인가 — 2개는 거칠고 4개는 과함

2개 Tier (엄격/유연)로는 SpotBugs 같은 중간 엔진이 분류 불가. 4개 Tier 는 Tier 2 와 Tier 3 의 경계가 모호해 실무 판단 비용 증가. 3개가 경험적으로 최적.

### 5.2 왜 Opengrep 이 Joern 과 같은 Tier 1 인가

침투도(1차 Pass 주력)와 룰 결합도(113개 YAML)가 Joern 보다 오히려 높다. Opengrep 이 깨지면 OpenSAST 전체 가치 제안이 무너진다. ADR-0002 가 Joern 에 적용한 엄격도는 Opengrep 에 **더 강한 이유로** 적용되어야 한다.

### 5.3 왜 Bandit/gosec 이 유연 Tier 인가

둘 다 단일 언어 전용(Python, Go)이고, 내장 rule 기반이라 OpenSAST 쪽 룰 결합도가 낮다. Upstream 변동성도 역사적으로 낮다. 완전 자동화된 Renovate 경로로 충분하며, 여기에 Tier 1 수준의 리뷰 부담을 걸면 오히려 CVE 대응 속도만 늦춘다.

### 5.4 왜 엔진별로 다른 Dockerfile 이미지가 아닌 `.env.versions` 단일 파일인가

이미지 분리(Dockerfile.opengrep, Dockerfile.joern 등)는 빌드 시간·저장 용량·CI 매트릭스를 폭증시킨다. `.env.versions` 한 파일에 모든 버전을 선언하고 Dockerfile 에서 ARG 로 받는 방식이 운영상 단순. 이미지 분리는 Joern 전용 heavy 이미지(ADR-0001 결정 1.3)에만 적용하며, 버전 선언 자체는 계속 `.env.versions` 가 SSOT.

## 6. 결과 (Consequences)

### 6.1 긍정적

- **불일치 해소**: Joern 특수 케이스에서 범용 거버넌스로 승격. 엔진 추가 시 Tier 선정만 하면 정책 자동 적용.
- **리스크 비례 통제**: 엔진별 중요도에 맞춘 차등으로 리뷰 부담 최적화. Bandit/gosec 의 patch 업그레이드가 자동 머지되어 보안 패치 지연 없음.
- **감사 증빙 일원화**: `/api/system/engines` 단일 엔드포인트 + `scan_engine_runs.metadata` 로 "어느 스캔이 어느 버전 조합으로 실행됐나" 전수 추적.
- **공급망 보안 강화**: Tier 1/2 에 SHA256 검증. `pip-audit` + Renovate `vulnerabilityAlerts` 로 CVE 자동 감지.

### 6.2 부정적

- **초기 구현 비용**: `EngineMeta` 레지스트리·`.env.versions`·Renovate 설정·CI 워크플로 신규 작성에 엔지니어링 시간 투입 (Phase 3 T+13 ~ Phase 4 T+15, 약 2주).
- **Tier 1 엔진 리뷰 부담**: Opengrep Tier 1 승격 후 월 1회 patch PR 수동 리뷰 고정 업무 추가.
- **룰 작성 규칙 추가**: Opengrep YAML 에 `metadata.compatible_with.opengrep: ">=1.XXX,<2.0"` 의무화 — 기존 113개 룰 전수 편집 필요(일회성).

### 6.3 중립 — 수용된 트레이드오프

- **Tier 경계 judgement call**: SpotBugs 를 Tier 2 로 둔 것은 현시점 판단. 향후 룰 결합도 증가 시 Tier 1 승격 ADR 발행 가능.
- **Renovate 외부 의존**: 사내 대안 전환 여지 유지.
- **LGPL-2.1 엔진 포함**: Opengrep/Semgrep 은 LGPL 이고 OpenSAST 는 Apache-2.0. subprocess 호출 구조에서는 LGPL 파생물 조항 미적용이지만, 사용자 가이드에 명시 필요.

## 7. 대안 (Alternatives Considered)

### 7.1 모든 엔진을 Tier 1 적용
- **기각** — Bandit/gosec 같은 저변동성 엔진에 월간 리뷰 부담 부과는 비경제적. 실제 리스크 대비 관리 비용 불균형.

### 7.2 모든 엔진을 Tier 3 유지 (ADR-0002 정책 폐기)
- **기각** — ADR-0002 의 Joern 특수 상황(CPG API 잦은 변경, 19개 `.sc` 룰 의존)을 부정하는 결정. 실제 운영상 Joern 업그레이드 시 룰 회귀가 반복 발생할 것.

### 7.3 엔진별 개별 ADR (ADR-0002, ADR-0005, ADR-0006, ...)
- **기각** — 엔진 수만큼 ADR 이 증식. 정책의 일관성 확보 어려움. 공통 정책은 한 ADR 로 묶고, 엔진별 세부는 Tier 매핑으로 처리하는 것이 관리 가능.

### 7.4 상용 의존성 관리 서비스(Snyk 등) 도입
- **기각** — 공공 온프레미스 환경에서 외부 상용 서비스 의존은 운영 부담 증가. Renovate(오픈소스) 로 충분.

## 8. 참조

- SSOT 파일: `.env.versions` (Phase 3 T+13 전까지 신설)
- 엔진 메타: `opensast/engines/base.py::EngineMeta` (Phase 3 T+13 전까지 추가)
- 감사 API: `GET /api/system/engines` (Phase 3 T+13 전까지 구현)
- Renovate 설정: `.github/renovate.json`
- CI 게이트: `.github/workflows/engine-regression.yml`
- License check: `scripts/check_licenses.py` — Apache-2.0, MIT, BSD-2/3, EPL-2.0, LGPL-2.1 허용
- Tier 1 엔진별 ADR: ADR-0002 (Joern), ADR-0005 예정 (Opengrep, Phase 4 초)

### 예약 ADR 번호

- **ADR-0003**: 예약 — 용도 미정
- **ADR-0005** (예정): Opengrep 엄격 고정 — Phase 4 초 발행 목표
