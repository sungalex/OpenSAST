# 커스텀 룰 작성

> 이 문서는 `docs/USER_GUIDE.md`(1,926줄 단일 파일)를 독자별로 분할한 것이다
> ([ADR-0007](../adr/0007-documentation-architecture.md)).

---

## 커스텀 룰 작성

### 9.1 Opengrep YAML 룰

위치: `rules/opengrep/{java,python,javascript,go,common}/*.yml`

**메타데이터 규약** (자동 MOIS 매핑용):

```yaml
rules:
  - id: mois-sr1-1-python-sql-fstring
    metadata:
      mois_id: "SR1-1"           # 필수: 행안부 ID
      cwe: "CWE-89"              # 필수: CWE ID
      category: "입력데이터 검증 및 표현"
      severity: "HIGH"
      description: "..."
      remediation: "..."
    languages: [python]
    severity: ERROR
    message: "..."
    patterns:
      - pattern: $CUR.execute(f"...{$X}...")
```

> SARIF 정규화 시 `properties.tags` 에 `mois-SR1-1` 형태 태그가 있거나 `cwe-*` 태그가 있으면 Finding에 자동으로 `mois_id`가 설정된다. 태그가 없어도 CWE ID가 있으면 `items_for_cwe()`로 역매핑된다.

기본 제공 룰 요약:

| 파일 | 다루는 MOIS |
|------|-------------|
| `java/sql-injection.yml` | SR1-1 (JDBC concat, MyBatis `${}`) |
| `java/command-injection.yml` | SR1-4 / SR1-2 |
| `java/xss.yml` | SR1-3 / SR1-17 |
| `java/crypto.yml` | SR2-4 / SR2-8 |
| `java/deserialization.yml` | SR1-18 / SR1-11 |
| `python/injection.yml` | SR1-1 / SR1-4 / SR1-17 / SR1-18 |
| `python/crypto.yml` | SR2-4 / SR2-8 / SR2-11 |
| `javascript/injection.yml` | SR1-3 / SR1-17 / SR1-4 |
| `go/injection.yml` | SR1-4 / SR1-1 |
| `common/secrets.yml` | SR2-6 / SR4-1 / SR6-2 |

### 9.2 CodeQL 쿼리

위치: `rules/codeql/<language>/*.ql`

예시: `rules/codeql/java/toctou.ql`(SR3-1 TOCTOU). 쿼리 헤더 주석에
`@id mois/sr3-1-...`, `@tags mois/sr3-1` 와 같이 MOIS ID를 포함하면
SARIF 결과에 반영되어 자동 매핑된다.

---
